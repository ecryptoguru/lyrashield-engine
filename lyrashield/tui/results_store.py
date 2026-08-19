# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Local SQLite results store for LyraShield Local, encrypted at rest.

Findings and reports persist locally — no cloud required. The SQLite database
is encrypted at rest via app-level envelope encryption: a data-encryption key
(DEK) wraps each row's payload, and the DEK itself is stored in the OS
keychain via the ``keyring`` library. This avoids a hard SQLCipher build
dependency while still keeping the database unreadable without the keychain.

The store never contains raw BYOK credentials — only scan results and report
artifacts. Secrets stay in the keychain via ``byok_config``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.fernet import Fernet


if TYPE_CHECKING:
    from collections.abc import Iterator


logger = logging.getLogger(__name__)


KEYCHAIN_SERVICE = "LyraShield-Local"
KEYCHAIN_DEK = "results-store-dek"

# Default location for the local results store. Kept under the user's home so
# it survives app updates and is never bundled into the wheel.
DEFAULT_STORE_DIR = Path.home() / ".lyrashield" / "local"
DEFAULT_STORE_PATH = DEFAULT_STORE_DIR / "results.db"


# ---------------------------------------------------------------------------
# OS keychain helpers. These are the single point where ``keyring`` is
# imported so tests can monkeypatch the backend.
# ---------------------------------------------------------------------------


def keyring_set(service: str, key: str, value: str) -> bool:
    """Store ``value`` under ``service``/``key`` in the OS keychain.

    Returns ``True`` on success. If no keyring backend is available (e.g. a
    headless CI container), falls back to returning ``False`` so callers can
    decide whether to degrade gracefully. Never writes a plaintext file.
    """
    try:
        import keyring  # noqa: PLC0415

        keyring.set_password(service, key, value)
    except Exception:  # noqa: BLE001
        logger.warning("keyring backend unavailable; secret not stored")
        return False
    return True


def keyring_get(service: str, key: str) -> str | None:
    """Retrieve a secret from the OS keychain, or ``None`` if absent/unavailable."""
    try:
        import keyring  # noqa: PLC0415

        return keyring.get_password(service, key)
    except Exception:  # noqa: BLE001
        return None


def keyring_delete(service: str, key: str) -> bool:
    try:
        import keyring  # noqa: PLC0415

        keyring.delete_password(service, key)
    except Exception:  # noqa: BLE001
        return False
    return True


# ---------------------------------------------------------------------------
# Envelope encryption: a single DEK stored in the keychain wraps row payloads.
# ---------------------------------------------------------------------------


def _get_or_create_dek() -> bytes:
    """Return the Fernet DEK from the keychain, creating it if absent."""
    dek = keyring_get(KEYCHAIN_SERVICE, KEYCHAIN_DEK)
    if dek:
        return dek.encode()
    dek = Fernet.generate_key().decode()
    keyring_set(KEYCHAIN_SERVICE, KEYCHAIN_DEK, dek)
    return dek.encode()


def _fernet() -> Fernet:
    return Fernet(_get_or_create_dek())


def _encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# Results store.
# ---------------------------------------------------------------------------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_mode TEXT NOT NULL,
    provider TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""


@dataclass
class RunRecord:
    run_id: str
    target: str
    scan_mode: str
    provider: str
    created_at: int
    status: str
    payload: dict[str, Any]


@dataclass
class FindingRecord:
    finding_id: str
    run_id: str
    severity: str
    title: str
    payload: dict[str, Any]


class ResultsStore:
    """Encrypted-at-rest local SQLite results store."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_STORE_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False so the TUI's async loop can share the handle.
        return sqlite3.connect(str(self.path), check_same_thread=False)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def save_run(self, run: RunRecord) -> None:
        payload = _encrypt(json.dumps(run.payload, separators=(",", ":")))
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runs "
                "(run_id, target, scan_mode, provider, created_at, status, encrypted_payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run.run_id,
                    run.target,
                    run.scan_mode,
                    run.provider,
                    run.created_at,
                    run.status,
                    payload,
                ),
            )
            conn.commit()

    def update_run_status(self, run_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE runs SET status = ? WHERE run_id = ?",
                (status, run_id),
            )
            conn.commit()

    def save_finding(self, finding: FindingRecord) -> None:
        payload = _encrypt(json.dumps(finding.payload, separators=(",", ":")))
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO findings "
                "(finding_id, run_id, severity, title, encrypted_payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    finding.finding_id,
                    finding.run_id,
                    finding.severity,
                    finding.title,
                    payload,
                ),
            )
            conn.commit()

    def list_runs(self) -> list[RunRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, target, scan_mode, provider, created_at, status, encrypted_payload "
                "FROM runs ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_run(r) for r in rows]

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT run_id, target, scan_mode, provider, created_at, status, encrypted_payload "
                "FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return self._row_to_run(row) if row else None

    def list_findings(self, run_id: str) -> list[FindingRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT finding_id, run_id, severity, title, encrypted_payload "
                "FROM findings WHERE run_id = ? ORDER BY severity",
                (run_id,),
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def delete_run(self, run_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            conn.commit()

    def iter_runs(self) -> Iterator[RunRecord]:
        yield from self.list_runs()

    @staticmethod
    def _row_to_run(row: tuple[Any, ...]) -> RunRecord:
        run_id, target, scan_mode, provider, created_at, status, encrypted = row
        payload: dict[str, Any] = {}
        try:
            payload = json.loads(_decrypt(encrypted))
        except Exception:  # noqa: BLE001
            logger.warning("Failed to decrypt run payload for %s", run_id)
        return RunRecord(
            run_id=run_id,
            target=target,
            scan_mode=scan_mode,
            provider=provider,
            created_at=created_at,
            status=status,
            payload=payload,
        )

    @staticmethod
    def _row_to_finding(row: tuple[Any, ...]) -> FindingRecord:
        finding_id, run_id, severity, title, encrypted = row
        payload: dict[str, Any] = {}
        try:
            payload = json.loads(_decrypt(encrypted))
        except Exception:  # noqa: BLE001
            logger.warning("Failed to decrypt finding payload for %s", finding_id)
        return FindingRecord(
            finding_id=finding_id,
            run_id=run_id,
            severity=severity,
            title=title,
            payload=payload,
        )


def new_run_id() -> str:
    """Generate a stable, unique run id for the local store."""
    return f"local-{int(time.time())}-{secrets.token_hex(4)}"


def store_path_from_env(env: dict[str, str] | None = None) -> Path:
    """Resolve the store path from env, falling back to the default."""
    e = env if env is not None else os.environ
    p = e.get("LYRASHIELD_LOCAL_STORE_PATH")
    return Path(p) if p else DEFAULT_STORE_PATH
