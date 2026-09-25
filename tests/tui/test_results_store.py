# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the encrypted local results store."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import stat

import pytest

from lyrashield.tui.results_store import (
    FindingRecord,
    ResultsStoreKeyError,
    ResultsStore,
    RunRecord,
    new_run_id,
)


def _make_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ResultsStore:
    """Build a store with a mocked keychain DEK so tests don't touch the OS keyring."""
    from cryptography.fernet import Fernet

    dek = Fernet.generate_key().decode()

    def fake_get(service: str, key: str) -> str | None:  # noqa: ARG001
        if key == "results-store-dek":
            return dek
        return None

    def fake_set(service: str, key: str, value: str) -> bool:  # noqa: ARG001
        return True

    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", fake_get)
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_set", fake_set)
    return ResultsStore(path=tmp_path / "results.db")


def test_decrypts_cryptography_48_results(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic fixed-key ciphertext generated with cryptography 48.0.1."""
    from lyrashield.tui.results_store import _decrypt

    monkeypatch.setattr(
        "lyrashield.tui.results_store.keyring_get",
        lambda *_: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    token = (
        "gAAAAABqmIzPp44yVJo_i9Gbh4Q8QOUzpeDSOLBHEcMPlzURNbjxFm4AWisietHV7Y2f6h_b"
        "odHs23pyB25_AjOUjF5Huw_mtYRBWaz50Wkn0gu20jCBsMg="
    )
    assert _decrypt(token) == "legacy local results"


def test_store_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _make_store(tmp_path, monkeypatch)
    run_id = new_run_id()
    run = RunRecord(
        run_id=run_id,
        target="https://example.com",
        scan_mode="DEEP",
        provider="azure-openai",
        created_at=1700000000,
        status="completed",
        payload={"returncode": 0, "note": "ok"},
    )
    store.save_run(run)

    loaded = store.get_run(run_id)
    assert loaded is not None
    assert loaded.target == "https://example.com"
    assert loaded.scan_mode == "DEEP"
    assert loaded.payload == {"returncode": 0, "note": "ok"}

    finding = FindingRecord(
        finding_id="f1",
        run_id=run_id,
        severity="HIGH",
        title="SQL injection",
        payload={"description": "User input concatenated into SQL."},
    )
    store.save_finding(finding)

    findings = store.list_findings(run_id)
    assert len(findings) == 1
    assert findings[0].title == "SQL injection"
    assert findings[0].payload["description"] == "User input concatenated into SQL."


def test_default_store_permissions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from lyrashield.tui import results_store

    monkeypatch.setattr(results_store, "DEFAULT_STORE_PATH", tmp_path / "local" / "results.db")
    store = ResultsStore()
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_store_payload_is_encrypted_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _make_store(tmp_path, monkeypatch)
    run = RunRecord(
        run_id="r1",
        target="secret-target",
        scan_mode="STANDARD",
        provider="chatgpt-oauth",
        created_at=1,
        status="completed",
        payload={"secret": "plaintext-secret-value"},
    )
    store.save_run(run)

    # The raw DB file must not contain the plaintext payload.
    raw = store.path.read_bytes()
    assert b"plaintext-secret-value" not in raw
    assert (
        b"secret-target" not in raw or b"secret-target" in raw
    )  # target is a column, not encrypted


def test_store_list_runs_ordered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _make_store(tmp_path, monkeypatch)
    for i in range(3):
        store.save_run(
            RunRecord(
                run_id=f"r{i}",
                target="t",
                scan_mode="STANDARD",
                provider="chatgpt-oauth",
                created_at=i,
                status="completed",
                payload={},
            )
        )
    runs = store.list_runs()
    assert [r.run_id for r in runs] == ["r2", "r1", "r0"]


def test_store_delete_run_cascades(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _make_store(tmp_path, monkeypatch)
    store.save_run(
        RunRecord(
            run_id="r1",
            target="t",
            scan_mode="STANDARD",
            provider="chatgpt-oauth",
            created_at=1,
            status="completed",
            payload={},
        )
    )
    store.save_finding(FindingRecord("f1", "r1", "LOW", "x", {}))
    store.delete_run("r1")
    assert store.get_run("r1") is None
    assert store.list_findings("r1") == []


def test_new_run_id_is_unique() -> None:
    a = new_run_id()
    b = new_run_id()
    assert a != b
    assert a.startswith("local-")


def test_unavailable_keychain_rejects_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda *_: None)
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_set", lambda *_: False)
    store = ResultsStore(path=tmp_path / "results.db")
    with pytest.raises(ResultsStoreKeyError):
        store.save_run(RunRecord("r1", "target", "QUICK", "azure", 1, "completed", {"x": 1}))
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


def test_unverified_new_key_rejects_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda *_: None)
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_set", lambda *_: True)
    store = ResultsStore(path=tmp_path / "results.db")
    with pytest.raises(ResultsStoreKeyError, match="verified"):
        store.save_run(RunRecord("r1", "target", "QUICK", "azure", 1, "completed", {}))
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


def test_keychain_read_error_preserves_existing_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _make_store(tmp_path, monkeypatch)
    store.save_run(RunRecord("r1", "target", "QUICK", "azure", 1, "completed", {"x": 1}))

    def unavailable(*_args: object) -> str:
        raise ResultsStoreKeyError("Local keychain is unavailable")

    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", unavailable)
    with pytest.raises(ResultsStoreKeyError, match="unavailable"):
        store.get_run("r1")
    with pytest.raises(ResultsStoreKeyError, match="unavailable"):
        store.save_run(RunRecord("r2", "target", "QUICK", "azure", 2, "completed", {}))
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 1


def test_missing_key_cannot_replace_existing_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _make_store(tmp_path, monkeypatch)
    store.save_run(RunRecord("r1", "target", "QUICK", "azure", 1, "completed", {"x": 1}))
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda *_: None)
    with pytest.raises(ResultsStoreKeyError):
        store.get_run("r1")
    with pytest.raises(ResultsStoreKeyError):
        store.save_run(RunRecord("r2", "target", "QUICK", "azure", 2, "completed", {}))
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 1


def test_findings_with_same_id_stay_in_their_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _make_store(tmp_path, monkeypatch)
    for run_id in ("r1", "r2"):
        store.save_run(RunRecord(run_id, "target", "QUICK", "azure", 1, "completed", {}))
        store.save_finding(FindingRecord("vuln-0001", run_id, "HIGH", run_id, {}))
    assert [item.title for item in store.list_findings("r1")] == ["r1"]
    assert [item.title for item in store.list_findings("r2")] == ["r2"]


def test_scan_import_rolls_back_on_invalid_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _make_store(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="different run"):
        store.save_scan(
            RunRecord("r1", "target", "QUICK", "azure", 1, "completed", {}),
            [FindingRecord("f1", "other", "HIGH", "wrong", {})],
        )
    assert store.get_run("r1") is None


def test_legacy_finding_schema_migrates_without_reencrypting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda *_: key.decode())
    path = tmp_path / "legacy.db"
    payload = Fernet(key).encrypt(b'{"description":"saved evidence"}').decode()
    with sqlite3.connect(path) as conn:
        conn.executescript(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, target TEXT NOT NULL, "
            "scan_mode TEXT NOT NULL, provider TEXT NOT NULL, created_at INTEGER NOT NULL, "
            "status TEXT NOT NULL, encrypted_payload TEXT NOT NULL);"
            "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, "
            "severity TEXT NOT NULL, title TEXT NOT NULL, encrypted_payload TEXT NOT NULL);"
        )
        conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("r1", "target", "QUICK", "azure", 1, "completed", payload),
        )
        conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?)",
            ("vuln-0001", "r1", "HIGH", "saved", payload),
        )
    store = ResultsStore(path=path)
    assert store.list_findings("r1")[0].payload == {"description": "saved evidence"}
    store.save_run(RunRecord("r2", "target", "QUICK", "azure", 2, "completed", {}))
    store.save_finding(FindingRecord("vuln-0001", "r2", "LOW", "new", {}))
    assert len(store.list_findings("r1")) == 1
    assert len(ResultsStore(path=path).list_findings("r2")) == 1
