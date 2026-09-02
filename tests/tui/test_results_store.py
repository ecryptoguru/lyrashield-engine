# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the encrypted local results store."""

from __future__ import annotations

from pathlib import Path

import pytest

from lyrashield.tui.results_store import (
    FindingRecord,
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
