# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the scan flow (shells into engine CLI)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from lyrashield.tui.byok_config import AzureConfig, ByokConfig, ChatGptConfig, Provider
from lyrashield.tui.results_store import ResultsStore
from lyrashield.tui.scan_flow import (
    ScanRequest,
    build_argv,
    build_env,
    export_report,
    export_sarif,
    run_scan,
)


def test_build_argv_includes_all_modes() -> None:
    """All scan modes produce a valid engine argv — no depth gating."""
    cfg = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    for mode in ("SAFE", "QUICK", "STANDARD", "DEEP", "CUSTOM"):
        req = ScanRequest(target="https://example.com", scan_mode=mode, max_budget_usd=2.0)
        argv = build_argv(req, cfg)
        assert "--target" in argv
        assert "https://example.com" in argv
        assert "--non-interactive" in argv
        assert "--max-budget" in argv
        assert "2.0" in argv


def test_build_env_applies_byok() -> None:
    cfg = ByokConfig(
        provider=Provider.AZURE_OPENAI,
        azure=AzureConfig(api_key="k", endpoint="https://x.openai.azure.com", deployment="dep"),
    )
    env = build_env(cfg, {"PATH": "/usr/bin"})
    assert env["AZURE_OPENAI_API_KEY"] == "k"
    assert env["LYRASHIELD_LLM"] == "azure/dep"
    assert env["PATH"] == "/usr/bin"


def test_build_env_chatgpt() -> None:
    cfg = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    env = build_env(cfg, {})
    assert env["LYRASHIELD_LLM"] == "chatgpt/gpt-5.6"


def test_run_scan_no_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When the engine CLI is absent, the scan surfaces a FileNotFoundError."""
    from lyrashield.tui import scan_flow

    async def fake_exec(*args: object, **kwargs: object) -> int:  # noqa: ARG001
        raise FileNotFoundError("lyrashield")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    cfg = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    req = ScanRequest(target="https://example.com", scan_mode="QUICK")

    # Patch the store to avoid touching the keychain.
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda s, k: None)
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_set", lambda s, k, v: True)
    store = ResultsStore(path=tmp_path / "r.db")

    async def _run() -> None:
        await run_scan(req, cfg, store)

    try:
        asyncio.run(_run())
    except FileNotFoundError:
        pass  # expected


def test_export_sarif_and_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from lyrashield.tui.results_store import FindingRecord, RunRecord

    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda s, k: None)
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_set", lambda s, k, v: True)
    store = ResultsStore(path=tmp_path / "r.db")
    store.save_run(
        RunRecord(
            run_id="r1",
            target="t",
            scan_mode="DEEP",
            provider="chatgpt-oauth",
            created_at=1,
            status="completed",
            payload={},
        )
    )
    store.save_finding(FindingRecord("f1", "r1", "HIGH", "SQLi", {"description": "desc"}))

    sarif_dest = tmp_path / "out.sarif"
    export_sarif("r1", store, sarif_dest)
    assert sarif_dest.exists()
    content = sarif_dest.read_text()
    assert "LyraShield Local" in content
    assert "SQLi" in content

    report_dest = tmp_path / "out.md"
    export_report("r1", store, report_dest)
    assert report_dest.exists()
    assert "SQLi" in report_dest.read_text()


def test_export_missing_run_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda s, k: None)
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_set", lambda s, k, v: True)
    store = ResultsStore(path=tmp_path / "r.db")
    try:
        export_sarif("nope", store, tmp_path / "x.sarif")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError")
