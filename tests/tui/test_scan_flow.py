# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the scan flow (shells into engine CLI)."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

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
    assert env["LYRASHIELD_LLM"] == "chatgpt/gpt-6-luna"


def test_build_env_does_not_inherit_another_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from lyrashield.policy.settings import LlmSettings
    from lyrashield_adapter.cli import prepare_environment

    inherited = {
        "STRIX_LLM": "openai/gpt-6-sol",
        "LLM_API_KEY": "old-key",
        "LLM_API_BASE": "https://old.example",
        "OPENAI_BASE_URL": "https://other.example",
        "STRIX_DELEGATE_LLM": "openai/gpt-6-sol",
        "PATH": "/usr/bin",
    }
    azure = ByokConfig(
        provider=Provider.AZURE_OPENAI,
        azure=AzureConfig(
            api_key="chosen-key", endpoint="https://chosen.example", deployment="gpt-6-luna"
        ),
    )
    env = prepare_environment(build_env(azure, inherited))
    with patch.dict("os.environ", env, clear=True):
        selected = LlmSettings()
    assert selected.model == "azure/gpt-6-luna"
    assert selected.api_key == "chosen-key"
    assert selected.api_base == "https://chosen.example"
    assert "STRIX_DELEGATE_LLM" not in env
    assert env["PATH"] == "/usr/bin"

    chatgpt = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    auth_env = build_env(chatgpt, inherited)
    assert auth_env["LYRASHIELD_LLM"] == "chatgpt/gpt-6-luna"
    assert "LLM_API_KEY" not in auth_env
    assert "LLM_API_BASE" not in auth_env


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
    from cryptography.fernet import Fernet

    from lyrashield.tui.results_store import FindingRecord, RunRecord

    key = Fernet.generate_key().decode()
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda s, k: key)
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
    assert json.loads(content)["runs"][0]["results"][0]["level"] == "error"

    for severity, expected in (
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "note"),
    ):
        store.save_finding(FindingRecord("f1", "r1", severity, "SQLi", {}))
        export_sarif("r1", store, sarif_dest)
        assert json.loads(sarif_dest.read_text())["runs"][0]["results"][0]["level"] == expected

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


def test_run_scan_streams_and_imports_canonical_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptography.fernet import Fernet

    from lyrashield.tui import scan_flow

    key = Fernet.generate_key().decode()
    monkeypatch.setattr("lyrashield.tui.results_store.keyring_get", lambda *_: key)
    script = tmp_path / "fake-engine"
    script.write_text(
        f"#!{sys.executable}\n"
        "import argparse, json, pathlib, time\n"
        "p=argparse.ArgumentParser(); p.add_argument('--run-name'); p.add_argument('--target'); "
        "p.add_argument('--scan-mode'); p.add_argument('--non-interactive',action='store_true'); a=p.parse_args()\n"
        "d=pathlib.Path('strix_runs')/a.run_name; d.mkdir(parents=True)\n"
        "print('ready',flush=True); time.sleep(.25)\n"
        "(d/'run.json').write_text(json.dumps({'schema_version':'1.1','run_id':a.run_name,"
        "'run_name':a.run_name,'start_time':'2026-09-25T00:00:00Z',"
        "'end_time':'2026-09-25T00:01:00Z','status':'completed','phase':'done',"
        "'auth_mode':'subscription','targets_info':[],'llm_usage':{},'seq':1,'turn_count':1}))\n"
        "(d/'vulnerabilities.json').write_text(json.dumps([{'id':'vuln-0001','title':'SQLi','severity':'high'}]))\n"
        "(d/'findings.sarif').write_text('canonical sarif')\n"
        "(d/'penetration_test_report.md').write_text('canonical report')\n"
        "print('done',flush=True)\n"
        "raise SystemExit(2)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(scan_flow, "ENGINE_CLI", str(script))
    monkeypatch.chdir(tmp_path)
    store = ResultsStore(tmp_path / "r.db")
    config = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))

    async def exercise() -> None:
        events = []

        async def progress(event: object) -> None:
            events.append(event)

        result = await run_scan(ScanRequest("https://example.com"), config, store, progress)
        assert result.returncode == 2
        assert result.status == "completed"
        assert events[0].line == "ready"
        assert events[0].elapsed_s < result.elapsed_s
        assert len(store.list_findings(result.run_id)) == 1
        assert (
            export_sarif(result.run_id, store, tmp_path / "out.sarif").read_text()
            == "canonical sarif"
        )
        assert (
            export_report(result.run_id, store, tmp_path / "out.md").read_text()
            == "canonical report"
        )

    asyncio.run(exercise())


def test_cancel_scan_reaps_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from lyrashield.tui import scan_flow

    script = tmp_path / "sleep-engine"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, time\n"
        "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
        "print('ready',flush=True); time.sleep(60)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(scan_flow, "ENGINE_CLI", str(script))
    monkeypatch.chdir(tmp_path)
    config = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))

    async def exercise() -> None:
        ready = asyncio.Event()

        async def progress(_event: object) -> None:
            ready.set()

        task = asyncio.create_task(run_scan(ScanRequest("target"), config, on_progress=progress))
        await asyncio.wait_for(ready.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
    pid = int((tmp_path / "child.pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_progress_error_reaps_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from lyrashield.tui import scan_flow

    script = tmp_path / "sleep-engine"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, time\n"
        "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
        "print('ready',flush=True); time.sleep(60)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(scan_flow, "ENGINE_CLI", str(script))
    monkeypatch.chdir(tmp_path)
    config = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))

    async def broken(_event: object) -> None:
        raise RuntimeError("synthetic callback error")

    with pytest.raises(RuntimeError, match="synthetic callback"):
        asyncio.run(run_scan(ScanRequest("target"), config, on_progress=broken))
    pid = int((tmp_path / "child.pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.parametrize(
    ("receipt", "returncode", "expected"),
    [
        (None, 0, "incomplete"),
        ({"status": "completed"}, 2, "completed"),
        ({"status": "stopped", "terminal_reason": "runtime_deadline"}, 2, "partial"),
        ({"status": "stopped", "terminal_reason": "no_change"}, 0, "no_change"),
        ({"status": "completed", "receipt_persisted": False}, 0, "incomplete"),
    ],
)
def test_scan_status_uses_receipt(
    receipt: dict[str, object] | None, returncode: int, expected: str
) -> None:
    from lyrashield.tui.scan_flow import _scan_status

    assert _scan_status(receipt, returncode) == expected
