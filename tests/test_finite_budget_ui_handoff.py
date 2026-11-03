"""The paid preflight owner is handed to either UI without replaying its usage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agents.usage import Usage

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.interface import cli
from lyrashield.interface.tui import app as tui


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["cli", "tui"])
async def test_preflight_owner_and_settled_usage_handoff_once(tmp_path, monkeypatch, surface):
    owner = ReportState("handoff")
    owner._run_dir = tmp_path
    journal = owner.enable_finite_budget(0.8)
    admission = journal.reserve(0.6)
    usage = Usage(requests=1, input_tokens=7, output_tokens=2, total_tokens=9)
    assert owner.record_sdk_usage(
        agent_id="warmup",
        model="openai/gpt-6-luna",
        usage=usage,
        budget_attempt=admission,
        budget_cost=0.17,
    )
    args = SimpleNamespace(
        run_name="handoff",
        targets_info=[{"original": "offline.test"}],
        instruction=None,
        scan_mode="quick",
        non_interactive=True,
        interactive=False,
        max_budget_usd=None,
        runtime_budget_seconds=100,
        resume=True,
        warm_up_usages=[("openai/gpt-6-luna", usage)],
        _preflight_usage_owner=owner,
    )
    monkeypatch.setattr(state_module, "_global_report_state", None)

    def reject_new_owner(*_args, **_kwargs):
        raise AssertionError("UI must reuse the financial preflight owner")

    if surface == "cli":
        monkeypatch.setattr(cli, "ReportState", reject_new_owner)
        monkeypatch.setattr(cli, "_resolve_sandbox_image", lambda: "owned-offline-fixture")
        monkeypatch.setattr(
            cli, "run_strix_scan", AsyncMock(return_value=SimpleNamespace(final_output="done"))
        )
        monkeypatch.setattr(cli.session_manager, "cleanup", AsyncMock(return_value="removed"))
        monkeypatch.setattr(cli.atexit, "register", lambda *_args: None)
        monkeypatch.setattr(cli.signal, "signal", lambda *_args: None)
        await cli.run_cli(args)
    else:
        monkeypatch.setattr(tui, "ReportState", reject_new_owner)
        monkeypatch.setattr(tui.StrixTUIApp, "_setup_cleanup_handlers", lambda _self: None)
        app = tui.StrixTUIApp(args)
        assert app.report_state is owner
    assert args.max_budget_usd == 0.8
    assert owner.run_record["llm_usage"]["requests"] == 1
    assert owner.run_record["llm_usage"]["total_tokens"] == 9
    assert journal.snapshot()["_finite_budget_guard"]["pending"] == []
