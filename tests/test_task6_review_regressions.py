"""Regressions from the independent Task 6 review."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from importlib import import_module
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from openai import RateLimitError

from lyrashield.agents import factory
from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.policy import diagnostics
from lyrashield.policy.diagnostics import DiagnosticModel
from lyrashield.policy.settings import RuntimeSettings
from lyrashield.tools.finish.tool import _do_finish
from lyrashield_adapter.cli import _register_lyrashield_skills
from strix import skills
from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from tests.test_runtime_budget_preprocessing import _stub_scan_environment


main_module = import_module("lyrashield.interface.main")


@pytest.mark.parametrize("incomplete", [False, True])
def test_default_schema_threshold_uses_actual_finish_assessment(
    tmp_path, monkeypatch, incomplete
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "0")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    hydrate_coverage_from_disk(tmp_path)
    state = ReportState("review-default-schema")
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: state)
    _record_impl(
        surface="application",
        risk_area="baseline",
        outcome="no_issue_found",
        evidence="Assigned baseline assessed",
        agent_id="root",
        agent_name="root",
    )
    graph = {"statuses": {"root": "running"}, "parent_of": {"root": None}}
    if incomplete:
        graph["statuses"]["child"] = "failed"
        graph["parent_of"]["child"] = "root"
    result = _do_finish(
        parent_id=None,
        executive_summary="Assessment complete.",
        methodology="Reviewed authorized baseline.",
        technical_analysis="No confirmed findings.",
        recommendations="Retest after changes.",
        agent_graph=graph,
    )
    assert result["success"] is True
    assert "scan_quality" not in state.run_record
    assert result["coverage_complete"] is (not incomplete)
    assert main_module._non_interactive_exit_code(
        state, fail_on="high", finish_result=json.dumps(result)
    ) == (5 if incomplete else 0)
    assert main_module._non_interactive_exit_code(state) == 0
    hydrate_coverage_from_disk(tmp_path / "cleared")


@pytest.mark.parametrize("enabled", [False, True])
def test_root_coverage_guidance_matches_actual_registered_tools(monkeypatch, enabled) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1" if enabled else "0")
    _register_lyrashield_skills()
    agent = factory.build_strix_agent(is_root=True)
    names = {tool.name for tool in agent.tools}
    prompt = agent.instructions
    assert ("list_coverage" in names) is enabled
    assert ("`list_coverage`" in prompt) is enabled
    assert "Coverage Reconciliation" in prompt
    assert "unresolved" in prompt
    if not enabled:
        assert "filed reports" in prompt


def test_unknown_skill_category_cannot_match_real_bare_alias() -> None:
    settings = RuntimeSettings(subagent_turn_limits={"imaginary/xss": 3})
    assert settings.skill_turn_limit(["xss"], hard_limit=50) is None
    assert settings.skill_turn_limit(["imaginary/xss"], hard_limit=50) is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO regression")
def test_diagnostics_fifo_cannot_block_scan(tmp_path) -> None:
    directory = tmp_path / ".state"
    directory.mkdir()
    path = directory / "request-diagnostics.json"
    os.mkfifo(path)
    script = (
        "from pathlib import Path; import sys; "
        "from lyrashield.policy.diagnostics import append_diagnostic; "
        "append_diagnostic(Path(sys.argv[1]), {'outcome':'completed'}); print('done')"
    )
    try:
        result = subprocess.run(  # noqa: S603 - fixed child code and test-owned path
            [sys.executable, "-c", script, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("diagnostic FIFO blocked the synchronous scan-finalization writer")
    assert result.stdout.strip() == "done"
    assert stat.S_ISFIFO(path.lstat().st_mode)


@pytest.mark.asyncio
@pytest.mark.parametrize("streamed", [False, True])
async def test_sdk_error_request_id_is_allowlisted_without_error_body(tmp_path, streamed) -> None:
    response = httpx.Response(
        429,
        headers={"x-request-id": "req_fixture"},
        request=httpx.Request("POST", "https://provider.invalid"),
    )
    failure = RateLimitError("PRIVATE ERROR", response=response, body={"prompt": "PRIVATE BODY"})

    class Inner:
        async def get_response(self):
            raise failure

        async def stream_response(self):
            raise failure
            yield

    model = DiagnosticModel(
        Inner(), model_name="model", route="responses", run_dir=lambda: tmp_path
    )
    with pytest.raises(RateLimitError):
        if streamed:
            async for _ in model.stream_response():
                pass
        else:
            await model.get_response()
    content = (tmp_path / ".state" / "request-diagnostics.json").read_text()
    entry = json.loads(content)["entries"][0]
    assert entry["request_id"] == "req_fixture"
    assert entry["retry_reason"] == "rate_limited"
    assert "PRIVATE" not in content


@pytest.mark.asyncio
async def test_running_shell_notice_does_not_instruct_duplicate_execution() -> None:
    async def invoke(_ctx: Any, _input: str):
        return "Process running with session ID 7\nOutput:\nstarted"

    tool = factory._wrap_exec_command(
        factory.FunctionTool(
            name="exec_command",
            description="shell",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=invoke,
        )
    )
    result = await tool.on_invoke_tool(None, '{"cmd":"side-effecting-command"}')
    assert "remains active" in result
    assert "before retrying" in result
    assert "Rerun it" not in result


@pytest.mark.parametrize("incomplete", [False, True])
def test_main_passes_finish_result_to_explicit_gate(tmp_path, monkeypatch, incomplete) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "0")
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(source),
            "-n",
            "--run-name",
            "review-main",
            "--scope-mode",
            "full",
            "--fail-on",
            "high",
        ],
    )
    _stub_scan_environment(monkeypatch)
    monkeypatch.setattr(main_module, "pull_docker_image", Mock())
    state = SimpleNamespace(
        run_record={"status": "completed"}, vulnerability_reports=[], cleanup=Mock()
    )
    monkeypatch.setattr(main_module, "get_global_report_state", lambda: state)
    result = {
        "success": True,
        "scan_completed": True,
        "coverage_complete": not incomplete,
        "assessment_reasons": ["agent_work_incomplete"] if incomplete else ["no_findings_recorded"],
    }
    monkeypatch.setattr(
        main_module,
        "run_cli",
        AsyncMock(return_value=SimpleNamespace(final_output=json.dumps(result))),
    )
    if incomplete:
        with pytest.raises(SystemExit) as exit_info:
            main_module.main()
        assert exit_info.value.code == 5
    else:
        main_module.main()


def test_bare_skill_ambiguity_cannot_select_an_arbitrary_mapping(monkeypatch) -> None:

    monkeypatch.setattr(
        skills,
        "get_available_skills",
        lambda: {"vulnerabilities": [{"name": "xss"}], "custom": [{"name": "xss"}]},
    )
    settings = RuntimeSettings(subagent_turn_limits={"vulnerabilities/xss": 20, "custom/xss": 30})
    assert settings.skill_turn_limit(["xss"], hard_limit=50) is None
    assert settings.skill_turn_limit(["custom/xss"], hard_limit=50) == 30


def test_diagnostic_read_remains_bound_to_opened_regular_file(tmp_path, monkeypatch) -> None:

    path = tmp_path / "diagnostics.json"
    path.write_text('{"entries":[],"dropped":7}')
    different = tmp_path / "different.json"
    different.write_text('{"entries":[],"dropped":999}')
    original_open = diagnostics._open_attachment_fd

    def swap_after_open(target):
        descriptor = original_open(target)
        target.unlink()
        target.symlink_to(different)
        return descriptor

    monkeypatch.setattr(diagnostics, "_open_attachment_fd", swap_after_open)
    assert diagnostics._read_existing(path)["dropped"] == 7


def test_first_diagnostic_creates_state_directory_before_safe_handle_open(
    tmp_path, monkeypatch
) -> None:
    def open_like_windows(path):
        if not path.parent.is_dir():
            raise OSError(3, "path not found")
        raise FileNotFoundError(2, "file not found")

    monkeypatch.setattr(diagnostics, "_open_attachment_fd", open_like_windows)
    diagnostics.append_diagnostic(tmp_path, {"outcome": "completed"})
    assert (tmp_path / ".state" / "request-diagnostics.json").is_file()
