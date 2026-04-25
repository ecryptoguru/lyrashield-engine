"""Smoke tests for the remaining local SDK tool wrappers.

Covers: web_search, file_edit (str_replace_editor + list_files +
search_files), reporting (create_vulnerability_report), finish_scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch

import pytest
from agents.tool import FunctionTool

from strix.tools.file_edit.tools import (
    list_files,
    search_files,
    str_replace_editor,
)
from strix.tools.finish.tool import finish_scan
from strix.tools.reporting.tool import create_vulnerability_report
from strix.tools.web_search.tool import web_search


@dataclass
class _Ctx:
    context: dict[str, Any] = field(default_factory=dict)


def _ctx_for(agent_id: str = "test-agent") -> _Ctx:
    return _Ctx(
        context={
            "agent_id": agent_id,
            "tool_server_host_port": 12345,
            "sandbox_token": "test-token",
        },
    )


async def _invoke(tool: FunctionTool, ctx: _Ctx, **kwargs: Any) -> dict[str, Any]:
    from agents.tool_context import ToolContext

    tool_ctx = ToolContext(
        context=ctx.context,
        usage=None,
        tool_name=tool.name,
        tool_call_id="test-call-id",
        tool_arguments=json.dumps(kwargs),
    )
    result = await tool.on_invoke_tool(tool_ctx, json.dumps(kwargs))
    assert isinstance(result, str)
    decoded = json.loads(result)
    assert isinstance(decoded, dict)
    return decoded


def test_all_remaining_tools_are_function_tools() -> None:
    for tool in (
        web_search,
        str_replace_editor,
        list_files,
        search_files,
        create_vulnerability_report,
        finish_scan,
    ):
        assert isinstance(tool, FunctionTool)


# --- web_search -----------------------------------------------------------


@pytest.mark.asyncio
async def test_web_search_no_api_key_returns_structured_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The legacy function returns a structured error when the env var is
    missing — verify the wrapper passes that through verbatim."""
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

    out = await _invoke(web_search, _ctx_for(), query="anything")
    assert out["success"] is False
    assert "PERPLEXITY_API_KEY" in out["message"]


@pytest.mark.asyncio
async def test_web_search_delegates_to_perplexity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wrapper invokes the Perplexity HTTP path on a thread."""
    monkeypatch.setenv("PERPLEXITY_API_KEY", "fake-key")

    fake_result = {
        "success": True,
        "query": "xss techniques",
        "content": "Reflected XSS payload examples...",
        "message": "Web search completed successfully",
    }
    with patch(
        "strix.tools.web_search.tool._do_search",
        return_value=fake_result,
    ) as do_search:
        out = await _invoke(web_search, _ctx_for(), query="xss techniques")

    assert out == fake_result
    do_search.assert_called_once_with("xss techniques")


# --- file_edit (sandbox-bound) -------------------------------------------


@pytest.mark.asyncio
async def test_str_replace_editor_routes_to_sandbox() -> None:
    """file_edit tools must POST to the in-sandbox tool server, not run locally."""
    fake_response = {"result": {"content": "file viewed"}}
    with patch(
        "strix.tools.file_edit.tools.post_to_sandbox",
        return_value=fake_response,
    ) as dispatch:
        out = await _invoke(
            str_replace_editor,
            _ctx_for(),
            command="view",
            path="src/foo.py",
        )

    assert out == fake_response
    assert dispatch.call_count == 1
    # post_to_sandbox is called positionally as (ctx, tool_name, kwargs).
    args, _ = dispatch.call_args
    assert args[1] == "str_replace_editor"
    assert args[2]["command"] == "view"
    assert args[2]["path"] == "src/foo.py"
    # All optional file-edit params are forwarded as None (parity with legacy schema).
    assert args[2]["file_text"] is None
    assert args[2]["old_str"] is None


@pytest.mark.asyncio
async def test_list_files_routes_to_sandbox() -> None:
    fake_response = {"result": {"files": ["a.py"], "directories": []}}
    with patch(
        "strix.tools.file_edit.tools.post_to_sandbox",
        return_value=fake_response,
    ) as dispatch:
        out = await _invoke(list_files, _ctx_for(), path="src", recursive=True)

    assert out == fake_response
    args, _ = dispatch.call_args
    assert args[1] == "list_files"
    assert args[2] == {"path": "src", "recursive": True}


@pytest.mark.asyncio
async def test_search_files_routes_to_sandbox() -> None:
    fake_response = {"result": {"output": "src/foo.py:1:match"}}
    with patch(
        "strix.tools.file_edit.tools.post_to_sandbox",
        return_value=fake_response,
    ) as dispatch:
        out = await _invoke(
            search_files,
            _ctx_for(),
            path="src",
            regex="TODO",
            file_pattern="*.py",
        )

    assert out == fake_response
    args, _ = dispatch.call_args
    assert args[1] == "search_files"
    assert args[2] == {"path": "src", "regex": "TODO", "file_pattern": "*.py"}


# --- reporting -----------------------------------------------------------


@pytest.mark.asyncio
async def test_create_vulnerability_report_validates_required_fields() -> None:
    """Empty required fields should be rejected by the validator."""
    out = await _invoke(
        create_vulnerability_report,
        _ctx_for(),
        title="",  # empty -> validation error
        description="d",
        impact="i",
        target="t",
        technical_analysis="ta",
        poc_description="pd",
        poc_script_code="curl ...",
        remediation_steps="rs",
        cvss_breakdown={"attack_vector": "N"},
    )
    assert out["success"] is False
    assert "errors" in out
    assert any("Title" in e for e in out["errors"])


@pytest.mark.asyncio
async def test_create_vulnerability_report_delegates_to_impl() -> None:
    """Verify the wrapper threads its kwargs through to the implementation."""
    fake_result = {
        "success": True,
        "message": "Vulnerability report 'X' created successfully",
        "report_id": "abc123",
        "severity": "high",
        "cvss_score": 7.5,
    }
    with patch(
        "strix.tools.reporting.tool._do_create",
        return_value=fake_result,
    ) as do_create:
        out = await _invoke(
            create_vulnerability_report,
            _ctx_for(),
            title="t",
            description="d",
            impact="i",
            target="tg",
            technical_analysis="ta",
            poc_description="pd",
            poc_script_code="pc",
            remediation_steps="rs",
            cvss_breakdown={"attack_vector": "N"},
            cve="CVE-2024-12345",
        )

    assert out == fake_result
    kwargs = do_create.call_args.kwargs
    assert kwargs["title"] == "t"
    assert kwargs["cve"] == "CVE-2024-12345"
    # Optional params we didn't pass should still be forwarded as None.
    assert kwargs["endpoint"] is None
    assert kwargs["method"] is None


# --- finish_scan ---------------------------------------------------------


@pytest.mark.asyncio
async def test_finish_scan_validates_empty_fields() -> None:
    """Legacy validation: every section must be non-empty."""
    out = await _invoke(
        finish_scan,
        _ctx_for(),
        executive_summary="",
        methodology="m",
        technical_analysis="ta",
        recommendations="r",
    )
    assert out["success"] is False
    assert any("Executive summary" in e for e in out["errors"])


@pytest.mark.asyncio
async def test_finish_scan_rejects_subagent() -> None:
    """A subagent (parent_id is set) must not be able to finish the scan."""
    ctx = _Ctx(
        context={
            "agent_id": "child-1",
            "parent_id": "root-1",
            "tool_server_host_port": 12345,
            "sandbox_token": "test-token",
        },
    )
    out = await _invoke(
        finish_scan,
        ctx,
        executive_summary="es",
        methodology="m",
        technical_analysis="ta",
        recommendations="r",
    )
    assert out["success"] is False
    assert out["error"] == "finish_scan_wrong_agent"


@pytest.mark.asyncio
async def test_finish_scan_persists_via_tracer() -> None:
    """When a global tracer exists, finish_scan should write the four sections."""
    from unittest.mock import MagicMock

    fake_tracer = MagicMock()
    fake_tracer.vulnerability_reports = [{}, {}, {}]

    with patch(
        "strix.telemetry.tracer.get_global_tracer",
        return_value=fake_tracer,
    ):
        out = await _invoke(
            finish_scan,
            _ctx_for("root-agent"),
            executive_summary="es",
            methodology="m",
            technical_analysis="ta",
            recommendations="r",
        )

    assert out["success"] is True
    assert out["vulnerabilities_found"] == 3
    fake_tracer.update_scan_final_fields.assert_called_once_with(
        executive_summary="es",
        methodology="m",
        technical_analysis="ta",
        recommendations="r",
    )
