"""Smoke tests for the sandbox-bound SDK tool wrappers.

Covers: browser_action, terminal_execute, python_action, file_edit
helpers, and the seven Caido proxy tools.

These wrappers are pure pass-throughs to ``post_to_sandbox`` — there's
no per-tool logic to assert, so the tests focus on:

- ``FunctionTool`` registration succeeds (which proves the SDK could
  derive a JSON schema from the type hints — a non-trivial check given
  Literal types, ``dict[str, str]``, and strict-mode opt-outs).
- The dispatch payload to ``post_to_sandbox`` carries the right
  ``kwargs`` shape so the in-container tool server can dispatch to the
  matching action.
- The ``send_request`` / ``repeat_request`` tools opt out of strict
  schema mode (their ``headers`` / ``modifications`` dicts are
  free-form and would otherwise fail registration).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch

import pytest
from agents.tool import FunctionTool

from strix.tools.browser.tool import browser_action
from strix.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    send_request,
    view_request,
    view_sitemap_entry,
)
from strix.tools.python.tool import python_action
from strix.tools.terminal.tool import terminal_execute


_ALL_SANDBOX_TOOLS = (
    browser_action,
    terminal_execute,
    python_action,
    list_requests,
    view_request,
    send_request,
    repeat_request,
    scope_rules,
    list_sitemap,
    view_sitemap_entry,
)


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


def test_all_sandbox_tools_register() -> None:
    for tool in _ALL_SANDBOX_TOOLS:
        assert isinstance(tool, FunctionTool)


def test_send_and_repeat_request_opt_out_of_strict_mode() -> None:
    """The two free-form-dict tools must turn off strict JSON schema."""
    assert send_request.strict_json_schema is False
    assert repeat_request.strict_json_schema is False
    # All other tools should keep strict mode on (the SDK default).
    for tool in (
        browser_action,
        terminal_execute,
        python_action,
        list_requests,
        view_request,
        scope_rules,
        list_sitemap,
        view_sitemap_entry,
    ):
        assert tool.strict_json_schema is True, tool.name


# --- browser ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_browser_action_dispatches_full_payload() -> None:
    """All optional browser_action params must forward as None when unset
    (the in-container handler distinguishes ``None`` from missing)."""
    fake = {"result": {"screenshot": "data:image/png;base64,..."}}
    with patch(
        "strix.tools.browser.tool.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        out = await _invoke(
            browser_action,
            _ctx_for(),
            action="goto",
            url="https://example.com",
        )

    assert out == fake
    args, _ = dispatch.call_args
    assert args[1] == "browser_action"
    payload = args[2]
    assert payload["action"] == "goto"
    assert payload["url"] == "https://example.com"
    # All optional params are present in the payload (as None / defaults)
    # so the legacy in-container handler sees the full kwarg surface.
    for key in (
        "coordinate",
        "text",
        "tab_id",
        "js_code",
        "duration",
        "key",
        "file_path",
    ):
        assert key in payload, key
        assert payload[key] is None
    assert payload["clear"] is False


# --- terminal --------------------------------------------------------------


@pytest.mark.asyncio
async def test_terminal_execute_dispatches() -> None:
    fake = {"result": {"content": "hello\n", "exit_code": 0}}
    with patch(
        "strix.tools.terminal.tool.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        out = await _invoke(
            terminal_execute,
            _ctx_for(),
            command="echo hello",
            terminal_id="term-1",
        )

    assert out == fake
    args, _ = dispatch.call_args
    assert args[1] == "terminal_execute"
    assert args[2]["command"] == "echo hello"
    assert args[2]["terminal_id"] == "term-1"
    assert args[2]["is_input"] is False
    assert args[2]["no_enter"] is False
    assert args[2]["timeout"] is None


# --- python ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_python_action_dispatches() -> None:
    fake = {"result": {"stdout": "42\n", "is_running": False}}
    with patch(
        "strix.tools.python.tool.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        out = await _invoke(
            python_action,
            _ctx_for(),
            action="execute",
            code="print(6*7)",
            session_id="sess-1",
        )

    assert out == fake
    args, _ = dispatch.call_args
    assert args[1] == "python_action"
    assert args[2] == {
        "action": "execute",
        "code": "print(6*7)",
        "timeout": 30,
        "session_id": "sess-1",
    }


# --- proxy / Caido --------------------------------------------------------


@pytest.mark.asyncio
async def test_list_requests_forwards_full_query() -> None:
    fake: dict[str, Any] = {"result": {"requests": []}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(
            list_requests,
            _ctx_for(),
            httpql_filter="resp.code:eq:500",
            page_size=20,
            sort_by="response_time",
            sort_order="asc",
        )

    args, _ = dispatch.call_args
    assert args[1] == "list_requests"
    assert args[2]["httpql_filter"] == "resp.code:eq:500"
    assert args[2]["page_size"] == 20
    assert args[2]["sort_by"] == "response_time"
    assert args[2]["sort_order"] == "asc"
    # Defaults preserved.
    assert args[2]["start_page"] == 1
    assert args[2]["end_page"] == 1


@pytest.mark.asyncio
async def test_view_request_dispatches() -> None:
    fake = {"result": {"raw": "GET / HTTP/1.1..."}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(
            view_request,
            _ctx_for(),
            request_id="req-9",
            part="response",
            search_pattern="Set-Cookie",
        )

    args, _ = dispatch.call_args
    assert args[1] == "view_request"
    assert args[2]["request_id"] == "req-9"
    assert args[2]["part"] == "response"
    assert args[2]["search_pattern"] == "Set-Cookie"


@pytest.mark.asyncio
async def test_send_request_normalizes_missing_headers() -> None:
    """Legacy schema treats omitted ``headers`` as ``{}``; the wrapper must too."""
    fake = {"result": {"status": 200}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(
            send_request,
            _ctx_for(),
            method="POST",
            url="https://api.example.com/login",
            body='{"u":"x"}',
        )

    args, _ = dispatch.call_args
    assert args[1] == "send_request"
    assert args[2]["headers"] == {}  # not None
    assert args[2]["method"] == "POST"
    assert args[2]["body"] == '{"u":"x"}'


@pytest.mark.asyncio
async def test_repeat_request_normalizes_missing_modifications() -> None:
    fake = {"result": {"status": 200}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(repeat_request, _ctx_for(), request_id="req-1")

    args, _ = dispatch.call_args
    assert args[1] == "repeat_request"
    assert args[2]["modifications"] == {}


@pytest.mark.asyncio
async def test_scope_rules_dispatches() -> None:
    fake = {"result": {"scope_id": "s-1"}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(
            scope_rules,
            _ctx_for(),
            action="create",
            scope_name="prod",
            allowlist=["*.example.com"],
        )

    args, _ = dispatch.call_args
    assert args[1] == "scope_rules"
    assert args[2]["action"] == "create"
    assert args[2]["scope_name"] == "prod"
    assert args[2]["allowlist"] == ["*.example.com"]
    assert args[2]["denylist"] is None


@pytest.mark.asyncio
async def test_list_sitemap_defaults() -> None:
    fake: dict[str, Any] = {"result": {"entries": []}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(list_sitemap, _ctx_for())

    args, _ = dispatch.call_args
    assert args[1] == "list_sitemap"
    assert args[2]["depth"] == "DIRECT"
    assert args[2]["page"] == 1


@pytest.mark.asyncio
async def test_view_sitemap_entry_dispatches() -> None:
    fake = {"result": {"entry_id": "e-1"}}
    with patch(
        "strix.tools.proxy.tools.post_to_sandbox",
        return_value=fake,
    ) as dispatch:
        await _invoke(view_sitemap_entry, _ctx_for(), entry_id="e-1")

    args, _ = dispatch.call_args
    assert args[1] == "view_sitemap_entry"
    assert args[2] == {"entry_id": "e-1"}
