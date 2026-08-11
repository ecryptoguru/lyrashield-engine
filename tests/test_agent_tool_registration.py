"""Tests for scan-agent tool registration in factory."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from agents.tool import FunctionTool

from lyrashield_adapter.cli import _register_lyrashield_tool_overrides
from strix.agents import factory


if TYPE_CHECKING:
    from agents.tool_context import ToolContext


def _tool(name: str) -> FunctionTool:
    # A per-tool closure keeps two same-named tools unequal, which is what the
    # duplicate-name tests exercise.
    async def invoke(_ctx: ToolContext[Any], _input: str) -> str:
        return "ok"

    return FunctionTool(
        name=name,
        description="test tool",
        params_json_schema={"type": "object", "properties": {}, "additionalProperties": False},
        on_invoke_tool=invoke,
    )


@pytest.fixture(autouse=True)
def _reset_registry() -> object:  # pyright: ignore[reportUnusedFunction]
    saved = list(factory._EXTRA_TOOLS)
    factory._EXTRA_TOOLS.clear()
    try:
        yield
    finally:
        factory._EXTRA_TOOLS[:] = saved


@pytest.fixture(autouse=True)
def _reset_tool_overrides() -> object:  # pyright: ignore[reportUnusedFunction]
    saved = dict(factory._TOOL_OVERRIDES)
    factory._TOOL_OVERRIDES.clear()
    try:
        yield
    finally:
        factory._TOOL_OVERRIDES.update(saved)


def test_register_agent_tools_is_deduped() -> None:
    tool = _tool("dup")
    factory.register_agent_tools(tool)
    factory.register_agent_tools(tool)
    assert factory.registered_agent_tools() == (tool,)


def test_registered_tools_appear_before_lifecycle_tool() -> None:
    tool = _tool("extra")
    factory.register_agent_tools(tool)

    root = factory.build_strix_agent(is_root=True)
    child = factory.build_strix_agent(is_root=False)

    root_names = [t.name for t in root.tools]
    child_names = [t.name for t in child.tools]

    assert root_names[-2:] == ["extra", "finish_scan"]
    assert child_names[-2:] == ["extra", "agent_finish"]


def test_per_call_extra_tools_stack_with_registry() -> None:
    factory.register_agent_tools(_tool("registered"))

    agent = factory.build_strix_agent(is_root=True, extra_tools=[_tool("per_call")])
    names = [t.name for t in agent.tools]

    assert "registered" in names
    assert "per_call" in names
    assert names[-1] == "finish_scan"


def test_register_agent_tools_rejects_duplicate_names() -> None:
    factory.register_agent_tools(_tool("same_name"))

    with pytest.raises(ValueError, match="same_name"):
        factory.register_agent_tools(_tool("same_name"))


def test_per_call_extra_tools_reject_duplicate_registered_names() -> None:
    factory.register_agent_tools(_tool("same_name"))

    with pytest.raises(ValueError, match="same_name"):
        factory.build_strix_agent(is_root=True, extra_tools=[_tool("same_name")])


def test_instructions_override_is_used_verbatim() -> None:
    custom = "You are a scan agent. Follow the provided scope."

    agent = factory.build_strix_agent(is_root=True, instructions_override=custom)

    assert agent.instructions == custom


def test_no_override_renders_builtin_prompt() -> None:
    agent = factory.build_strix_agent(is_root=True)

    assert isinstance(agent.instructions, str)
    assert agent.instructions != ""


def test_respond_to_user_is_interactive_only() -> None:
    """Yielding to the user is meaningless when no user is attached."""
    interactive = factory.build_strix_agent(is_root=True, interactive=True)
    autonomous = factory.build_strix_agent(is_root=True, interactive=False)

    assert "respond_to_user" in [t.name for t in interactive.tools]
    assert "respond_to_user" not in [t.name for t in autonomous.tools]


def test_wait_for_agents_is_available_in_both_modes() -> None:
    for interactive in (True, False):
        agent = factory.build_strix_agent(is_root=True, interactive=interactive)
        assert "wait_for_agents" in [t.name for t in agent.tools]


def test_report_review_tools_are_root_only() -> None:
    """Leaf agents file evidence; only the coordinator reviews scan-wide reports."""
    root = factory.build_strix_agent(is_root=True)
    child = factory.build_strix_agent(is_root=False)

    root_names = [tool.name for tool in root.tools]
    child_names = [tool.name for tool in child.tools]

    assert {"list_reports", "get_report"} <= set(root_names)
    assert {"list_reports", "get_report"}.isdisjoint(child_names)


def test_register_tool_override_replaces_base_tool() -> None:
    """A product tool can replace an upstream base tool by name."""
    override = _tool("web_search")
    factory.register_tool_override("web_search", override)

    agent = factory.build_strix_agent(is_root=True)
    web_search_tools = [t for t in agent.tools if t.name == "web_search"]

    assert web_search_tools == [override]


def test_adapter_registers_lyrashield_web_search() -> None:
    """The product entry point registers the LyraShield web_search override."""
    _register_lyrashield_tool_overrides()

    assert "web_search" in factory._TOOL_OVERRIDES
    assert factory._TOOL_OVERRIDES["web_search"].name == "web_search"


def test_adapter_registers_lyrashield_respond_to_user() -> None:
    """The product entry point registers the LyraShield respond_to_user override."""
    _register_lyrashield_tool_overrides()

    assert "respond_to_user" in factory._TOOL_OVERRIDES
    assert factory._TOOL_OVERRIDES["respond_to_user"].name == "respond_to_user"


def test_adapter_registers_lyrashield_reporting_tools() -> None:
    """The product entry point registers the LyraShield reporting tool overrides."""
    _register_lyrashield_tool_overrides()

    for name in (
        "create_vulnerability_report",
        "create_dependency_report",
        "list_reports",
        "get_report",
    ):
        assert name in factory._TOOL_OVERRIDES
        assert factory._TOOL_OVERRIDES[name].name == name


def test_adapter_registers_lyrashield_proxy_tools() -> None:
    """The product entry point registers the LyraShield Caido proxy tool overrides."""
    _register_lyrashield_tool_overrides()

    for name in (
        "list_requests",
        "view_request",
        "repeat_request",
        "list_sitemap",
        "view_sitemap_entry",
        "scope_rules",
    ):
        assert name in factory._TOOL_OVERRIDES
        assert factory._TOOL_OVERRIDES[name].name == name


def test_adapter_registers_lyrashield_todo_tools() -> None:
    """The product entry point registers the LyraShield todo tool overrides."""
    _register_lyrashield_tool_overrides()

    for name in (
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "mark_todo_pending",
        "delete_todo",
    ):
        assert name in factory._TOOL_OVERRIDES
        assert factory._TOOL_OVERRIDES[name].name == name
