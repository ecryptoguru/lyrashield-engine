"""Phase 3 tests for the multi-agent graph SDK tools.

Six tools: view_agent_graph, agent_status, send_message_to_agent,
wait_for_message, create_agent, agent_finish.

Strategy:

- Build a real ``AgentMessageBus`` in each test and put it under
  ``ctx.context['bus']`` so the tools exercise the same code path
  production runs do.
- ``create_agent`` is the only tool that touches ``Runner.run`` and
  ``asyncio.create_task``. Its test injects a stub agent factory and
  patches the SDK's ``Runner.run`` to a sentinel coroutine — we verify
  the spawn shape (bus.register called, task handle stored, identity
  block in initial input) without spinning up a real LLM.
- ``wait_for_message`` is exercised on both branches: a message arrives
  mid-poll, and the timeout path.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from agents.tool import FunctionTool

from strix.orchestration.bus import AgentMessageBus
from strix.tools.agents_graph.tools import (
    agent_finish,
    agent_status,
    create_agent,
    send_message_to_agent,
    view_agent_graph,
    wait_for_message,
)


@dataclass
class _Ctx:
    context: dict[str, Any] = field(default_factory=dict)


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


async def _make_bus_with_agents() -> AgentMessageBus:
    """Bus prepopulated with a root + two registered children."""
    bus = AgentMessageBus()
    await bus.register("root-1", "root", parent_id=None)
    await bus.register("child-A", "scanner", parent_id="root-1")
    await bus.register("child-B", "exploiter", parent_id="root-1")
    return bus


def _ctx_for(bus: AgentMessageBus, agent_id: str = "root-1") -> _Ctx:
    return _Ctx(context={"bus": bus, "agent_id": agent_id, "parent_id": None})


# --- registration ---------------------------------------------------------


def test_all_graph_tools_are_function_tools() -> None:
    for tool in (
        view_agent_graph,
        agent_status,
        send_message_to_agent,
        wait_for_message,
        create_agent,
        agent_finish,
    ):
        assert isinstance(tool, FunctionTool)


# --- view_agent_graph -----------------------------------------------------


@pytest.mark.asyncio
async def test_view_agent_graph_renders_tree() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(view_agent_graph, _ctx_for(bus))
    assert out["success"] is True
    assert "root (root-1)" in out["graph_structure"]
    assert "scanner (child-A)" in out["graph_structure"]
    assert "exploiter (child-B)" in out["graph_structure"]
    # The "you" marker should be on the calling agent's line.
    you_lines = [line for line in out["graph_structure"].splitlines() if "← you" in line]
    assert len(you_lines) == 1
    assert "root-1" in you_lines[0]
    assert out["summary"]["total"] == 3
    assert out["summary"]["running"] == 3


@pytest.mark.asyncio
async def test_view_agent_graph_handles_missing_bus() -> None:
    out = await _invoke(view_agent_graph, _Ctx(context={}))
    assert out["success"] is False
    assert "Bus" in out["error"]


# --- agent_status ---------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_status_returns_state() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(agent_status, _ctx_for(bus), agent_id="child-A")
    assert out["success"] is True
    assert out["agent_id"] == "child-A"
    assert out["name"] == "scanner"
    assert out["status"] == "running"
    assert out["parent_id"] == "root-1"
    assert out["pending_messages"] == 0


@pytest.mark.asyncio
async def test_agent_status_unknown_id() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(agent_status, _ctx_for(bus), agent_id="nope")
    assert out["success"] is False
    assert "Unknown" in out["error"]


# --- send_message_to_agent -----------------------------------------------


@pytest.mark.asyncio
async def test_send_message_queues_into_target_inbox() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(
        send_message_to_agent,
        _ctx_for(bus, agent_id="child-A"),
        target_agent_id="child-B",
        message="hello sibling",
        priority="high",
    )
    assert out["success"] is True
    assert out["delivery_status"] == "queued"
    # Drain via the same API the filter uses; confirm the message landed.
    msgs = await bus.drain("child-B")
    assert len(msgs) == 1
    assert msgs[0]["from"] == "child-A"
    assert msgs[0]["content"] == "hello sibling"
    assert msgs[0]["priority"] == "high"


@pytest.mark.asyncio
async def test_send_message_unknown_target() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(
        send_message_to_agent,
        _ctx_for(bus),
        target_agent_id="ghost",
        message="hi",
    )
    assert out["success"] is False
    assert "not found" in out["error"]


@pytest.mark.asyncio
async def test_send_message_to_finalized_agent_is_rejected() -> None:
    """A finalized target should not silently swallow messages."""
    bus = await _make_bus_with_agents()
    await bus.finalize("child-A", "completed")
    out = await _invoke(
        send_message_to_agent,
        _ctx_for(bus),
        target_agent_id="child-A",
        message="too late",
    )
    assert out["success"] is False
    # finalize() also clears parent_of/names, so the user-visible state is
    # "completed" — confirm the wrapper treats finalized agents as
    # undeliverable rather than queuing into a dropped inbox.
    assert "completed" in out["error"] or "not found" in out["error"]


# --- wait_for_message ----------------------------------------------------


@pytest.mark.asyncio
async def test_wait_for_message_returns_when_message_arrives() -> None:
    bus = await _make_bus_with_agents()

    async def deliver_after_short_pause() -> None:
        await asyncio.sleep(0.1)
        await bus.send("child-A", {"from": "child-B", "content": "ping", "type": "info"})

    sender = asyncio.create_task(deliver_after_short_pause())
    out = await _invoke(
        wait_for_message,
        _ctx_for(bus, agent_id="child-A"),
        timeout_seconds=3,
    )
    await sender
    assert out["success"] is True
    assert out["status"] == "message_arrived"
    assert out["pending_messages"] >= 1
    # Status must be returned to "running" after the wait completes.
    assert bus.statuses["child-A"] == "running"


@pytest.mark.asyncio
async def test_wait_for_message_times_out() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(
        wait_for_message,
        _ctx_for(bus, agent_id="child-A"),
        timeout_seconds=1,
    )
    assert out["success"] is True
    assert out["status"] == "timeout"
    assert out["timeout_seconds"] == 1
    assert bus.statuses["child-A"] == "running"


# --- create_agent --------------------------------------------------------


@pytest.mark.asyncio
async def test_create_agent_requires_factory_in_context() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(
        create_agent,
        _ctx_for(bus),
        name="recon-bot",
        task="enumerate hosts",
    )
    assert out["success"] is False
    assert "agent_factory" in out["error"]


@pytest.mark.asyncio
async def test_create_agent_spawns_and_registers_child() -> None:
    """Verify the spawn shape without running a real LLM."""
    bus = await _make_bus_with_agents()

    factory_calls: list[dict[str, Any]] = []

    def fake_factory(*, name: str, skills: list[str]) -> Any:
        factory_calls.append({"name": name, "skills": list(skills)})
        # The Runner.run patch below ignores this object; any sentinel
        # works.
        return object()

    runner_calls: list[dict[str, Any]] = []

    async def fake_runner_run(*args: Any, **kwargs: Any) -> Any:
        # Capture the input + max_turns so the test can assert the
        # identity block + delegation envelope are present.
        runner_calls.append({"args": args, "kwargs": kwargs})
        await asyncio.sleep(0)  # cooperate so create_task can return
        return None

    ctx = _Ctx(
        context={
            "bus": bus,
            "agent_id": "root-1",
            "parent_id": None,
            "agent_factory": fake_factory,
            "sandbox_session": None,
            "sandbox_client": None,
            "sandbox_token": "token",
            "tool_server_host_port": 12345,
            "caido_host_port": None,
            "tracer": None,
            "model": "anthropic/claude-sonnet-4-6",
            "model_settings": None,
            "max_turns": 300,
            "is_whitebox": False,
        }
    )

    with patch(
        "strix.tools.agents_graph.tools.Runner.run",
        side_effect=fake_runner_run,
    ):
        out = await _invoke(
            create_agent,
            ctx,
            name="recon-bot",
            task="enumerate hosts",
            inherit_context=False,
            skills=["recon"],
        )
        # The spawned task must be allowed to run so Runner.run side-effect
        # records the call.
        new_id = out["agent_id"]
        await asyncio.gather(*(t for t in bus.tasks.values()), return_exceptions=True)

    assert out["success"] is True
    assert factory_calls == [{"name": "recon-bot", "skills": ["recon"]}]
    assert len(runner_calls) == 1

    # Bus state: child registered, task stored.
    assert new_id in bus.statuses
    assert bus.parent_of[new_id] == "root-1"
    assert bus.names[new_id] == "recon-bot"
    assert new_id in bus.tasks

    # Initial input shape: identity preamble + task message at the end.
    initial_input = runner_calls[0]["kwargs"]["input"]
    assert any(
        isinstance(item, dict) and "You are agent recon-bot" in item.get("content", "")
        for item in initial_input
    )
    assert initial_input[-1]["content"] == "enumerate hosts"


@pytest.mark.asyncio
async def test_create_agent_inherits_parent_history() -> None:
    bus = await _make_bus_with_agents()

    def fake_factory(*, name: str, skills: list[str]) -> Any:
        return object()

    runner_calls: list[dict[str, Any]] = []

    async def fake_runner_run(*args: Any, **kwargs: Any) -> Any:
        runner_calls.append(kwargs)
        return None

    parent_history = [
        {"role": "user", "content": "scope: example.com"},
        {"role": "assistant", "content": "I'll start with subdomain enum."},
    ]
    ctx = _Ctx(
        context={
            "bus": bus,
            "agent_id": "root-1",
            "parent_id": None,
            "agent_factory": fake_factory,
            "parent_input_items": parent_history,
            "sandbox_session": None,
            "sandbox_client": None,
            "sandbox_token": "token",
            "tool_server_host_port": 12345,
            "caido_host_port": None,
            "tracer": None,
            "model": "anthropic/claude-sonnet-4-6",
            "model_settings": None,
            "max_turns": 300,
        }
    )

    with patch(
        "strix.tools.agents_graph.tools.Runner.run",
        side_effect=fake_runner_run,
    ):
        await _invoke(
            create_agent,
            ctx,
            name="child",
            task="do thing",
            inherit_context=True,
        )
        await asyncio.gather(*(t for t in bus.tasks.values()), return_exceptions=True)

    initial_input = runner_calls[0]["input"]
    contents = [item.get("content", "") for item in initial_input]
    assert any("Inherited context from parent" in c for c in contents)
    assert any("End of inherited context" in c for c in contents)
    # Parent's exact items should be in between.
    assert any(c == "scope: example.com" for c in contents)


# --- agent_finish --------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_finish_rejects_root() -> None:
    bus = await _make_bus_with_agents()
    out = await _invoke(
        agent_finish,
        _ctx_for(bus, agent_id="root-1"),
        result_summary="done",
    )
    assert out["success"] is False
    assert "agent_finish is for subagents" in out["error"]


@pytest.mark.asyncio
async def test_agent_finish_posts_report_to_parent_inbox() -> None:
    bus = await _make_bus_with_agents()
    ctx = _Ctx(
        context={
            "bus": bus,
            "agent_id": "child-A",
            "parent_id": "root-1",
            "agent_finish_called": False,
        }
    )
    out = await _invoke(
        agent_finish,
        ctx,
        result_summary="found 3 issues",
        findings=["xss in /search", "open redirect", "stored xss"],
        final_recommendations=["sanitize search input"],
        success=True,
    )
    assert out["success"] is True
    assert out["agent_completed"] is True
    assert out["parent_notified"] is True

    # Side effects: agent_finish_called flipped (so on_agent_end records
    # "completed", not "crashed"), and the parent's inbox got the report.
    assert ctx.context["agent_finish_called"] is True
    parent_msgs = await bus.drain("root-1")
    assert len(parent_msgs) == 1
    msg = parent_msgs[0]
    assert msg["type"] == "completion"
    assert msg["from"] == "child-A"
    payload = json.loads(msg["content"])
    assert payload["kind"] == "agent_completion_report"
    assert payload["summary"] == "found 3 issues"
    assert "xss in /search" in payload["findings"]
    assert "sanitize search input" in payload["recommendations"]


@pytest.mark.asyncio
async def test_agent_finish_skips_parent_when_report_to_parent_false() -> None:
    bus = await _make_bus_with_agents()
    ctx = _Ctx(
        context={
            "bus": bus,
            "agent_id": "child-A",
            "parent_id": "root-1",
            "agent_finish_called": False,
        }
    )
    out = await _invoke(
        agent_finish,
        ctx,
        result_summary="silent done",
        report_to_parent=False,
    )
    assert out["success"] is True
    assert out["parent_notified"] is False
    assert ctx.context["agent_finish_called"] is True
    parent_msgs = await bus.drain("root-1")
    assert parent_msgs == []


# --- bus integration sanity ---------------------------------------------


@pytest.mark.asyncio
async def test_create_agent_spawn_is_cancelable_via_bus() -> None:
    """Verify bus.cancel_descendants reaches a child task we just spawned."""
    bus = await _make_bus_with_agents()

    def fake_factory(*, name: str, skills: list[str]) -> Any:
        return object()

    # Long-lived child that yields control so we can cancel it before it
    # finishes naturally.
    async def slow_runner_run(*args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(60)
        return None

    ctx = _Ctx(
        context={
            "bus": bus,
            "agent_id": "root-1",
            "parent_id": None,
            "agent_factory": fake_factory,
            "sandbox_session": None,
            "sandbox_client": None,
            "sandbox_token": "t",
            "tool_server_host_port": 12345,
            "caido_host_port": None,
            "tracer": None,
            "model": "anthropic/claude-sonnet-4-6",
            "model_settings": None,
            "max_turns": 300,
        }
    )

    runner_mock = AsyncMock(side_effect=slow_runner_run)
    with patch(
        "strix.tools.agents_graph.tools.Runner.run",
        new=runner_mock,
    ):
        out = await _invoke(
            create_agent,
            ctx,
            name="long-running",
            task="do thing",
            inherit_context=False,
        )
        child_id = out["agent_id"]
        # Let the task actually start.
        await asyncio.sleep(0.05)
        await bus.cancel_descendants("root-1")

    # The cancel should have propagated; the task is done (cancelled).
    assert bus.tasks[child_id].done()
