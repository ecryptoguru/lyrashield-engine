"""Phase 0 smoke tests for StrixOrchestrationHooks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from strix.orchestration.bus import AgentMessageBus
from strix.orchestration.hooks import StrixOrchestrationHooks


@dataclass
class _Ctx:
    """Minimal stand-in for RunContextWrapper / AgentHookContext.

    Only ``.context`` is exercised by the hooks under test; SDK's real wrappers
    expose much more, but the hooks treat ``.context`` as the dict we put in.
    """

    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Tool:
    name: str


class _FakeTracer:
    def __init__(self) -> None:
        self.starts: list[tuple[str, str]] = []
        self.ends: list[tuple[str, str, Any]] = []

    def log_tool_start(self, agent_id: str, tool_name: str) -> None:
        self.starts.append((agent_id, tool_name))

    def log_tool_end(self, agent_id: str, tool_name: str, result: Any) -> None:
        self.ends.append((agent_id, tool_name, result))


@pytest.mark.asyncio
async def test_on_llm_start_injects_85_percent_warning() -> None:
    hooks = StrixOrchestrationHooks()
    items: list[Any] = []
    ctx = _Ctx(context={"max_turns": 100, "turn_count": 85})
    await hooks.on_llm_start(ctx, agent=None, system_prompt="x", input_items=items)
    assert len(items) == 1
    assert "85%" in items[0]["content"]


@pytest.mark.asyncio
async def test_on_llm_start_injects_n_minus_3_warning() -> None:
    hooks = StrixOrchestrationHooks()
    items: list[Any] = []
    ctx = _Ctx(context={"max_turns": 100, "turn_count": 97})
    await hooks.on_llm_start(ctx, agent=None, system_prompt="x", input_items=items)
    assert len(items) == 1
    assert "3 iterations left" in items[0]["content"]


@pytest.mark.asyncio
async def test_on_llm_start_no_warning_at_other_turns() -> None:
    hooks = StrixOrchestrationHooks()
    items: list[Any] = []
    ctx = _Ctx(context={"max_turns": 100, "turn_count": 50})
    await hooks.on_llm_start(ctx, agent=None, system_prompt="x", input_items=items)
    assert items == []


@pytest.mark.asyncio
async def test_on_llm_end_records_usage_and_increments_turn() -> None:
    hooks = StrixOrchestrationHooks()
    bus = AgentMessageBus()
    await bus.register("a1", "alpha", parent_id=None)
    ctx = _Ctx(context={"bus": bus, "agent_id": "a1", "turn_count": 0})

    class _Details:
        cached_tokens = 5

    class _Usage:
        input_tokens = 10
        output_tokens = 20
        input_tokens_details = _Details()

    class _Resp:
        usage = _Usage()

    await hooks.on_llm_end(ctx, agent=None, response=_Resp())
    assert ctx.context["turn_count"] == 1
    assert bus.stats_live["a1"]["in"] == 10


@pytest.mark.asyncio
async def test_on_agent_end_detects_crash() -> None:
    """on_agent_end without agent_finish_called posts crash message to parent."""
    hooks = StrixOrchestrationHooks()
    bus = AgentMessageBus()
    await bus.register("root", "root", parent_id=None)
    await bus.register("child", "specialist", parent_id="root")
    ctx = _Ctx(context={"bus": bus, "agent_id": "child"})

    await hooks.on_agent_end(ctx, agent=None, output=None)  # crashed (output=None)

    drained = await bus.drain("root")
    assert len(drained) == 1
    assert "[Agent crash]" in drained[0]["content"]
    assert "child" in drained[0]["content"]
    assert drained[0]["type"] == "crash"
    assert bus.statuses["child"] == "crashed"


@pytest.mark.asyncio
async def test_on_agent_end_no_crash_when_finish_called() -> None:
    hooks = StrixOrchestrationHooks()
    bus = AgentMessageBus()
    await bus.register("root", "root", parent_id=None)
    await bus.register("child", "specialist", parent_id="root")
    ctx = _Ctx(
        context={
            "bus": bus,
            "agent_id": "child",
            "agent_finish_called": True,
        }
    )

    await hooks.on_agent_end(ctx, agent=None, output="done")

    assert await bus.drain("root") == []
    assert bus.statuses["child"] == "completed"


@pytest.mark.asyncio
async def test_on_tool_end_marks_finish_called() -> None:
    """When agent_finish or finish_scan returns, mark context flag for crash detection."""
    hooks = StrixOrchestrationHooks()
    ctx = _Ctx(context={"agent_id": "a1"})
    await hooks.on_tool_end(ctx, agent=None, tool=_Tool("agent_finish"), result="ok")
    assert ctx.context["agent_finish_called"] is True


@pytest.mark.asyncio
async def test_on_tool_end_other_tool_does_not_set_flag() -> None:
    hooks = StrixOrchestrationHooks()
    ctx = _Ctx(context={"agent_id": "a1"})
    await hooks.on_tool_end(ctx, agent=None, tool=_Tool("terminal_execute"), result="x")
    assert ctx.context.get("agent_finish_called") is None


@pytest.mark.asyncio
async def test_on_tool_start_logs_to_tracer() -> None:
    hooks = StrixOrchestrationHooks()
    tracer = _FakeTracer()
    ctx = _Ctx(context={"tracer": tracer, "agent_id": "a1"})
    await hooks.on_tool_start(ctx, agent=None, tool=_Tool("browser_action"))
    assert tracer.starts == [("a1", "browser_action")]


@pytest.mark.asyncio
async def test_hook_exception_does_not_propagate() -> None:
    """C15 (AUDIT_R3): a bug in the hook body must never tear down the run."""
    hooks = StrixOrchestrationHooks()

    class _BrokenBus:
        async def record_usage(self, *_: Any, **__: Any) -> None:
            raise RuntimeError("simulated")

    ctx = _Ctx(context={"bus": _BrokenBus(), "agent_id": "a1"})

    class _Resp:
        usage = None

    # Should not raise.
    await hooks.on_llm_end(ctx, agent=None, response=_Resp())
