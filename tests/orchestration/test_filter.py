"""Phase 0 smoke tests for inject_messages_filter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from agents.run_config import CallModelData, ModelInputData

from strix.orchestration.bus import AgentMessageBus
from strix.orchestration.filter import inject_messages_filter


@dataclass
class _FakeAgent:
    name: str = "agent"


def _call_data(
    context: Any,
    items: list[Any],
    instructions: str | None = "system",
) -> CallModelData[Any]:
    return CallModelData(
        model_data=ModelInputData(input=items, instructions=instructions),
        agent=_FakeAgent(),
        context=context,
    )


@pytest.mark.asyncio
async def test_empty_inbox_passes_through() -> None:
    bus = AgentMessageBus()
    await bus.register("a1", "alpha", parent_id=None)
    data = _call_data({"bus": bus, "agent_id": "a1"}, [{"role": "user", "content": "x"}])

    out = await inject_messages_filter(data)

    assert out.input == [{"role": "user", "content": "x"}]
    assert out.instructions == "system"


@pytest.mark.asyncio
async def test_pending_messages_appended_in_order() -> None:
    bus = AgentMessageBus()
    await bus.register("a1", "alpha", parent_id=None)
    await bus.send("a1", {"from": "b", "content": "hello", "type": "info", "priority": "normal"})
    await bus.send("a1", {"from": "c", "content": "second", "type": "info", "priority": "high"})
    data = _call_data({"bus": bus, "agent_id": "a1"}, [{"role": "user", "content": "task"}])

    out = await inject_messages_filter(data)

    assert len(out.input) == 3
    assert out.input[0] == {"role": "user", "content": "task"}
    assert "<inter_agent_message from='b'" in out.input[1]["content"]
    assert "hello" in out.input[1]["content"]
    assert "second" in out.input[2]["content"]
    assert "priority='high'" in out.input[2]["content"]


@pytest.mark.asyncio
async def test_user_sender_skips_xml_wrap() -> None:
    bus = AgentMessageBus()
    await bus.register("a1", "alpha", parent_id=None)
    await bus.send("a1", {"from": "user", "content": "follow-up question"})
    data = _call_data({"bus": bus, "agent_id": "a1"}, [])

    out = await inject_messages_filter(data)

    assert out.input == [{"role": "user", "content": "follow-up question"}]


@pytest.mark.asyncio
async def test_no_bus_in_context_passes_through() -> None:
    data = _call_data({"agent_id": "a1"}, [{"role": "user", "content": "x"}])
    out = await inject_messages_filter(data)
    assert out.input == [{"role": "user", "content": "x"}]


@pytest.mark.asyncio
async def test_filter_exception_returns_unmodified() -> None:
    """C14 (AUDIT_R3): filter exception is caught; original data returned."""

    class _BrokenBus:
        async def drain(self, _: str) -> list[dict[str, Any]]:
            raise RuntimeError("simulated bug")

    data = _call_data(
        {"bus": _BrokenBus(), "agent_id": "a1"},
        [{"role": "user", "content": "still works"}],
    )

    out = await inject_messages_filter(data)
    assert out.input == [{"role": "user", "content": "still works"}]
