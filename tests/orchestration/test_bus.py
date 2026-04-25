"""Phase 0 smoke tests for AgentMessageBus."""

from __future__ import annotations

import asyncio

import pytest

from strix.orchestration.bus import AgentMessageBus


@pytest.fixture
def bus() -> AgentMessageBus:
    return AgentMessageBus()


@pytest.mark.asyncio
async def test_register_records_agent(bus: AgentMessageBus) -> None:
    await bus.register("a1", "alpha", parent_id=None)
    assert bus.statuses["a1"] == "running"
    assert bus.parent_of["a1"] is None
    assert bus.names["a1"] == "alpha"
    assert bus.inboxes["a1"] == []
    assert bus.stats_live["a1"]["calls"] == 0


@pytest.mark.asyncio
async def test_send_and_drain_fifo(bus: AgentMessageBus) -> None:
    await bus.register("a1", "alpha", parent_id=None)
    await bus.send("a1", {"from": "b", "content": "first"})
    await bus.send("a1", {"from": "c", "content": "second"})
    drained = await bus.drain("a1")
    assert [m["content"] for m in drained] == ["first", "second"]
    assert await bus.drain("a1") == []


@pytest.mark.asyncio
async def test_send_to_unknown_agent_is_dropped(bus: AgentMessageBus) -> None:
    await bus.send("ghost", {"from": "user", "content": "x"})
    assert "ghost" not in bus.inboxes


@pytest.mark.asyncio
async def test_finalize_clears_inbox_parent_name(bus: AgentMessageBus) -> None:
    """C13 (AUDIT_R3): finalize cleans up routing state to avoid orphan messages."""
    await bus.register("a1", "alpha", parent_id=None)
    await bus.register("a2", "beta", parent_id="a1")
    await bus.send("a1", {"from": "a2", "content": "hi"})
    await bus.finalize("a1", "completed")
    # Inbox / parent / name removed so siblings can't accidentally re-fill.
    assert "a1" not in bus.inboxes
    assert "a1" not in bus.parent_of
    assert "a1" not in bus.names
    # Status remains for diagnostics.
    assert bus.statuses["a1"] == "completed"
    # Messages sent to a finalized agent are dropped silently.
    await bus.send("a1", {"from": "a2", "content": "ignored"})
    assert "a1" not in bus.inboxes


@pytest.mark.asyncio
async def test_record_usage_aggregates(bus: AgentMessageBus) -> None:
    await bus.register("a1", "alpha", parent_id=None)

    class _Details:
        cached_tokens = 10

    class _Usage:
        input_tokens = 100
        output_tokens = 50
        input_tokens_details = _Details()

    await bus.record_usage("a1", _Usage())
    await bus.record_usage("a1", _Usage())
    stats = bus.stats_live["a1"]
    assert stats["in"] == 200
    assert stats["out"] == 100
    assert stats["cached"] == 20
    assert stats["calls"] == 2


@pytest.mark.asyncio
async def test_record_usage_handles_none(bus: AgentMessageBus) -> None:
    await bus.register("a1", "alpha", parent_id=None)
    await bus.record_usage("a1", None)
    assert bus.stats_live["a1"]["calls"] == 0


@pytest.mark.asyncio
async def test_total_stats_snapshot(bus: AgentMessageBus) -> None:
    """C12 (AUDIT_R2): total_stats acquires the lock for a consistent snapshot."""
    await bus.register("a1", "alpha", parent_id=None)
    await bus.register("a2", "beta", parent_id="a1")

    class _Details:
        cached_tokens = 5

    class _Usage:
        input_tokens = 10
        output_tokens = 20
        input_tokens_details = _Details()

    await bus.record_usage("a1", _Usage())
    await bus.record_usage("a2", _Usage())
    await bus.finalize("a2", "completed")

    totals = await bus.total_stats()
    assert totals["in"] == 20
    assert totals["out"] == 40
    assert totals["cached"] == 10
    assert totals["calls"] == 2


@pytest.mark.asyncio
async def test_concurrent_send_drain_no_lost_messages() -> None:
    bus = AgentMessageBus()
    await bus.register("a1", "alpha", parent_id=None)

    async def producer(start: int, count: int) -> None:
        for i in range(count):
            await bus.send("a1", {"from": "p", "content": str(start + i)})

    # 50 producers x 20 messages = 1000 messages; drain in 1 reader.
    producers = [asyncio.create_task(producer(i * 20, 20)) for i in range(50)]
    await asyncio.gather(*producers)
    drained = await bus.drain("a1")
    assert len(drained) == 1000


@pytest.mark.asyncio
async def test_cancel_descendants_cancels_whole_tree() -> None:
    """C9 (AUDIT_R2): cancel_descendants cancels every transitive child."""
    bus = AgentMessageBus()
    await bus.register("root", "root", parent_id=None)
    await bus.register("child1", "c1", parent_id="root")
    await bus.register("grandchild1", "g1", parent_id="child1")
    await bus.register("child2", "c2", parent_id="root")

    pending = asyncio.get_event_loop().create_future()

    async def fake_run() -> None:
        await pending  # block until cancelled

    for aid in ("root", "child1", "grandchild1", "child2"):
        bus.tasks[aid] = asyncio.create_task(fake_run())

    await bus.cancel_descendants("root")

    for aid in ("root", "child1", "grandchild1", "child2"):
        assert bus.tasks[aid].cancelled() or bus.tasks[aid].done()


@pytest.mark.asyncio
async def test_cancel_descendants_triggers_leaves_before_root() -> None:
    """C9: explicit ordering check — leaves' .cancel() called before root's."""
    bus = AgentMessageBus()
    await bus.register("root", "root", parent_id=None)
    await bus.register("child1", "c1", parent_id="root")
    await bus.register("grandchild1", "g1", parent_id="child1")

    cancel_call_order: list[str] = []
    pending = asyncio.get_event_loop().create_future()

    class _RecordingTask:
        """Wrap a real Task; record the moment .cancel() is invoked."""

        def __init__(self, name: str, task: asyncio.Task) -> None:
            self._name = name
            self._task = task

        def done(self) -> bool:
            return self._task.done()

        def cancelled(self) -> bool:
            return self._task.cancelled()

        def cancel(self, *args: object, **kwargs: object) -> bool:
            cancel_call_order.append(self._name)
            return self._task.cancel()

        def __await__(self):
            return self._task.__await__()

    async def fake_run() -> None:
        await pending

    for aid in ("root", "child1", "grandchild1"):
        real = asyncio.create_task(fake_run())
        bus.tasks[aid] = _RecordingTask(aid, real)  # type: ignore[assignment]

    await bus.cancel_descendants("root")

    # grandchild and child must have .cancel() called before root.
    assert cancel_call_order.index("grandchild1") < cancel_call_order.index("root")
    assert cancel_call_order.index("child1") < cancel_call_order.index("root")
