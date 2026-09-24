from __future__ import annotations

import math

import pytest

from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.deadline import RunDeadline


@pytest.mark.parametrize("seconds", [0, -1, math.nan, math.inf])
def test_invalid_runtime_allowance_fails_closed(seconds: float) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        RunDeadline.start(seconds)


def test_deadline_uses_monotonic_clock_and_wrap_reserve() -> None:
    now = [0.0]
    deadline = RunDeadline.start(720, clock=lambda: now[0])
    assert deadline.wrap_at == 600
    now[0] = 601
    assert deadline.wrapping_up()
    assert deadline.remaining_seconds() == 119
    now[0] = 721
    assert deadline.remaining_seconds() == 0


@pytest.mark.asyncio
async def test_children_cannot_get_new_work_after_wrap() -> None:
    now = [0.0]
    coordinator = AgentCoordinator()
    coordinator.run_deadline = RunDeadline.start(100, clock=lambda: now[0])
    await coordinator.register("root", "strix", parent_id=None)
    assert await coordinator.can_spawn_agent()
    now[0] = 81
    assert not await coordinator.can_spawn_agent()
    with pytest.raises(RuntimeError, match="wrapping up"):
        await coordinator.register("late-child", "recon", parent_id="root")


@pytest.mark.asyncio
async def test_late_wrap_notice_does_not_reactivate_completed_agent() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.set_status("root", "completed")
    assert not await coordinator.send(
        "root", {"from": "system", "type": "runtime_wrap", "content": "finish"}, interrupt=False
    )
    assert await coordinator.get_status("root") == "completed"
