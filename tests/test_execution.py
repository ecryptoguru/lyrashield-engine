"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from strix.core.agents import AgentCoordinator
from strix.core.execution import _final_output_metadata
from strix.core.runner import _coordinator_for_scan_mode


@pytest.mark.asyncio
async def test_budget_stop_sets_flag() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    assert coordinator.budget_stopped is False
    await coordinator.trigger_budget_stop()
    assert coordinator.budget_stopped is True


@pytest.mark.asyncio
async def test_budget_stop_unblocks_parked_agent() -> None:
    # A parent parked in wait_for_message (awaiting a child) must be released so
    # it can exit, no matter where in the tree the budget limit was hit.
    coordinator = AgentCoordinator()
    await coordinator.register("parent", "strix", parent_id=None)

    waiter = asyncio.create_task(coordinator.wait_for_message("parent"))
    await asyncio.sleep(0)  # let the waiter park
    assert not waiter.done()

    await coordinator.trigger_budget_stop()
    await asyncio.wait_for(waiter, timeout=1.0)


@pytest.mark.asyncio
async def test_wait_for_message_returns_immediately_after_budget_stop() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("agent", "recon", parent_id="parent")
    await coordinator.trigger_budget_stop()

    # No pending messages, but the stop flag short-circuits the wait.
    await asyncio.wait_for(coordinator.wait_for_message("agent"), timeout=1.0)


@pytest.mark.asyncio
async def test_agent_limit_is_enforced_atomically_during_registration() -> None:
    coordinator = AgentCoordinator(max_agents=1)
    await coordinator.register("root", "strix", parent_id=None)

    with pytest.raises(RuntimeError, match=r"Scan agent limit reached \(1\)"):
        await coordinator.register("child", "recon", parent_id="root")


def test_caller_supplied_coordinator_is_capped_by_scan_mode() -> None:
    coordinator = AgentCoordinator(max_agents=20)

    resolved = _coordinator_for_scan_mode(coordinator, "quick")

    assert resolved is coordinator
    assert resolved.max_agents == 2


def test_invalid_final_output_logs_metadata_without_content() -> None:
    target_content = "target-derived-sensitive-content"

    metadata = _final_output_metadata(SimpleNamespace(final_output=target_content))

    assert metadata == f"type=str length={len(target_content)}"
    assert target_content not in metadata


@pytest.mark.asyncio
async def test_overfull_caller_supplied_coordinator_is_rejected() -> None:
    coordinator = AgentCoordinator(max_agents=20)
    for index in range(3):
        await coordinator.register(f"agent-{index}", f"agent-{index}", parent_id=None)

    with pytest.raises(RuntimeError, match=r"above the quick mode limit \(2\)"):
        _coordinator_for_scan_mode(coordinator, "quick")
