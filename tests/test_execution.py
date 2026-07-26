"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from agents.memory import SQLiteSession

from strix.core.agents import AgentCoordinator
from strix.core.execution import (
    _final_output_metadata,  # pyright: ignore[reportPrivateUsage]
    _notify_parent_on_crash,  # pyright: ignore[reportPrivateUsage]
)
from strix.core.runner import _coordinator_for_scan_mode  # pyright: ignore[reportPrivateUsage]


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


@pytest.mark.asyncio
async def test_send_rejects_messages_to_terminal_agents() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("root", session=SQLiteSession(session_id="root"))
    await coordinator.attach_runtime("child", session=SQLiteSession(session_id="child"))

    for terminal_status in ("completed", "stopped", "crashed", "failed"):
        await coordinator.set_status("child", terminal_status)
        delivered = await coordinator.send(
            "child",
            {
                "from": "root",
                "type": "instruction",
                "priority": "normal",
                "content": "are you done?",
            },
        )
        assert not delivered, f"send should fail for status {terminal_status}"
        pending, _ = await coordinator.consume_pending("child")
        assert pending == 0, f"pending count should not grow for status {terminal_status}"


@pytest.mark.asyncio
async def test_send_delivers_to_waiting_agents() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("child", session=SQLiteSession(session_id="child"))
    await coordinator.set_status("child", "waiting")

    delivered = await coordinator.send(
        "child",
        {
            "from": "root",
            "type": "instruction",
            "priority": "normal",
            "content": "wake up",
        },
    )
    assert delivered
    pending, _ = await coordinator.consume_pending("child")
    assert pending == 1


@pytest.mark.asyncio
async def test_notify_parent_on_crash_wakes_parent_for_terminal_statuses() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("root", session=SQLiteSession(session_id="root"))

    for terminal_status in ("crashed", "failed", "stopped"):
        await coordinator.set_status("child", "running")
        # Reset parent inbox
        await coordinator.consume_pending("root")
        await _notify_parent_on_crash(coordinator, "child", terminal_status)

        pending, items = await coordinator.consume_pending("root", include_items=True)
        assert pending == 1, f"parent should be notified for {terminal_status}"
        content = items[-1].get("content", "")
        assert "crash" in content
        assert "child" in content


@pytest.mark.asyncio
async def test_notify_parent_on_crash_ignores_completed_and_root() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")

    await _notify_parent_on_crash(coordinator, "child", "completed")
    pending, _ = await coordinator.consume_pending("root")
    assert pending == 0

    # Root has no parent, so nothing should happen.
    await _notify_parent_on_crash(coordinator, "root", "crashed")
    pending, _ = await coordinator.consume_pending("root")
    assert pending == 0


@pytest.mark.asyncio
async def test_terminal_child_notifies_waiting_parent() -> None:
    """A child that becomes terminal must wake a parent parked in wait_for_message."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("root", session=SQLiteSession(session_id="root"))

    parent_wait = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)  # let parent park
    assert not parent_wait.done()

    await coordinator.set_status("child", "crashed")
    await _notify_parent_on_crash(coordinator, "child", "crashed")

    await asyncio.wait_for(parent_wait, timeout=1.0)
    pending, _ = await coordinator.consume_pending("root")
    assert pending == 1


@pytest.mark.asyncio
async def test_request_stop_notifies_waiting_parent() -> None:
    """A graceful stop (stop_agent / request_stop) must wake a waiting parent."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("root", session=SQLiteSession(session_id="root"))

    parent_wait = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)  # let parent park
    assert not parent_wait.done()

    await coordinator.request_stop("child")

    await asyncio.wait_for(parent_wait, timeout=1.0)
    pending, items = await coordinator.consume_pending("root", include_items=True)
    assert pending == 1
    assert "stopped" in items[-1].get("content", "").lower()


@pytest.mark.asyncio
async def test_request_stop_does_not_double_notify() -> None:
    """Calling request_stop twice on the same child must only notify the parent once."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("root", session=SQLiteSession(session_id="root"))

    await coordinator.request_stop("child")
    await coordinator.request_stop("child")

    pending, _ = await coordinator.consume_pending("root")
    assert pending == 1


@pytest.mark.asyncio
async def test_request_stop_does_not_notify_for_already_terminal_child() -> None:
    """request_stop on a completed child must not send a redundant notification."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.attach_runtime("root", session=SQLiteSession(session_id="root"))
    await coordinator.set_status("child", "completed")

    await coordinator.request_stop("child")

    pending, _ = await coordinator.consume_pending("root")
    assert pending == 0
