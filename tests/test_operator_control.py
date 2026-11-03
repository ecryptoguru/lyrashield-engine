"""Operator messages must never grant more spend or implicitly resume work."""

import asyncio
from unittest.mock import Mock

import pytest

from lyrashield.interface.tui.messages import deliver_user_message
from lyrashield.lifecycle.agents import AgentCoordinator


@pytest.mark.asyncio
async def test_paused_messages_queue_without_waking_or_extending() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.pause_for_budget("root")
    extend = Mock()
    coordinator.set_budget_extender(extend)
    waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)
    assert await coordinator.send("missing", {"from": "user", "content": "go"}) is False
    assert await coordinator.send("root", {"from": "user", "content": "go"}) is True
    await asyncio.sleep(0)
    assert coordinator.budget_paused
    assert coordinator.statuses["root"] == "budget_paused"
    extend.assert_not_called()
    assert not waiter.done()
    assert await coordinator.operator_control("increase_budget", "increase-1")
    extend.assert_called_once()
    assert coordinator.budget_paused
    assert not waiter.done()
    assert await coordinator.operator_control("resume", "resume-1")
    await asyncio.wait_for(waiter, 1)
    assert coordinator.statuses["root"] == "waiting"
    assert await coordinator.operator_control("increase_budget", "increase-1")
    extend.assert_called_once()


@pytest.mark.asyncio
async def test_control_cannot_revive_stopped_scan_or_headless_budget() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.pause_for_budget("root")
    assert not await coordinator.operator_control("increase_budget", "no-hook")
    assert not await coordinator.operator_control("resume", "headless")
    extend = Mock()
    coordinator.set_budget_extender(extend)
    await coordinator.trigger_budget_stop()
    assert not await coordinator.operator_control("increase_budget", "stop")
    assert not await coordinator.operator_control("resume", "stop-resume")
    assert not await coordinator.send("root", {"from": "user", "content": "go"})
    extend.assert_not_called()


@pytest.mark.asyncio
async def test_delivery_is_acknowledged_and_idempotent_on_same_loop() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    view = Mock()
    kwargs = {
        "coordinator": coordinator,
        "loop": asyncio.get_running_loop(),
        "live_view": view,
        "target_agent_id": "root",
        "message": "review auth",
        "submission_id": "send-1",
    }
    assert await deliver_user_message(**kwargs) == "queued"
    assert await deliver_user_message(**kwargs) == "queued"
    assert coordinator.pending_counts["root"] == 1
    view.record_user_message.assert_called_once_with("root", "review auth")
    assert (
        await deliver_user_message(
            **{**kwargs, "target_agent_id": "missing", "submission_id": "send-2"}
        )
        == "rejected"
    )
    assert view.record_user_message.call_count == 1


@pytest.mark.asyncio
async def test_duplicate_identifier_with_changed_payload_is_rejected() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    message = {"from": "user", "content": "first", "submission_id": "same"}
    assert await coordinator.send("root", message)
    assert not await coordinator.send("root", {**message, "content": "different"})
    assert coordinator.pending_counts["root"] == 1


@pytest.mark.asyncio
async def test_timeout_retry_recovers_acceptance_without_duplicate_delivery() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    original_send = coordinator.send
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_send(*args: object, **kwargs: object) -> bool:
        entered.set()
        await release.wait()
        return await original_send(*args, **kwargs)  # type: ignore[arg-type]

    coordinator.send = slow_send  # type: ignore[method-assign]
    view = Mock()
    kwargs = {
        "coordinator": coordinator,
        "loop": asyncio.get_running_loop(),
        "live_view": view,
        "target_agent_id": "root",
        "message": "review",
        "submission_id": "slow",
        "timeout": 0.01,
    }
    pending = asyncio.create_task(deliver_user_message(**kwargs))
    await entered.wait()
    assert not pending.done()
    assert view.record_user_message.call_count == 0
    assert await pending == "unknown"
    assert coordinator.pending_counts.get("root", 0) == 0
    release.set()
    assert await deliver_user_message(**kwargs) == "queued"
    assert coordinator.pending_counts["root"] == 1
    view.record_user_message.assert_called_once_with("root", "review")


@pytest.mark.asyncio
async def test_submission_validation_preserves_stopped_states_and_pause() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    await coordinator.set_status("child", "stopped")
    await coordinator.pause_for_budget("root")
    extend = Mock()
    coordinator.set_budget_extender(extend)
    assert not await coordinator.send("child", {"from": "user", "content": "go"})
    assert coordinator.statuses["child"] == "stopped"
    assert not await coordinator.operator_control("increase_budget", "x" * 129)
    assert not await coordinator.operator_control("unknown", "invalid")
    assert await coordinator.operator_control("increase_budget", "one")
    assert not await coordinator.operator_control("resume", "one")
    assert coordinator.budget_paused
    extend.assert_called_once()
    assert await coordinator.operator_control("resume", "two")
    assert coordinator.statuses["child"] == "stopped"


@pytest.mark.asyncio
async def test_late_delivery_to_completed_agent_stays_paused_until_resume() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    await coordinator.set_status("child", "completed")
    await coordinator.pause_for_budget("root")
    coordinator.set_budget_extender(Mock())
    assert await coordinator.send("child", {"from": "user", "content": "follow up"})
    assert coordinator.statuses["child"] == "budget_paused"
    assert await coordinator.operator_control("resume", "resume-late")
    assert coordinator.statuses["child"] == "waiting"


@pytest.mark.asyncio
async def test_sync_transport_refuses_own_loop_without_scheduling() -> None:
    from lyrashield.interface.tui.messages import send_user_message_to_agent  # noqa: PLC0415

    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    with pytest.raises(RuntimeError, match="Use deliver_user_message"):
        send_user_message_to_agent(
            coordinator=coordinator,
            loop=asyncio.get_running_loop(),
            live_view=Mock(),
            target_agent_id="root",
            message="review",
            submission_id="same-loop",
        )
    assert coordinator.pending_counts.get("root", 0) == 0


def test_headless_hooks_cannot_extend_budget() -> None:
    from lyrashield.lifecycle.hooks import ReportUsageHooks  # noqa: PLC0415

    hooks = ReportUsageHooks(model="test-model", max_budget_usd=1.2, interactive=False)
    with pytest.raises(ValueError, match="interactive"):
        hooks.extend_budget()
    assert hooks.budget_control_state()["increment_usd"] == 1.2
    assert hooks.budget_control_state()["limit_usd"] == 1.2


@pytest.mark.asyncio
async def test_stop_during_budget_pause_wakes_waiter_and_cannot_be_revived() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.pause_for_budget("root")
    extend = Mock()
    coordinator.set_budget_extender(extend)
    waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)
    await coordinator.request_stop("root")
    await asyncio.wait_for(waiter, 1)
    assert coordinator.statuses["root"] == "stopped"
    assert not await coordinator.operator_control("resume", "after-stop-resume")
    assert not await coordinator.operator_control("increase_budget", "after-stop-increase")
    assert not await coordinator.send("root", {"from": "user", "content": "go"})
    extend.assert_not_called()
