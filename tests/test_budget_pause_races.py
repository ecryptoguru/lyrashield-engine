"""Real driver regressions for scan-wide operator pause and waiter races."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, Mock

import pytest

from lyrashield.lifecycle import execution
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.execution import run_agent_loop
from lyrashield.lifecycle.sessions import open_agent_session


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


async def _until(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(1):
        while not predicate():
            await asyncio.sleep(0.001)


@pytest.mark.asyncio
@pytest.mark.parametrize("steering", [False, True])
async def test_existing_timed_driver_stays_alive_and_paused_until_explicit_resume(
    monkeypatch: pytest.MonkeyPatch,
    steering: bool,
    tmp_path: Path,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    await coordinator.park_waiting("child", wait_kind="agents")
    increase = Mock()
    coordinator.set_budget_extender(increase)
    entered_wait = asyncio.Event()
    original_wait = coordinator.wait_for_message

    async def wait(agent_id: str, *, timeout: float | None = None) -> bool:
        entered_wait.set()
        return await original_wait(agent_id, timeout=timeout)

    calls: list[tuple[bool, int]] = []
    session = open_agent_session("child", tmp_path / "agents.sqlite")

    async def provider_cycle(*_args: Any, **_kwargs: Any) -> None:
        calls.append((coordinator.budget_paused, coordinator.pending_counts.get("child", 0)))
        await coordinator.park_waiting("child", wait_kind="user")

    monkeypatch.setattr(coordinator, "wait_for_message", wait)
    monkeypatch.setattr(execution, "_WAITING_AUTO_RESUME_TIMEOUT_S", 0.01)
    monkeypatch.setattr(execution, "_validate_model_route", Mock())
    monkeypatch.setattr(execution, "_run_until_lifecycle", provider_cycle)
    task = asyncio.create_task(
        run_agent_loop(
            agent=None,
            initial_input=[],
            run_config=MagicMock(),
            context={"parent_id": "root"},
            max_turns=4,
            coordinator=coordinator,
            agent_id="child",
            interactive=True,
            start_parked=True,
            session=session,
        )
    )
    try:
        await asyncio.wait_for(entered_wait.wait(), 1)
        await coordinator.pause_for_budget("root")
        if steering:
            assert await coordinator.send(
                "child", {"from": "user", "content": "retry", "submission_id": "queued"}
            )
        await asyncio.sleep(0.04)
        assert calls == []
        assert not task.done()
        if steering:
            assert coordinator.pending_counts["child"] == 1
        assert await coordinator.operator_control("increase_budget", "increase")
        await asyncio.sleep(0.04)
        assert calls == []
        assert not task.done()
        assert coordinator.budget_paused
        assert await coordinator.operator_control("resume", "resume")
        await _until(lambda: bool(calls))
        assert calls == [(False, 0)]
        assert coordinator.pending_counts["child"] == 0
        assert not task.done()
        items = await session.get_items()
        assert sum("retry" in str(item) for item in items) == int(steering)
    finally:
        task.cancel()
        await task
        session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["failed", "crashed"])
@pytest.mark.parametrize("sender", ["user", "root"])
async def test_failed_agent_only_user_steering_recovers_after_pause(
    status: str,
    sender: str,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    await coordinator.set_status("child", status, error="provider failed")  # type: ignore[arg-type]
    await coordinator.pause_for_budget("root")
    coordinator.set_budget_extender(Mock())
    assert await coordinator.send("child", {"from": sender, "content": "retry"})
    assert coordinator.budget_paused
    assert await coordinator.operator_control("resume", "resume")
    assert await coordinator.wait_for_message("child", timeout=0.01) is (sender == "user")
    assert coordinator.runtimes["child"].user_wake_required is (sender != "user")
    assert ("child" in coordinator.errors) is (sender != "user")


@pytest.mark.asyncio
async def test_child_stop_notice_cannot_reactivate_stopped_root() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    await coordinator.pause_for_budget("root")
    increase = Mock()
    coordinator.set_budget_extender(increase)
    await coordinator.request_stop("root")
    await coordinator.request_stop("child")
    assert coordinator.statuses["root"] == "stopped"
    assert not await coordinator.operator_control("increase_budget", "increase")
    assert not await coordinator.operator_control("resume", "resume")
    increase.assert_not_called()


@pytest.mark.asyncio
async def test_exited_attached_driver_is_not_reachable() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    task = asyncio.create_task(asyncio.sleep(0))
    await task
    await coordinator.attach_runtime("root", task=task)
    reachable, _ = await coordinator.reachability("root")
    assert not reachable
    assert not await coordinator.send("root", {"from": "user", "content": "retry"})


@pytest.mark.asyncio
@pytest.mark.parametrize("restored", [False, True])
async def test_fresh_or_restored_driver_cannot_start_under_existing_pause(
    monkeypatch: pytest.MonkeyPatch,
    restored: bool,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.pause_for_budget("root")
    await coordinator.register("child", "child", parent_id="root")
    if restored:
        snapshot = await coordinator.snapshot()
        coordinator = AgentCoordinator()
        await coordinator.restore(snapshot)
    coordinator.set_budget_extender(Mock())
    calls: list[bool] = []

    async def provider_cycle(*_args: Any, **_kwargs: Any) -> None:
        calls.append(coordinator.budget_paused)
        await coordinator.park_waiting("child", wait_kind="user")

    monkeypatch.setattr(execution, "_validate_model_route", Mock())
    monkeypatch.setattr(execution, "_run_until_lifecycle", provider_cycle)
    task = asyncio.create_task(
        run_agent_loop(
            agent=None,
            initial_input=[],
            run_config=MagicMock(),
            context={"parent_id": "root"},
            max_turns=4,
            coordinator=coordinator,
            agent_id="child",
            interactive=True,
        )
    )
    try:
        await asyncio.sleep(0.02)
        assert calls == []
        assert not task.done()
        assert await coordinator.operator_control("increase_budget", "increase")
        await asyncio.sleep(0.02)
        assert calls == []
        assert await coordinator.operator_control("resume", "resume")
        await _until(lambda: bool(calls))
        assert calls == [False]
    finally:
        task.cancel()
        await task


@pytest.mark.asyncio
async def test_pause_during_cycle_preparation_does_not_start_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    session = open_agent_session("child", tmp_path / "agents.sqlite")

    async def compact(*_args: Any, **_kwargs: Any) -> bool:
        await coordinator.pause_for_budget("root")
        return False

    provider = Mock()
    monkeypatch.setattr(execution, "_compact_session", compact)
    monkeypatch.setattr(execution.Runner, "run_streamed", provider)
    from lyrashield.lifecycle.hooks import BudgetPausedError  # noqa: PLC0415

    try:
        with pytest.raises(BudgetPausedError):
            await execution._run_until_lifecycle(
                None,
                coordinator,
                "child",
                initial_input=[],
                run_config=MagicMock(),
                context={"parent_id": "root"},
                max_turns=4,
                session=session,
                interactive=True,
                event_sink=None,
                hooks=None,
            )
        provider.assert_not_called()
        assert coordinator.statuses["child"] == "budget_paused"
    finally:
        session.close()


@pytest.mark.asyncio
async def test_late_lifecycle_park_keeps_global_pause_and_preserves_stop() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.register("child", "child", parent_id="root")
    await coordinator.pause_for_budget("root")
    await coordinator.park_waiting("child", wait_kind="agents")
    assert coordinator.statuses["child"] == "budget_paused"
    await coordinator.request_stop("child")
    await coordinator.park_waiting("child", wait_kind="agents")
    assert coordinator.statuses["child"] == "stopped"
