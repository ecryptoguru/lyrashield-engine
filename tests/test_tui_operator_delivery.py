"""Draft retention and pending feedback through the normal TUI input widget."""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING, cast
from unittest.mock import Mock

import pytest
from textual import events
from textual.app import App

from lyrashield.interface.tui import app as tui_app
from lyrashield.interface.tui import messages
from lyrashield.interface.tui.app import ChatTextArea, StrixTUIApp
from lyrashield.lifecycle.agents import AgentCoordinator


if TYPE_CHECKING:
    from textual.app import ComposeResult

    from lyrashield.interface.tui.messages import Delivery


class _DeliveryApp(App[None]):
    def __init__(self, outcome: Delivery) -> None:
        super().__init__()
        self.outcome = outcome
        self.selected_agent_id = "root"
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.submissions: list[str] = []

    def compose(self) -> ComposeResult:
        area = ChatTextArea("review auth")
        area.set_app_reference(cast("StrixTUIApp", self))
        yield area

    async def _send_user_message(
        self, message: str, submission_id: str, target_agent_id: str | None
    ) -> Delivery:
        assert target_agent_id == "root"
        assert message == "review auth"
        self.submissions.append(submission_id)
        self.started.set()
        await self.release.wait()
        return self.outcome


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["queued", "rejected", "unknown"])
async def test_input_keeps_draft_until_acceptance_and_reuses_unknown_submission(
    outcome: Delivery,
) -> None:
    app = _DeliveryApp(outcome)
    async with app.run_test() as pilot:
        area = app.query_one(ChatTextArea)
        pending = asyncio.create_task(area._on_key(events.Key("enter", "\r")))
        await app.started.wait()
        assert area.text == "review auth"
        assert area.read_only
        app.release.set()
        await pending
        assert area.read_only is (outcome == "unknown")
        assert area.text == ("" if outcome == "queued" else "review auth")
        if outcome != "queued":
            await area._on_key(events.Key("enter", "\r"))
            assert (app.submissions[0] == app.submissions[1]) is (outcome == "unknown")
        await pilot.pause()


class _BridgeApp(App[None]):
    """Run the real widget, TUI sender and async mailbox bridge without a scan."""

    _send_user_message = StrixTUIApp._send_user_message
    _notify_budget_pause = StrixTUIApp._notify_budget_pause

    def __init__(self, coordinator: object, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self.coordinator = coordinator
        self._scan_loop = loop
        self.live_view = Mock()
        self.selected_agent_id = "root"
        self._displayed_events: list[str] = []
        self._budget_pause_notified = False
        self.notices: list[str] = []

    def compose(self) -> ComposeResult:
        area = ChatTextArea("review auth")
        area.set_app_reference(cast("StrixTUIApp", self))
        yield area

    def notify(self, message: str, **_kwargs: object) -> None:
        self.notices.append(message)

    def _update_chat_view(self) -> None:
        pass

    def _focus_chat_input(self) -> None:
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("close_loop", [False, True])
async def test_unknown_widget_retry_freezes_target_text_and_id_after_loop_closes(
    monkeypatch: pytest.MonkeyPatch,
    close_loop: bool,
) -> None:
    coordinator = AgentCoordinator()
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    released = threading.Event()
    original_send = coordinator.send

    async def delayed_send(*args: object, **kwargs: object) -> bool:
        accepted = await original_send(*args, **kwargs)
        while not released.is_set():
            await asyncio.sleep(0.001)
        return accepted

    async def setup() -> None:
        await coordinator.register("root", "Root", parent_id=None)
        await coordinator.register("child", "Child", parent_id="root")

    asyncio.run_coroutine_threadsafe(setup(), loop).result(timeout=3)
    monkeypatch.setattr(coordinator, "send", delayed_send)

    async def short_delivery(**kwargs: object) -> messages.Delivery:
        return await messages.deliver_user_message(**kwargs, timeout=0.01)

    monkeypatch.setattr(tui_app, "deliver_user_message", short_delivery)
    app = _BridgeApp(coordinator, loop)
    try:
        async with app.run_test() as pilot:
            area = app.query_one(ChatTextArea)
            await pilot.press("enter")
            assert "Delivery unknown" in app.notices[-1]
            assert coordinator.pending_counts["root"] == 1
            app.selected_agent_id = "child"
            await pilot.press("x", "shift+enter")
            assert area.text == "review auth"
            released.set()

            async def settled() -> None:
                await asyncio.sleep(0.02)

            asyncio.run_coroutine_threadsafe(settled(), loop).result(timeout=3)
            if close_loop:
                loop.call_soon_threadsafe(loop.stop)
                thread.join(timeout=3)
                loop.close()
                app.selected_agent_id = None
            await pilot.press("enter")
            assert area.text == ""
            assert "Queued" in app.notices
            assert coordinator.pending_counts["root"] == 1
            assert coordinator.pending_counts["child"] == 0
            app.live_view.record_user_message.assert_called_once_with("root", "review auth")
    finally:
        released.set()
        if not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=3)
            loop.close()


@pytest.mark.asyncio
async def test_tui_subcent_budget_notices_describe_actual_increment_and_limit() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    budget = {"limit_usd": 0.004, "increment_usd": 0.004}

    def increase() -> None:
        budget["limit_usd"] += budget["increment_usd"]

    coordinator.set_budget_extender(increase, budget_state=lambda: dict(budget))
    await coordinator.pause_for_budget("root")
    app = _BridgeApp(coordinator, asyncio.get_running_loop())
    async with app.run_test():
        app._notify_budget_pause({"root": "budget_paused"})
        assert "Current limit $0.004; /increase-budget adds $0.004." in app.notices[-1]
        assert await app._send_user_message("/increase-budget", "budget-once", "root") == "queued"
        assert (
            app.notices[-1]
            == "Budget increase accepted; current limit $0.008. Scan remains paused."
        )
        assert budget["limit_usd"] == 0.008
        assert coordinator.budget_paused
        assert coordinator.statuses["root"] == "budget_paused"


@pytest.mark.asyncio
async def test_unknown_draft_requires_explicit_discard_before_different_submission() -> None:
    app = _DeliveryApp("unknown")
    app.release.set()
    async with app.run_test() as pilot:
        area = app.query_one(ChatTextArea)
        await pilot.press("enter")
        first = app.submissions[-1]
        await pilot.press("ctrl+n")
        assert not area.read_only
        assert area.text == ""
        assert area._pending_submission is None
        area.text = "review auth"
        await pilot.press("enter")
        assert app.submissions[-1] != first


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["steer", "control"])
@pytest.mark.parametrize("cancel_during_retry", [False, True])
async def test_cancelled_inner_delivery_stays_unknown_with_live_loop(
    monkeypatch: pytest.MonkeyPatch, kind: str, cancel_during_retry: bool
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.pause_for_budget("root")
    increase = Mock()
    coordinator.set_budget_extender(increase)
    release = asyncio.Event()
    inner: asyncio.Task[object] | None = None
    original = coordinator.send if kind == "steer" else coordinator.operator_control
    calls = 0

    async def delayed(*args: object, **kwargs: object) -> bool:
        nonlocal inner, calls
        calls += 1
        inner = asyncio.current_task()
        accepted = await original(*args, **kwargs)
        await release.wait()
        return accepted

    monkeypatch.setattr(coordinator, "send" if kind == "steer" else "operator_control", delayed)
    monkeypatch.setattr(messages, "DELIVERY_TIMEOUT_SECONDS", 0.01)
    view = Mock()

    async def deliver() -> messages.Delivery:
        if kind == "steer":
            return await messages.deliver_user_message(
                coordinator=coordinator,
                loop=asyncio.get_running_loop(),
                live_view=view,
                target_agent_id="root",
                message="original instruction",
                submission_id="cancelled",
                timeout=0.01,
            )
        return await messages.deliver_operator_control(
            coordinator=coordinator,
            loop=asyncio.get_running_loop(),
            action="increase_budget",
            submission_id="cancelled",
        )

    assert await deliver() == "unknown"
    assert inner is not None
    if cancel_during_retry:
        retry = asyncio.create_task(deliver())
        await asyncio.sleep(0)
    inner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await inner
    fingerprint = (
        ("steer", "root", "original instruction")
        if kind == "steer"
        else ("control", "increase_budget")
    )
    assert messages.read_submission_receipt(coordinator, "cancelled", fingerprint) == "unknown"
    if cancel_during_retry:
        assert await retry == "unknown"
    assert await deliver() == "unknown"
    assert calls == 1
    assert coordinator.pending_counts.get("root", 0) == (1 if kind == "steer" else 0)
    assert increase.call_count == (1 if kind == "control" else 0)
    assert coordinator.budget_paused


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["steer", "control"])
async def test_operator_caller_cancellation_propagates_without_cancelling_delivery(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.pause_for_budget("root")
    increase = Mock()
    coordinator.set_budget_extender(increase)
    started = asyncio.Event()
    release = asyncio.Event()
    original = coordinator.send if kind == "steer" else coordinator.operator_control
    calls = 0

    async def delayed(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        calls += 1
        accepted = await original(*args, **kwargs)
        started.set()
        await release.wait()
        return accepted

    monkeypatch.setattr(coordinator, "send" if kind == "steer" else "operator_control", delayed)
    view = Mock()

    async def deliver() -> messages.Delivery:
        if kind == "steer":
            return await messages.deliver_user_message(
                coordinator=coordinator,
                loop=asyncio.get_running_loop(),
                live_view=view,
                target_agent_id="root",
                message="original instruction",
                submission_id="outer-cancel",
            )
        return await messages.deliver_operator_control(
            coordinator=coordinator,
            loop=asyncio.get_running_loop(),
            action="increase_budget",
            submission_id="outer-cancel",
        )

    caller = asyncio.create_task(deliver())
    await started.wait()
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert caller.cancelled()
    release.set()
    assert await deliver() == "queued"
    assert calls == 1
    assert coordinator.pending_counts.get("root", 0) == (1 if kind == "steer" else 0)
    assert increase.call_count == (1 if kind == "control" else 0)
    assert coordinator.budget_paused
    if kind == "steer":
        view.record_user_message.assert_called_once_with("root", "original instruction")


@pytest.mark.asyncio
async def test_recovered_budget_acceptance_reports_current_state_after_other_operator_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    budget = {"limit_usd": 0.004, "increment_usd": 0.004}
    increases = 0

    def increase() -> None:
        nonlocal increases
        increases += 1
        budget["limit_usd"] += budget["increment_usd"]

    coordinator.set_budget_extender(increase, budget_state=lambda: dict(budget))
    await coordinator.pause_for_budget("root")
    original = coordinator.operator_control
    release = asyncio.Event()
    accepted = asyncio.Event()
    delivery_task: asyncio.Task[bool] | None = None

    async def delayed(action: str, submission_id: str) -> bool:
        nonlocal delivery_task
        delivery_task = asyncio.current_task()
        result = await original(action, submission_id)
        accepted.set()
        await release.wait()
        return result

    monkeypatch.setattr(coordinator, "operator_control", delayed)
    monkeypatch.setattr(messages, "DELIVERY_TIMEOUT_SECONDS", 0.01)
    app = _BridgeApp(coordinator, asyncio.get_running_loop())
    async with app.run_test():
        assert await app._send_user_message("/increase-budget", "lost-budget", "root") == "unknown"
        await accepted.wait()
        assert await original("resume", "other-operator")
        assert not coordinator.budget_paused
        release.set()
        # Finish only the original delivery, then reconcile without an active bridge loop.
        assert delivery_task is not None
        assert await delivery_task
        app._scan_loop = None
        assert await app._send_user_message("/increase-budget", "lost-budget", "root") == "queued"
        assert app.notices[-1] == "Budget increase accepted; current limit $0.008."
        assert budget["limit_usd"] == 0.008
        assert increases == 1
        assert not coordinator.budget_paused
