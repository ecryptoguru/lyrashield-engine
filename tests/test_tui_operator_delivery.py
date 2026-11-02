"""Draft retention and pending feedback through the normal TUI input widget."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import pytest
from textual import events
from textual.app import App

from lyrashield.interface.tui.app import ChatTextArea, StrixTUIApp


if TYPE_CHECKING:
    from textual.app import ComposeResult

    from lyrashield.interface.tui.messages import Delivery


class _DeliveryApp(App[None]):
    def __init__(self, outcome: Delivery) -> None:
        super().__init__()
        self.outcome = outcome
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.submissions: list[str] = []

    def compose(self) -> ComposeResult:
        area = ChatTextArea("review auth")
        area.set_app_reference(cast("StrixTUIApp", self))
        yield area

    async def _send_user_message(self, message: str, submission_id: str) -> Delivery:
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
        assert not area.read_only
        assert area.text == ("" if outcome == "queued" else "review auth")
        if outcome != "queued":
            await area._on_key(events.Key("enter", "\r"))
            assert (app.submissions[0] == app.submissions[1]) is (outcome == "unknown")
        await pilot.pause()
