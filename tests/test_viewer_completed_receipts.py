"""Completed scans reconcile accepted submissions without accepting new writes."""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.error
import urllib.request
from typing import TYPE_CHECKING
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest

from lyrashield.interface.tui import messages
from lyrashield.interface.viewer.server import serve
from lyrashield.lifecycle.agents import AgentCoordinator


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("kind", ["steer", "control"])
def test_completed_run_reconciles_previously_accepted_submission(tmp_path: Path, kind: str) -> None:
    run = tmp_path / "run"
    run.mkdir()
    record = run / "run.json"
    record.write_text(json.dumps({"status": "running"}))
    calls: list[tuple[str, ...]] = []

    def accept(*args: str) -> bool:
        calls.append(args)
        return True

    server, url, token = serve(
        run, open_browser=False, steer_handler=accept, control_handler=accept
    )
    headers = {
        "Cookie": f"strix_viewer_session_{urlsplit(url).port}={token}",
        "Content-Type": "application/json",
    }
    body = {"run": "run", "submission_id": "known"}
    body.update(
        {"agent_id": "root", "message": "review"}
        if kind == "steer"
        else {"action": "increase_budget"}
    )
    endpoint = "/api/agents/steer" if kind == "steer" else "/api/scan/control"

    def post(payload: dict[str, str]) -> dict[str, object]:
        request = urllib.request.Request(  # noqa: S310 - local fixture URL
            url + endpoint, data=json.dumps(payload).encode(), headers=headers
        )
        with urllib.request.urlopen(request) as response:  # noqa: S310
            return json.load(response)

    try:
        assert post(body)["ok"] is True
        record.write_text(json.dumps({"status": "completed", "end_time": "2026-11-02T00:00:00Z"}))
        assert post(body)["ok"] is True
        assert len(calls) == 1
        for changed in [
            {**body, "submission_id": "new"},
            {**body, "message": "altered"} if kind == "steer" else {**body, "action": "resume"},
        ]:
            with pytest.raises(urllib.error.HTTPError) as error:
                post(changed)
            assert error.value.code == 409
        assert len(calls) == 1
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("kind", ["steer", "control"])
@pytest.mark.parametrize("pending", [False, True])
def test_lost_ack_reconciles_only_receipt_after_finished_loop_close(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, pending: bool
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    record = run / "run.json"
    record.write_text(json.dumps({"status": "running"}))
    coordinator = AgentCoordinator()
    live_view = Mock()
    increase = Mock()
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    async def setup() -> None:
        await coordinator.register("root", "Root", parent_id=None)
        coordinator.set_budget_extender(increase)
        await coordinator.pause_for_budget("root")

    asyncio.run_coroutine_threadsafe(setup(), loop).result(timeout=3)
    monkeypatch.setattr(messages, "DELIVERY_TIMEOUT_SECONDS", 0.01)
    if pending:

        async def blocked(*_args: object, **_kwargs: object) -> bool:
            await asyncio.Event().wait()
            return True

        monkeypatch.setattr(coordinator, "send" if kind == "steer" else "operator_control", blocked)
    calls = 0

    def steer(aid: str, text: str, submission_id: str) -> bool:
        nonlocal calls
        calls += 1
        assert messages.send_user_message_to_agent(
            coordinator=coordinator,
            loop=loop,
            live_view=live_view,
            target_agent_id=aid,
            message=text,
            submission_id=submission_id,
        )
        raise TimeoutError("acknowledgement lost after acceptance")

    def control(action: str, submission_id: str) -> bool:
        nonlocal calls
        calls += 1
        assert messages.send_operator_control(
            coordinator=coordinator, loop=loop, action=action, submission_id=submission_id
        )
        raise TimeoutError("acknowledgement lost after acceptance")

    server, url, token = serve(
        run,
        open_browser=False,
        steer_handler=steer,
        control_handler=control,
        submission_receipt_handler=lambda sid, fp: messages.read_submission_receipt(
            coordinator, sid, fp
        ),
    )
    headers = {
        "Cookie": f"strix_viewer_session_{urlsplit(url).port}={token}",
        "Content-Type": "application/json",
    }
    body = {"run": "run", "submission_id": "lost"}
    body.update(
        {"agent_id": "root", "message": "review"}
        if kind == "steer"
        else {"action": "increase_budget"}
    )
    endpoint = "/api/agents/steer" if kind == "steer" else "/api/scan/control"

    def post(payload: dict[str, str]) -> dict[str, object]:
        request = urllib.request.Request(  # noqa: S310 - local fixture URL
            url + endpoint, data=json.dumps(payload).encode(), headers=headers
        )
        with urllib.request.urlopen(request) as response:  # noqa: S310
            return json.load(response)

    async def cancel_remaining() -> None:
        tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    try:
        assert post(body) == {"ok": False, "error": "delivery_unknown"}
        record.write_text(json.dumps({"status": "completed", "end_time": "2026-11-02T00:00:00Z"}))
        if pending:
            assert post(body) == {"ok": False, "error": "delivery_unknown"}
        asyncio.run_coroutine_threadsafe(cancel_remaining(), loop).result(timeout=3)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=3)
        assert not thread.is_alive()
        loop.close()
        result = post(body)
        assert result == (
            {"ok": False, "error": "delivery_unknown"}
            if pending
            else {"ok": True, "status": "queued"}
        )
        assert calls == 1
        for changed in [
            {**body, "submission_id": "new"},
            {**body, "run": "historical"},
            {**body, "message": "altered"} if kind == "steer" else {**body, "action": "resume"},
        ]:
            with pytest.raises(urllib.error.HTTPError) as error:
                post(changed)
            assert error.value.code == 409
        assert calls == 1
        if not pending:
            if kind == "steer":
                assert coordinator.pending_counts["root"] == 1
                live_view.record_user_message.assert_called_once_with("root", "review")
                assert messages.send_user_message_to_agent(
                    coordinator=coordinator,
                    loop=loop,
                    live_view=live_view,
                    target_agent_id="root",
                    message="review",
                    submission_id="lost",
                )
            else:
                increase.assert_called_once()
                assert messages.send_operator_control(
                    coordinator=coordinator,
                    loop=loop,
                    action="increase_budget",
                    submission_id="lost",
                )
    finally:
        server.shutdown()
        server.server_close()
        if not loop.is_closed():
            asyncio.run_coroutine_threadsafe(cancel_remaining(), loop).result(timeout=3)
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=3)
            loop.close()


@pytest.mark.parametrize("kind", ["steer", "control"])
def test_read_only_receipt_endpoint_never_enqueues_unknown_or_pending_ids(
    tmp_path: Path, kind: str
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "run.json").write_text(json.dumps({"status": "running"}))
    calls = Mock(side_effect=TimeoutError("acknowledgement unknown"))
    receipt = Mock(return_value="unknown")
    server, url, token = serve(
        run,
        open_browser=False,
        steer_handler=calls,
        control_handler=calls,
        submission_receipt_handler=receipt,
    )
    headers = {
        "Cookie": f"strix_viewer_session_{urlsplit(url).port}={token}",
        "Content-Type": "application/json",
    }
    body = {"run": "run", "submission_id": "known"}
    body.update(
        {"agent_id": "root", "message": "review"}
        if kind == "steer"
        else {"action": "increase_budget"}
    )

    def post(
        payload: dict[str, str], path: str = "/api/receipts/check", authenticated: bool = True
    ) -> dict[str, object]:
        request = urllib.request.Request(  # noqa: S310 - local fixture URL
            url + path,
            data=json.dumps(payload).encode(),
            headers=headers if authenticated else {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request) as response:  # noqa: S310
            return json.load(response)

    try:
        assert post(body) == {"ok": False, "error": "delivery_unknown"}
        calls.assert_not_called()
        receipt.assert_not_called()
        assert post(body, "/api/agents/steer" if kind == "steer" else "/api/scan/control") == {
            "ok": False,
            "error": "delivery_unknown",
        }
        assert post(body) == {"ok": False, "error": "delivery_unknown"}
        assert calls.call_count == 1
        receipt.return_value = "queued"
        assert post(body) == {"ok": True, "status": "queued"}
        assert post(body) == {"ok": True, "status": "queued"}
        assert calls.call_count == 1
        for changed in [
            {**body, "run": "historical"},
            {**body, "message": "altered"} if kind == "steer" else {**body, "action": "resume"},
        ]:
            with pytest.raises(urllib.error.HTTPError) as error:
                post(changed)
            assert error.value.code == 409
        with pytest.raises(urllib.error.HTTPError) as error:
            post(body, authenticated=False)
        assert error.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
