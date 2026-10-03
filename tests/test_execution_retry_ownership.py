from __future__ import annotations

from typing import Any, Literal, cast

import httpx
import pytest
from agents import RunConfig, Runner
from openai import APIError, BadRequestError

from lyrashield.lifecycle import execution
from lyrashield.lifecycle.agents import AgentCoordinator


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://api.openai.com/v1/responses")


class _FailedStream:
    def __init__(
        self, event: object, exc: APIError, surface: Literal["iterator", "run_loop_exception"]
    ) -> None:
        self._event = event
        self._exc = exc if surface == "iterator" else None
        self.run_loop_exception = exc if surface == "run_loop_exception" else None

    async def stream_events(self) -> Any:
        yield self._event
        if self._exc is not None:
            raise self._exc


@pytest.mark.asyncio
@pytest.mark.parametrize("error_kind", ["api", "bad_request"])
@pytest.mark.parametrize("surface", ["iterator", "run_loop_exception"])
async def test_run_cycle_does_not_replay_failed_paid_stream(
    monkeypatch: pytest.MonkeyPatch,
    error_kind: Literal["api", "bad_request"],
    surface: Literal["iterator", "run_loop_exception"],
) -> None:
    failure = (
        APIError("An error occurred while processing the request.", _request(), body=None)
        if error_kind == "api"
        else BadRequestError(
            "Invalid request", response=httpx.Response(400, request=_request()), body=None
        )
    )
    event = object()
    stream = _FailedStream(event, failure, surface)
    stream_calls = 0
    delivered_events: list[object] = []

    def run_streamed(*_args: Any, **_kwargs: Any) -> _FailedStream:
        nonlocal stream_calls
        stream_calls += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    with pytest.raises(type(failure)) as raised:
        await execution._run_cycle(
            object(),
            coordinator,
            "root",
            input_data="task",
            run_config=cast("RunConfig", object()),
            context={},
            max_turns=5,
            session=None,
            interactive=False,
            event_sink=lambda _agent_id, observed: delivered_events.append(observed),
            hooks=None,
        )

    assert raised.value is failure
    assert stream_calls == 1
    assert delivered_events == [event]
