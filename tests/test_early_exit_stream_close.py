"""Early exits close the agent's streamed run (E2.3, PRs #184/#187/#190).

Every early exit from a streamed run cycle — deadline refusal, budget stop,
idle-stream timeout, cancellation — must deterministically stop the SDK run
instead of leaving it streaming in the background. The regressions from the
bounded-deadline and bounded-stream work cover the salvage behavior; this
covers the stream teardown branch itself.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lyrashield.lifecycle.execution import _run_cycle


class _FakeStream:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.run_loop_exception = exc
        self.cancel_calls: list[str] = []

    def cancel(self, *, mode: str) -> None:
        self.cancel_calls.append(mode)

    def stream_events(self) -> Any:
        return self._iterate()

    async def _iterate(self) -> Any:
        if self.run_loop_exception is not None:
            raise self.run_loop_exception
        yield {"type": "response.completed"}
        return


def _coordinator() -> Any:
    coordinator = AsyncMock()
    coordinator.mark_running = AsyncMock()
    coordinator.attach_stream = AsyncMock()
    coordinator.detach_stream = AsyncMock()
    coordinator.track_conversation_id = AsyncMock()
    coordinator.is_shutting_down = False
    return coordinator


@pytest.mark.asyncio
@pytest.mark.parametrize("exc_kind", ["idle_timeout", "clean"])
async def test_run_cycle_stops_the_stream_on_every_exit(exc_kind: str) -> None:
    exc: BaseException | None = (
        TimeoutError("model stream produced no event for 300s")
        if exc_kind == "idle_timeout"
        else None
    )
    stream = _FakeStream(exc)
    coordinator = _coordinator()

    with patch("lyrashield.lifecycle.execution.Runner.run_streamed", return_value=stream):
        if exc is not None:
            with pytest.raises(TimeoutError, match="model stream produced no event"):
                await _run_cycle(
                    agent=MagicMock(),
                    coordinator=coordinator,
                    agent_id="agent-1",
                    input_data=[],
                    run_config=MagicMock(),
                    context={"parent_id": None},
                    max_turns=8,
                    session=None,
                    interactive=False,
                    event_sink=None,
                    hooks=None,
                )
        else:
            result = await _run_cycle(
                agent=MagicMock(),
                coordinator=coordinator,
                agent_id="agent-1",
                input_data=[],
                run_config=MagicMock(),
                context={"parent_id": None},
                max_turns=8,
                session=None,
                interactive=False,
                event_sink=None,
                hooks=None,
            )
            assert result is stream

    coordinator.detach_stream.assert_awaited_once()
    assert stream.cancel_calls == ["immediate"]
