"""Bounded stream-idle/provider timeouts salvage partial findings (E1.2).

The owned stream wrapper classifies its idle timeout (and supported provider
request timeouts) so the root agent routes them through the existing
partial/finalization behavior instead of failing the whole scan. Unrelated
internal timeouts stay failures, even if their message resembles the old idle
marker.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agents.exceptions import ModelBehaviorError
from agents.model_settings import ModelSettings
from openai import APITimeoutError

from lyrashield.lifecycle.fallback import FallbackServices, run_root_agent
from lyrashield.policy.models import (
    BoundedStreamTimeoutError,
    _RequestBoundTurnGuardModel,
    is_bounded_stream_timeout,
)


_STREAM_IDLE_MESSAGE = "model stream produced no event for 300s"


@dataclass
class _FakeRunConfig:
    model: str = "openai/gpt-6-sol"
    model_settings: Any = None


def _runtime(delegate_model: str | None = "delegate/model") -> SimpleNamespace:
    scan_context = SimpleNamespace(
        settings=SimpleNamespace(),
        llm_settings=SimpleNamespace(force_required_tool_choice=False, extra_headers=None),
        resolved_model="openai/gpt-6-sol",
        delegate_model=delegate_model,
        delegate_reasoning_effort="high",
        scan_mode="quick",
    )
    return SimpleNamespace(
        scan_context=scan_context,
        root_agent=object(),
        initial_input=[],
        run_config=_FakeRunConfig(),
        context={"parent_id": None},
        root_session=None,
        root_status="running",
        hooks=None,
        model_request_timeout=60.0,
        bounded_runtime=None,
        max_output_tokens=4096,
        root_instructions="instructions",
        delegate_routing=False,
        delegate_cache_options=None,
        is_whitebox=False,
        skills=[],
        root_context={},
        root_id="root-1",
    )


def _services(run_agent_loop: Any, report_state: Any) -> FallbackServices:
    return FallbackServices(
        run_agent_loop=run_agent_loop,
        is_output_token_truncation=lambda _exc: False,
        is_content_filter_error=lambda _exc: False,
        uses_chat_completions_tool_schema=lambda _model, _settings: False,
        make_model_settings=lambda *_a, **_k: SimpleNamespace(),
        stable_prompt_cache_key=lambda *_a, **_k: "cache-key",
        build_strix_agent=lambda **_k: object(),
        report_state_getter=lambda: report_state,
        delegate_output_token_ceiling=1024,
    )


def _coordinator() -> Any:
    coordinator = AsyncMock()
    coordinator.cancel_descendants = AsyncMock()
    coordinator.set_status = AsyncMock()
    return coordinator


async def _assert_salvaged(exc: BaseException, *, delegate_model: str | None) -> None:
    runtime = _runtime(delegate_model=delegate_model)
    coordinator = _coordinator()
    report_state = MagicMock()
    run_agent_loop = AsyncMock(side_effect=exc)

    result = await run_root_agent(
        runtime=runtime,
        coordinator=coordinator,
        scan_id="scan-stream",
        max_turns=8,
        interactive=False,
        is_resume=False,
        event_sink=None,
        services=_services(run_agent_loop, report_state),
    )

    assert result is None
    coordinator.cancel_descendants.assert_awaited_once_with(runtime.root_id)
    coordinator.set_status.assert_awaited_once_with(runtime.root_id, "stopped")
    report_state.set_terminal_reason.assert_called_once_with("engine_stopped")
    # No new model call is made during salvage: the failed loop is the only one.
    assert run_agent_loop.await_count == 1


@pytest.mark.asyncio
async def test_stream_idle_timeout_salvages_partial_findings() -> None:
    """The owned wrapper's classified idle timeout is salvaged."""
    await _assert_salvaged(
        BoundedStreamTimeoutError(_STREAM_IDLE_MESSAGE), delegate_model="openai/gpt-6-sol"
    )


@pytest.mark.asyncio
async def test_owned_classified_timeout_salvages_partial_findings() -> None:
    await _assert_salvaged(
        BoundedStreamTimeoutError(_STREAM_IDLE_MESSAGE), delegate_model="openai/gpt-6-sol"
    )


@pytest.mark.asyncio
async def test_provider_request_timeout_salvages_partial_findings() -> None:
    await _assert_salvaged(APITimeoutError("request timed out"), delegate_model="openai/gpt-6-sol")


@pytest.mark.asyncio
async def test_inner_timeout_with_idle_marker_fails_through_wrapper_and_fallback() -> None:
    class Inner:
        async def stream_response(self, *_args: Any, **_kwargs: Any) -> Any:
            raise TimeoutError(_STREAM_IDLE_MESSAGE)
            yield  # pragma: no cover

    model = _RequestBoundTurnGuardModel(
        inner=Inner(), max_tool_calls_per_turn=5, stream_idle_timeout=0.01
    )

    async def run_agent_loop(**_kwargs: Any) -> None:
        async for _event in model.stream_response(
            None,
            [],
            ModelSettings(),
            [],
            None,
            [],
            None,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        ):
            pass

    runtime = _runtime(delegate_model="delegate/model")
    coordinator = _coordinator()
    report_state = MagicMock()

    with pytest.raises(TimeoutError, match="model stream produced no event"):
        await run_root_agent(
            runtime=runtime,
            coordinator=coordinator,
            scan_id="scan-marker-collision",
            max_turns=8,
            interactive=False,
            is_resume=False,
            event_sink=None,
            services=_services(run_agent_loop, report_state),
        )

    coordinator.cancel_descendants.assert_not_awaited()
    coordinator.set_status.assert_not_awaited()
    report_state.set_terminal_reason.assert_not_called()


@pytest.mark.asyncio
async def test_no_finding_timeout_is_still_incomplete_never_clean_success() -> None:
    """A bounded stream timeout with zero findings still records a stop reason."""
    runtime = _runtime(delegate_model="openai/gpt-6-sol")
    coordinator = _coordinator()
    report_state = MagicMock()
    run_agent_loop = AsyncMock(side_effect=BoundedStreamTimeoutError(_STREAM_IDLE_MESSAGE))

    result = await run_root_agent(
        runtime=runtime,
        coordinator=coordinator,
        scan_id="scan-stream-empty",
        max_turns=8,
        interactive=False,
        is_resume=False,
        event_sink=None,
        services=_services(run_agent_loop, report_state),
    )

    assert result is None
    report_state.set_terminal_reason.assert_called_once_with("engine_stopped")


@pytest.mark.asyncio
async def test_unrelated_internal_timeout_remains_failed() -> None:
    """A TimeoutError that is not the stream-idle guard re-raises unchanged."""
    runtime = _runtime(delegate_model="openai/gpt-6-sol")
    coordinator = _coordinator()
    run_agent_loop = AsyncMock(side_effect=TimeoutError("internal wait_for expired"))

    with pytest.raises(TimeoutError, match="internal wait_for expired"):
        await run_root_agent(
            runtime=runtime,
            coordinator=coordinator,
            scan_id="scan-internal",
            max_turns=8,
            interactive=False,
            is_resume=False,
            event_sink=None,
            services=_services(run_agent_loop, MagicMock()),
        )

    coordinator.cancel_descendants.assert_not_awaited()


@pytest.mark.asyncio
async def test_arbitrary_exception_remains_failed() -> None:
    runtime = _runtime(delegate_model="openai/gpt-6-sol")
    coordinator = _coordinator()
    run_agent_loop = AsyncMock(side_effect=RuntimeError("engine blew up"))

    with pytest.raises(RuntimeError, match="engine blew up"):
        await run_root_agent(
            runtime=runtime,
            coordinator=coordinator,
            scan_id="scan-crash",
            max_turns=8,
            interactive=False,
            is_resume=False,
            event_sink=None,
            services=_services(run_agent_loop, MagicMock()),
        )

    coordinator.cancel_descendants.assert_not_awaited()


@pytest.mark.asyncio
async def test_bounded_timeout_during_delegate_fallback_salvages() -> None:
    """A silent stream during the delegate fallback also salvages."""
    runtime = _runtime(delegate_model="delegate/model")
    coordinator = _coordinator()
    report_state = MagicMock()
    run_agent_loop = AsyncMock(
        side_effect=[
            ModelBehaviorError("primary model error"),
            BoundedStreamTimeoutError(_STREAM_IDLE_MESSAGE),
        ]
    )

    result = await run_root_agent(
        runtime=runtime,
        coordinator=coordinator,
        scan_id="scan-fallback",
        max_turns=8,
        interactive=False,
        is_resume=False,
        event_sink=None,
        services=_services(run_agent_loop, report_state),
    )

    assert result is None
    assert run_agent_loop.await_count == 2
    coordinator.cancel_descendants.assert_awaited_once_with(runtime.root_id)
    report_state.set_terminal_reason.assert_called_once_with("engine_stopped")


@pytest.mark.asyncio
async def test_output_token_truncation_path_unchanged() -> None:
    """The existing output-token salvage keeps its reason and single loop."""
    runtime = _runtime(delegate_model="openai/gpt-6-sol")
    coordinator = _coordinator()
    report_state = MagicMock()
    run_agent_loop = AsyncMock(side_effect=ModelBehaviorError("truncated"))
    services = _services(run_agent_loop, report_state)
    services = replace(services, is_output_token_truncation=lambda _exc: True)

    result = await run_root_agent(
        runtime=runtime,
        coordinator=coordinator,
        scan_id="scan-tokens",
        max_turns=8,
        interactive=False,
        is_resume=False,
        event_sink=None,
        services=services,
    )

    assert result is None
    report_state.set_terminal_reason.assert_called_once_with("engine_stopped")
    assert run_agent_loop.await_count == 1


@pytest.mark.asyncio
async def test_content_filter_path_unchanged() -> None:
    """The existing content-filter salvage keeps its reason."""
    runtime = _runtime(delegate_model="openai/gpt-6-sol")
    coordinator = _coordinator()
    report_state = MagicMock()
    run_agent_loop = AsyncMock(side_effect=ModelBehaviorError("blocked"))
    services = _services(run_agent_loop, report_state)
    services = replace(services, is_content_filter_error=lambda _exc: True)

    result = await run_root_agent(
        runtime=runtime,
        coordinator=coordinator,
        scan_id="scan-filter",
        max_turns=8,
        interactive=False,
        is_resume=False,
        event_sink=None,
        services=services,
    )

    assert result is None
    report_state.set_terminal_reason.assert_called_once_with("content_filter_stopped")


def test_classifier_selects_only_bounded_stream_timeouts() -> None:
    assert is_bounded_stream_timeout(TimeoutError(_STREAM_IDLE_MESSAGE)) is False
    assert is_bounded_stream_timeout(BoundedStreamTimeoutError(_STREAM_IDLE_MESSAGE)) is True
    assert is_bounded_stream_timeout(APITimeoutError("request timed out")) is True
    assert is_bounded_stream_timeout(TimeoutError("internal wait_for expired")) is False
    assert is_bounded_stream_timeout(ModelBehaviorError("bad output")) is False
    assert is_bounded_stream_timeout(RuntimeError("engine blew up")) is False


@pytest.mark.asyncio
async def test_owned_stream_wrapper_reclassifies_the_guard_timeout() -> None:
    """The owned credentialed-route wrapper classifies its own idle expiry."""

    async def silent_guard_stream(*_args: Any, **_kwargs: Any) -> Any:
        await asyncio.Event().wait()
        yield  # pragma: no cover

    with patch("strix.config.models._TurnGuardModel.stream_response", silent_guard_stream):
        model = _RequestBoundTurnGuardModel(
            inner=MagicMock(),
            max_tool_calls_per_turn=5,
            stream_idle_timeout=0.01,
        )
        with pytest.raises(BoundedStreamTimeoutError, match="model stream produced no event"):
            async for _event in model.stream_response(
                None,
                [],
                ModelSettings(),
                [],
                None,
                [],
                None,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ):
                pass
