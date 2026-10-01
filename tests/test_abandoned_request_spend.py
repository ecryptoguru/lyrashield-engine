"""Abandoned requests count toward conservative spend (E1.3).

A request that started but never reported usage may still have been billed
by the provider. The reservation for an abandoned attempt becomes a bounded
estimated-spend floor instead of being written off as zero; actual usage
reconciles only the estimate for the same request attempt. Estimates stay in
process-local budget accounting and never enter the verified usage receipt.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from agents.model_settings import ModelSettings
from agents.util._asyncio_tasks import gather_with_cancel

import lyrashield.lifecycle.hooks as hooks_module
from lyrashield.lifecycle.hooks import (
    BudgetExceededError,
    ReportUsageHooks,
    set_active_hooks,
)
from lyrashield.policy.models import _completed_stream_event, _RequestBoundTurnGuardModel


_RATE_CARD = (1.0, 0.0, 0.0, 1.0)


def _context(agent_id: str = "agent-a") -> Any:
    return SimpleNamespace(context={"agent_id": agent_id, "parent_id": None})


def _agent(model: str = "openai/gpt-6-sol") -> Any:
    return SimpleNamespace(name="Agent", model=model, model_settings=None)


def _usage(input_tokens: int, output_tokens: int) -> Any:
    return SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        input_tokens_details=None,
        output_tokens_details=None,
        request_usage_entries=None,
    )


def _hooks(max_budget_usd: float) -> ReportUsageHooks:
    return ReportUsageHooks(
        model="openai/gpt-6-sol",
        max_budget_usd=max_budget_usd,
        # With the patched $1/1M rate card each bounded attempt reserves
        # 200_000 * $1 / 1M = $0.20.
        max_output_tokens=200_000,
    )


def _active_attempt(hooks: ReportUsageHooks, context: Any) -> tuple[str, int] | None:
    active = hooks._active_attempts.get((id(context), "agent-a"))
    return active[1] if active is not None and active[0] is context else None


@pytest.fixture(autouse=True)
def _flat_rate_card(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: _RATE_CARD)
    # _reservation_input_rate is functools-cached: clear entries captured
    # while the rate card is patched so they cannot leak into later tests.
    hooks_module._reservation_input_rate.cache_clear()
    yield
    hooks_module._reservation_input_rate.cache_clear()


@pytest.mark.asyncio
async def test_repeated_starts_cannot_recover_an_abandoned_allowance() -> None:
    """The abandoned attempt's reservation stays a floor, not a write-off."""
    hooks = _hooks(max_budget_usd=0.3)
    context = _context()
    agent = _agent()

    await hooks.on_llm_start(context, agent, None, [])

    # The prior attempt was abandoned: a repeated start without an intervening
    # on_llm_end must count the abandoned reservation against the budget.
    with pytest.raises(BudgetExceededError, match="Next bounded request"):
        await hooks.on_llm_start(context, agent, None, [])


@pytest.mark.asyncio
async def test_retry_usage_does_not_replace_the_prior_abandoned_floor() -> None:
    """A retry response cannot reconcile an unreceipted earlier attempt."""
    hooks = _hooks(max_budget_usd=0.55)
    context = _context()
    agent = _agent()

    await hooks.on_llm_start(context, agent, None, [])
    # The first attempt is abandoned; the retry reserves on top of its floor.
    await hooks.on_llm_start(context, agent, None, [])

    response = SimpleNamespace(usage=_usage(100_000, 100_000), response_id="resp-1")
    await hooks.on_llm_end(context, agent, response)

    # This callback belongs to the retry. It cannot reconcile the abandoned
    # first request, so the next $0.20 reservation would exceed $0.55.
    with pytest.raises(BudgetExceededError, match="Next bounded request"):
        await hooks.on_llm_start(context, agent, None, [])


@pytest.mark.asyncio
async def test_late_receipt_reconciles_only_its_request_attempt() -> None:
    hooks = _hooks(max_budget_usd=0.5)
    first_context = _context()
    retry_context = _context()
    agent = _agent()

    await hooks.on_llm_start(first_context, agent, None, [])
    first_attempt = _active_attempt(hooks, first_context)
    await hooks.on_llm_start(retry_context, agent, None, [])
    retry_attempt = _active_attempt(hooks, retry_context)
    assert first_attempt is not None
    assert retry_attempt is not None
    assert first_attempt != retry_attempt

    await hooks.on_llm_end(
        retry_context,
        agent,
        SimpleNamespace(usage=_usage(100_000, 100_000), response_id="retry"),
    )
    assert first_attempt in hooks._agent_reservations
    assert retry_attempt not in hooks._agent_reservations

    late_response = SimpleNamespace(usage=_usage(10_000, 10_000), response_id="first-attempt")
    await hooks.on_llm_end(first_context, agent, late_response)

    assert first_attempt not in hooks._agent_reservations
    assert first_attempt not in hooks._agent_abandoned_floors
    await hooks.on_llm_start(retry_context, agent, None, [])


@pytest.mark.asyncio
async def test_abandoned_out_of_band_request_keeps_a_floor() -> None:
    """A released out-of-band request without usage keeps its bounded floor."""
    hooks = _hooks(max_budget_usd=0.3)

    await hooks.reserve_out_of_band_request(
        key="dedupe-1", model="openai/gpt-6-sol", input_tokens=0, max_output_tokens=200_000
    )
    await hooks.release_out_of_band_request(key="dedupe-1", model="openai/gpt-6-sol", usage=None)

    with pytest.raises(BudgetExceededError, match="Next bounded request"):
        await hooks.reserve_out_of_band_request(
            key="dedupe-2", model="openai/gpt-6-sol", input_tokens=0, max_output_tokens=200_000
        )


@pytest.mark.asyncio
async def test_out_of_band_floor_and_late_usage_count_without_double_counting() -> None:
    """The abandoned floor persists and the retry's usage commits exactly once."""
    hooks = _hooks(max_budget_usd=0.65)

    await hooks.reserve_out_of_band_request(
        key="dedupe-1", model="openai/gpt-6-sol", input_tokens=0, max_output_tokens=200_000
    )
    await hooks.release_out_of_band_request(key="dedupe-1", model="openai/gpt-6-sol", usage=None)

    # The retry succeeds and reports real usage ($0.20 bound). Honest
    # accounting: $0.20 abandoned estimate + $0.20 verified usage. The next
    # $0.20 reservation fits within $0.65; double-counting the retry's usage
    # ($0.80) would not.
    await hooks.reserve_out_of_band_request(
        key="dedupe-2", model="openai/gpt-6-sol", input_tokens=0, max_output_tokens=200_000
    )
    await hooks.release_out_of_band_request(
        key="dedupe-2",
        model="openai/gpt-6-sol",
        usage=_usage(100_000, 100_000),
    )
    await hooks.reserve_out_of_band_request(
        key="dedupe-3", model="openai/gpt-6-sol", input_tokens=0, max_output_tokens=200_000
    )


@pytest.mark.asyncio
async def test_estimates_never_enter_the_verified_usage_receipt() -> None:
    """The floor lives in budget accounting only; receipts keep verified usage."""
    hooks = _hooks(max_budget_usd=5.0)
    context = _context()
    agent = _agent()
    report_state = MagicMock()
    report_state.get_total_llm_cost.return_value = 0.0
    with patch("lyrashield.lifecycle.hooks.get_global_report_state", return_value=report_state):
        await hooks.on_llm_start(context, agent, None, [])
        await hooks.on_llm_start(context, agent, None, [])  # abandons the first attempt

        response = SimpleNamespace(usage=_usage(100_000, 100_000), response_id="resp-1")
        await hooks.on_llm_end(context, agent, response)

    # Only the real response usage was recorded — no estimated tokens or costs
    # were fabricated into the receipt.
    report_state.record_sdk_usage.assert_called_once_with(
        agent_id="agent-a",
        agent_name="Agent",
        model="openai/gpt-6-sol",
        usage=response.usage,
        response_id="resp-1",
    )


@pytest.mark.asyncio
async def test_metered_usage_remains_accounted_after_reconciliation() -> None:
    """Verified per-model usage still enforces the budget after a reconcile."""
    hooks = _hooks(max_budget_usd=0.25)
    context = _context()
    agent = _agent()

    await hooks.on_llm_start(context, agent, None, [])
    response = SimpleNamespace(usage=_usage(100_000, 100_000), response_id="resp-1")
    await hooks.on_llm_end(context, agent, response)

    # $0.20 of verified usage is committed; the next $0.20 attempt breaches
    # the $0.25 budget.
    with pytest.raises(BudgetExceededError, match="Next bounded request"):
        await hooks.on_llm_start(context, agent, None, [])


@pytest.mark.asyncio
async def test_sdk_callback_tasks_reconcile_their_shared_attempt() -> None:
    """The Agents SDK runs start/end hooks in separate child tasks."""
    hooks = _hooks(max_budget_usd=0.45)
    context = _context()
    agent = _agent()

    await gather_with_cancel(hooks.on_llm_start(context, agent, None, []), asyncio.sleep(0))
    response = SimpleNamespace(usage=_usage(100_000, 100_000), response_id="sdk-response")
    await gather_with_cancel(hooks.on_llm_end(context, agent, response), asyncio.sleep(0))

    assert not hooks._agent_reservations
    assert not hooks._agent_abandoned_floors
    # $0.20 of actual usage plus a $0.20 next reservation fits under $0.45.
    await gather_with_cancel(hooks.on_llm_start(context, agent, None, []), asyncio.sleep(0))


@pytest.mark.asyncio
async def test_late_wrapper_response_does_not_release_newer_attempt_same_context() -> None:
    hooks = _hooks(max_budget_usd=1.0)
    set_active_hooks(hooks)
    context = _context()
    agent = _agent()
    first_input: list[Any] = [{"role": "user", "content": "first"}]
    retry_input: list[Any] = [{"role": "user", "content": "retry"}]

    class Inner:
        async def stream_response(self, *args: Any, **kwargs: Any):  # noqa: ARG002
            yield _completed_stream_event(
                SimpleNamespace(
                    output=[],
                    usage=None,
                    response_id="response-first",
                ),
                "openai/gpt-6-sol",
            )

    model = _RequestBoundTurnGuardModel(
        inner=Inner(), max_tool_calls_per_turn=5, stream_idle_timeout=0.0
    )
    try:
        await gather_with_cancel(
            hooks.on_llm_start(context, agent, None, first_input), asyncio.sleep(0)
        )
        first_attempt = _active_attempt(hooks, context)
        await gather_with_cancel(
            hooks.on_llm_start(context, agent, None, retry_input), asyncio.sleep(0)
        )
        retry_attempt = _active_attempt(hooks, context)
        assert first_attempt is not None
        assert retry_attempt is not None
        assert first_attempt in hooks._agent_abandoned_floors
        assert retry_attempt in hooks._agent_reservations

        async for _event in model.stream_response(
            None,
            first_input,
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
        await gather_with_cancel(
            hooks.on_llm_end(
                context,
                agent,
                SimpleNamespace(usage=_usage(100_000, 100_000), response_id="response-first"),
            ),
            asyncio.sleep(0),
        )

        assert first_attempt not in hooks._agent_abandoned_floors
        assert retry_attempt in hooks._agent_reservations
        assert _active_attempt(hooks, context) == retry_attempt
    finally:
        set_active_hooks(None)
