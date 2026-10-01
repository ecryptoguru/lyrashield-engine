"""Abandoned requests count toward conservative spend (E1.3).

A request that started but never reported usage may still have been billed
by the provider. The reservation for an abandoned attempt becomes a bounded
estimated-spend floor instead of being written off as zero; actual usage
reported later replaces the estimate. Estimates stay in process-local budget
accounting and never enter the verified usage receipt.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import lyrashield.lifecycle.hooks as hooks_module
from lyrashield.lifecycle.hooks import (
    BudgetExceededError,
    ReportUsageHooks,
)


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


@pytest.fixture(autouse=True)
def _flat_rate_card(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: _RATE_CARD)


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
async def test_late_actual_usage_replaces_the_abandoned_floor() -> None:
    """Verified usage reconciles the estimate instead of adding to it."""
    hooks = _hooks(max_budget_usd=0.5)
    context = _context()
    agent = _agent()

    await hooks.on_llm_start(context, agent, None, [])
    # The first attempt is abandoned; the retry reserves on top of its floor.
    await hooks.on_llm_start(context, agent, None, [])

    response = SimpleNamespace(usage=_usage(100_000, 100_000), response_id="resp-1")
    await hooks.on_llm_end(context, agent, response)

    # Committed $0.20 of verified usage; the abandoned floor is reconciled
    # away. A third attempt ($0.20) fits; double-counting the abandoned
    # reservation ($0.60 total) would not.
    await hooks.on_llm_start(context, agent, None, [])


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
