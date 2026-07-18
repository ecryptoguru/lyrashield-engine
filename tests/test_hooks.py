"""Tests for budget enforcement in ReportUsageHooks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from strix.core.hooks import (
    MODEL_INPUT_COMPACTION_TRIGGER_TOKENS,
    BudgetExceededError,
    ReportUsageHooks,
    _estimate_input_tokens,
)


def _make_hooks(max_budget: float | None) -> ReportUsageHooks:
    return ReportUsageHooks(model="gpt-5.6-luna", max_budget_usd=max_budget)


def _make_report_state(cost: float) -> MagicMock:
    state = MagicMock()
    state.get_total_llm_cost.return_value = cost
    state.record_sdk_usage = MagicMock()
    return state


def _make_context(agent_id: str = "test-agent") -> MagicMock:
    ctx: MagicMock = MagicMock()
    ctx.context = {"agent_id": agent_id}
    return ctx


@pytest.mark.asyncio
async def test_no_budget_never_raises() -> None:
    hooks = _make_hooks(None)
    state = _make_report_state(9999.0)
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_under_budget_does_not_raise() -> None:
    hooks = _make_hooks(10.0)
    state = _make_report_state(9.99)
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_at_budget_raises() -> None:
    hooks = _make_hooks(10.0)
    state = _make_report_state(10.0)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_over_budget_raises() -> None:
    hooks = _make_hooks(10.0)
    state = _make_report_state(10.01)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_budget_check_uses_live_cost_accessor() -> None:
    # The check must read the live ledger, not the persisted run-record snapshot,
    # so it stays accurate even when a save fails after a usage record.
    hooks = _make_hooks(5.0)
    state = _make_report_state(6.0)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
    state.get_total_llm_cost.assert_called_once()
    state.get_total_llm_usage.assert_not_called()


@pytest.mark.asyncio
async def test_error_message_includes_amounts() -> None:
    hooks = _make_hooks(5.0)
    state = _make_report_state(7.1234)
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        with pytest.raises(BudgetExceededError, match=r"\$5\.00") as exc_info:
            await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
        assert "7.1234" in str(exc_info.value)


@pytest.mark.asyncio
async def test_no_raise_when_report_state_none() -> None:
    hooks = _make_hooks(1.0)
    with patch("strix.core.hooks.get_global_report_state", return_value=None):
        # Should return early without raising, even with budget set
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.parametrize("bad_budget", [0.0, -0.01, -5.0])
def test_non_positive_budget_rejected(bad_budget: float) -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        ReportUsageHooks(model="test-model", max_budget_usd=bad_budget)


def test_budget_exceeded_error_is_runtime_error() -> None:
    err = BudgetExceededError("test")
    assert isinstance(err, RuntimeError)


@pytest.mark.asyncio
async def test_large_context_is_compacted_before_the_model_request() -> None:
    hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna")
    agent = MagicMock()
    agent.tools = []
    agent.output_type = None
    items = [
        {"role": "user", "content": "original scan task"},
        *[
            {
                "role": "assistant",
                "content": f"evidence-{index}-" + ("alpha beta gamma delta " * 5_000),
            }
            for index in range(60)
        ],
    ]

    await hooks.on_llm_start(_make_context(), agent, "system", items)

    assert len(items) < 61
    assert _estimate_input_tokens(hooks._model, "system", items, agent) < 272_000
    assert MODEL_INPUT_COMPACTION_TRIGGER_TOKENS < 272_000


@pytest.mark.asyncio
async def test_single_oversized_item_is_compacted_without_blocking() -> None:
    hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna")
    agent = MagicMock()
    agent.tools = []
    agent.output_type = None
    items = [{"role": "user", "content": "large task " * 300_000}]

    await hooks.on_llm_start(_make_context(), agent, "system", items)

    assert len(items) == 2
    assert _estimate_input_tokens(hooks._model, "system", items, agent) < 272_000


@pytest.mark.asyncio
async def test_request_is_rejected_before_call_when_bounded_cost_exceeds_budget() -> None:
    hooks = ReportUsageHooks(
        model="azure_ai/gpt-5.6-luna",
        max_budget_usd=0.001,
        max_output_tokens=4_096,
    )
    agent = MagicMock()
    agent.name = "root"
    agent.tools = []
    agent.output_type = None

    with pytest.raises(BudgetExceededError, match=r"Next bounded GPT-5\.6 request"):
        await hooks.on_llm_start(
            _make_context(), agent, "system", [{"role": "user", "content": "scan"}]
        )


@pytest.mark.asyncio
async def test_tool_call_and_output_remain_grouped_after_compaction() -> None:
    hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna")
    agent = MagicMock()
    agent.tools = []
    agent.output_type = None
    items = [
        {"role": "user", "content": "original task"},
        {"role": "assistant", "content": "old context " * 300_000},
        {"type": "function_call", "call_id": "call-1", "name": "shell"},
        {"type": "function_call_output", "call_id": "call-1", "output": "result"},
    ]

    await hooks.on_llm_start(_make_context(), agent, "system", items)

    retained_types = [item.get("type") for item in items if isinstance(item, dict)]
    assert ("function_call" in retained_types) == ("function_call_output" in retained_types)
