"""Tests for budget enforcement in ReportUsageHooks."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from strix.core.hooks import (
    _GPT56_LONG_CONTEXT_TOKENS,
    MODEL_INPUT_COMPACTION_TARGET_TOKENS,
    MODEL_INPUT_COMPACTION_TRIGGER_TOKENS,
    BudgetExceededError,
    ReportUsageHooks,
    _estimate_input_tokens,
    _usage_cost_upper_bound,
    resolve_compaction_thresholds,
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


def test_usage_upper_bound_honors_provider_reported_cache_reads() -> None:
    usage = SimpleNamespace(
        input_tokens=1_000,
        output_tokens=100,
        input_tokens_details=SimpleNamespace(cached_tokens=800),
        request_usage_entries=None,
    )

    assert _usage_cost_upper_bound("azure_ai/gpt-5.6-luna", usage) == pytest.approx(
        (200 * 1.0 + 800 * 0.1 + 100 * 6) / 1_000_000
    )


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
async def test_medium_context_is_compacted_to_the_budget_safe_target() -> None:
    hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna")
    agent = MagicMock()
    agent.tools = []
    agent.output_type = None
    items = [
        {"role": "user", "content": "original scan task"},
        {"role": "assistant", "content": "evidence " * 40_000},
    ]

    await hooks.on_llm_start(_make_context(), agent, "system", items)

    assert _estimate_input_tokens(hooks._model, "system", items, agent) <= (
        MODEL_INPUT_COMPACTION_TARGET_TOKENS
    )


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

    with pytest.raises(BudgetExceededError, match=r"Next bounded request"):
        await hooks.on_llm_start(
            _make_context(), agent, "system", [{"role": "user", "content": "scan"}]
        )


@pytest.mark.asyncio
async def test_delegate_request_reservation_uses_delegate_model_rate() -> None:
    hooks = ReportUsageHooks(
        model="azure_ai/gpt-5.6-terra",
        max_budget_usd=0.08,
        max_output_tokens=16_384,
    )
    agent = MagicMock()
    agent.name = "specialist"
    agent.model = "azure_ai/gpt-5.6-luna"
    agent.model_settings.max_tokens = 8_192
    agent.tools = []
    agent.output_type = None

    await hooks.on_llm_start(
        _make_context(), agent, "system", [{"role": "user", "content": "focused scan"}]
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


class TestCompactionThresholdResolution:
    """LYRASHIELD_MAX_INPUT_TOKENS is a compaction ceiling, never a hard reject."""

    def test_unset_preserves_the_module_defaults(self) -> None:
        assert resolve_compaction_thresholds(None) == (
            MODEL_INPUT_COMPACTION_TRIGGER_TOKENS,
            MODEL_INPUT_COMPACTION_TARGET_TOKENS,
        )

    def test_lower_ceiling_compacts_earlier_and_keeps_the_default_ratio(self) -> None:
        trigger, target = resolve_compaction_thresholds(48_000)

        assert trigger == 48_000
        assert trigger < MODEL_INPUT_COMPACTION_TRIGGER_TOKENS
        assert target < trigger
        # 2:3 target:trigger ratio carried over from the defaults (64k / 96k).
        assert target == int(
            48_000 * (MODEL_INPUT_COMPACTION_TARGET_TOKENS / MODEL_INPUT_COMPACTION_TRIGGER_TOKENS)
        )

    def test_ceiling_above_the_long_context_boundary_is_clamped_and_warned(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            trigger, target = resolve_compaction_thresholds(500_000)

        # Compaction exists to stay out of 2x input billing; a ceiling above that
        # boundary would defeat the protection this knob is meant to provide.
        assert trigger < _GPT56_LONG_CONTEXT_TOKENS
        assert target <= trigger
        assert any("clamping" in record.message for record in caplog.records)

    def test_documented_clamp_boundary_is_exact(self) -> None:
        # docs/advanced/configuration.mdx promises values above 240_000 are clamped
        # to 240_000 (272k boundary minus the 32k output margin). Pin it so the
        # documented number and the implementation cannot drift apart.
        assert resolve_compaction_thresholds(240_000)[0] == 240_000
        assert resolve_compaction_thresholds(240_001)[0] == 240_000
        assert resolve_compaction_thresholds(250_000)[0] == 240_000

    @pytest.mark.parametrize("ceiling", [1, 1_000, 50_000, 100_000, 271_999, 10_000_000])
    def test_resolved_trigger_never_reaches_the_long_context_boundary(self, ceiling: int) -> None:
        trigger, target = resolve_compaction_thresholds(ceiling)

        assert trigger < _GPT56_LONG_CONTEXT_TOKENS
        assert 0 < target <= trigger

    def test_pathologically_low_ceiling_still_yields_a_usable_target(self) -> None:
        trigger, target = resolve_compaction_thresholds(500)

        # Must not collapse to zero or exceed the trigger, or compaction could
        # never report progress and would loop or emit an empty request.
        assert trigger == 500
        assert 0 < target <= trigger


@pytest.mark.asyncio
async def test_custom_input_ceiling_compacts_a_context_the_default_would_allow() -> None:
    agent = MagicMock()
    agent.tools = []
    agent.output_type = None

    def _items() -> list[dict[str, str]]:
        return [
            {"role": "user", "content": "original scan task"},
            *[{"role": "assistant", "content": "evidence " * 500} for _ in range(20)],
        ]

    default_items = _items()
    await ReportUsageHooks(model="azure_ai/gpt-5.6-luna").on_llm_start(
        _make_context(), agent, "system", default_items
    )

    capped_items = _items()
    capped_hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna", max_input_tokens=6_000)
    await capped_hooks.on_llm_start(_make_context(), agent, "system", capped_items)

    # Below the 96k default this context passes untouched; the custom ceiling
    # brings compaction into play.
    assert len(default_items) == 21
    assert len(capped_items) < 21
    assert (
        _estimate_input_tokens(capped_hooks._model, "system", capped_items, agent)
        <= capped_hooks.compaction_trigger_tokens
    )


def test_applied_thresholds_are_exposed_for_the_run_record() -> None:
    default_hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna")
    assert default_hooks.compaction_trigger_tokens == MODEL_INPUT_COMPACTION_TRIGGER_TOKENS
    assert default_hooks.compaction_target_tokens == MODEL_INPUT_COMPACTION_TARGET_TOKENS

    # Post-clamp values, so the run record reflects what was actually enforced.
    clamped_hooks = ReportUsageHooks(model="azure_ai/gpt-5.6-luna", max_input_tokens=999_999)
    assert clamped_hooks.compaction_trigger_tokens < _GPT56_LONG_CONTEXT_TOKENS


@pytest.mark.asyncio
async def test_out_of_band_reservation_blocks_a_request_over_budget() -> None:
    """Dedupe calls must be refused when they would breach the scan budget."""
    hooks = _make_hooks(0.01)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=_make_report_state(0.0)),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.reserve_out_of_band_request(
            key="dedupe:1",
            model="gpt-5.6-luna",
            input_tokens=10_000_000,
            max_output_tokens=512,
        )


@pytest.mark.asyncio
async def test_out_of_band_reservation_counts_against_concurrent_requests() -> None:
    """A held reservation must shrink the headroom seen by the next request."""
    hooks = _make_hooks(0.05)
    with patch("strix.core.hooks.get_global_report_state", return_value=_make_report_state(0.0)):
        # ~0.04 of the 0.05 budget.
        await hooks.reserve_out_of_band_request(
            key="dedupe:a",
            model="gpt-5.6-luna",
            input_tokens=40_000,
            max_output_tokens=0,
        )
        with pytest.raises(BudgetExceededError):
            await hooks.reserve_out_of_band_request(
                key="dedupe:b",
                model="gpt-5.6-luna",
                input_tokens=40_000,
                max_output_tokens=0,
            )


@pytest.mark.asyncio
async def test_releasing_an_out_of_band_reservation_frees_headroom() -> None:
    """A failed or finished call must not strand its reservation for the whole scan."""
    hooks = _make_hooks(0.05)
    with patch("strix.core.hooks.get_global_report_state", return_value=_make_report_state(0.0)):
        await hooks.reserve_out_of_band_request(
            key="dedupe:a",
            model="gpt-5.6-luna",
            input_tokens=40_000,
            max_output_tokens=0,
        )
        # usage=None mirrors a request that raised before returning a response.
        await hooks.release_out_of_band_request(key="dedupe:a", model="gpt-5.6-luna", usage=None)
        await hooks.reserve_out_of_band_request(
            key="dedupe:b",
            model="gpt-5.6-luna",
            input_tokens=40_000,
            max_output_tokens=0,
        )


@pytest.mark.asyncio
async def test_out_of_band_reservation_is_a_noop_without_a_budget() -> None:
    hooks = _make_hooks(None)
    await hooks.reserve_out_of_band_request(
        key="dedupe:1",
        model="gpt-5.6-luna",
        input_tokens=10_000_000,
        max_output_tokens=512,
    )
    await hooks.release_out_of_band_request(key="dedupe:1", model="gpt-5.6-luna", usage=None)
