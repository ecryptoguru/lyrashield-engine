"""Budget upper bounds and atomic ancillary reservations (I8, I19, I20)."""

from __future__ import annotations

import asyncio
import json
import random
from typing import Any, Self

import httpx
import pytest
from agents.usage import Usage

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState, set_global_report_state
from lyrashield.artifacts.usage import LLMUsageLedger, _estimate_gpt56_cost
from lyrashield.lifecycle.hooks import (
    ReportUsageHooks,
    _reservation_input_rate,
    _usage_cost_upper_bound,
)
from lyrashield.tools.web_search.tool import _estimate_cost, web_search
from strix.config.loader import load_settings
from tests.test_web_search import _clear_settings_cache, _tool_ctx


# --- I8: reserved amount is never below the final cost for identical usage ---


def _usage_with_details(
    input_tokens: int,
    output_tokens: int,
    cached: int,
    cache_write: int,
) -> Usage:
    usage = Usage(
        requests=1,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )
    usage.input_tokens_details = {"cached_tokens": cached, "cache_write_tokens": cache_write}  # type: ignore[assignment]
    return usage


def _usage_without_details(input_tokens: int, output_tokens: int) -> dict[str, int]:
    """A provider receipt with no cache detail at all (dict form).

    Reservation-time views cannot know which input tokens will be billed as
    cache writes, so the bound must assume the worst input bucket.
    """
    return {"input_tokens": input_tokens, "output_tokens": output_tokens}


@pytest.mark.parametrize(
    "model", ["openai/gpt-5.6-terra", "openai/gpt-5.6-luna", "azure/eu/gpt-5.6-terra"]
)
@pytest.mark.parametrize("seed", range(20))
def test_upper_bound_never_below_final_cost_with_details(model: str, seed: int) -> None:
    rng = random.Random(seed)  # noqa: S311 - test data, not crypto
    cached = rng.randrange(0, 50_000)
    cache_write = rng.randrange(0, 50_000)
    usage = _usage_with_details(
        input_tokens=cached + cache_write + rng.randrange(0, 300_000),
        output_tokens=rng.randrange(0, 32_000),
        cached=cached,
        cache_write=cache_write,
    )
    final = _estimate_gpt56_cost(usage, model) or 0.0
    bound = _usage_cost_upper_bound(model, usage)
    assert bound >= final - 1e-12, (model, seed, bound, final)


@pytest.mark.parametrize("model", ["openai/gpt-5.6-terra", "openai/gpt-5.6-luna"])
@pytest.mark.parametrize("seed", range(20))
def test_upper_bound_never_below_final_cost_without_details(model: str, seed: int) -> None:
    """Entries without cache detail still reserve at the worst input bucket."""
    rng = random.Random(seed)  # noqa: S311 - test data, not crypto
    cache_write = rng.randrange(0, 100_000)
    cached = rng.randrange(0, 50_000)
    # The provider later reports this split; the reservation saw no details.
    final_usage = _usage_with_details(
        input_tokens=cached + cache_write + rng.randrange(0, 100_000),
        output_tokens=rng.randrange(0, 16_000),
        cached=cached,
        cache_write=cache_write,
    )
    no_details = _usage_without_details(final_usage.input_tokens, final_usage.output_tokens)
    final = _estimate_gpt56_cost(final_usage, model) or 0.0
    bound = _usage_cost_upper_bound(model, no_details)
    assert bound >= final - 1e-12, (model, seed, bound, final)


def test_long_context_upper_bound_covers_multipliers() -> None:
    usage = _usage_with_details(
        input_tokens=300_000, output_tokens=8_000, cached=100_000, cache_write=50_000
    )
    final = _estimate_gpt56_cost(usage, "openai/gpt-5.6-terra") or 0.0
    assert _usage_cost_upper_bound("openai/gpt-5.6-terra", usage) >= final - 1e-12


def test_reservation_input_rate_is_worst_input_bucket() -> None:
    assert _reservation_input_rate("openai/gpt-5.6-terra") == 2.5  # cache-write > input
    assert _reservation_input_rate("openai/gpt-5.6-luna") == 0.25


@pytest.mark.asyncio
async def test_out_of_band_reservation_is_upper_bound() -> None:
    hooks = ReportUsageHooks(model="openai/gpt-5.6-terra", max_budget_usd=10.0)
    input_tokens, max_output = 100_000, 8_000
    await hooks.reserve_out_of_band_request(
        key="dedupe:1",
        model="openai/gpt-5.6-terra",
        input_tokens=input_tokens,
        max_output_tokens=max_output,
    )
    # The costliest possible final receipt for this request must still fit
    # inside what was reserved (all cache-write input, long-context off).
    worst = _usage_with_details(
        input_tokens=input_tokens,
        output_tokens=max_output,
        cached=0,
        cache_write=input_tokens,
    )
    worst_final = _estimate_gpt56_cost(worst, "openai/gpt-5.6-terra") or 0.0
    reserved = hooks._reservations["dedupe:1"]
    assert reserved >= worst_final - 1e-12


# --- I19: subscription zero-cost never erases ancillary search cost ---


def test_subscription_receipt_retains_paid_search_and_reconciles_total(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    state = ReportState(run_name="sub-search")
    state._llm_usage.zero_cost = True
    state._llm_usage.record(
        agent_id="root",
        usage=_usage_with_details(1_000, 2_000, cached=0, cache_write=0),
        model="chatgpt/gpt-5.6-luna",
    )
    state.record_web_search_cost(0.03, query="cve lookup", mode="turbo")

    record = state._llm_usage.to_record()
    assert record["subscription"] is True
    assert record["ancillary_costs"] == {"web_search": 0.03}
    # Reconciled total equals the category sums (model tokens are $0).
    assert record["cost"] == 0.03
    assert state.get_total_llm_cost() == 0.03
    assert state.get_web_search_stats() == (1, 0.03)


def test_subscription_hydrate_does_not_double_count_search(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    state = ReportState(run_name="sub-hydrate")
    state._llm_usage.zero_cost = True
    state.record_web_search_cost(0.03, query="q", mode="turbo")
    record = state._llm_usage.to_record()

    resumed = LLMUsageLedger()
    resumed.zero_cost = True
    resumed.hydrate(record)
    assert resumed.total_cost == pytest.approx(0.03)
    assert resumed.to_record()["cost"] == pytest.approx(0.03)


# --- I20: concurrent web searches cannot exceed count or cost limits ---


class _FakeParallelClient:
    calls: int = 0

    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def post(self, *_: object, **__: object) -> Any:
        _FakeParallelClient.calls += 1
        await asyncio.sleep(0.01)

        class _Resp:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, Any]:
                return {"results": []}

        return _Resp()


@pytest.fixture
def _web_search_enabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> ReportState:
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_API_KEY", "pk_test")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", "1")
    monkeypatch.setattr(httpx, "AsyncClient", _FakeParallelClient)
    _clear_settings_cache()

    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    report_state = ReportState(run_name="concurrent-ws")
    set_global_report_state(report_state)
    yield report_state
    set_global_report_state(None)
    _clear_settings_cache()
    monkeypatch.delenv("LYRASHIELD_WEB_SEARCH_ENABLED", raising=False)
    monkeypatch.delenv("LYRASHIELD_WEB_SEARCH_API_KEY", raising=False)
    monkeypatch.delenv("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", raising=False)


@pytest.mark.asyncio
async def test_one_call_allowance_two_concurrent_calls_single_request(
    _web_search_enabled: ReportState,
) -> None:
    _FakeParallelClient.calls = 0
    args = {"query": "CVE for libxml"}
    results = await asyncio.gather(
        *(web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)) for _ in range(2))
    )
    parsed = [json.loads(r) for r in results]
    succeeded = [r for r in parsed if r["success"]]
    denied = [r for r in parsed if not r["success"]]
    # Exactly one provider request happened; the other was denied at the
    # reservation boundary, not after I/O.
    assert _FakeParallelClient.calls == 1
    assert len(succeeded) == 1
    assert len(denied) == 1
    assert "call limit reached" in denied[0]["message"]
    count, _cost = _web_search_enabled.get_web_search_stats()
    assert count == 1
    assert _web_search_enabled._web_search_inflight == 0
    assert _web_search_enabled._web_search_reserved_cost == 0.0


@pytest.mark.asyncio
async def test_failed_call_releases_its_slot(
    monkeypatch: pytest.MonkeyPatch, _web_search_enabled: ReportState
) -> None:
    class _FailingClient(_FakeParallelClient):
        async def post(self, *_: object, **__: object) -> Any:
            raise httpx.HTTPError("down")

    monkeypatch.setattr(httpx, "AsyncClient", _FailingClient)
    args = {"query": "anything"}
    parsed = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert parsed["success"] is False
    # The failed call released its slot and reserved charge...
    assert _web_search_enabled._web_search_inflight == 0
    assert _web_search_enabled._web_search_reserved_cost == 0.0

    # ...so a retry is admitted.
    monkeypatch.setattr(httpx, "AsyncClient", _FakeParallelClient)
    _FakeParallelClient.calls = 0
    retried = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert retried["success"] is True
    assert _FakeParallelClient.calls == 1


@pytest.mark.asyncio
async def test_timeout_releases_both_reservation_layers(
    monkeypatch: pytest.MonkeyPatch, _web_search_enabled: ReportState
) -> None:
    """E5: a timeout during the web_search call must release both the
    ReportState slot and the hooks reservation."""

    class _TimeoutClient(_FakeParallelClient):
        async def post(self, *_: object, **__: object) -> Any:
            raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(httpx, "AsyncClient", _TimeoutClient)
    args = {"query": "slow query"}
    parsed = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert parsed["success"] is False
    # Both reservation layers released.
    assert _web_search_enabled._web_search_inflight == 0
    assert _web_search_enabled._web_search_reserved_cost == 0.0


@pytest.mark.asyncio
async def test_cancellation_releases_both_reservation_layers(
    monkeypatch: pytest.MonkeyPatch, _web_search_enabled: ReportState
) -> None:
    """E5: a task cancellation during the web_search call must release both
    the ReportState slot and the hooks reservation."""

    class _CancellableClient(_FakeParallelClient):
        async def post(self, *_: object, **__: object) -> Any:
            raise asyncio.CancelledError("task cancelled")

    monkeypatch.setattr(httpx, "AsyncClient", _CancellableClient)
    args = {"query": "cancelled query"}
    import contextlib  # noqa: PLC0415

    with contextlib.suppress(asyncio.CancelledError):
        await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args))
    # Both reservation layers released even after cancellation.
    assert _web_search_enabled._web_search_inflight == 0
    assert _web_search_enabled._web_search_reserved_cost == 0.0


@pytest.mark.asyncio
async def test_timeout_releases_active_hooks_reservation(
    monkeypatch: pytest.MonkeyPatch, _web_search_enabled: ReportState
) -> None:
    """E5: a timeout must release the active global hooks reservation, not
    just the ReportState slot. Spies on ReportUsageHooks to prove it."""

    class _TimeoutClient(_FakeParallelClient):
        async def post(self, *_: object, **__: object) -> Any:
            raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(httpx, "AsyncClient", _TimeoutClient)
    hooks = ReportUsageHooks(model="gpt-5.6-luna", max_budget_usd=5.0)
    monkeypatch.setattr("lyrashield.lifecycle.hooks.get_active_hooks", lambda: hooks)
    args = {"query": "timeout with hooks"}
    parsed = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert parsed["success"] is False
    # ReportState slot released.
    assert _web_search_enabled._web_search_inflight == 0
    # Global hooks reservation released (no lingering reservation key).
    assert len(hooks._reservations) == 0


@pytest.mark.asyncio
async def test_success_commits_hooks_reservation_exactly_once(
    monkeypatch: pytest.MonkeyPatch, _web_search_enabled: ReportState
) -> None:
    """E5: a successful web_search call must commit the hooks reservation
    exactly once — the success-path release and the finally release must not
    double-commit the actual cost."""

    class _OkClient(_FakeParallelClient):
        async def post(self, *_: object, **__: object) -> Any:
            class _Resp:
                status_code = 200

                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict[str, Any]:
                    return {"results": [{"title": "t", "url": "https://x.example", "content": "c"}]}

            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _OkClient)
    hooks = ReportUsageHooks(model="gpt-5.6-luna", max_budget_usd=5.0)
    monkeypatch.setattr("lyrashield.lifecycle.hooks.get_active_hooks", lambda: hooks)
    args = {"query": "success exactly once"}
    # Compute the expected per-call cost from the same settings the tool uses
    # so the assertion is comparing floor to estimated cost, not just > 0.
    _clear_settings_cache()
    web_search_settings = load_settings().web_search
    expected_cost = _estimate_cost("turbo", web_search_settings)
    parsed = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert parsed["success"] is True
    # The hooks reservation is gone (released exactly once).
    assert len(hooks._reservations) == 0
    # The committed cost floor reflects exactly one call cost, not double.
    # (Duplicate finalization must not inflate committed cost.)
    assert hooks._committed_cost_floor == pytest.approx(expected_cost)
    # No lingering ReportState reservation.
    assert _web_search_enabled._web_search_inflight == 0
    assert _web_search_enabled._web_search_reserved_cost == 0.0


@pytest.mark.asyncio
async def test_duplicate_hooks_release_is_noop() -> None:
    """E5: calling release_web_search_call twice for the same key must not
    double-commit the cost — duplicate finalization is a no-op."""
    hooks = ReportUsageHooks(model="gpt-5.6-luna", max_budget_usd=5.0)
    await hooks.reserve_web_search_call(key="dup-key", estimated_cost=0.1)
    await hooks.release_web_search_call(key="dup-key", actual_cost=0.1)
    cost_after_first = hooks._committed_cost_floor
    # Second release must be a no-op (key already gone).
    await hooks.release_web_search_call(key="dup-key", actual_cost=0.1)
    assert hooks._committed_cost_floor == cost_after_first
    assert len(hooks._reservations) == 0


@pytest.mark.asyncio
async def test_cost_limit_counts_reserved_charges(
    monkeypatch: pytest.MonkeyPatch, _web_search_enabled: ReportState
) -> None:
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", "10")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_BUDGET_USD", "0.001")
    _clear_settings_cache()
    from lyrashield.tools.web_search.tool import _estimate_cost  # noqa: PLC0415

    settings = load_settings()
    per_call = _estimate_cost("turbo", settings.web_search)

    # A call costing more than the remaining budget is denied at reservation.
    error = _web_search_enabled.reserve_web_search_slot(per_call, max_calls=10, budget_usd=0.001)
    if per_call > 0.001:
        assert error is not None and "budget exceeded" in error
    else:
        assert error is None
        _web_search_enabled.release_web_search_reservation(per_call)
