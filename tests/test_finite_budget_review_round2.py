"""Floor attribution and the acquired native coordination handle are load bearing."""

from __future__ import annotations

import os
import stat

import pytest
from agents.usage import Usage

from lyrashield.artifacts import financial_io
from lyrashield.artifacts.finite_budget import GUARD, STAMP, BudgetJournal, FinancialStateError
from lyrashield.artifacts.state import ReportState
from lyrashield.artifacts.state_persistence import initial_run_record
from lyrashield.artifacts.writer import read_run_record, write_run_record
from lyrashield.lifecycle.hooks import _usage_cost_upper_bound


@pytest.mark.parametrize("observed_first", [False, True])
@pytest.mark.parametrize("prior_observed", [None, 0.048, 0.05])
@pytest.mark.parametrize("limit,allowed", [(0.055, False), (0.06, True)])
def test_real_sdk_rate_preserves_prior_floor_and_attributable_credit(
    tmp_path, monkeypatch, observed_first, prior_observed, limit, allowed
):
    route = "openrouter/anthropic/claude-sonnet"
    first = Usage(requests=1, input_tokens=10000, output_tokens=0, total_tokens=10000)
    second = Usage(requests=1, input_tokens=1000, output_tokens=0, total_tokens=1000)
    first_upper = _usage_cost_upper_bound(route, first)
    second_upper = _usage_cost_upper_bound(route, second)
    assert first_upper == 0.05 and second_upper == 0.005
    state = ReportState("actual-rates")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(limit)
    attempt = owner.reserve(first_upper)
    owner.authorize(attempt)
    assert state.record_sdk_usage(
        agent_id="root",
        model=route,
        response_id="first",
        usage=first,
        budget_attempt=attempt,
        budget_cost=first_upper,
    )
    if prior_observed is not None:
        state.record_observed_llm_cost(prior_observed, model=route, response_id="first")
    assert owner.spent == 0.05
    attempt = owner.reserve(second_upper)
    owner.authorize(attempt)

    def fail_projection(**_kwargs):
        raise OSError("post-commit projection failure")

    monkeypatch.setattr(state, "save_run_data", fail_projection)
    if observed_first:
        state.record_observed_llm_cost(second_upper, model=route, response_id="second")
    assert not state.record_sdk_usage(
        agent_id="root",
        model=route,
        response_id="second",
        usage=second,
        budget_attempt=attempt,
        budget_cost=second_upper,
    )
    if not observed_first:
        state.record_observed_llm_cost(second_upper, model=route, response_id="second")
    state.record_observed_llm_cost(second_upper, model=route, response_id="second")
    assert owner.spent == pytest.approx(0.055)
    assert owner.snapshot()[GUARD]["pending"] == []
    assert owner.snapshot()["llm_usage"]["cost"] == pytest.approx((prior_observed or 0) + 0.005)
    assert owner.snapshot()["llm_usage"]["total_tokens"] == 11000
    # Duplicate settlement and later callback cannot consume another attempt.
    assert state.record_sdk_usage(
        agent_id="root",
        model=route,
        response_id="second",
        usage=second,
        budget_attempt=attempt,
        budget_cost=second_upper,
    )
    owner.close()
    restored = ReportState("actual-rates")
    restored._run_dir = tmp_path
    restored.hydrate_from_run_dir()
    journal = restored.enable_finite_budget(None)
    restored.record_observed_llm_cost(second_upper, model=route, response_id="second")
    assert journal.spent == pytest.approx(0.055)
    assert restored.get_total_llm_usage()["total_tokens"] == 11000
    if allowed:
        journal.reserve(0.0025)
    else:
        with pytest.raises(FinancialStateError, match="exceeds"):
            journal.reserve(0.0025)


@pytest.mark.parametrize("allowed", [False, True])
def test_native_gpt_rate_positive_and_exact_exhaustion(tmp_path, allowed):
    route = "openai/gpt-6-luna"
    usages = [
        Usage(requests=1, input_tokens=n, output_tokens=0, total_tokens=n) for n in (10000, 1000)
    ]
    uppers = [_usage_cost_upper_bound(route, usage) for usage in usages]
    assert uppers == [0.001, 0.0001]
    limit = 0.0012 if allowed else 0.0011
    state = ReportState("native-rate")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(limit)
    for index, (usage, upper) in enumerate(zip(usages, uppers, strict=True)):
        attempt = owner.reserve(upper)
        owner.authorize(attempt)
        assert state.record_sdk_usage(
            agent_id="root",
            model=route,
            response_id=f"native-{index}",
            usage=usage,
            budget_attempt=attempt,
            budget_cost=upper,
        )
    assert owner.spent == pytest.approx(0.0011)
    if allowed:
        owner.reserve(0.00005)
    else:
        with pytest.raises(FinancialStateError, match="exceeds"):
            owner.reserve(0.00005)


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX mode/owner checks; native ACL counterpart runs separately"
)
@pytest.mark.parametrize("kind", ["hardlink", "public"])
def test_preplanted_coordination_file_is_rejected_without_changing_victim(tmp_path, kind):
    victim = tmp_path / "victim"
    victim.write_bytes(b"retained victim bytes")
    victim.chmod(0o600)
    coordination = tmp_path / ".finite-budget-transition"
    if kind == "hardlink":
        os.link(victim, coordination)
    else:
        coordination.write_bytes(victim.read_bytes())
        coordination.chmod(0o666)
    before = (
        coordination.read_bytes(),
        stat.S_IMODE(coordination.stat().st_mode),
        coordination.stat().st_nlink,
    )
    with pytest.raises((FinancialStateError, OSError)):
        BudgetJournal(tmp_path, initial_run_record("lock-file", auth_mode="api"), 1)
    assert (
        coordination.read_bytes(),
        stat.S_IMODE(coordination.stat().st_mode),
        coordination.stat().st_nlink,
    ) == before
    assert victim.read_bytes() == b"retained victim bytes"
    assert not (tmp_path / STAMP).exists()


@pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX mode fault; native acquired-handle ACL counterpart runs separately",
)
def test_actual_acquired_coordination_fd_is_qualified_after_open(tmp_path, monkeypatch):
    callback = getattr(financial_io, "_capture_transition_fd", lambda _fd: None)

    def broaden(fd):
        os.fchmod(fd, 0o666)
        callback(fd)

    monkeypatch.setattr(financial_io, "_capture_transition_fd", broaden, raising=False)
    with pytest.raises((FinancialStateError, OSError)):
        BudgetJournal(tmp_path, initial_run_record("actual-fd", auth_mode="api"), 1)
    assert stat.S_IMODE((tmp_path / ".finite-budget-transition").stat().st_mode) == 0o666
    assert not (tmp_path / STAMP).exists()


@pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX lock-file rename; Windows immutable/reparse/ACL controls separate",
)
def test_acquired_coordination_handle_must_match_preopened_and_current_path(tmp_path, monkeypatch):
    path = tmp_path / ".finite-budget-transition"
    path.write_bytes(b"held inode")
    path.chmod(0o600)
    retired = tmp_path / "retired"
    callback = getattr(financial_io, "_capture_transition_fd", lambda _fd: None)

    def replace_after_native_acquire(fd):
        path.rename(retired)
        path.write_bytes(b"replacement")
        path.chmod(0o600)
        callback(fd)

    monkeypatch.setattr(
        financial_io, "_capture_transition_fd", replace_after_native_acquire, raising=False
    )
    with pytest.raises((FinancialStateError, OSError)):
        BudgetJournal(tmp_path, initial_run_record("swapped-fd", auth_mode="api"), 1)
    assert retired.read_bytes() == b"held inode"
    assert path.read_bytes() == b"replacement"
    assert not (tmp_path / STAMP).exists()


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX permission compatibility; native wide-ACL legacy test separate"
)
def test_legacy_write_does_not_normalize_existing_coordination_permissions(tmp_path):
    tmp_path.chmod(0o775)
    path = tmp_path / ".finite-budget-transition"
    path.write_bytes(b"legacy coordination contents")
    path.chmod(0o666)
    record = initial_run_record("legacy", auth_mode="api")
    write_run_record(tmp_path, record)
    assert read_run_record(tmp_path) == record
    assert path.read_bytes() == b"legacy coordination contents"
    assert stat.S_IMODE(path.stat().st_mode) == 0o666
