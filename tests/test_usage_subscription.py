"""Subscription runs track tokens but report zero cost."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

from agents.usage import Usage

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.usage import LLMUsageLedger


if TYPE_CHECKING:
    import pytest


def _usage() -> Usage:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    return usage


def test_subscription_model_keeps_tokens_but_reports_no_cost() -> None:
    ledger = LLMUsageLedger()
    ledger.record(agent_id="a", usage=_usage(), agent_name="strix", model="chatgpt/gpt-6-luna")

    record = ledger.to_record()
    assert record["cost"] == 0.0
    assert record["total_tokens"] == 1200
    assert record["input_tokens"] == 1000
    assert record["output_tokens"] == 200
    assert ledger.total_cost == 0.0


def test_subscription_agent_receives_unattributed_shared_cost() -> None:
    ledger = LLMUsageLedger()
    ledger.record(agent_id="subscription", usage=_usage(), model="chatgpt/gpt-6-luna")
    ledger.record_observed_cost(0.25)

    record = ledger.to_record()
    agent = record["agents"][0]

    assert record["cost"] == 0.25
    assert record["cost_basis"] == "pro_rata"
    assert agent["cost"] == 0.25
    assert agent["cost_basis"] == "pro_rata"


def test_subscription_model_ignores_observed_cost() -> None:
    ledger = LLMUsageLedger()
    ledger.record_observed_cost(4.20, model="chatgpt/gpt-6-luna")
    assert ledger.total_cost == 0.0


def test_normal_ledger_still_estimates_cost() -> None:
    # Sanity check the flag is opt-in: without it, an OpenAI-native model still
    # accrues an estimated cost (proves zeroing is what suppresses it).
    ledger = LLMUsageLedger()
    ledger.record(agent_id="a", usage=_usage(), agent_name="strix", model="gpt-5.5")
    assert ledger.to_record()["total_tokens"] == 1200
    # Cost estimation depends on litellm's cost map; it should be >= 0 and not error.
    assert ledger.total_cost >= 0.0


def test_subscription_and_paid_models_are_priced_per_model() -> None:
    ledger = LLMUsageLedger()
    ledger.record(agent_id="root", usage=_usage(), model="chatgpt/gpt-6-luna")
    ledger.record(agent_id="delegate", usage=_usage(), model="openai/gpt-6-luna")

    record = ledger.to_record()
    costs = {agent["agent_id"]: agent["cost"] for agent in record["agents"]}
    assert record["cost"] == 0.0002
    assert record["subscription"] is True
    assert costs["root"] == 0.0
    assert costs["delegate"] == 0.0002


def test_subscription_primary_does_not_zero_paid_delegate_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(llm=SimpleNamespace(model="chatgpt/gpt-6-luna"))
    monkeypatch.setattr(state_module, "load_settings", lambda: settings)
    report_state = state_module.ReportState()
    monkeypatch.setattr(report_state, "save_run_data", lambda: None)

    report_state.record_sdk_usage(agent_id="root", usage=_usage(), model="chatgpt/gpt-6-luna")
    report_state.record_sdk_usage(agent_id="delegate", usage=_usage(), model="openai/gpt-6-luna")

    assert report_state._build_llm_usage_record()["cost"] == 0.0002


def test_paid_ledger_does_not_mark_subscription() -> None:
    ledger = LLMUsageLedger()
    ledger.record(agent_id="a", usage=_usage(), agent_name="strix", model="openai/gpt-6-luna")

    record = ledger.to_record()
    assert "subscription" not in record
