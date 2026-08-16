from __future__ import annotations

from agents.usage import Usage
from openai.types.responses.response_usage import InputTokensDetails

from lyrashield.artifacts.usage import LLMUsageLedger


def test_usage_ledger_preserves_provider_cache_write_receipts() -> None:
    details = InputTokensDetails.model_validate({"cached_tokens": 20, "cache_write_tokens": 5})
    usage = Usage(
        requests=1,
        input_tokens=100,
        output_tokens=10,
        total_tokens=110,
        input_tokens_details=details,
    )
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")

    assert ledger.to_record()["request_usage_entries"] == [
        {
            "input_tokens": 100,
            "output_tokens": 10,
            "total_tokens": 110,
            "input_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 5},
            "model": "azure/gpt-5.6-luna",
        }
    ]


def test_usage_ledger_does_not_invent_missing_cache_write_tokens() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")

    details = ledger.to_record()["request_usage_entries"][0]["input_tokens_details"]
    assert details == {"cached_tokens": 0}
    assert ledger.to_record()["request_usage_entries"][0]["model"] == "azure/gpt-5.6-luna"


def test_usage_ledger_omits_zero_cache_write_tokens() -> None:
    details = InputTokensDetails.model_validate({"cached_tokens": 20, "cache_write_tokens": 0})
    usage = Usage(
        requests=1,
        input_tokens=100,
        output_tokens=10,
        total_tokens=110,
        input_tokens_details=details,
    )
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")
    assert ledger.to_record()["request_usage_entries"][0]["input_tokens_details"] == {
        "cached_tokens": 20
    }


def test_usage_ledger_prices_gpt56_without_a_provider_cost_receipt() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")

    record = ledger.to_record()
    assert record["cost"] == 0.000032
    assert record["agents"][0]["cost"] == 0.000032
    assert ledger.total_cost == 0.000032


def test_usage_ledger_retains_observed_provider_cost() -> None:
    ledger = LLMUsageLedger()

    ledger.record_observed_cost(0.25)

    assert ledger.to_record()["cost"] == 0.25
    assert ledger.total_cost == 0.25


def test_usage_ledger_prices_gpt56_and_ignores_incorrect_litellm_cost() -> None:
    details = InputTokensDetails.model_validate({"cached_tokens": 20, "cache_write_tokens": 5})
    usage = Usage(
        requests=1,
        input_tokens=100,
        output_tokens=10,
        total_tokens=110,
        input_tokens_details=details,
    )
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure_ai/gpt-5.6-luna")
    ledger.record_observed_cost(0.01, model="azure_ai/gpt-5.6-luna")

    assert ledger.total_cost == 0.00002865
    assert ledger.to_record()["cost"] == 0.00002865


def test_usage_ledger_does_not_treat_multi_request_aggregate_as_a_receipt() -> None:
    usage = Usage(requests=2, input_tokens=200, output_tokens=20, total_tokens=220)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")

    assert "request_usage_entries" not in ledger.to_record()


def test_usage_ledger_handles_missing_provider_request_entries() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    usage.request_usage_entries = None
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")
    assert len(ledger.to_record()["request_usage_entries"]) == 1


def test_usage_ledger_preserves_request_model_during_hydration() -> None:
    ledger = LLMUsageLedger()
    ledger.hydrate(
        {
            "request_usage_entries": [
                {
                    "input_tokens": 100,
                    "output_tokens": 10,
                    "total_tokens": 110,
                    "input_tokens_details": {"cached_tokens": 20},
                    "model": "azure/gpt-5.6-luna",
                }
            ]
        }
    )

    assert ledger.to_record()["request_usage_entries"][0]["model"] == "azure/gpt-5.6-luna"


def test_usage_ledger_prices_each_agent_at_its_own_model_rate() -> None:
    # Terra coordinator ($2/$12) delegates to Luna ($0.2/$1.2): a token-share
    # split would cross-subsidize the expensive coordinator into the cheap
    # delegate. Each agent must be billed at its own rate card.
    terra = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    luna = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="coordinator", usage=terra, model="gpt-5.6-terra")
    assert ledger.record(agent_id="delegate", usage=luna, model="gpt-5.6-luna")

    record = ledger.to_record()
    costs = {a["agent_id"]: a["cost"] for a in record["agents"]}
    assert costs["coordinator"] == round((1000 * 2.0 + 1000 * 12.0) / 1_000_000, 10)
    assert costs["delegate"] == round((1000 * 0.2 + 1000 * 1.2) / 1_000_000, 10)
    # Invariant: per-agent costs sum to the run total (worker reconciliation).
    assert sum(costs.values()) == record["cost"] == ledger.total_cost
    assert record["cost_basis"] == "per_agent_priced"
    assert all(a["cost_basis"] == "per_agent_priced" for a in record["agents"])


def test_usage_ledger_marks_unattributable_cost_pro_rata() -> None:
    terra = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    luna = Usage(requests=1, input_tokens=3000, output_tokens=1000, total_tokens=4000)
    ledger = LLMUsageLedger()
    ledger.record(agent_id="coordinator", usage=terra, model="gpt-5.6-terra")
    ledger.record(agent_id="delegate", usage=luna, model="gpt-5.6-luna")

    # Observed cost with no agent attribution (e.g. web search): the residual
    # is shared pro-rata and the basis flips so the worker knows.
    ledger.record_observed_cost(1.0)

    record = ledger.to_record()
    costs = {a["agent_id"]: a["cost"] for a in record["agents"]}
    assert sum(costs.values()) == record["cost"] == ledger.total_cost
    assert record["cost_basis"] == "pro_rata"
    bases = {a["agent_id"]: a["cost_basis"] for a in record["agents"]}
    assert bases["delegate"] == "pro_rata"
    assert bases["coordinator"] == "pro_rata"


def test_usage_ledger_skips_token_estimate_when_observed_cost_covers_model() -> None:
    ledger = LLMUsageLedger()
    # Provider callback reports observed cost for a non-GPT-5.6 model first...
    ledger.record_observed_cost(0.25, model="openai/gpt-4o", response_id="resp_1")

    # ...then the SDK usage hook arrives for the same response: the token
    # estimate must be suppressed or the response is billed twice.
    usage = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    ledger.record(agent_id="agent-1", usage=usage, model="gpt-4o")

    record = ledger.to_record()
    assert record["cost"] == 0.25
    assert record["cost_basis"] == "pro_rata"


def test_usage_ledger_dedupes_observed_cost_by_response_id() -> None:
    ledger = LLMUsageLedger()

    ledger.record_observed_cost(0.25, model="openai/gpt-4o", response_id="resp_1")
    ledger.record_observed_cost(0.25, model="openai/gpt-4o", response_id="resp_1")
    ledger.record_observed_cost(0.10, model="openai/gpt-4o", response_id="resp_2")

    assert ledger.total_cost == 0.35


def test_usage_ledger_hydrates_per_agent_priced_costs() -> None:
    ledger = LLMUsageLedger()
    ledger.hydrate(
        {
            "cost": 1.5,
            "agents": [
                {
                    "agent_id": "coordinator",
                    "agent_name": "coordinator",
                    "model": "gpt-5.6-terra",
                    "input_tokens": 100,
                    "output_tokens": 10,
                    "total_tokens": 110,
                    "cost": 1.4,
                    "cost_basis": "per_agent_priced",
                },
                {
                    "agent_id": "delegate",
                    "agent_name": "delegate",
                    "model": "gpt-5.6-luna",
                    "input_tokens": 100,
                    "output_tokens": 10,
                    "total_tokens": 110,
                    "cost": 0.1,
                    "cost_basis": "per_agent_priced",
                },
            ],
        }
    )

    # A resumed run adds Luna-only usage; the hydrated Terra cost must stay
    # exactly attributed rather than being re-split by token share.
    extra = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger.record(agent_id="delegate", usage=extra, model="gpt-5.6-luna")

    record = ledger.to_record()
    costs = {a["agent_id"]: a["cost"] for a in record["agents"]}
    assert costs["coordinator"] == 1.4
    luna_alone = round((100 * 0.2 + 10 * 1.2) / 1_000_000, 10)
    assert costs["delegate"] == round(0.1 + luna_alone, 10)
    assert round(sum(costs.values()), 10) == record["cost"] == ledger.total_cost
