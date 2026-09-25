from __future__ import annotations

from agents.usage import Usage
from openai.types.responses.response_usage import InputTokensDetails

from lyrashield.artifacts.usage import LLMUsageLedger, extract_provider_usage


def test_raw_gpt6_usage_distinguishes_zero_from_missing() -> None:
    response = {
        "id": "response-1",
        "status": "completed",
        "usage": {
            "input_tokens": 100,
            "output_tokens": 10,
            "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
        },
    }
    assert extract_provider_usage(response) == {
        "response_id": "response-1",
        "input_tokens": 100,
        "output_tokens": 10,
        "total_tokens": 110,
        "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
    }
    del response["usage"]["input_tokens_details"]["cache_write_tokens"]
    assert extract_provider_usage(response) is None


def test_gpt6_ledger_requires_matching_raw_response_and_deduplicates() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()
    assert ledger.record(agent_id="root", usage=usage, model="azure_ai/gpt-6-luna")
    assert ledger.to_record()["accounting_complete"] is False

    complete = LLMUsageLedger()
    receipt = extract_provider_usage(
        {
            "id": "response-1",
            "status": "completed",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            },
        }
    )
    assert receipt is not None
    assert complete.record(
        agent_id="root", usage=usage, model="azure_ai/gpt-6-luna", provider_receipt=receipt
    )
    assert not complete.record(
        agent_id="root", usage=usage, model="azure_ai/gpt-6-luna", provider_receipt=receipt
    )
    record = complete.to_record()
    assert record["accounting_complete"] is True
    assert record["request_usage_entries"][0]["input_tokens_details"] == {
        "cached_tokens": 0,
        "cache_write_tokens": 0,
    }
    assert record["cost"] == 0.000015


def test_gpt6_ledger_resume_keeps_zero_receipt_and_completion() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    receipt = extract_provider_usage(
        {
            "id": "response-1",
            "status": "completed",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            },
        }
    )
    assert receipt is not None
    ledger = LLMUsageLedger()
    ledger.record(
        agent_id="root", usage=usage, model="azure_ai/gpt-6-luna", provider_receipt=receipt
    )
    restored = LLMUsageLedger()
    restored.hydrate(ledger.to_record())
    assert restored.to_record()["accounting_complete"] is True
    assert (
        restored.to_record()["request_usage_entries"][0]["input_tokens_details"][
            "cache_write_tokens"
        ]
        == 0
    )


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

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-4o")

    assert ledger.to_record()["request_usage_entries"] == [
        {
            "input_tokens": 100,
            "output_tokens": 10,
            "total_tokens": 110,
            "input_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 5},
            "model": "azure/gpt-4o",
        }
    ]


def test_usage_ledger_does_not_invent_missing_cache_write_tokens() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-4o")

    details = ledger.to_record()["request_usage_entries"][0]["input_tokens_details"]
    assert details == {"cached_tokens": 0}
    assert ledger.to_record()["request_usage_entries"][0]["model"] == "azure/gpt-4o"


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

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-4o")
    assert ledger.to_record()["request_usage_entries"][0]["input_tokens_details"] == {
        "cached_tokens": 20
    }


def test_usage_ledger_gpt6_without_a_provider_cost_receipt_records_estimated_cost() -> None:
    """GPT-6 usage without a provider receipt is still priced from the SDK
    usage buckets (missing cache buckets price as zero); the run is marked
    incomplete so the missing receipt stays visible."""
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-6-luna")

    record = ledger.to_record()
    # (100 * 0.1 + 10 * 0.5) / 1M — no cache buckets on the SDK usage.
    assert record["cost"] == 0.000015
    assert record["accounting_complete"] is False


def test_usage_ledger_retains_observed_provider_cost() -> None:
    ledger = LLMUsageLedger()

    ledger.record_observed_cost(0.25)

    assert ledger.to_record()["cost"] == 0.25
    assert ledger.total_cost == 0.25


def test_usage_ledger_prices_gpt6_and_ignores_incorrect_litellm_cost() -> None:
    usage = Usage(
        requests=1,
        input_tokens=100,
        output_tokens=10,
        total_tokens=110,
    )
    receipt = extract_provider_usage(
        {
            "id": "response-1",
            "status": "completed",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 5},
            },
        }
    )
    assert receipt is not None
    ledger = LLMUsageLedger()

    assert ledger.record(
        agent_id="agent-1", usage=usage, model="azure_ai/gpt-6-luna", provider_receipt=receipt
    )
    ledger.record_observed_cost(0.01, model="azure_ai/gpt-6-luna")

    # (100 - 20 - 5) * 0.1 + 20 * 0.01 + 5 * 0.125 + 10 * 0.5 = 13.325 / 1M
    assert ledger.total_cost == 0.000013325
    assert ledger.to_record()["cost"] == 0.000013325


def test_usage_ledger_does_not_treat_multi_request_aggregate_as_a_receipt() -> None:
    usage = Usage(requests=2, input_tokens=200, output_tokens=20, total_tokens=220)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-4o")

    assert "request_usage_entries" not in ledger.to_record()


def test_usage_ledger_handles_missing_provider_request_entries() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    usage.request_usage_entries = None
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-4o")
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
                    "model": "azure/gpt-4o",
                }
            ]
        }
    )

    assert ledger.to_record()["request_usage_entries"][0]["model"] == "azure/gpt-4o"


def test_usage_ledger_prices_each_agent_at_its_own_model_rate() -> None:
    # Sol coordinator ($2/$10) delegates to Luna ($0.1/$0.5): a token-share
    # split would cross-subsidize the expensive coordinator into the cheap
    # delegate. Each agent must be billed at its own rate card.
    sol = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    luna = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    sol_receipt = extract_provider_usage(
        {
            "id": "response-sol",
            "status": "completed",
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 1000,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            },
        }
    )
    luna_receipt = extract_provider_usage(
        {
            "id": "response-luna",
            "status": "completed",
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 1000,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            },
        }
    )
    assert sol_receipt is not None and luna_receipt is not None
    ledger = LLMUsageLedger()

    assert ledger.record(
        agent_id="coordinator", usage=sol, model="gpt-6-sol", provider_receipt=sol_receipt
    )
    assert ledger.record(
        agent_id="delegate", usage=luna, model="gpt-6-luna", provider_receipt=luna_receipt
    )

    record = ledger.to_record()
    costs = {a["agent_id"]: a["cost"] for a in record["agents"]}
    assert costs["coordinator"] == round((1000 * 2.0 + 1000 * 10.0) / 1_000_000, 10)
    assert costs["delegate"] == round((1000 * 0.1 + 1000 * 0.5) / 1_000_000, 10)
    # Invariant: per-agent costs sum to the run total (worker reconciliation).
    assert sum(costs.values()) == record["cost"] == ledger.total_cost
    assert record["cost_basis"] == "per_agent_priced"
    assert all(a["cost_basis"] == "per_agent_priced" for a in record["agents"])


def test_usage_ledger_marks_unattributable_cost_pro_rata() -> None:
    sol = Usage(requests=1, input_tokens=1000, output_tokens=1000, total_tokens=2000)
    luna = Usage(requests=1, input_tokens=3000, output_tokens=1000, total_tokens=4000)
    ledger = LLMUsageLedger()
    ledger.record(agent_id="coordinator", usage=sol, model="gpt-6-sol")
    ledger.record(agent_id="delegate", usage=luna, model="gpt-6-luna")

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
    # Provider callback reports observed cost for a non-rate-card model first...
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
                    "model": "gpt-6-sol",
                    "input_tokens": 100,
                    "output_tokens": 10,
                    "total_tokens": 110,
                    "cost": 1.4,
                    "cost_basis": "per_agent_priced",
                },
                {
                    "agent_id": "delegate",
                    "agent_name": "delegate",
                    "model": "gpt-6-luna",
                    "input_tokens": 100,
                    "output_tokens": 10,
                    "total_tokens": 110,
                    "cost": 0.1,
                    "cost_basis": "per_agent_priced",
                },
            ],
        }
    )

    # A resumed run adds Luna-only usage; the hydrated Sol cost must stay
    # exactly attributed rather than being re-split by token share.
    extra = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    receipt = extract_provider_usage(
        {
            "id": "response-extra",
            "status": "completed",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            },
        }
    )
    assert receipt is not None
    ledger.record(agent_id="delegate", usage=extra, model="gpt-6-luna", provider_receipt=receipt)

    record = ledger.to_record()
    costs = {a["agent_id"]: a["cost"] for a in record["agents"]}
    assert costs["coordinator"] == 1.4
    luna_alone = round((100 * 0.1 + 10 * 0.5) / 1_000_000, 10)
    assert costs["delegate"] == round(0.1 + luna_alone, 10)
    assert round(sum(costs.values()), 10) == record["cost"] == ledger.total_cost
