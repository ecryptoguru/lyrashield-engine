from __future__ import annotations

from agents.usage import Usage
from openai.types.responses.response_usage import InputTokensDetails

from strix.report.usage import LLMUsageLedger


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


def test_usage_ledger_omits_unavailable_native_provider_cost() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")

    record = ledger.to_record()
    assert "cost" not in record
    assert "cost" not in record["agents"][0]
    assert ledger.total_cost == 0


def test_usage_ledger_retains_observed_provider_cost() -> None:
    ledger = LLMUsageLedger()

    ledger.record_observed_cost(0.25)

    assert ledger.to_record()["cost"] == 0.25
    assert ledger.total_cost == 0.25


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
