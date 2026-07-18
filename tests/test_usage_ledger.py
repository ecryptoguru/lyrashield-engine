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
        }
    ]


def test_usage_ledger_does_not_invent_missing_cache_write_tokens() -> None:
    usage = Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110)
    ledger = LLMUsageLedger()

    assert ledger.record(agent_id="agent-1", usage=usage, model="azure/gpt-5.6-luna")

    details = ledger.to_record()["request_usage_entries"][0]["input_tokens_details"]
    assert details == {"cached_tokens": 0}
