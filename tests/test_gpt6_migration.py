"""The new scan admission, Azure route, caching, and token prices move together."""

from __future__ import annotations

import pytest
from agents.models.openai_responses import OpenAIResponsesModel

from lyrashield.artifacts.usage import estimate_gpt56_request_cost_usd
from lyrashield.lifecycle.hooks import _model_rate_card, _reservation_input_rate
from lyrashield.lifecycle.inputs import prompt_cache_options_for_model, prompt_cache_routing_enabled
from lyrashield.policy.models import StrixProvider, is_gpt6_supported_provider
from lyrashield.policy.settings import LlmSettings, Settings
from lyrashield_adapter.cli import prepare_environment


@pytest.mark.parametrize(
    "model", ["azure_ai/gpt-6-luna", "azure_ai/gpt-6-sol", "azure/gpt-6-sol", "openai/gpt-6-luna"]
)
def test_gpt6_admitted(model: str) -> None:
    assert is_gpt6_supported_provider(model)


@pytest.mark.parametrize(
    "model",
    [
        "azure_ai/gpt-5.6-luna",
        "azure_ai/gpt-5.6-terra",
        "gpt-5-nano",
        "evil/azure_ai/gpt-6-sol",
        "azure_ai/gpt-6-sol.evil",
    ],
)
def test_old_and_untrusted_routes_rejected(model: str) -> None:
    assert not is_gpt6_supported_provider(model)
    with pytest.raises(SystemExit, match="approved GPT-6"):
        prepare_environment({"LYRASHIELD_LLM": model})


def test_azure_gpt6_uses_responses_route() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-6-luna",
            api_key="test-key",
            api_base="https://example.services.ai.azure.com",
        )
    )
    model = StrixProvider(settings=settings).get_model("azure_ai/gpt-6-luna")
    assert isinstance(model, OpenAIResponsesModel)
    assert model.model == "gpt-6-luna"


def test_gpt6_explicit_cache_and_read_write_rates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", "1")
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    assert prompt_cache_options_for_model("azure_ai/gpt-6-luna") == {
        "mode": "explicit",
        "ttl": "30m",
    }
    assert prompt_cache_routing_enabled("azure_ai/gpt-6-luna")
    assert _model_rate_card("azure_ai/gpt-6-sol") == (2.0, 0.2, 2.5, 10.0)
    assert _model_rate_card("azure_ai/gpt-6-luna") == (0.1, 0.01, 0.125, 0.5)
    assert _reservation_input_rate("azure_ai/gpt-6-luna") == 0.125
    assert estimate_gpt56_request_cost_usd(
        "azure_ai/gpt-6-luna",
        input_tokens=10_000,
        cached_input_tokens=2_000,
        cache_write_input_tokens=3_000,
        output_tokens=1_000,
    ) == pytest.approx(0.001395)
