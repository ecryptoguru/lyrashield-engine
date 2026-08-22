"""Tests for LLM model recommendation helpers."""

from __future__ import annotations

import pytest
from agents.model_settings import ModelSettings
from agents.models.openai_responses import OpenAIResponsesModel

from lyrashield.policy.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    _azure_responses_base_url,
    is_gpt56_model,
    is_gpt56_supported_provider,
    is_recommended_or_frontier_model,
    parse_model_route,
    request_timeout_extra_args,
    uses_chat_completions_tool_schema,
)
from lyrashield.policy.settings import LlmSettings, Settings


@pytest.mark.parametrize("model_name", RECOMMENDED_MODEL_NAMES)
def test_recommended_models_are_accepted(model_name: str) -> None:
    assert is_recommended_or_frontier_model(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        "openai/gpt-5.6-luna",
        "azure/eu/gpt-5.6-terra",
        "azure_ai/gpt-5.6-luna",
        "bedrock_mantle/openai.gpt-5.6-luna",
        "chatgpt/gpt-5.6-luna",
    ],
)
def test_gpt56_supported_providers_are_accepted(model_name: str) -> None:
    assert is_gpt56_model(model_name)
    assert is_gpt56_supported_provider(model_name)
    assert is_recommended_or_frontier_model(model_name)


def test_request_timeout_extra_args_positive() -> None:
    assert request_timeout_extra_args(300) == {"timeout": 300}
    assert request_timeout_extra_args(10) == {"timeout": 10}


def test_request_timeout_extra_args_survives_model_settings_json_dump() -> None:
    """The Chat Completions and LiteLLM paths pydantic-serialize ModelSettings for
    their tracing span; a non-JSON-serializable timeout fails every turn there."""
    settings = ModelSettings(extra_args=request_timeout_extra_args(300))
    assert settings.to_json_dict()["extra_args"] == {"timeout": 300}


@pytest.mark.parametrize("value", [None, 0, -1])
def test_request_timeout_extra_args_disabled(value: float | None) -> None:
    assert request_timeout_extra_args(value) is None


def test_recommended_models_are_matched_case_insensitively() -> None:
    assert is_recommended_or_frontier_model("Vertex_AI/Gemini-3-Pro-Preview")


@pytest.mark.parametrize(
    "model_name",
    [
        "gpt-5.6-luna",
        "azure_ai/gpt-5.6-terra",
        "openai/gpt-5.6-terra",
        "prod-gpt-5.6-luna",
        "azure/eu/gpt-5.6-luna",
        "bedrock_mantle/openai.gpt-5.6-luna",
    ],
)
def test_gpt56_deployment_names_are_accepted(model_name: str) -> None:
    assert is_gpt56_model(model_name)
    assert is_gpt56_supported_provider(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        None,
        "",
        "gpt-5.5",
        "gpt-5.60",
        "gpt-5.6fake",
        # Sol was retired from the supported set. It must be rejected here at
        # startup, because budget enforcement no longer carries a Sol rate and
        # would otherwise raise mid-scan.
        "gpt-5.6-sol",
        "openai/gpt-5.6-sol",
    ],
)
def test_non_gpt56_deployment_names_are_rejected(model_name: str | None) -> None:
    assert not is_gpt56_model(model_name)


@pytest.mark.parametrize(
    ("api_base", "expected"),
    [
        (
            "https://example.services.ai.azure.com",
            "https://example.services.ai.azure.com/openai/v1/",
        ),
        (
            "https://example.openai.azure.com/openai/v1/",
            "https://example.openai.azure.com/openai/v1/",
        ),
        (
            "https://example.services.ai.azure.com/api/projects/demo",
            "https://example.services.ai.azure.com/api/projects/demo/openai/v1/",
        ),
    ],
)
def test_azure_responses_base_url(api_base: str, expected: str) -> None:
    assert _azure_responses_base_url(api_base) == expected


def test_azure_gpt56_routes_through_responses_with_stripped_deployment_name() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-5.6-luna",
            delegate_model="azure_ai/gpt-5.6-luna",
            api_key="test-key",
            api_base="https://example.services.ai.azure.com",
        )
    )

    model = StrixProvider(settings=settings).get_model("azure_ai/gpt-5.6-luna")

    assert isinstance(model, OpenAIResponsesModel)
    assert model.model == "gpt-5.6-luna"
    assert str(model._client.base_url) == "https://example.services.ai.azure.com/openai/v1/"


def test_azure_multi_segment_name_uses_final_deployment() -> None:
    """``azure/<region>/<deployment>`` must resolve to just the deployment slug."""
    settings = Settings(
        llm=LlmSettings(
            model="azure/eu/gpt-5.6-terra",
            api_key="test-key",
            api_base="https://example.openai.azure.com",
        )
    )

    model = StrixProvider(settings=settings).get_model("azure/eu/gpt-5.6-terra")

    assert isinstance(model, OpenAIResponsesModel)
    assert model.model == "gpt-5.6-terra"
    assert str(model._client.base_url) == "https://example.openai.azure.com/openai/v1/"


def test_azure_gpt56_route_fails_closed_without_endpoint() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-5.6-luna",
            api_key="test-key",
        )
    )

    with pytest.raises(RuntimeError, match="requires LLM_API_BASE"):
        StrixProvider(settings=settings)


def test_azure_gpt56_keeps_json_tools_without_programmatic_opt_in() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-5.6-terra",
            api_base="https://example.services.ai.azure.com",
        )
    )

    assert uses_chat_completions_tool_schema("azure_ai/gpt-5.6-terra", settings)


def test_azure_gpt56_uses_responses_tools_when_programmatic_is_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LYRASHIELD_PROGRAMMATIC_TOOL_CALLING", "1")
    settings = Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-5.6-terra",
            api_base="https://example.services.ai.azure.com",
        )
    )

    assert not uses_chat_completions_tool_schema("azure_ai/gpt-5.6-terra", settings)


@pytest.mark.parametrize(
    "model_name",
    [
        "gpt-5.5",
        "chatgpt/gpt-5.4",
        "litellm/openai/gpt-5.4-pro",
        "azure_ai/gpt-5.5-pro",
        "bedrock_mantle/openai.gpt-5.5",
        "anthropic/claude-opus-5",
        "anthropic/claude-opus-4-8",
        "anthropic.claude-opus-4-8",
        "anthropic/claude-opus-4-7",
        "anthropic/claude-fable-5",
        "anthropic/claude-sonnet-5",
        "vertex_ai/claude-sonnet-5@default",
        "vertex_ai/claude-sonnet-4-6@default",
        "any-llm/anthropic/claude-sonnet-4-6",
        "vertex_ai/gemini-3.1-pro-preview",
        "openrouter/google/gemini-3.1-pro-preview",
        "deepseek/deepseek-v4-pro",
        "deepseek/deepseek-r1-0528",
        "deepseek/deepseek-reasoner",
        "dashscope/qwen3-max-2026-01-23",
        "qwen3.7-max",
        "dashscope/qwen3.8-max",
        "moonshot/kimi-k2.6",
        "kimi-k2.7-code",
        "moonshot/kimi-k3",
    ],
)
def test_frontier_model_families_are_accepted(model_name: str) -> None:
    assert is_recommended_or_frontier_model(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        "",
        "openai/gpt-4.1",
        "anthropic/claude-3-5-sonnet-latest",
        "ollama/llama3.1",
        "deepseek/deepseek-chat",
        "custom-ollama/gpt-5-mini-local",
        "custom-provider/claude-opus-4-local",
        "xai/grok-4.5",
        "openrouter/x-ai/grok-4",
        "openrouter/gpt-5.6-luna",
        "bedrock/gpt-5.6-terra",
        "vertex_ai/gpt-5.6-luna",
        "novita/gpt-5.6-luna",
        "mistral/mistral-medium-3-5",
        "mistral/magistral-medium-latest",
    ],
)
def test_non_frontier_models_are_rejected(model_name: str) -> None:
    assert not is_recommended_or_frontier_model(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        "openrouter/gpt-5.6-luna",
        "bedrock/gpt-5.6-terra",
        "vertex_ai/gpt-5.6-luna",
        "novita/gpt-5.6-luna",
    ],
)
def test_gpt56_unsupported_providers_are_rejected(model_name: str) -> None:
    assert is_gpt56_model(model_name)
    assert not is_gpt56_supported_provider(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        # Structural rejects: nested/repeated wrappers and empty components can
        # never reach routing, which parses through the same grammar.
        "litellm/litellm/azure/gpt-5.6-luna",
        "any-llm/litellm/azure/gpt-5.6-luna",
        "azure//gpt-5.6-luna",
        "azure/",
        "/gpt-5.6-luna",
        "litellm/",
    ],
)
def test_structurally_invalid_route_forms_are_rejected(model_name: str) -> None:
    with pytest.raises(ValueError, match="model route"):
        parse_model_route(model_name)
    assert not is_gpt56_supported_provider(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        # Permitted provider appearing only later in the string is a different,
        # unapproved route (C6): routing selects the first component.
        "evil/azure/gpt-5.6-luna",
        "evil.azure/gpt-5.6-luna",
        "evil/openai/gpt-5.6-terra",
        "not-chatgpt/chatgpt/gpt-5.6-luna",
        "litellm/evil/azure/gpt-5.6-luna",
    ],
)
def test_late_permitted_provider_does_not_admit_route(model_name: str) -> None:
    assert is_gpt56_model(model_name)
    assert parse_model_route(model_name) is not None
    assert not is_gpt56_supported_provider(model_name)


def test_admission_checks_exactly_the_provider_routing_selects() -> None:
    """For every accepted fixture, the admitted provider equals the leading
    component routing will select (wrapper stripped, bare means OpenAI)."""
    accepted = [
        "gpt-5.6-luna",
        "prod-gpt-5.6-luna",
        "openai/gpt-5.6-luna",
        "azure/eu/gpt-5.6-terra",
        "azure_ai/gpt-5.6-luna",
        "bedrock_mantle/openai.gpt-5.6-luna",
        "chatgpt/gpt-5.6-luna",
        "litellm/azure/gpt-5.6-luna",
    ]
    for model_name in accepted:
        route = parse_model_route(model_name)
        assert route is not None, model_name
        assert is_gpt56_supported_provider(model_name), model_name
        selected = route.provider or "openai"
        assert selected in {"openai", "azure", "azure_ai", "bedrock_mantle", "chatgpt"}, model_name


def test_parse_model_route_documented_forms() -> None:
    assert parse_model_route(None) is None
    assert parse_model_route("   ") is None
    bare = parse_model_route("gpt-5.6-luna")
    assert (bare.wrapper, bare.provider, bare.model_path) == (None, None, "gpt-5.6-luna")
    wrapped = parse_model_route("litellm/deepseek/deepseek-chat")
    assert (wrapped.wrapper, wrapped.provider, wrapped.model_path) == (
        "litellm",
        "deepseek",
        "deepseek-chat",
    )
    azure = parse_model_route("azure/eu/gpt-5.6-terra")
    assert (azure.provider, azure.model_path) == ("azure", "eu/gpt-5.6-terra")
    bedrock = parse_model_route("bedrock_mantle/openai.gpt-5.6-luna")
    assert (bedrock.provider, bedrock.model_path) == ("bedrock_mantle", "openai.gpt-5.6-luna")
