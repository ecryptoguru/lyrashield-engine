"""Tests for the dedicated deduplication model configuration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from openai import AsyncOpenAI, OpenAIError
from openai.types.responses import (
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
)
from pydantic import ValidationError

from lyrashield.artifacts import dedupe as dedupe_module
from lyrashield.artifacts.dedupe import (
    _DEDUPE_MAX_OUTPUT_TOKENS,
    _MAX_EXISTING_REPORTS_CHARS,
    DedupeJudgement,
    _bound_existing_reports,
    _dedupe_model_settings,
    _extract_balanced_json,
    _parse_dedupe_response,
    _related_reports,
    _validated_dedupe_result,
    resolve_dedupe_model,
)
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.policy import loader
from lyrashield.policy.models import StrixProvider, _AzureUsageResponsesModel
from lyrashield.policy.settings import DedupeSettings, LlmSettings, Settings


def test_dedupe_output_schema_uses_supported_numeric_keywords() -> None:
    schema = DedupeJudgement.model_json_schema()
    confidence = schema["properties"]["confidence"]

    branches = confidence["anyOf"]
    assert [branch["type"] for branch in branches] == ["number", "integer"]
    assert all(set(branch) <= {"type", "minimum", "maximum"} for branch in branches)
    assert all(branch["minimum"] == 0 and branch["maximum"] == 1 for branch in branches)
    for value in (0, 1, 0.0, 1.0):
        assert (
            DedupeJudgement.model_validate({"is_duplicate": False, "confidence": value}).confidence
            == value
        )
    for value in (True, False, "0", "0.5", "1"):
        with pytest.raises(ValidationError):
            DedupeJudgement.model_validate({"is_duplicate": False, "confidence": value})
    with pytest.raises(ValidationError):
        DedupeJudgement.model_validate({"is_duplicate": False, "confidence": -0.1})
    with pytest.raises(ValidationError):
        DedupeJudgement.model_validate({"is_duplicate": False, "confidence": 1.1})


def _unwrap(model: object) -> object:
    while hasattr(model, "_inner"):
        model = model._inner
    return model


def test_dedupe_key_bound_to_model_client_not_global_env() -> None:
    dedupe = DedupeSettings(_env_file=None, model="openai/gpt-6-luna", api_key="dedupe-key")
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna"),
    )
    model = _unwrap(resolve_dedupe_model(dedupe, "openai/gpt-6-luna", settings=settings))
    # The key is bound to the dedupe model's own client, so a shared-provider
    # main key can't clobber it (and vice versa) through the process globals —
    # and it never rides on the request, where every model implementation's own
    # api_key kwarg would collide with it.
    assert model._client.api_key == "dedupe-key"  # type: ignore[attr-defined]


def test_dedupe_settings_carry_no_request_credentials() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert "api_key" not in (settings.extra_args or {})
    assert "api_base" not in (settings.extra_args or {})


def test_dedupe_endpoint_bound_to_model_client() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="openai/gpt-6-luna",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-sol"),
    )
    model = _unwrap(resolve_dedupe_model(dedupe, "openai/gpt-6-luna", settings=settings))
    client = model._client  # type: ignore[attr-defined]
    assert client.api_key == "dedupe-key"
    assert str(client.base_url).startswith("https://dedupe.example/v1")


def test_dedupe_without_any_openai_credentials_fails_closed() -> None:
    dedupe = DedupeSettings(_env_file=None, model="openai/gpt-6-luna")
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna"),
    )
    with pytest.raises(OpenAIError, match="Missing credentials"):
        resolve_dedupe_model(dedupe, "openai/gpt-6-luna", settings=settings)


def test_dedupe_omits_parallel_tool_setting_for_azure_gpt6() -> None:
    """Azure GPT-6 rejects ``parallel_tool_calls`` even when false."""
    settings = _dedupe_model_settings(DedupeSettings(), "azure_ai/gpt-6-luna", 300)
    assert settings.parallel_tool_calls is None


def test_dedupe_settings_cap_matches_reserved_output() -> None:
    settings = _dedupe_model_settings(DedupeSettings(), "azure_ai/gpt-6-luna", 300)
    assert settings.max_tokens == _DEDUPE_MAX_OUTPUT_TOKENS


def test_dedicated_dedupe_model_uses_own_headers_not_main() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_EXTRA_HEADERS={"X-Dedupe": "yes"},
    )
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert settings.extra_headers == {"X-Dedupe": "yes"}


def test_dedicated_dedupe_model_gets_no_main_headers_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Main": "secret"}))
    loader._cached = None
    try:
        dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap")
        settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
        assert settings.extra_headers is None
    finally:
        loader._cached = None


def test_fallback_dedupe_inherits_main_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Main": "svc"}))
    loader._cached = None
    try:
        settings = _dedupe_model_settings(DedupeSettings(), "openai/main-model", 300)
        assert settings.extra_headers == {"X-Main": "svc"}
    finally:
        loader._cached = None


def test_cross_provider_openai_dedupe_uses_openai_connection_not_main_azure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "caller-openai-key")
    settings = Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-6-sol",
            api_key="main-azure-key",
            api_base="https://main.azure.example",
            extra_headers={"X-Main": "private"},
        )
    )
    dedupe = DedupeSettings(model="openai/gpt-6-luna")

    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))

    assert isinstance(model, OpenAIResponsesModel)
    assert model._client.api_key == "caller-openai-key"
    assert str(model._client.base_url) == "https://api.openai.com/v1/"
    assert "X-Main" not in model._client.default_headers


def test_cross_provider_azure_dedupe_uses_its_own_responses_connection() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="openai/gpt-6-sol",
            api_key="main-openai-key",
            api_base="https://main.openai.example/v1",
            extra_headers={"X-Main": "private"},
        )
    )
    dedupe = DedupeSettings(
        model="litellm/azure-ai/Region/GPT-6-Luna",
        api_key="dedupe-azure-key",
        api_base="https://dedupe.azure.example",
        extra_headers={"X-Dedupe": "own"},
    )

    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))

    assert isinstance(model, _AzureUsageResponsesModel)
    assert model.model == "GPT-6-Luna"
    assert model._client.api_key == "dedupe-azure-key"
    assert str(model._client.base_url) == "https://dedupe.azure.example/openai/v1/"
    assert model._client.default_headers["X-Dedupe"] == "own"
    assert "X-Main" not in model._client.default_headers


def test_dedicated_dedupe_rejects_anthropic_route() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="openai/gpt-6-sol",
            api_key="main-openai-key",
            api_base="https://main.openai.example/v1",
        )
    )
    dedupe = DedupeSettings(model="anthropic/claude-sonnet-4-5")

    with pytest.raises(RuntimeError, match="metered OpenAI or Azure/Azure AI GPT-6"):
        resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings)


@pytest.mark.parametrize(
    ("main_route", "dedupe_route", "main_key", "dedupe_base", "provider_env"),
    [
        (
            "azure_ai/gpt-6-sol",
            "openai/gpt-6-luna",
            "main-azure-sentinel",
            "https://custom.openai.example/v1",
            "OPENAI_API_KEY",
        ),
        (
            "openai/gpt-6-sol",
            "openai/gpt-6-luna",
            "main-openai-sentinel",
            "https://custom.openai.example/v1",
            "OPENAI_API_KEY",
        ),
        (
            "openai/gpt-6-sol",
            "azure_ai/gpt-6-luna",
            "main-openai-sentinel",
            "https://custom.azure.example",
            "AZURE_OPENAI_API_KEY",
        ),
    ],
)
def test_custom_dedupe_endpoint_never_inherits_a_process_or_main_key(
    monkeypatch: pytest.MonkeyPatch,
    main_route: str,
    dedupe_route: str,
    main_key: str,
    dedupe_base: str,
    provider_env: str,
) -> None:
    monkeypatch.setenv(provider_env, "provider-env-sentinel")
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model=main_route,
            api_key=main_key,
            api_base="https://main.example/v1",
        ),
    )
    dedupe = DedupeSettings(
        _env_file=None,
        model=dedupe_route,
        api_base=dedupe_base,
    )

    with pytest.raises(RuntimeError, match=r"custom .* endpoint requires DEDUPE_LLM_API_KEY"):
        resolve_dedupe_model(dedupe, dedupe_route, settings=settings)


def test_custom_same_provider_endpoint_does_not_inherit_main_headers() -> None:
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model="openai/gpt-6-sol",
            api_key="main-openai-key",
            api_base="https://main.openai.example/v1",
            extra_headers={
                "X-Main-Secret": "main-tenant",
                "Cookie": "session=main-secret",
            },
        ),
    )
    dedupe = DedupeSettings(
        _env_file=None,
        model="openai/gpt-6-luna",
        api_key="dedupe-openai-key",
        api_base="https://dedupe.openai.example/v1",
    )

    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))
    model_settings = _dedupe_model_settings(dedupe, dedupe.model or "", 30, settings=settings)

    assert model._client.api_key == "dedupe-openai-key"
    assert str(model._client.base_url) == "https://dedupe.openai.example/v1/"
    assert "X-Main-Secret" not in model._client.default_headers
    assert "Cookie" not in model._client.default_headers
    assert model_settings.extra_headers is None


def test_explicit_openai_base_does_not_use_ambient_openai_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-main-key")
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna"),
    )

    model = _unwrap(
        StrixProvider(settings=settings, base_url="https://custom.openai.example/v1").get_model(
            "openai/gpt-6-luna"
        )
    )

    assert model._client.api_key == "not-needed"


def test_same_provider_dedupe_inherits_main_connection_and_headers() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="openai/gpt-6-sol",
            api_key="main-openai-key",
            api_base="https://main.openai.example/v1",
            extra_headers={"X-Main": "tenant"},
        )
    )
    dedupe = DedupeSettings(model="openai/gpt-6-luna")

    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))
    model_settings = _dedupe_model_settings(dedupe, dedupe.model or "", 30, settings=settings)

    assert model._client.api_key == "main-openai-key"
    assert str(model._client.base_url) == "https://main.openai.example/v1/"
    assert model._client.default_headers["X-Main"] == "tenant"
    assert model_settings.extra_headers == {"X-Main": "tenant"}


def test_same_provider_dedupe_headers_override_main_headers() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="openai/gpt-6-sol",
            api_key="main-openai-key",
            extra_headers={"X-Main": "tenant"},
        )
    )
    dedupe = DedupeSettings(
        model="openai/gpt-6-luna",
        extra_headers={"X-Dedupe": "judge"},
    )

    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))
    model_settings = _dedupe_model_settings(dedupe, dedupe.model or "", 30, settings=settings)

    assert model._client.default_headers["X-Dedupe"] == "judge"
    assert "X-Main" not in model._client.default_headers
    assert model_settings.extra_headers == {"X-Dedupe": "judge"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("main_route", "dedupe_route", "dedupe_key", "dedupe_base", "expected_url"),
    [
        (
            "azure_ai/gpt-6-sol",
            "openai/gpt-6-luna",
            "caller-openai-key",
            None,
            "https://api.openai.com/v1/responses",
        ),
        (
            "openai/gpt-6-sol",
            "litellm/azure-ai/Region/GPT-6-Luna",
            "dedupe-azure-key",
            "https://dedupe.azure.example",
            "https://dedupe.azure.example/openai/v1/responses",
        ),
    ],
)
async def test_dedicated_dedupe_sdk_request_uses_only_its_provider_connection(
    monkeypatch: pytest.MonkeyPatch,
    main_route: str,
    dedupe_route: str,
    dedupe_key: str,
    dedupe_base: str | None,
    expected_url: str,
) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    monkeypatch.setenv(
        "OPENAI_API_KEY", dedupe_key if main_route.startswith("azure") else "caller-openai-key"
    )
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model=main_route,
            api_key="main-route-secret",
            api_base="https://main-route.example/v1",
            extra_headers={"X-Main": "private"},
        ),
    )
    dedupe = DedupeSettings(
        _env_file=None,
        model=dedupe_route,
        api_key=None if main_route.startswith("azure") else dedupe_key,
        api_base=dedupe_base,
        extra_headers={"X-Dedupe": "own"},
    )
    model = _unwrap(resolve_dedupe_model(dedupe, dedupe_route, settings=settings))
    captured: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "id": "resp_dedupe_test",
                "object": "response",
                "created_at": 1,
                "status": "completed",
                "model": "gpt-6-luna",
                "output": [],
                "usage": {
                    "input_tokens": 1,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 1,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 2,
                },
            },
        )

    route_client = model._client
    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    model._client = AsyncOpenAI(
        api_key=route_client.api_key,
        base_url=route_client.base_url,
        default_headers=route_client.default_headers,
        http_client=mock_http,
    )
    try:
        result = await model.get_response(
            None,
            "Compare these reports.",
            ModelSettings(),
            [],
            None,
            [],
            ModelTracing.DISABLED,
        )
    finally:
        await model._client.close()
        await route_client.close()

    assert result.response_id == "resp_dedupe_test"
    assert len(captured) == 1
    request = captured[0]
    assert str(request.url) == expected_url
    assert request.headers["authorization"] == f"Bearer {dedupe_key}"
    assert request.headers["x-dedupe"] == "own"
    assert "x-main" not in request.headers


@pytest.mark.asyncio
async def test_custom_azure_dedupe_request_does_not_inherit_main_headers() -> None:
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model="azure_ai/gpt-6-sol",
            api_key="main-azure-key",
            api_base="https://main.azure.example",
            extra_headers={"X-Main-Secret": "main-tenant"},
        ),
    )
    dedupe = DedupeSettings(
        _env_file=None,
        model="azure_ai/gpt-6-luna",
        api_key="dedupe-azure-key",
        api_base="https://dedupe.azure.example",
    )
    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))
    assert isinstance(model, _AzureUsageResponsesModel)
    route_client = model._client
    captured: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "id": "resp_azure_dedupe_test",
                "object": "response",
                "created_at": 1,
                "status": "completed",
                "model": "gpt-6-luna",
                "output": [],
                "usage": {
                    "input_tokens": 1,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 1,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 2,
                },
            },
        )

    model._client = AsyncOpenAI(
        api_key=route_client.api_key,
        base_url=route_client.base_url,
        default_headers=route_client.default_headers,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    try:
        result = await model.get_response(
            None,
            "Compare these reports.",
            ModelSettings(),
            [],
            None,
            [],
            ModelTracing.DISABLED,
        )
    finally:
        await model._client.close()
        await route_client.close()

    assert result.response_id == "resp_azure_dedupe_test"
    assert len(captured) == 1
    request = captured[0]
    assert str(request.url) == "https://dedupe.azure.example/openai/v1/responses"
    assert request.headers["authorization"] == "Bearer dedupe-azure-key"
    assert "x-main-secret" not in request.headers


@pytest.mark.asyncio
async def test_custom_openai_dedupe_endpoint_sends_only_dedupe_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-openai-sentinel")
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model="openai/gpt-6-sol",
            api_key="main-openai-sentinel",
            api_base="https://main.openai.example/v1",
            extra_headers={"X-Main": "private"},
        ),
    )
    dedupe = DedupeSettings(
        _env_file=None,
        model="openai/gpt-6-luna",
        api_key="dedupe-openai-key",
        api_base="https://dedupe.openai.example/v1",
    )
    model = _unwrap(resolve_dedupe_model(dedupe, dedupe.model or "", settings=settings))
    assert isinstance(model, OpenAIChatCompletionsModel)
    captured: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl_dedupe_test",
                "object": "chat.completion",
                "created": 1,
                "model": "gpt-6-luna",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "OK"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            },
        )

    route_client = model._client
    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    model._client = AsyncOpenAI(
        api_key=route_client.api_key,
        base_url=route_client.base_url,
        default_headers=route_client.default_headers,
        http_client=mock_http,
    )
    try:
        result = await model.get_response(
            None,
            "Compare these reports.",
            ModelSettings(),
            [],
            None,
            [],
            ModelTracing.DISABLED,
        )
    finally:
        await model._client.close()
        await route_client.close()

    assert result.response_id is None
    assert getattr(result.output[0].content[0], "text", None) == "OK"
    assert len(captured) == 1
    request = captured[0]
    assert str(request.url) == "https://dedupe.openai.example/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer dedupe-openai-key"
    assert "x-main" not in request.headers
    assert "ambient-openai-sentinel" not in request.headers["authorization"]


def test_dedupe_defaults_are_empty() -> None:
    settings = DedupeSettings()
    assert settings.model is None
    assert settings.reasoning_effort is None
    assert settings.api_key is None


def test_dedupe_model_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DEDUPE_MODEL", "deepseek/deepseek-v4-flash")
    monkeypatch.setenv("STRIX_DEDUPE_REASONING_EFFORT", "low")

    settings = DedupeSettings()

    assert settings.model == "deepseek/deepseek-v4-flash"
    assert settings.reasoning_effort == "low"


def test_config_file_loads_dedupe_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "STRIX_DEDUPE_MODEL",
        "STRIX_DEDUPE_REASONING_EFFORT",
    ):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM": "openai/root",
                    "STRIX_DEDUPE_MODEL": "deepseek/cheap",
                    "STRIX_DEDUPE_REASONING_EFFORT": "minimal",
                }
            }
        ),
        encoding="utf-8",
    )
    loader._cached = None
    loader._override = path
    try:
        settings = loader.load_settings()
    finally:
        loader._cached = None
        loader._override = None

    assert settings.dedupe.model == "deepseek/cheap"
    assert settings.dedupe.reasoning_effort == "minimal"
    # Main model stays independent of the dedupe override.
    assert settings.llm.model == "openai/root"


def test_bound_existing_reports_keeps_small_lists_intact() -> None:
    reports = [{"id": f"vuln-{i}", "title": "x" * 100} for i in range(50)]
    assert _bound_existing_reports(reports) == reports


def test_bound_existing_reports_drops_oldest_beyond_budget() -> None:
    big = "x" * 8000
    reports = [{"id": f"vuln-{i:04d}", "description": big} for i in range(100)]
    bounded = _bound_existing_reports(reports)
    assert 0 < len(bounded) < len(reports)
    # Newest reports are retained, in original order.
    assert bounded == reports[len(reports) - len(bounded) :]
    assert sum(len(json.dumps(r)) for r in bounded) <= _MAX_EXISTING_REPORTS_CHARS


def test_bound_existing_reports_truncates_an_oversized_newest_report() -> None:
    oversized = {"id": "vuln-big", "description": "x" * (_MAX_EXISTING_REPORTS_CHARS + 1)}
    bounded = _bound_existing_reports([{"id": "vuln-old"}, oversized])
    assert len(bounded) == 1
    kept = bounded[0]
    # Identity is preserved, the payload is not.
    assert kept["id"] == "vuln-big"
    assert kept["description"].endswith("...[truncated]")
    assert len(json.dumps(kept, indent=2)) <= _MAX_EXISTING_REPORTS_CHARS


def test_bound_existing_reports_encoded_payload_never_exceeds_the_cap() -> None:
    """The transmitted payload is indented, so the cap must hold against that form."""
    reports = [{"id": f"vuln-{i:04d}", "description": "x" * 8000} for i in range(200)]
    bounded = _bound_existing_reports(reports)
    assert len(json.dumps(bounded, indent=2)) <= _MAX_EXISTING_REPORTS_CHARS


def test_bound_existing_reports_drops_a_report_whose_identity_alone_overflows() -> None:
    unshrinkable = {"id": "x" * (_MAX_EXISTING_REPORTS_CHARS + 1)}
    assert _bound_existing_reports([unshrinkable]) == []


@pytest.mark.asyncio
async def test_dedupe_call_reserves_and_releases_against_the_scan_budget() -> None:
    """The dedupe model call is metered, so it must reserve like any agent request."""
    events: list[str] = []

    reserved: list[object] = []

    class _Hooks:
        async def reserve_out_of_band_request(self, **kwargs: object) -> None:
            events.append(f"reserve:{kwargs['key']}")
            reserved.append(kwargs["max_output_tokens"])

        async def release_out_of_band_request(self, **kwargs: object) -> None:
            events.append(f"release:{kwargs['key']}")

    async def _fake_get_response(**_kwargs: object) -> SimpleNamespace:
        events.append("request")
        return SimpleNamespace(usage=None)

    hooks_module.set_active_hooks(cast("Any", _Hooks()))
    try:
        response = await dedupe_module._request_dedupe_judgement(
            model=SimpleNamespace(get_response=_fake_get_response),
            model_name="gpt-6-luna",
            model_settings=cast("Any", None),
            user_msg="compare",
        )
    finally:
        hooks_module.set_active_hooks(None)

    assert response is not None
    assert [e.split(":")[0] for e in events] == ["reserve", "request", "release"]
    assert reserved == [_DEDUPE_MAX_OUTPUT_TOKENS]


def test_semantic_duplicate_requires_compared_id_and_confidence() -> None:
    reports = [{"id": "known"}]
    for result in (
        {"is_duplicate": True, "duplicate_id": "", "confidence": 1.0},
        {"is_duplicate": True, "duplicate_id": "unknown", "confidence": 1.0},
        {"is_duplicate": True, "duplicate_id": "known", "confidence": 0.01},
    ):
        assert _validated_dedupe_result(result, reports)["is_duplicate"] is False
    assert (
        _validated_dedupe_result(
            {"is_duplicate": True, "duplicate_id": "known", "confidence": 0.8}, reports
        )["is_duplicate"]
        is True
    )


@pytest.mark.parametrize("same_title", [False, True])
def test_related_reports_allow_title_and_line_drift_without_broad_comparison(
    same_title: bool,
) -> None:
    candidate = {
        "target": "repo",
        "cwe": "CWE-89",
        "title": "Unsanitized login SQL query",
        "code_locations": [{"file": "app/login.py", "start_line": 20, "end_line": 22}],
    }
    related = {
        "id": "related",
        "target": "repo",
        "cwe": "CWE-89",
        "title": candidate["title"] if same_title else "SQL injection in login",
        "code_locations": [{"file": "app/login.py", "start_line": 10, "end_line": 12}],
    }
    unrelated = {**related, "id": "other", "cwe": "CWE-79"}
    distant = {
        **related,
        "id": "distant",
        "code_locations": [{"file": "app/login.py", "start_line": 100, "end_line": 102}],
    }
    assert _related_reports(candidate, [related, unrelated, distant]) == [related]


@pytest.mark.asyncio
async def test_semantic_duplicate_must_name_a_transmitted_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports = [{"id": f"vuln-{i:04d}", "description": "x" * 8000} for i in range(100)]
    settings = SimpleNamespace(
        dedupe=DedupeSettings(), llm=SimpleNamespace(model="openai/test", timeout=300)
    )
    monkeypatch.setattr(dedupe_module, "load_settings", lambda: settings)
    monkeypatch.setattr(dedupe_module, "configure_sdk_model_defaults", lambda _: None)
    monkeypatch.setattr(dedupe_module, "_dedupe_model_settings", lambda *_a, **_k: {})
    monkeypatch.setattr(
        dedupe_module, "StrixProvider", lambda **_kw: SimpleNamespace(get_model=lambda _: None)
    )
    monkeypatch.setattr(dedupe_module, "get_global_report_state", lambda: None)
    transmitted_ids: list[str] = []

    async def fake_request(**kwargs: Any) -> SimpleNamespace:
        payload = json.loads(dedupe_module._extract_balanced_json(kwargs["user_msg"]))
        transmitted_ids.extend(r["id"] for r in payload["existing_reports"])
        return SimpleNamespace(usage=None)

    monkeypatch.setattr(dedupe_module, "_request_dedupe_judgement", fake_request)
    monkeypatch.setattr(
        dedupe_module,
        "_extract_text",
        lambda _: json.dumps(
            {"is_duplicate": True, "duplicate_id": reports[0]["id"], "confidence": 0.99}
        ),
    )
    result = await dedupe_module.check_duplicate({"title": "candidate"}, reports)
    assert transmitted_ids
    assert reports[0]["id"] not in transmitted_ids
    assert result["is_duplicate"] is False


@pytest.mark.asyncio
async def test_dedupe_releases_its_reservation_when_the_request_fails() -> None:
    """A provider error must not strand the reservation for the rest of the scan."""
    events: list[str] = []

    class _Hooks:
        async def reserve_out_of_band_request(self, **_kwargs: object) -> None:
            events.append("reserve")

        async def release_out_of_band_request(self, **_kwargs: object) -> None:
            events.append("release")

    async def _boom(**_kwargs: object) -> None:
        raise RuntimeError("provider exploded")

    hooks_module.set_active_hooks(cast("Any", _Hooks()))
    try:
        with pytest.raises(RuntimeError, match="provider exploded"):
            await dedupe_module._request_dedupe_judgement(
                model=SimpleNamespace(get_response=_boom),
                model_name="gpt-6-luna",
                model_settings=cast("Any", None),
                user_msg="compare",
            )
    finally:
        hooks_module.set_active_hooks(None)

    assert events == ["reserve", "release"]


@pytest.mark.asyncio
async def test_dedupe_works_without_active_hooks() -> None:
    """Dedupe outside a scan (no registered hooks) must not crash."""
    assert hooks_module.get_active_hooks() is None

    async def _fake_get_response(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(usage=None)

    response = await dedupe_module._request_dedupe_judgement(
        model=SimpleNamespace(get_response=_fake_get_response),
        model_name="gpt-6-luna",
        model_settings=cast("Any", None),
        user_msg="compare",
    )
    assert response is not None


def test_runner_clears_active_hooks_on_every_exit_path() -> None:
    """The runner scopes hooks to a scan and always clears them during finalization."""
    runner = Path("lyrashield/lifecycle/runner.py").read_text(encoding="utf-8")
    root_agent = Path("lyrashield/lifecycle/root_agent.py").read_text(encoding="utf-8")
    finalizer = Path("lyrashield/lifecycle/finalize.py").read_text(encoding="utf-8")
    assert "services.set_active_hooks(hooks)" in root_agent
    assert "services.set_active_hooks(None)" in finalizer
    # Cleanup is awaited from `finally`, so success, failure, and cancellation clear hooks.
    finally_block = runner.split("\n    finally:\n", 1)[1]
    assert "cleanup_scan_resources(" in finally_block


def test_extract_balanced_json_handles_fences_and_nesting() -> None:
    cases = [
        ('{"is_duplicate": true, "confidence": 0.9}', '{"is_duplicate": true, "confidence": 0.9}'),
        ('```json\n{"is_duplicate": true}\n```', '{"is_duplicate": true}'),
        (
            'Here is the result: {"is_duplicate": true, "reason": "same"}',
            '{"is_duplicate": true, "reason": "same"}',
        ),
        (
            json.dumps({"is_duplicate": True, "reason": 'has a { brace and " escaped quote'}),
            json.dumps({"is_duplicate": True, "reason": 'has a { brace and " escaped quote'}),
        ),
        (
            '{"outer": {"inner": 1}}',
            '{"outer": {"inner": 1}}',
        ),
    ]
    for raw, expected in cases:
        assert _extract_balanced_json(raw) == expected


def test_extract_balanced_json_rejects_missing_object() -> None:
    with pytest.raises(ValueError, match="No JSON object found"):
        _extract_balanced_json("just prose")


def test_extract_balanced_json_rejects_unbalanced_object() -> None:
    with pytest.raises(ValueError, match="No balanced JSON object found"):
        _extract_balanced_json('{"is_duplicate": true')


def test_parse_dedupe_response_fails_open_on_invalid_schema() -> None:
    payload = json.dumps(
        {
            "is_duplicate": "false",
            "duplicate_id": "x" * 100,
            "confidence": 0.99,
            "reason": "y" * 1000,
            "extra_field": "ignored",
        }
    )
    parsed = _parse_dedupe_response(payload)
    assert parsed["is_duplicate"] is False
    assert parsed["duplicate_id"] == ""
    assert parsed["confidence"] == 0.0
    assert parsed["reason"]


def test_parse_dedupe_response_validates_via_schema() -> None:
    """A well-formed response should pass Pydantic schema validation."""
    payload = json.dumps(
        {
            "is_duplicate": True,
            "duplicate_id": "vuln-0001",
            "confidence": 0.95,
            "reason": "Same endpoint and payload",
        }
    )
    parsed = _parse_dedupe_response(payload)
    assert parsed["is_duplicate"] is True
    assert parsed["duplicate_id"] == "vuln-0001"
    assert parsed["confidence"] == 0.95
    assert parsed["reason"] == "Same endpoint and payload"


def test_parse_dedupe_response_keeps_narrow_lenient_fallback() -> None:
    """An extra provider field should not discard an otherwise valid verdict."""
    payload = json.dumps(
        {
            "is_duplicate": True,
            "duplicate_id": "vuln-0001",
            "confidence": 0.95,
            "reason": "Same endpoint and payload",
            "provider_metadata": {"trace": "ignored"},
        }
    )

    parsed = _parse_dedupe_response(payload)

    assert parsed["is_duplicate"] is True
    assert parsed["duplicate_id"] == "vuln-0001"
    assert parsed["confidence"] == 0.95
    assert parsed["reason"] == "Same endpoint and payload"


def test_parse_dedupe_response_does_not_coerce_invalid_duplicate_claims() -> None:
    """Invalid model output must preserve the candidate instead of suppressing it."""
    payload = json.dumps(
        {
            "is_duplicate": "yes",
            "duplicate_id": "vuln-0002",
            "confidence": "high",
            "reason": "Similar finding",
            "extra_field": "ignored",
        }
    )
    parsed = _parse_dedupe_response(payload)
    assert parsed["is_duplicate"] is False
    assert parsed["duplicate_id"] == ""
    assert parsed["confidence"] == 0.0


def test_dedupe_ignores_incomplete_or_refused_output_messages() -> None:
    incomplete = ResponseOutputMessage(
        id="msg-incomplete",
        content=[
            ResponseOutputText(type="output_text", annotations=[], text='{"is_duplicate":true}')
        ],
        role="assistant",
        status="incomplete",
        type="message",
    )
    refused = ResponseOutputMessage(
        id="msg-refused",
        content=[ResponseOutputRefusal(type="refusal", refusal="not allowed")],
        role="assistant",
        status="completed",
        type="message",
    )
    assert dedupe_module._extract_text(SimpleNamespace(output=[incomplete])) == ""
    assert dedupe_module._extract_text(SimpleNamespace(output=[refused])) == ""


def test_dedupe_judgement_schema_validates_correct_fields() -> None:
    """DedupeJudgement Pydantic model enforces field types and confidence range."""
    j = DedupeJudgement(is_duplicate=True, duplicate_id="vuln-0001", confidence=0.8, reason="dup")
    assert j.is_duplicate is True
    assert j.duplicate_id == "vuln-0001"
    assert j.confidence == 0.8

    j2 = DedupeJudgement(is_duplicate=False)
    assert j2.is_duplicate is False
    assert j2.duplicate_id == ""
    assert j2.confidence == 0.0
    assert j2.reason == ""
