# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Literal


if TYPE_CHECKING:
    from collections.abc import Mapping

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _lyra(upstream: str) -> AliasChoices:
    """Product alias pair for a single upstream STRIX_* env var."""
    product = upstream.replace("STRIX_", "LYRASHIELD_", 1)
    return AliasChoices(upstream, product)


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    # Docker Compose commonly injects optional variables as empty strings. Ignore
    # those placeholders so an earlier generic alias cannot mask a configured
    # provider-specific alias later in AliasChoices.
    env_ignore_empty=True,
    populate_by_name=True,
    extra="ignore",
)


# Set by the LyraShield product entry point (``lyrashield_adapter.cli``) to mark
# the process as running behind the product boundary. Gates that must not apply
# to the bare upstream ``strix`` dev CLI check for it. Lives here so the adapter
# and the CLI share one definition without ``strix`` importing the adapter.
PRODUCT_BOUNDARY_ENV_VAR = "LYRASHIELD_PRODUCT_BOUNDARY"


def is_lyrashield_product() -> bool:
    """Return whether the process is running behind the LyraShield product boundary."""
    return os.environ.get(PRODUCT_BOUNDARY_ENV_VAR, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def is_chatgpt_subscription_allowed(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the ChatGPT subscription path is enabled.

    Enabled by default. Set ``LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0``
    (or ``false`` / ``no`` / ``off``) to disable it.
    """
    env = environ or os.environ

    def _lookup(*names: str) -> str | None:
        for name in names:
            name_upper = name.upper()
            for key, value in env.items():
                if key.upper() == name_upper:
                    return value
        return None

    raw = (
        (
            _lookup(
                "LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION",
                "STRIX_ALLOW_CHATGPT_SUBSCRIPTION",
            )
            or "1"
        )
        .strip()
        .lower()
    )
    return raw not in {
        "0",
        "false",
        "no",
        "off",
    }


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, validation_alias=_lyra("STRIX_LLM"))
    delegate_model: str | None = Field(
        default=None,
        validation_alias=_lyra("STRIX_DELEGATE_LLM"),
    )
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_KEY",
            "OPENAI_API_KEY",
            "AZURE_OPENAI_API_KEY",
            "AZURE_AI_API_KEY",
        ),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
            "AZURE_OPENAI_ENDPOINT",
            "AZURE_OPENAI_API_BASE",
            "AZURE_AI_API_BASE",
        ),
    )
    api_version: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_VERSION",
            "AZURE_API_VERSION",
            "AZURE_OPENAI_API_VERSION",
        ),
    )
    extra_headers: dict[str, str] | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_EXTRA_HEADERS", "LYRASHIELD_EXTRA_HEADERS"),
    )
    reasoning_effort: ReasoningEffort = Field(
        default="medium",
        validation_alias=_lyra("STRIX_REASONING_EFFORT"),
    )
    delegate_reasoning_effort: ReasoningEffort = Field(
        default="medium",
        validation_alias=_lyra("STRIX_DELEGATE_REASONING_EFFORT"),
    )
    prompt_cache: bool = Field(
        default=True,
        validation_alias=_lyra("STRIX_PROMPT_CACHE"),
    )
    disable_streaming: bool = Field(
        default=False,
        validation_alias=AliasChoices("LLM_DISABLE_STREAMING", "LYRASHIELD_DISABLE_STREAMING"),
    )
    force_required_tool_choice: bool = Field(
        default=False,
        validation_alias=_lyra("STRIX_FORCE_REQUIRED_TOOL_CHOICE"),
    )
    timeout: int = Field(
        default=300,
        validation_alias=AliasChoices("LLM_TIMEOUT", "LYRASHIELD_LLM_TIMEOUT"),
    )
    # Hard cap on tokens generated per request. Unset keeps the per-scan-mode
    # default chosen by the runner; when set it replaces that default for every
    # agent (delegates stay separately clamped). Also tightens the pre-request
    # budget reservation, which reads this back off ``ModelSettings.max_tokens``.
    max_output_tokens: int | None = Field(
        default=None,
        gt=0,
        validation_alias=_lyra("STRIX_MAX_OUTPUT_TOKENS"),
    )
    # Ceiling that history compaction keeps a request's input under. This is NOT
    # a hard reject: exceeding it compacts older history rather than failing the
    # request. Clamped below the GPT-5.6 long-context boundary, above which input
    # is billed at 2x — the clamp is what stops this knob from raising cost.
    max_input_tokens: int | None = Field(
        default=None,
        gt=0,
        validation_alias=_lyra("STRIX_MAX_INPUT_TOKENS"),
    )

    @field_validator("api_base", "api_key", "api_version", mode="before")
    @classmethod
    def _empty_env_to_none(cls, value: Any) -> Any:
        return None if value == "" else value


class DedupeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(
        default=None,
        alias="STRIX_DEDUPE_MODEL",
        validation_alias=_lyra("STRIX_DEDUPE_MODEL"),
    )
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_DEDUPE_REASONING_EFFORT",
        validation_alias=_lyra("STRIX_DEDUPE_REASONING_EFFORT"),
    )
    api_key: str | None = Field(
        default=None,
        alias="DEDUPE_LLM_API_KEY",
        validation_alias=AliasChoices(
            "DEDUPE_LLM_API_KEY",
            "LYRASHIELD_DEDUPE_LLM_API_KEY",
        ),
    )
    api_base: str | None = Field(
        default=None,
        alias="DEDUPE_LLM_API_BASE",
        validation_alias=AliasChoices(
            "DEDUPE_LLM_API_BASE",
            "LYRASHIELD_DEDUPE_LLM_API_BASE",
        ),
    )
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="DEDUPE_LLM_EXTRA_HEADERS",
    )

    @field_validator("api_base", "api_key", mode="before")
    @classmethod
    def _empty_env_to_none(cls, value: Any) -> Any:
        return None if value == "" else value


class ContextSettings(BaseSettings):
    """Context-window management: per-tool-output caps and history compaction."""

    model_config = _BASE_CONFIG

    auto_compact: bool = Field(
        default=True,
        validation_alias=_lyra("STRIX_CONTEXT_AUTO_COMPACT"),
    )
    compact_buffer_tokens: int = Field(
        default=20_000,
        gt=0,
        validation_alias=_lyra("STRIX_CONTEXT_BUFFER_TOKENS"),
    )
    keep_tokens: int = Field(
        default=8_000,
        gt=0,
        validation_alias=_lyra("STRIX_CONTEXT_KEEP_TOKENS"),
    )
    fallback_context_tokens: int = Field(
        default=200_000,
        gt=0,
        validation_alias=_lyra("STRIX_CONTEXT_FALLBACK_TOKENS"),
    )
    summary_max_tokens: int = Field(
        default=4_096,
        gt=0,
        validation_alias=_lyra("STRIX_CONTEXT_SUMMARY_TOKENS"),
    )
    tool_output_max_tokens: int = Field(
        default=8_000,
        gt=0,
        validation_alias=_lyra("STRIX_TOOL_OUTPUT_MAX_TOKENS"),
    )
    tool_output_max_lines: int = Field(
        default=2_000,
        gt=0,
        validation_alias=_lyra("STRIX_TOOL_OUTPUT_MAX_LINES"),
    )
    # Floor above the truncation-notice size so a preview always fits.
    tool_output_max_bytes: int = Field(
        default=50 * 1024,
        ge=1024,
        validation_alias=_lyra("STRIX_TOOL_OUTPUT_MAX_BYTES"),
    )


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="strix-sandbox:dev",
        validation_alias=_lyra("STRIX_IMAGE"),
    )
    backend: str = Field(
        default="docker",
        validation_alias=_lyra("STRIX_RUNTIME_BACKEND"),
    )
    # Hard cap on a local target's size before we refuse to stream it into the
    # sandbox file-by-file (the SDK copies every file individually, which stalls
    # on large repos). Above this, the user must bind-mount via ``--mount``.
    # Set to 0 (or less) to disable the pre-flight check entirely.
    max_local_copy_mb: int = Field(
        default=1024,
        validation_alias=_lyra("STRIX_MAX_LOCAL_COPY_MB"),
    )
    # Max screenshot/image tool outputs kept live per agent context (0 = none).
    max_context_images: int = Field(
        default=3,
        ge=0,
        validation_alias=_lyra("STRIX_MAX_CONTEXT_IMAGES"),
    )
    # Use OpenAI server-managed conversations (OpenAIConversationsSession) instead of
    # the local SQLiteSession. Requires an endpoint that supports the conversations
    # API and is off by default until endpoint capability is proven.
    server_conversation: bool = Field(
        default=False,
        validation_alias=_lyra("STRIX_SERVER_CONVERSATION"),
    )


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(
        default=False,
        validation_alias=_lyra("STRIX_TELEMETRY"),
    )


class ViewerSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Base URL of the Strix relay the local viewer proxies to for email
    # verification and encrypted report delivery. The browser never talks to
    # the relay directly; the local server is the only caller.
    app_url: str = Field(
        default="https://app.strix.ai",
        alias="STRIX_APP_URL",
        validation_alias=_lyra("STRIX_APP_URL"),
    )


class WebSearchSettings(BaseSettings):
    """Optional live web search via Parallel Search for real-time OSINT."""

    model_config = _BASE_CONFIG

    enabled: bool = Field(
        default=False,
        validation_alias=_lyra("STRIX_WEB_SEARCH_ENABLED"),
    )
    provider: Literal["parallel"] = Field(
        default="parallel",
        validation_alias=_lyra("STRIX_WEB_SEARCH_PROVIDER"),
    )
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LYRASHIELD_WEB_SEARCH_API_KEY",
            "PARALLEL_API_KEY",
            "STRIX_WEB_SEARCH_API_KEY",
        ),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=_lyra("STRIX_WEB_SEARCH_API_BASE"),
    )
    mode: Literal["turbo", "basic", "advanced"] = Field(
        default="turbo",
        validation_alias=_lyra("STRIX_WEB_SEARCH_MODE"),
    )
    max_results: int = Field(
        default=5,
        ge=1,
        le=20,
        validation_alias=_lyra("STRIX_WEB_SEARCH_MAX_RESULTS"),
    )
    max_chars_total: int = Field(
        default=4000,
        ge=1000,
        le=20000,
        validation_alias=_lyra("STRIX_WEB_SEARCH_MAX_CHARS_TOTAL"),
    )
    max_calls_per_scan: int = Field(
        default=50,
        ge=0,
        validation_alias=_lyra("STRIX_WEB_SEARCH_MAX_CALLS_PER_SCAN"),
    )
    budget_usd: float = Field(
        default=1.0,
        ge=0.0,
        validation_alias=_lyra("STRIX_WEB_SEARCH_BUDGET_USD"),
    )
    turbo_cost_per_call: float = Field(
        default=0.001,
        ge=0.0,
        validation_alias=_lyra("STRIX_WEB_SEARCH_TURBO_COST"),
    )
    basic_cost_per_call: float = Field(
        default=0.005,
        ge=0.0,
        validation_alias=_lyra("STRIX_WEB_SEARCH_BASIC_COST"),
    )
    advanced_cost_per_call: float = Field(
        default=0.005,
        ge=0.0,
        validation_alias=_lyra("STRIX_WEB_SEARCH_ADVANCED_COST"),
    )

    @field_validator("api_base", "api_key", mode="before")
    @classmethod
    def _empty_env_to_none(cls, value: Any) -> Any:
        return None if value == "" else value


class IntegrationSettings(BaseSettings):
    """Third-party API keys and service credentials."""

    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(
        default=None,
        alias="PERPLEXITY_API_KEY",
        validation_alias=AliasChoices("PERPLEXITY_API_KEY", "LYRASHIELD_PERPLEXITY_API_KEY"),
        repr=False,
    )
    postman_api_key: str | None = Field(
        default=None,
        alias="POSTMAN_API_KEY",
        validation_alias=AliasChoices("POSTMAN_API_KEY", "LYRASHIELD_POSTMAN_API_KEY"),
        repr=False,
    )


class ProductSettings(BaseSettings):
    """LyraShield product-behavior switches with no upstream equivalent."""

    model_config = _BASE_CONFIG

    allow_chatgpt_subscription: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION",
            "STRIX_ALLOW_CHATGPT_SUBSCRIPTION",
        ),
    )


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    viewer: ViewerSettings = Field(default_factory=ViewerSettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    product: ProductSettings = Field(default_factory=ProductSettings)
    web_search: WebSearchSettings = Field(default_factory=WebSearchSettings)
