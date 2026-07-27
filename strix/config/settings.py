# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _lyra(upstream: str) -> AliasChoices:
    """Product alias pair for a single upstream STRIX_* env var."""
    product = upstream.replace("STRIX_", "LYRASHIELD_", 1)
    return AliasChoices(upstream, product)


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


# Set by the LyraShield product entry point (``lyrashield_adapter.cli``) to mark
# the process as running behind the product boundary. Gates that must not apply
# to the bare upstream ``strix`` dev CLI check for it. Lives here so the adapter
# and the CLI share one definition without ``strix`` importing the adapter.
PRODUCT_BOUNDARY_ENV_VAR = "LYRASHIELD_PRODUCT_BOUNDARY"


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
    reasoning_effort: ReasoningEffort = Field(
        default="medium",
        validation_alias=_lyra("STRIX_REASONING_EFFORT"),
    )
    delegate_reasoning_effort: ReasoningEffort = Field(
        default="medium",
        validation_alias=_lyra("STRIX_DELEGATE_REASONING_EFFORT"),
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

    model: str | None = Field(default=None, alias="STRIX_DEDUPE_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_DEDUPE_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="DEDUPE_LLM_API_KEY")
    api_base: str | None = Field(default=None, alias="DEDUPE_LLM_API_BASE")


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
        default=True,
        validation_alias=_lyra("STRIX_TELEMETRY"),
    )


class ViewerSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Base URL of the Strix relay the local viewer proxies to for email
    # verification and encrypted report delivery. The browser never talks to
    # the relay directly; the local server is the only caller.
    app_url: str = Field(default="https://app.strix.ai", alias="STRIX_APP_URL")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    viewer: ViewerSettings = Field(default_factory=ViewerSettings)
