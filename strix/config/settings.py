"""Strix application settings — pydantic-settings powered.

Three sources, env-precedence-first:

1. Environment variables (``STRIX_LLM``, ``LLM_API_KEY``, etc.) — highest.
2. ``~/.strix/cli-config.json`` (or ``--config <path>``) — middle.
3. Field defaults — lowest.

Bool fields auto-parse ``"0"``/``"false"``/``"no"``/``"off"`` as falsy
and any other non-empty string as truthy. Int fields auto-coerce from
string env. The ``api_base`` field walks an alias chain so users can
point at any OpenAI-compatible endpoint via whichever env name they
prefer (``LLM_API_BASE`` / ``OPENAI_API_BASE`` / ``LITELLM_BASE_URL`` /
``OLLAMA_API_BASE``).

Each sub-model is a :class:`BaseSettings` so it reads env independently
— the alternative (one mega-BaseSettings with flat fields) would lose
the logical grouping ``s.llm.model`` / ``s.runtime.image`` / etc.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["low", "medium", "high"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    """LLM provider + model + per-call defaults."""

    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_LLM")
    api_key: str | None = Field(default=None, alias="LLM_API_KEY")
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="STRIX_REASONING_EFFORT")
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")


class RuntimeSettings(BaseSettings):
    """Sandbox image + backend selector."""

    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:0.2.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")


class TelemetrySettings(BaseSettings):
    """Telemetry toggles. ``posthog`` is None → inherit ``master``."""

    model_config = _BASE_CONFIG

    master: bool = Field(default=True, alias="STRIX_TELEMETRY")
    posthog: bool | None = Field(default=None, alias="STRIX_POSTHOG_TELEMETRY")

    @property
    def posthog_enabled(self) -> bool:
        """Effective PostHog toggle: explicit value if set, else ``master``."""
        return self.master if self.posthog is None else self.posthog


class IntegrationSettings(BaseSettings):
    """Third-party integration credentials."""

    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")


class Settings(BaseSettings):
    """Composite Strix settings. Instantiate via :func:`strix.config.load_settings`."""

    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
