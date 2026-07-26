# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK model configuration helpers."""

from __future__ import annotations

import contextlib
import inspect
import os
import re
from typing import TYPE_CHECKING, Any, cast

from agents import (
    set_default_openai_api,
    set_default_openai_key,
    set_tracing_disabled,
)
from agents.model_settings import ModelSettings
from agents.models.multi_provider import MultiProvider
from agents.models.openai_responses import OpenAIResponsesModel
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    RetryPolicyContext,
    retry_policies,
)
from openai.types.shared import Reasoning

from strix.config import codex
from strix.config.loader import load_settings


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from agents.models.interface import Model, ModelProvider
    from openai import AsyncOpenAI

    from strix.config.settings import ReasoningEffort, Settings


def request_timeout_extra_args(timeout_s: float | None) -> dict[str, float] | None:
    """Per-request model timeout; a plain float so ``ModelSettings.to_json_dict()`` stays serializable."""  # noqa: E501
    if not timeout_s or timeout_s <= 0:
        return None
    return {"timeout": timeout_s}


def is_gpt56_model(model_name: str | None) -> bool:
    r"""Return whether a configured deployment is one of LyraShield's GPT-5.6 tiers.

    Matches the worker's allowed set: Terra or Luna. The worker regex is
    ``/(?:^|[/.-])gpt-5\.6-(?:terra|luna)(?:$|[/.-])/`` after lower-casing and
    converting underscores to dashes. Sol was retired from the supported set, so
    it is rejected here at startup rather than reaching budget enforcement (which
    no longer carries a Sol rate) and failing mid-scan.
    """
    if not model_name:
        return False
    normalized = model_name.strip().lower().replace("_", "-")
    return re.search(r"(?:^|[/.-])gpt-5\.6-(?:terra|luna)(?:$|[/.-])", normalized) is not None


def model_supports_programmatic_tool_calling(model_name: str | None) -> bool:
    """Return whether the resolved model is known to support programmatic tool calling.

    The feature is enabled by default for OpenAI ``gpt-5.6-*`` deployments, which
    currently support the ``programmatic_tool_calling`` Responses tool type. Azure AI
    ``azure_ai/gpt-5.6-*`` requires a Trusted Access / Cyber-enabled deployment and is
    only enabled when ``LYRASHIELD_PROGRAMMATIC_TOOL_CALLING=1`` is explicitly set.
    Use ``LYRASHIELD_PROGRAMMATIC_TOOL_CALLING=0`` to force it off.
    """
    if not model_name:
        return False
    env = os.environ.get("LYRASHIELD_PROGRAMMATIC_TOOL_CALLING", "").strip().lower()
    if env in ("0", "false", "no"):
        return False
    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    if env in ("1", "true", "yes"):
        return is_gpt56_model(name)
    # Default: only OpenAI direct deployments are known to support PTC today.
    return name.startswith("openai/") and is_gpt56_model(name)


def _retry_statusless_provider_errors(context: RetryPolicyContext) -> bool:
    """Retry statusless provider errors (e.g. mid-stream quota/billing), but not aborts."""
    normalized = context.normalized
    if normalized.is_abort:
        return False
    if codex.is_content_guardrail_error(context.error):
        return False
    return normalized.status_code is None


class _CodexResponsesModel(OpenAIResponsesModel):
    """Responses model for the ChatGPT subscription backend (always streamed, stateless)."""

    def __init__(
        self,
        model: str,
        openai_client: AsyncOpenAI,
        *,
        reasoning_effort: ReasoningEffort | None = None,
    ) -> None:
        super().__init__(model, openai_client)
        self._reasoning_effort = reasoning_effort

    def _codex_settings(self, model_settings: ModelSettings) -> ModelSettings:
        overrides = ModelSettings(store=False, response_include=["reasoning.encrypted_content"])
        effort = self._reasoning_effort
        if effort and effort != "none":
            # Clamp to efforts the backend accepts.
            if effort == "minimal":
                effort = "low"
            elif effort == "xhigh":
                effort = "high"
            overrides = overrides.resolve(
                ModelSettings(reasoning=Reasoning(effort=cast("ReasoningEffort", effort)))
            )
        return model_settings.resolve(overrides)

    async def _fetch_response(self, *args: Any, stream: bool = False, **kwargs: Any) -> Any:
        if len(args) >= 3:  # model_settings is positional arg 2
            args = (*args[:2], self._codex_settings(args[2]), *args[3:])
        try:
            events = await super()._fetch_response(*args, stream=True, **kwargs)  # type: ignore[call-overload]
        except Exception as exc:
            guardrail = self._as_guardrail(exc)
            if guardrail is not None:
                raise guardrail from exc
            raise
        guarded = self._guarded(events)
        if stream:
            return guarded
        final_response = None
        async for event in guarded:
            if getattr(event, "type", None) == "response.completed":
                final_response = event.response
        if final_response is None:
            msg = "ChatGPT backend stream ended without a completed response"
            raise RuntimeError(msg)
        return final_response

    def _as_guardrail(self, exc: BaseException) -> codex.CodexContentGuardrailError | None:
        if isinstance(exc, codex.CodexContentGuardrailError):
            return exc
        if codex.is_content_guardrail_error(exc):
            return codex.CodexContentGuardrailError(self.model, exc)
        return None

    async def _guarded(self, events: Any) -> AsyncIterator[Any]:
        """Convert mid-stream guardrail rejections and close the stream on exit."""
        try:
            async for event in events:
                yield event
        except Exception as exc:
            guardrail = self._as_guardrail(exc)
            if guardrail is not None:
                raise guardrail from exc
            raise
        finally:
            await self._aclose(events)

    @staticmethod
    async def _aclose(events: Any) -> None:
        aclose = getattr(events, "aclose", None)
        if callable(aclose):
            with contextlib.suppress(Exception):
                await cast("Any", aclose())
            return
        close = getattr(events, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                result = close()
                if inspect.isawaitable(result):
                    await result


class StrixProvider(MultiProvider):
    """Route any non-OpenAI prefix through LiteLLM with the prefix preserved,
    so users type ``deepseek/deepseek-chat`` rather than
    ``litellm/deepseek/deepseek-chat``.
    """

    def __init__(self, *, settings: Settings | None = None) -> None:
        llm = settings.llm if settings is not None else None
        configured_models = (
            (getattr(llm, "model", None), getattr(llm, "delegate_model", None))
            if llm is not None
            else (None, None)
        )
        self._azure_responses_enabled = any(
            _is_azure_model(model_name) and is_gpt56_model(model_name)
            for model_name in configured_models
        )

        if self._azure_responses_enabled:
            if llm is None or not llm.api_base:
                raise RuntimeError(
                    "Azure GPT-5.6 requires LLM_API_BASE or an Azure endpoint variable."
                )
            super().__init__(
                openai_api_key=llm.api_key,
                openai_base_url=_azure_responses_base_url(llm.api_base),
                openai_use_responses=True,
            )
        else:
            super().__init__()

    def _resolve_prefixed_model(
        self,
        *,
        original_model_name: str,
        prefix: str,
        stripped_model_name: str | None,
    ) -> tuple[ModelProvider, str | None]:
        if prefix in {"azure", "azure_ai"} and self._azure_responses_enabled:
            return self.openai_provider, stripped_model_name
        if prefix in {"openai", "litellm", "any-llm"}:
            return super()._resolve_prefixed_model(
                original_model_name=original_model_name,
                prefix=prefix,
                stripped_model_name=stripped_model_name,
            )
        if prefix == "ollama" and stripped_model_name:
            return self._get_fallback_provider("litellm"), f"ollama_chat/{stripped_model_name}"
        return self._get_fallback_provider("litellm"), original_model_name

    def get_model(self, model_name: str | None) -> Model:
        slug = codex.subscription_model(model_name)
        if slug:
            return _CodexResponsesModel(
                slug,
                codex.get_subscription_client(),
                reasoning_effort=load_settings().llm.reasoning_effort,
            )
        return super().get_model(model_name)


def _azure_responses_base_url(api_base: str) -> str:
    """Normalize an Azure resource or project endpoint for the v1 Responses API."""
    base = api_base.strip().rstrip("/")
    if not base:
        raise RuntimeError("Azure GPT-5.6 requires a non-empty API base URL.")
    if not base.lower().endswith("/openai/v1"):
        base = f"{base}/openai/v1"
    return f"{base}/"


DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
        _retry_statusless_provider_errors,
    ),
)

RECOMMENDED_MODEL_NAMES = (
    "openai/gpt-5.6-luna",
    "openai/gpt-5.6-terra",
)

_RECOMMENDED_MODEL_NAME_SET = frozenset(name.lower() for name in RECOMMENDED_MODEL_NAMES)

FRONTIER_MODEL_FAMILIES = (
    (("azure", "azure_ai", "bedrock_mantle", "chatgpt", "openai"), ("gpt-5",)),
    (
        ("anthropic", "azure_ai", "bedrock", "claude", "databricks", "snowflake", "vertex_ai"),
        ("claude-fable-5", "claude-opus-5", "claude-opus-4", "claude-sonnet-5", "claude-sonnet-4"),
    ),
    (("google", "gemini", "vertex_ai"), ("gemini-3",)),
    (("deepseek",), ("deepseek-v4", "deepseek-r1", "deepseek-reasoner")),
    (("alibaba", "dashscope", "qwen"), ("qwen3.8", "qwen3.7", "qwen3-max")),
    (("moonshot", "moonshotai", "kimi"), ("kimi-k3", "kimi-k2.7", "kimi-k2.6")),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply Strix config to SDK-native defaults."""
    llm = settings.llm
    set_tracing_disabled(True)
    if codex.subscription_model(llm.model):
        return
    _configure_litellm_compatibility()
    _configure_openrouter_attribution(llm.model)
    if llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        _configure_litellm_default("api_key", llm.api_key)
        _mirror_api_key_to_provider_env(llm.model, llm.api_key)
    if llm.api_base:
        _configure_litellm_default("api_base", llm.api_base)
        if not _is_azure_model(llm.model):
            os.environ["OPENAI_BASE_URL"] = llm.api_base
            set_default_openai_api("chat_completions")
        else:
            set_default_openai_api("responses")
    else:
        set_default_openai_api("responses")
    if llm.api_version:
        _configure_litellm_default("api_version", llm.api_version)
    _mirror_azure_env(llm.model, llm.api_base, llm.api_version)


def _is_azure_model(model_name: str | None) -> bool:
    """Return True if the model is routed through Azure or Azure AI."""
    if not model_name:
        return False
    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.startswith(("azure/", "azure_ai/"))


def _mirror_api_key_to_provider_env(model_name: str | None, api_key: str) -> None:
    if not model_name:
        return
    import litellm

    name = model_name.strip()
    for prefix in ("litellm/", "any-llm/"):
        if name.lower().startswith(prefix):
            name = name[len(prefix) :]
            break
    try:
        report = cast(
            "dict[str, Any]",
            litellm.validate_environment(model=name.lower()),  # pyright: ignore[reportUnknownMemberType]
        )
    except Exception:  # noqa: BLE001
        return
    missing_keys = report.get("missing_keys")
    if isinstance(missing_keys, list):
        missing_keys = cast("list[Any]", missing_keys)
        for env_key in missing_keys:
            if isinstance(env_key, str) and env_key.endswith("_API_KEY"):
                os.environ.setdefault(env_key, api_key)


def _mirror_azure_env(
    model_name: str | None,
    api_base: str | None,
    api_version: str | None,
) -> None:
    """Mirror Azure OpenAI / Azure AI config into LiteLLM's expected env vars."""
    if not model_name:
        return

    name = model_name.strip()
    for prefix in ("litellm/", "any-llm/"):
        if name.lower().startswith(prefix):
            name = name[len(prefix) :]
            break
    if not name.lower().startswith(("azure/", "azure_ai/")):
        return

    if api_base:
        os.environ.setdefault("AZURE_API_BASE", api_base)
        os.environ.setdefault("AZURE_AI_API_BASE", api_base)
    if api_version:
        os.environ.setdefault("AZURE_API_VERSION", api_version)
        os.environ.setdefault("AZURE_AI_API_VERSION", api_version)


def _configure_litellm_compatibility() -> None:
    """Apply LiteLLM compatibility, privacy, and callback settings."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True
    litellm.turn_off_message_logging = True
    # Strix uses LiteLLM's success callback to capture provider-reported cost.
    # Disabling streaming logging also disables that callback for streamed calls.
    litellm.disable_streaming_logging = False
    litellm.suppress_debug_info = True

    _register_litellm_cost_callback()


_OPENROUTER_ATTRIBUTION_HEADERS = {
    "HTTP-Referer": "https://strix.ai",
    "X-Title": "Strix",
    "X-OpenRouter-Categories": "cli-agent",
}


def _configure_openrouter_attribution(model_name: str | None) -> None:
    import litellm

    current: dict[str, str] | None = getattr(litellm, "headers", None)
    existing: dict[str, str] = current if isinstance(current, dict) else {}
    if not model_name or "openrouter/" not in model_name.strip().lower():
        if any(key in existing for key in _OPENROUTER_ATTRIBUTION_HEADERS):
            remaining = {
                k: v for k, v in existing.items() if k not in _OPENROUTER_ATTRIBUTION_HEADERS
            }
            litellm.headers = remaining or None  # type: ignore[assignment]
        return

    litellm.headers = {**existing, **_OPENROUTER_ATTRIBUTION_HEADERS}  # type: ignore[assignment]


def _register_litellm_cost_callback() -> None:
    import litellm

    from strix.report.state import litellm_cost_callback

    for bucket_name in ("success_callback", "_async_success_callback"):
        bucket = getattr(litellm, bucket_name, None)
        if not isinstance(bucket, list):
            continue
        bucket = cast("list[Any]", bucket)
        if litellm_cost_callback in bucket:
            continue
        bucket.append(litellm_cost_callback)


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    # ponytail: explicit operator opt-in is the provider capability assertion.
    # Keep Azure on its proven JSON-tool path unless that assertion is present.
    if model_supports_programmatic_tool_calling(model_name):
        return False
    if codex.subscription_model(model_name):
        return False
    model = model_name.strip().lower()
    if "/" in model and not model.startswith("openai/"):
        return True
    if settings.llm.api_base:
        return True
    return not model_supports_reasoning(model_name)


def _model_cost_entry(model_cost: dict[str, Any], name: str) -> dict[str, Any] | None:
    entry: Any = model_cost.get(name)
    return cast("dict[str, Any]", entry) if isinstance(entry, dict) else None


def model_supports_reasoning(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    model_cost = cast("dict[str, Any]", litellm.model_cost)
    entry = _model_cost_entry(model_cost, name)
    if entry is None and "/" in name:
        entry = _model_cost_entry(model_cost, name.rsplit("/", 1)[1])
    return bool(entry is not None and entry.get("supports_reasoning"))


def is_recommended_or_frontier_model(model_name: str) -> bool:
    """Return whether a model is recommended or in a frontier model family."""
    name = _normalized_model_name(model_name)
    if not name:
        return False
    if name in _RECOMMENDED_MODEL_NAME_SET:
        return True
    provider_name, bare_model_name = _split_model_provider(name)
    return any(
        _matches_frontier_family(provider_name, bare_model_name, provider_markers, prefixes)
        for provider_markers, prefixes in FRONTIER_MODEL_FAMILIES
    )


def _normalized_model_name(model_name: str) -> str:
    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name


def _split_model_provider(model_name: str) -> tuple[str | None, str]:
    if "/" not in model_name:
        return None, model_name
    provider_name, bare_model_name = model_name.rsplit("/", 1)
    return provider_name, bare_model_name


def _matches_frontier_family(
    provider_name: str | None,
    model_name: str,
    provider_markers: tuple[str, ...],
    model_prefixes: tuple[str, ...],
) -> bool:
    if not _matches_model_prefix(model_name, model_prefixes):
        return False
    if provider_name is None:
        return True
    return _contains_provider_marker(
        provider_name, provider_markers, split_compound_names=True
    ) or _contains_provider_marker(model_name, provider_markers)


def _matches_model_prefix(model_name: str, model_prefixes: tuple[str, ...]) -> bool:
    return any(
        candidate.startswith(prefix)
        for candidate in _model_name_candidates(model_name)
        for prefix in model_prefixes
    )


def _model_name_candidates(model_name: str) -> tuple[str, ...]:
    if "." not in model_name:
        return (model_name,)
    suffixes = tuple(
        model_name.split(".", index)[-1] for index in range(1, model_name.count(".") + 1)
    )
    return (model_name, *suffixes)


def _contains_provider_marker(
    value: str, provider_markers: tuple[str, ...], *, split_compound_names: bool = False
) -> bool:
    parts = set(value.replace(".", "/").split("/"))
    if split_compound_names:
        for separator in ("_", "-"):
            parts.update(piece for part in tuple(parts) for piece in part.split(separator))
    return any(marker in parts for marker in provider_markers)


def is_known_openai_bare_model(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    if not name or "/" in name:
        return False
    model_cost = cast("dict[str, Any]", litellm.model_cost)
    entry = _model_cost_entry(model_cost, name)
    return bool(entry is not None and entry.get("litellm_provider") == "openai")
