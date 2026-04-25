"""Multi-provider routing setup for Strix on top of the SDK MultiProvider.

The SDK's ``MultiProvider`` resolves a model name like ``"strix/claude-sonnet-4.6"``
by stripping the prefix (``"strix"``) and dispatching to a registered
``ModelProvider`` keyed on that prefix. We register two custom providers:

- ``"strix"`` → ``StrixModelProvider``: aliases the short name to a Strix-proxy
  ``openai/<base>`` model URL, but knows whether the underlying provider is
  Anthropic so cache-control still gets injected at the message layer.
- ``"litellm/anthropic"`` → ``LitellmAnthropicProvider``: direct Anthropic
  routing via LiteLLM, always Anthropic, always caching.

Other prefixes fall through to the SDK's built-in OpenAI / LiteLLM defaults.

References:
    - PLAYBOOK.md §2.7
    - AUDIT_R3.md C17 (model alias validation; raise UserError on unknown alias)
    - Legacy: strix/llm/utils.py STRIX_MODEL_MAP and resolve_strix_model
    - Legacy: strix/config/config.py STRIX_API_BASE
"""

from __future__ import annotations

from agents.exceptions import UserError
from agents.extensions.models.litellm_model import LitellmModel
from agents.models.interface import Model, ModelProvider
from agents.models.multi_provider import MultiProvider, MultiProviderMap

from strix.config.config import STRIX_API_BASE
from strix.llm.anthropic_cache_wrapper import AnthropicCachingLitellmModel
from strix.llm.utils import STRIX_MODEL_MAP


def _is_anthropic_canonical(canonical: str) -> bool:
    """Return True if ``canonical`` looks like an Anthropic provider/model."""
    c = canonical.lower()
    return "anthropic/" in c or "claude" in c


class StrixModelProvider(ModelProvider):
    """Resolves the ``strix/`` prefix.

    The MultiProvider strips the prefix before calling ``get_model``, so we
    receive ``"claude-sonnet-4.6"`` for ``"strix/claude-sonnet-4.6"``. The
    ``api_model`` (what we actually send over the wire) is always
    ``openai/<base>`` against the Strix proxy (which is OpenAI-compatible).
    The ``canonical`` model name is what the upstream provider sees and is
    used to decide whether to inject Anthropic prompt caching at the message
    layer.

    C17: unknown aliases raise ``UserError`` listing valid options instead of
    failing opaquely later in the LLM call.
    """

    def get_model(self, model_name: str | None) -> Model:
        if not model_name:
            raise UserError("StrixModelProvider requires a non-empty model name.")
        if model_name not in STRIX_MODEL_MAP:
            valid = ", ".join(sorted(STRIX_MODEL_MAP.keys()))
            raise UserError(
                f"Unknown Strix model alias 'strix/{model_name}'. Valid aliases: {valid}",
            )
        canonical = STRIX_MODEL_MAP[model_name]
        api_model = f"openai/{model_name}"
        if _is_anthropic_canonical(canonical):
            return AnthropicCachingLitellmModel(
                model=api_model,
                base_url=STRIX_API_BASE,
                is_anthropic_override=True,
            )
        return LitellmModel(model=api_model, base_url=STRIX_API_BASE)


class LitellmAnthropicProvider(ModelProvider):
    """Resolves the ``litellm/anthropic`` prefix.

    The MultiProvider strips the matched prefix; for ``litellm/anthropic/...``
    with a registered provider mapping of ``"litellm/anthropic"``, the call
    arrives with ``model_name`` like ``"claude-sonnet-4-5-20250929"`` (the
    suffix after the prefix). Always wraps in the caching model.
    """

    def get_model(self, model_name: str | None) -> Model:
        if not model_name:
            raise UserError(
                "LitellmAnthropicProvider requires a non-empty model name.",
            )
        # Re-prefix for litellm so it routes to Anthropic.
        full = f"anthropic/{model_name}"
        return AnthropicCachingLitellmModel(model=full)


def build_multi_provider() -> MultiProvider:
    """Build the configured MultiProvider for Strix.

    Registers Strix-specific prefix routes; OpenAI and other LiteLLM-prefixed
    models are handled by the SDK's built-in routing.
    """
    pmap = MultiProviderMap()  # type: ignore[no-untyped-call]
    pmap.add_provider("strix", StrixModelProvider())
    pmap.add_provider("litellm/anthropic", LitellmAnthropicProvider())
    return MultiProvider(provider_map=pmap)
