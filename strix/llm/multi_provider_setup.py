"""Multi-provider routing setup.

Wraps the SDK's :class:`MultiProvider` and registers a custom Anthropic
route so models named ``anthropic/<model>`` go through
:class:`AnthropicCachingLitellmModel` (which injects ``cache_control``
on the system message). Every other prefix
(``openai/`` / ``gemini/`` / ``openrouter/`` / ``litellm/...``) falls
through to the SDK's built-in litellm routing.
"""

from __future__ import annotations

import logging

from agents.exceptions import UserError
from agents.models.interface import Model, ModelProvider
from agents.models.multi_provider import MultiProvider, MultiProviderMap

from strix.llm.anthropic_cache_wrapper import AnthropicCachingLitellmModel


logger = logging.getLogger(__name__)


class _AnthropicCachingProvider(ModelProvider):
    """Routes ``anthropic/<model>`` aliases through
    :class:`AnthropicCachingLitellmModel`.

    The SDK's ``MultiProvider`` strips the matched prefix before calling
    ``get_model``, so we receive bare ``"<model>"`` (e.g.
    ``"claude-sonnet-4-6"``) and re-prefix with ``anthropic/`` so litellm
    routes to the Anthropic API.
    """

    def get_model(self, model_name: str | None) -> Model:
        if not model_name:
            raise UserError(
                "Anthropic provider requires a non-empty model name (e.g. 'claude-sonnet-4-6').",
            )
        full = model_name if model_name.startswith("anthropic/") else f"anthropic/{model_name}"
        logger.debug("Anthropic provider: building cached model for %s", full)
        return AnthropicCachingLitellmModel(model=full)


def build_multi_provider() -> MultiProvider:
    """Build the configured MultiProvider.

    Registers the ``anthropic/`` route through our caching wrapper so
    prompt caching kicks in; everything else falls through to the SDK's
    built-in routing.
    """
    pmap = MultiProviderMap()  # type: ignore[no-untyped-call]
    pmap.add_provider("anthropic", _AnthropicCachingProvider())
    logger.debug("MultiProvider built with anthropic/ caching route")
    return MultiProvider(provider_map=pmap)
