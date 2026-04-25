"""Phase 0 smoke tests for multi_provider_setup."""

from __future__ import annotations

import pytest
from agents.exceptions import UserError
from agents.extensions.models.litellm_model import LitellmModel

from strix.config.config import STRIX_API_BASE
from strix.llm.anthropic_cache_wrapper import AnthropicCachingLitellmModel
from strix.llm.multi_provider_setup import (
    LitellmAnthropicProvider,
    StrixModelProvider,
    build_multi_provider,
)


def test_strix_provider_resolves_anthropic_alias_with_override() -> None:
    provider = StrixModelProvider()
    model = provider.get_model("claude-sonnet-4.6")
    assert isinstance(model, AnthropicCachingLitellmModel)
    # Goes via Strix proxy as openai/<base>, but is_anthropic still True.
    assert model.model == "openai/claude-sonnet-4.6"
    assert str(model.base_url) == STRIX_API_BASE
    assert model._is_anthropic() is True


def test_strix_provider_resolves_openai_alias_without_override() -> None:
    provider = StrixModelProvider()
    model = provider.get_model("gpt-5.4")
    # Plain LitellmModel, NOT the caching subclass.
    assert isinstance(model, LitellmModel)
    assert not isinstance(model, AnthropicCachingLitellmModel)
    assert model.model == "openai/gpt-5.4"


def test_strix_provider_unknown_alias_raises_user_error() -> None:
    """C17 (AUDIT_R3): unknown alias must surface a clear error with valid options."""
    provider = StrixModelProvider()
    with pytest.raises(UserError, match="Unknown Strix model alias"):
        provider.get_model("typo-model-name")


def test_strix_provider_empty_name_raises() -> None:
    provider = StrixModelProvider()
    with pytest.raises(UserError, match="non-empty"):
        provider.get_model(None)


def test_litellm_anthropic_provider_wraps_in_caching_model() -> None:
    provider = LitellmAnthropicProvider()
    model = provider.get_model("claude-3-5-sonnet-20241022")
    assert isinstance(model, AnthropicCachingLitellmModel)
    assert model.model == "anthropic/claude-3-5-sonnet-20241022"
    assert model._is_anthropic() is True


def test_build_multi_provider_registers_strix_prefix() -> None:
    mp = build_multi_provider()
    # The MultiProvider stores the map; the easiest check is that resolving
    # "strix/claude-sonnet-4.6" goes through StrixModelProvider.
    model = mp.get_model("strix/claude-sonnet-4.6")
    assert isinstance(model, AnthropicCachingLitellmModel)
    assert model.model == "openai/claude-sonnet-4.6"
