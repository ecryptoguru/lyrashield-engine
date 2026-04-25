"""Phase 0 smoke tests for AnthropicCachingLitellmModel."""

from __future__ import annotations

import pytest

from strix.llm.anthropic_cache_wrapper import AnthropicCachingLitellmModel


def _make(model: str, **kwargs: object) -> AnthropicCachingLitellmModel:
    # ``LitellmModel.__init__`` only validates that model is a string; we
    # don't need a real API key for in-memory ``_patch`` testing.
    return AnthropicCachingLitellmModel(model=model, api_key="test-key", **kwargs)


def test_is_anthropic_detects_anthropic_prefix() -> None:
    m = _make("anthropic/claude-3-5-sonnet")
    assert m._is_anthropic() is True


def test_is_anthropic_detects_claude_substring() -> None:
    m = _make("openrouter/anthropic-claude-haiku")
    assert m._is_anthropic() is True


def test_is_anthropic_false_for_openai() -> None:
    m = _make("openai/gpt-4o")
    assert m._is_anthropic() is False


def test_is_anthropic_false_for_gemini() -> None:
    m = _make("gemini/gemini-1.5-pro")
    assert m._is_anthropic() is False


def test_explicit_override_true_wins() -> None:
    """For Strix proxy routing where api_model is openai/<base> but
    canonical is Anthropic, the override forces cache injection."""
    m = _make("openai/claude-sonnet-4.6", is_anthropic_override=True)
    assert m._is_anthropic() is True


def test_explicit_override_false_wins() -> None:
    m = _make("anthropic/claude-3-5-sonnet", is_anthropic_override=False)
    assert m._is_anthropic() is False


def test_patch_anthropic_adds_cache_control_to_system() -> None:
    m = _make("anthropic/claude-3-5-sonnet")
    items: list = [
        {"role": "system", "content": "You are a helpful agent."},
        {"role": "user", "content": "hi"},
    ]
    out = m._patch(items)
    assert out[0]["role"] == "system"
    content = out[0]["content"]
    assert isinstance(content, list)
    assert content[0]["type"] == "text"
    assert content[0]["text"] == "You are a helpful agent."
    assert content[0]["cache_control"] == {"type": "ephemeral"}
    # Second item passes through unchanged.
    assert out[1] == {"role": "user", "content": "hi"}


def test_patch_non_anthropic_passes_through() -> None:
    m = _make("openai/gpt-4o")
    items: list = [
        {"role": "system", "content": "You are a helpful agent."},
        {"role": "user", "content": "hi"},
    ]
    assert m._patch(items) is items  # exact same list reference, no copy


def test_patch_skips_non_string_system_content() -> None:
    """If system content is already structured (e.g., previously patched),
    don't re-wrap — pass through unchanged."""
    m = _make("anthropic/claude-3-5-sonnet")
    items: list = [
        {"role": "system", "content": [{"type": "text", "text": "x"}]},
        {"role": "user", "content": "hi"},
    ]
    out = m._patch(items)
    assert out[0]["content"] == [{"type": "text", "text": "x"}]


def test_patch_handles_empty_list() -> None:
    m = _make("anthropic/claude-3-5-sonnet")
    assert m._patch([]) == []


@pytest.mark.parametrize(
    "model",
    [
        "openai/claude-sonnet-4.6",  # Strix proxy with Anthropic underneath
        "openai/gpt-5.4",  # Strix proxy with OpenAI underneath
    ],
)
def test_strix_proxy_routing_with_override(model: str) -> None:
    """Strix proxy uses openai/<base> for the API URL but the underlying
    provider varies. The override flag is the source of truth."""
    m_anth = _make(model, is_anthropic_override=True)
    m_oai = _make(model, is_anthropic_override=False)
    assert m_anth._is_anthropic() is True
    assert m_oai._is_anthropic() is False
