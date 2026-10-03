"""Supported-provider boundary for dedicated deduplication routes."""

from __future__ import annotations

import pytest

from lyrashield.artifacts.dedupe import resolve_dedupe_model
from lyrashield.policy.models import StrixProvider
from lyrashield.policy.settings import DedupeSettings, LlmSettings, Settings


@pytest.mark.parametrize(
    "route",
    [
        "anthropic/claude-sonnet-4-5",
        "openai/gpt-4o-mini",
        "chatgpt/gpt-6-luna",
    ],
)
def test_dedupe_rejects_unmetered_or_unapproved_model_routes(route: str) -> None:
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model="openai/gpt-6-sol",
            api_key="main-key",
            api_base="https://main.example/v1",
        ),
    )
    dedupe = DedupeSettings(
        _env_file=None,
        model=route,
        api_key="dedupe-key",
        api_base="https://dedupe.example/v1",
    )

    with pytest.raises(RuntimeError, match="metered OpenAI or Azure/Azure AI GPT-6"):
        resolve_dedupe_model(dedupe, route, settings=settings)


def test_unconfigured_dedupe_keeps_the_main_chatgpt_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="chatgpt/gpt-6-luna"),
    )
    expected_model = object()
    selected: list[str | None] = []

    def get_model(_provider: StrixProvider, model_name: str | None) -> object:
        selected.append(model_name)
        return expected_model

    monkeypatch.setattr(StrixProvider, "get_model", get_model)

    result = resolve_dedupe_model(DedupeSettings(_env_file=None), "chatgpt/gpt-6-luna", settings)

    assert result is expected_model
    assert selected == ["chatgpt/gpt-6-luna"]
