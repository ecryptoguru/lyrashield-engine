"""Regression coverage for provider capability gates without a live endpoint."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from strix import provider_contract
from strix.config.settings import LlmSettings, Settings


class _FakeModel:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    async def get_response(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _settings() -> Settings:
    return Settings(
        llm=LlmSettings(
            model="azure_ai/gpt-5.6-terra",
            api_base="https://example.services.ai.azure.com",
            api_key="test-key",
            timeout=5,
        )
    )


def _use_fake_model(monkeypatch: pytest.MonkeyPatch, fake: _FakeModel) -> None:
    monkeypatch.setattr(provider_contract, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        provider_contract.StrixProvider,
        "get_model",
        lambda _self, _name: fake,
    )


@pytest.mark.asyncio
async def test_probe_reports_supported_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeModel(
        [
            SimpleNamespace(response_id="resp_1", output=[{"type": "message"}]),
            SimpleNamespace(response_id="resp_2", output=[{"type": "program"}]),
            SimpleNamespace(response_id="resp_3", output=[{"type": "message"}]),
        ]
    )
    _use_fake_model(monkeypatch, fake)

    result = await provider_contract.probe_provider_contract(_settings())

    assert result.baseline.supported
    assert result.programmatic_tool_calling.supported
    assert result.previous_response_id.supported
    assert fake.calls[1]["tools"][1].__class__.__name__ == "ProgrammaticToolCallingTool"
    assert fake.calls[2]["previous_response_id"] == "resp_1"
    assert result.meets_requirements(
        require_programmatic_tool_calling=True,
        require_previous_response_id=True,
    )


@pytest.mark.asyncio
async def test_probe_fails_closed_when_programmatic_tool_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeModel(
        [
            SimpleNamespace(response_id="resp_1", output=[{"type": "message"}]),
            ValueError("provider returned a sensitive response body"),
            SimpleNamespace(response_id="resp_2", output=[{"type": "message"}]),
        ]
    )
    _use_fake_model(monkeypatch, fake)

    result = await provider_contract.probe_provider_contract(_settings())

    assert not result.programmatic_tool_calling.supported
    assert result.programmatic_tool_calling.error == "ValueError"
    assert result.previous_response_id.supported
    assert not result.meets_requirements(
        require_programmatic_tool_calling=True,
        require_previous_response_id=False,
    )


@pytest.mark.asyncio
async def test_probe_skips_dependents_when_baseline_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeModel([RuntimeError("raw endpoint data")])
    _use_fake_model(monkeypatch, fake)

    result = await provider_contract.probe_provider_contract(_settings())

    assert not result.baseline.supported
    assert result.baseline.error == "RuntimeError"
    assert result.programmatic_tool_calling.error == "baseline_unavailable"
    assert result.previous_response_id.error == "baseline_unavailable"
