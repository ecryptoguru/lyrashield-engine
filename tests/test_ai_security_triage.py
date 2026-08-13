from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from lyrashield.lifecycle.hooks import BudgetExceededError
from lyrashield.triage import service
from lyrashield.triage.cli import run_triage_cli


if TYPE_CHECKING:
    from pathlib import Path


def _input(*, candidates: int = 1) -> service.TriageInput:
    return service.TriageInput.model_validate(
        {
            "schemaVersion": service.TRIAGE_INPUT_SCHEMA_VERSION,
            "commitSha": "a" * 40,
            "detectorVersion": "detector/1",
            "ruleVersion": "rules/1",
            "candidates": [
                {
                    "findingIdentity": "b" * 64,
                    "controlId": "AI-01",
                    "ruleId": "unsafe-log",
                    "severity": "MEDIUM",
                    "selectionReason": "MEDIUM_CONFIDENCE",
                    "evidenceChecksum": "b" * 64,
                    "evidenceExcerpt": "token=keep-secret email@example.com https://private.example/a",
                }
                for index in range(candidates)
            ],
        }
    )


@pytest.mark.asyncio
async def test_disabled_triage_is_additive_and_redacted() -> None:
    artifact = await service.run_triage(
        _input(), model_route="azure_ai/gpt-5.6-luna", enabled=False
    )

    assert artifact["status"] == "DISABLED"
    assert artifact["terminalReason"] == "TRIAGE_DISABLED"
    assert artifact["results"] == []
    assert artifact["redactionReceipt"]["redactedFieldCounts"]


@pytest.mark.asyncio
async def test_triage_accepts_only_structured_additive_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts: list[str] = []

    async def fake_request(**kwargs: object) -> tuple[service.TriageJudgement, object]:
        prompts.append(str(kwargs["prompt"]))
        return (
            service.TriageJudgement(
                disposition="NEEDS_REVIEW", confidence=0.7, explanation="Bounded review needed"
            ),
            SimpleNamespace(usage=None),
        )

    monkeypatch.setattr(service, "_request_judgement", fake_request)
    artifact = await service.run_triage(
        _input(), model_route="azure_ai/gpt-5.6-luna", enabled=True, model=SimpleNamespace()
    )

    assert artifact["status"] == "COMPLETED"
    assert artifact["results"] == [
        {
            "findingIdentity": "b" * 64,
            "disposition": "NEEDS_REVIEW",
            "confidence": 0.7,
            "explanation": "Bounded review needed",
            "evidenceChecksum": "b" * 64,
        }
    ]
    assert "keep-secret" not in prompts[0]
    assert "private.example" not in prompts[0]


@pytest.mark.asyncio
async def test_budget_stop_never_changes_deterministic_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exhausted(**_kwargs: object) -> tuple[service.TriageJudgement, object]:
        raise BudgetExceededError("cap")

    monkeypatch.setattr(service, "_request_judgement", exhausted)
    artifact = await service.run_triage(
        _input(), model_route="azure_ai/gpt-5.6-luna", enabled=True, model=SimpleNamespace()
    )

    assert artifact["status"] == "BUDGET_STOPPED"
    assert artifact["terminalReason"] == "TRIAGE_BUDGET_EXHAUSTED"
    assert artifact["results"] == []


@pytest.mark.asyncio
async def test_triage_never_exceeds_two_simultaneous_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    active = 0
    peak = 0

    async def bounded(**_kwargs: object) -> tuple[service.TriageJudgement, object]:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
        return (
            service.TriageJudgement(
                disposition="LIKELY_VALID",
                confidence=0.8,
                explanation="Bounded evidence supports it",
            ),
            SimpleNamespace(usage=None),
        )

    monkeypatch.setattr(service, "_request_judgement", bounded)
    artifact = await service.run_triage(
        _input(candidates=3),
        model_route="azure_ai/gpt-5.6-luna",
        enabled=True,
        model=SimpleNamespace(),
    )

    assert artifact["status"] == "COMPLETED"
    assert peak == 2


def test_cli_writes_disabled_artifact_without_a_model(tmp_path: Path) -> None:
    workspace = tmp_path
    input_path = workspace / "candidates.json"
    output_path = workspace / "ai-security-triage.json"
    input_path.write_text(
        json.dumps(_input().model_dump(mode="json", by_alias=True)), encoding="utf-8"
    )

    assert run_triage_cli(["--input", str(input_path), "--output", str(output_path)]) == 0
    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    assert artifact["status"] == "DISABLED"
    assert artifact["results"] == []
