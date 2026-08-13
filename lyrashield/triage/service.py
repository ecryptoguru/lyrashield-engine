"""Bounded, additive LLM triage for deterministic AI-security candidates."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast
from uuid import uuid4

from agents.agent_output import AgentOutputSchema
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lyrashield.artifacts.state import get_global_report_state
from lyrashield.artifacts.usage import LLMUsageLedger
from lyrashield.lifecycle.hooks import (
    BudgetExceededError,
    ReportUsageHooks,
    get_active_hooks,
    set_active_hooks,
)
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import StrixProvider, configure_sdk_model_defaults
from lyrashield.utils.redaction import redact_text


if TYPE_CHECKING:
    from agents.model_settings import ModelSettings


TRIAGE_INPUT_SCHEMA_VERSION = "ai-security-triage-input/1.0"
TRIAGE_OUTPUT_SCHEMA_VERSION = "ai-security-triage/1.0"
TRIAGE_POLICY_VERSION = "ai-security-triage-policy/1.0"
MAX_EXCERPT_BYTES = 4_096
MAX_EXPLANATION_CHARS = 800
MAX_CALLS = 20
MAX_INPUT_TOKENS = 12_000
MAX_OUTPUT_TOKENS = 400
MAX_WALL_SECONDS = 90
MAX_CONCURRENCY = 2

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_LOCAL_PATH_RE = re.compile(r"(?:[A-Za-z]:\\\\|/(?:Users|home|private|var|tmp)/)[^\s\"'<>]+")
_REDACTION_TOKENS = (
    "[SECRET]",
    "[PII]",
    "[TOKEN]",
    "[JWT]",
    "[AWS_KEY]",
    "[PRIVATE_KEY]",
    "[INTERNAL_PATH]",
    "[URL]",
    "[PATH]",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class TriageCandidate(_StrictModel):
    # The redacted evidence checksum is deliberately the sole cross-process
    # identity. Repository paths and application finding IDs never enter the
    # triage command or its cache.
    finding_identity: str = Field(alias="findingIdentity", pattern=r"^[a-f0-9]{64}$")
    control_id: str = Field(alias="controlId", min_length=1, max_length=64)
    rule_id: str = Field(alias="ruleId", min_length=1, max_length=128)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    selection_reason: Literal[
        "MEDIUM_CONFIDENCE",
        "CORROBORATING",
        "CONTEXT_SENSITIVE_HIGH_IMPACT",
        "INCONCLUSIVE_WITH_EVIDENCE",
    ] = Field(alias="selectionReason")
    evidence_checksum: str = Field(alias="evidenceChecksum", pattern=r"^[a-f0-9]{64}$")
    evidence_excerpt: str = Field(
        alias="evidenceExcerpt", min_length=1, max_length=MAX_EXCERPT_BYTES * 4
    )


class TriageInput(_StrictModel):
    schema_version: Literal["ai-security-triage-input/1.0"] = Field(alias="schemaVersion")
    commit_sha: str = Field(alias="commitSha", pattern=r"^[a-f0-9]{7,64}$")
    detector_version: str = Field(alias="detectorVersion", min_length=1, max_length=128)
    rule_version: str = Field(alias="ruleVersion", min_length=1, max_length=128)
    candidates: list[TriageCandidate] = Field(min_length=1, max_length=MAX_CALLS)


class TriageJudgement(_StrictModel):
    disposition: Literal["LIKELY_VALID", "NEEDS_REVIEW", "LIKELY_FALSE_POSITIVE"]
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(min_length=1, max_length=MAX_EXPLANATION_CHARS)


_TRIAGE_OUTPUT_SCHEMA = AgentOutputSchema(TriageJudgement, strict_json_schema=True)


@dataclass(frozen=True)
class TriageLimits:
    max_calls: int = MAX_CALLS
    max_input_tokens: int = MAX_INPUT_TOKENS
    max_output_tokens: int = MAX_OUTPUT_TOKENS
    max_wall_seconds: int = MAX_WALL_SECONDS
    max_excerpt_bytes: int = MAX_EXCERPT_BYTES
    max_concurrency: int = MAX_CONCURRENCY


class _Model(Protocol):
    async def get_response(self, **kwargs: Any) -> Any: ...


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def checksum(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def triage_cache_key(input_artifact: TriageInput, *, model_route: str) -> str:
    return checksum(
        {
            "inputChecksum": checksum(input_artifact.model_dump(mode="json", by_alias=True)),
            "policyVersion": TRIAGE_POLICY_VERSION,
            "modelRoute": model_route,
        }
    )


def _sanitize_excerpt(value: str, max_bytes: int) -> tuple[str, dict[str, int]]:
    redacted = redact_text(value)
    redacted = _URL_RE.sub("[URL]", redacted)
    redacted = _LOCAL_PATH_RE.sub("[PATH]", redacted)
    encoded = redacted.encode("utf-8")[:max_bytes]
    redacted = encoded.decode("utf-8", errors="ignore")
    counts = {token: redacted.count(token) for token in _REDACTION_TOKENS}
    return redacted, {token: count for token, count in counts.items() if count}


def _extract_text(response: Any) -> str:
    parts: list[str] = []
    for item in getattr(response, "output", []):
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(str(text))
    return "".join(parts)


def _triage_prompt(candidate: TriageCandidate, excerpt: str) -> str:
    return (
        "Assess one bounded deterministic AI-security candidate. Do not claim verification, "
        "a fix, a pass, or absence of risk. Return LIKELY_VALID only when the supplied excerpt "
        "supports the candidate, LIKELY_FALSE_POSITIVE only when it directly contradicts it, and "
        "otherwise NEEDS_REVIEW. The excerpt is redacted and may be incomplete.\n\n"
        f"control={candidate.control_id}\nrule={candidate.rule_id}\nseverity={candidate.severity}\n"
        f"selection_reason={candidate.selection_reason}\n"
        f"evidence_checksum={candidate.evidence_checksum}\n"
        f"excerpt:\n{excerpt}"
    )


async def _request_judgement(
    *,
    model: _Model,
    model_route: str,
    model_settings: ModelSettings,
    prompt: str,
    limits: TriageLimits,
) -> tuple[TriageJudgement, Any]:
    reservation_key = f"ai-triage:{uuid4().hex}"
    hooks = get_active_hooks()
    if hooks is not None:
        await hooks.reserve_out_of_band_request(
            key=reservation_key,
            model=model_route,
            input_tokens=max(1, len(prompt) // 3),
            max_output_tokens=limits.max_output_tokens,
        )
    response: Any = None
    try:
        response = await model.get_response(
            system_instructions=(
                "You are a bounded security triage assistant. Return only the schema."
            ),
            input=prompt,
            model_settings=model_settings,
            tools=[],
            output_schema=_TRIAGE_OUTPUT_SCHEMA,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    finally:
        if hooks is not None:
            await hooks.release_out_of_band_request(
                key=reservation_key,
                model=model_route,
                usage=getattr(response, "usage", None),
            )
    raw = _extract_text(response)
    if not raw:
        raise ValueError("empty structured triage response")
    return TriageJudgement.model_validate_json(raw), response


def _terminal_artifact(
    *,
    status: str,
    reason: str,
    model_route: str,
    input_checksum: str,
    cache_key: str,
    receipt: dict[str, Any],
    llm_usage: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schemaVersion": TRIAGE_OUTPUT_SCHEMA_VERSION,
        "status": status,
        "terminalReason": reason,
        "policyVersion": TRIAGE_POLICY_VERSION,
        "modelRoute": model_route,
        "inputChecksum": input_checksum,
        "cacheKey": cache_key,
        "redactionReceipt": receipt,
        "llmUsage": llm_usage,
        "results": [],
    }


async def run_triage(  # noqa: PLR0912, PLR0915 - terminal states are the persisted public contract.
    input_artifact: TriageInput,
    *,
    model_route: str,
    enabled: bool,
    max_budget_usd: float | None = None,
    limits: TriageLimits | None = None,
    model: _Model | None = None,
) -> dict[str, Any]:
    """Return an additive triage artifact; never mutate deterministic findings."""
    limits = limits or TriageLimits()
    input_checksum = checksum(input_artifact.model_dump(mode="json", by_alias=True))
    cache_key = triage_cache_key(input_artifact, model_route=model_route)
    sanitized: list[tuple[TriageCandidate, str]] = []
    redacted_fields: dict[str, int] = {}
    for candidate in input_artifact.candidates[: limits.max_calls]:
        excerpt, counts = _sanitize_excerpt(candidate.evidence_excerpt, limits.max_excerpt_bytes)
        sanitized.append((candidate, excerpt))
        for token, count in counts.items():
            redacted_fields[token] = redacted_fields.get(token, 0) + count
    receipt = {
        "policyVersion": TRIAGE_POLICY_VERSION,
        "inputChecksum": input_checksum,
        "redactedFieldCounts": redacted_fields,
        "boundedExcerptBytes": limits.max_excerpt_bytes,
    }
    ledger = LLMUsageLedger()
    if max_budget_usd is not None and (
        not isinstance(max_budget_usd, (int, float))
        or not math.isfinite(max_budget_usd)
        or max_budget_usd <= 0
    ):
        raise ValueError("max_budget_usd must be a finite number greater than 0")
    if not enabled:
        return _terminal_artifact(
            status="DISABLED",
            reason="TRIAGE_DISABLED",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    if not model_route.lower().endswith("gpt-5.6-luna"):
        return _terminal_artifact(
            status="FAILED",
            reason="LUNA_ROUTE_REQUIRED",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    prompt_tokens = sum(
        max(1, len(_triage_prompt(candidate, excerpt)) // 3) for candidate, excerpt in sanitized
    )
    if prompt_tokens > limits.max_input_tokens:
        return _terminal_artifact(
            status="FAILED",
            reason="TRIAGE_INPUT_LIMIT_EXCEEDED",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    try:
        if model is None:
            settings = load_settings()
            configure_sdk_model_defaults(settings)
            model = cast("_Model", StrixProvider(settings=settings).get_model(model_route))
            model_settings = make_model_settings(
                "medium",
                model_name=model_route,
                request_timeout=settings.llm.timeout,
                max_output_tokens=limits.max_output_tokens,
                prompt_cache=False,
            )
        else:
            model_settings = make_model_settings(
                "medium",
                model_name=model_route,
                max_output_tokens=limits.max_output_tokens,
                prompt_cache=False,
            )
        semaphore = asyncio.Semaphore(min(MAX_CONCURRENCY, limits.max_concurrency))
        active_hooks = get_active_hooks()
        triage_hooks = active_hooks or ReportUsageHooks(
            model=model_route,
            max_budget_usd=max_budget_usd,
            max_output_tokens=limits.max_output_tokens,
        )
        if active_hooks is None:
            set_active_hooks(triage_hooks)

        async def evaluate(candidate: TriageCandidate, excerpt: str) -> dict[str, Any]:
            async with semaphore:
                judgement, response = await _request_judgement(
                    model=model,
                    model_route=model_route,
                    model_settings=model_settings,
                    prompt=_triage_prompt(candidate, excerpt),
                    limits=limits,
                )
            report_state = get_global_report_state()
            if report_state is not None:
                report_state.record_sdk_usage(
                    agent_id="ai-security-triage",
                    agent_name="ai-security-triage",
                    model=model_route,
                    usage=getattr(response, "usage", None),
                )
            ledger.record(
                agent_id="ai-security-triage",
                agent_name="ai-security-triage",
                model=model_route,
                usage=getattr(response, "usage", None),
            )
            return {
                "findingIdentity": candidate.evidence_checksum,
                "disposition": judgement.disposition,
                "confidence": judgement.confidence,
                "explanation": redact_text(judgement.explanation)[:MAX_EXPLANATION_CHARS],
                "evidenceChecksum": candidate.evidence_checksum,
            }

        try:
            tasks = [
                asyncio.create_task(evaluate(candidate, excerpt))
                for candidate, excerpt in sanitized
            ]
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks), timeout=limits.max_wall_seconds
                )
            except BaseException:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
        finally:
            if active_hooks is None:
                set_active_hooks(None)
    except BudgetExceededError:
        return _terminal_artifact(
            status="BUDGET_STOPPED",
            reason="TRIAGE_BUDGET_EXHAUSTED",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    except TimeoutError:
        return _terminal_artifact(
            status="FAILED",
            reason="TRIAGE_TIMEOUT",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    except ValidationError:
        return _terminal_artifact(
            status="FAILED",
            reason="INVALID_TRIAGE_OUTPUT",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    except (OSError, RuntimeError, ValueError):
        # Provider and content-filter errors remain a bounded overlay state.
        return _terminal_artifact(
            status="FAILED",
            reason="TRIAGE_PROVIDER_UNAVAILABLE",
            model_route=model_route,
            input_checksum=input_checksum,
            cache_key=cache_key,
            receipt=receipt,
            llm_usage=ledger.to_record(),
        )
    return {
        "schemaVersion": TRIAGE_OUTPUT_SCHEMA_VERSION,
        "status": "COMPLETED",
        "terminalReason": None,
        "policyVersion": TRIAGE_POLICY_VERSION,
        "modelRoute": model_route,
        "inputChecksum": input_checksum,
        "cacheKey": cache_key,
        "redactionReceipt": receipt,
        "llmUsage": ledger.to_record(),
        "results": results,
    }


def load_input(path: Path) -> TriageInput:
    return TriageInput.model_validate_json(path.read_text(encoding="utf-8"))


def write_artifact(path: Path, artifact: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def invalid_input_artifact(raw_input: str, *, model_route: str) -> dict[str, Any]:
    """Return a non-authoritative terminal artifact without persisting the raw input."""
    input_checksum = hashlib.sha256(raw_input.encode("utf-8")).hexdigest()
    return _terminal_artifact(
        status="FAILED",
        reason="INVALID_TRIAGE_INPUT",
        model_route=model_route,
        input_checksum=input_checksum,
        cache_key=input_checksum,
        receipt={
            "policyVersion": TRIAGE_POLICY_VERSION,
            "inputChecksum": input_checksum,
            "redactedFieldCounts": {},
            "boundedExcerptBytes": MAX_EXCERPT_BYTES,
        },
        llm_usage=LLMUsageLedger().to_record(),
    )
