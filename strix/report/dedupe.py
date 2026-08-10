# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK-native vulnerability-report deduplication."""

from __future__ import annotations

import json
import logging
import math
import re
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from agents.agent_output import AgentOutputSchema
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage
from pydantic import BaseModel, Field, ValidationError

from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import (
    StrixProvider,
    configure_sdk_model_defaults,
)
from strix.core.inputs import make_model_settings
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents.items import ModelResponse

    from lyrashield.policy.settings import DedupeSettings, Settings


logger = logging.getLogger(__name__)


def dedupe_extra_args(dedupe: DedupeSettings) -> dict[str, str]:
    """Per-call credential + endpoint for the dedupe model.

    Provider env vars and the global base URL are process-wide, so a
    shared-provider dedupe key or a distinct dedupe endpoint can't be installed
    globally without clobbering (or being clobbered by) the main model's
    config. Passing them per call keeps the two apart. Only applies when a
    dedicated dedupe model is configured.
    """
    if not dedupe.model:
        return {}
    extra: dict[str, str] = {}
    if dedupe.api_key and dedupe.api_key.strip():
        extra["api_key"] = dedupe.api_key.strip()
    if dedupe.api_base and dedupe.api_base.strip():
        extra["api_base"] = dedupe.api_base.strip()
    return extra


def _dedupe_model_settings(
    dedupe: DedupeSettings,
    model_name: str,
    request_timeout: float | None,
    settings: Settings | None = None,
) -> ModelSettings:
    llm = settings.llm if settings is not None else load_settings().llm
    model_settings = make_model_settings(
        dedupe.reasoning_effort,
        model_name=model_name,
        force_required_tool_choice=False,
        request_timeout=request_timeout,
        # The main model's headers apply only when dedupe falls back to the main
        # model; a dedicated dedupe model may route to another provider, which
        # must never receive the main endpoint's credentials. A dedicated model
        # gets its own DEDUPE_LLM_EXTRA_HEADERS instead.
        extra_headers=dedupe.extra_headers if dedupe.model else llm.extra_headers,
    )
    extra = dedupe_extra_args(dedupe)
    if extra:
        model_settings = model_settings.resolve(ModelSettings(extra_args=extra))
    return model_settings


DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

4. DEPENDENCY-CVE reports use package identity:
   - Same CVE and same package/ecosystem is a duplicate
   - Same CVE but different package/ecosystem is NOT a duplicate
   - Same package/ecosystem but different CVE is NOT a duplicate

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

Respond with a single JSON object and nothing else:

{
  "is_duplicate": true,
  "duplicate_id": "vuln-0001",
  "confidence": 0.95,
  "reason": "Both reports describe SQL injection in /api/login via the username parameter"
}

Or, if not a duplicate:

{
  "is_duplicate": false,
  "duplicate_id": "",
  "confidence": 0.90,
  "reason": "Different endpoints: candidate is /api/search, existing is /api/login"
}

Rules:
- ``is_duplicate`` is a boolean.
- ``duplicate_id`` is the exact id from existing reports, or "" if not a duplicate.
- ``confidence`` is a number between 0 and 1.
- ``reason`` is a specific explanation mentioning endpoint/parameter/root cause.
- Output ONLY the JSON object — no surrounding prose, no code fences."""


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    relevant_fields = [
        "id",
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "endpoint",
        "method",
        "cve",
        "dependency_metadata",
    ]

    cleaned: dict[str, Any] = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


# Upper bound on the serialized existing-report payload sent to the dedupe
# model. Per-report fields are already truncated at 8k chars, but the report
# COUNT is unbounded — every new finding compares against all prior ones, so a
# long scan's dedupe calls would otherwise grow without limit (and each token is
# metered). ~200k chars keeps the request well under the long-context pricing
# boundary while fitting hundreds of typical reports.
_MAX_EXISTING_REPORTS_CHARS = 200_000

_TRUNCATION_MARKER = "...[truncated]"

# Per-item cost of the enclosing JSON list: the separator plus the indentation
# the encoder adds to each nested line. Small and deliberately generous — the
# budget must never be under-counted.
_PER_ITEM_ENCODING_OVERHEAD = 8

# Output allowance reserved for a dedupe reply. The response is a small fixed
# JSON object, so this is deliberately generous rather than tuned.
_DEDUPE_MAX_OUTPUT_TOKENS = 512


class DedupeJudgement(BaseModel):
    """Enforced response schema for the LLM deduplication judge.

    The model is asked to return only this object; ``AgentOutputSchema`` turns
    the definition into a provider-level ``response_format`` so the output is
    constrained to these fields and no surrounding prose.
    """

    is_duplicate: bool
    duplicate_id: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""


_DEDUPE_OUTPUT_SCHEMA: AgentOutputSchema = AgentOutputSchema(
    DedupeJudgement,
    strict_json_schema=True,
)

# Conservative chars-per-token ratio for sizing the reservation. Under-counting
# would let the reservation understate real spend, so round pessimistically.
_CHARS_PER_TOKEN = 3.5


def _estimate_reservation_tokens(*parts: str) -> int:
    """Rough upper-bound token count for the reservation.

    The exact count is only known after the provider responds; the reservation
    just needs to be a safe over-estimate that is released immediately after.
    """
    return max(1, math.ceil(sum(len(part) for part in parts) / _CHARS_PER_TOKEN))


async def _request_dedupe_judgement(
    *,
    model: Any,
    model_name: str,
    model_settings: ModelSettings,
    user_msg: str,
) -> ModelResponse:
    """Run the dedupe model call under a scan-budget reservation.

    This call is metered but does not flow through the agent run hooks, so it
    reserves explicitly. Without a reservation, dedupe traffic is only counted
    after the fact and a scan can overshoot ``max_budget_usd``.
    """
    # Lazy import: strix.core.hooks imports strix.report.state, so a
    # module-level import here would close a cycle.
    from lyrashield.lifecycle.hooks import get_active_hooks

    hooks = get_active_hooks()
    reservation_key = f"dedupe:{uuid4().hex}"
    if hooks is not None:
        await hooks.reserve_out_of_band_request(
            key=reservation_key,
            model=model_name,
            input_tokens=_estimate_reservation_tokens(DEDUPE_SYSTEM_PROMPT, user_msg),
            max_output_tokens=_DEDUPE_MAX_OUTPUT_TOKENS,
        )
    response: ModelResponse | None = None
    try:
        response = await model.get_response(
            system_instructions=DEDUPE_SYSTEM_PROMPT,
            input=user_msg,
            model_settings=model_settings,
            tools=[],
            output_schema=_DEDUPE_OUTPUT_SCHEMA,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    finally:
        # Always release: a failed request must not strand its reservation and
        # shrink the remaining budget for the rest of the scan.
        if hooks is not None:
            await hooks.release_out_of_band_request(
                key=reservation_key,
                model=model_name,
                usage=response.usage if response is not None else None,
            )
    if response is None:
        raise RuntimeError("Dedupe model call did not return a response")
    return response


def _truncate_report_to_budget(report: dict[str, Any], budget: int) -> dict[str, Any] | None:
    """Shrink one report's longest text fields until it encodes within ``budget``.

    Applies to a single report large enough to blow the whole budget on its own.
    Identity fields (``id``, ``target``, ``endpoint``, ``method``) are never
    truncated — they are what the model compares on — so a report is dropped
    outright if even those exceed the budget.
    """
    identity_fields = {"id", "target", "endpoint", "method"}
    trimmed = dict(report)
    while _encoded_size(trimmed) > budget:
        longest = max(
            (f for f in trimmed if f not in identity_fields and isinstance(trimmed[f], str)),
            key=lambda f: len(trimmed[f]),
            default=None,
        )
        if longest is None:
            return None
        excess = _encoded_size(trimmed) - budget
        keep = len(trimmed[longest]) - excess - len(_TRUNCATION_MARKER)
        if keep <= 0:
            del trimmed[longest]
        else:
            trimmed[longest] = trimmed[longest][:keep] + _TRUNCATION_MARKER
    return trimmed


def _encoded_size(report: dict[str, Any]) -> int:
    """Encoded length of one report as it appears in the transmitted payload.

    Matches ``json.dumps(..., indent=2)`` at the call site: indentation and the
    enclosing list's separators are what actually reach the model, so a compact
    estimate would under-count and let the payload exceed the cap.
    """
    return len(json.dumps(report, indent=2)) + _PER_ITEM_ENCODING_OVERHEAD


def _bound_existing_reports(cleaned: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the most recent cleaned reports within the payload budget.

    Newest-first retention: a fresh candidate most often duplicates a recent
    finding from the same testing phase, and deterministic identity checks have
    already run against the full report list before the LLM is consulted.

    The budget is a hard limit on the encoded payload. A newest report that
    exceeds it alone is truncated rather than passed through, so a single
    oversized finding cannot defeat the cost guard.
    """
    total = 0
    kept_reversed: list[dict[str, Any]] = []
    for report in reversed(cleaned):
        size = _encoded_size(report)
        if total + size > _MAX_EXISTING_REPORTS_CHARS:
            if kept_reversed:
                break
            truncated = _truncate_report_to_budget(report, _MAX_EXISTING_REPORTS_CHARS)
            if truncated is None:
                break
            kept_reversed.append(truncated)
            logger.info("Dedupe comparison payload bounded: truncated an oversized report")
            break
        total += size
        kept_reversed.append(report)
    if len(kept_reversed) < len(cleaned):
        logger.info(
            "Dedupe comparison payload bounded: keeping %d of %d existing reports",
            len(kept_reversed),
            len(cleaned),
        )
    return list(reversed(kept_reversed))


def _dependency_identity(report: dict[str, Any]) -> tuple[str, str, str] | None:
    metadata = report.get("dependency_metadata")
    if not isinstance(metadata, dict):
        return None
    metadata = cast("dict[str, Any]", metadata)

    raw_cve = report.get("cve")
    raw_package = metadata.get("package_name")
    if not raw_cve or not raw_package:
        return None

    cve = str(raw_cve).strip().upper()
    ecosystem = str(metadata.get("package_ecosystem") or "").strip().lower()
    package_name = str(raw_package).strip().lower()
    if not cve or not package_name:
        return None
    return cve, ecosystem, package_name


def _report_cve(report: dict[str, Any]) -> str:
    return str(report.get("cve") or "").strip().upper()


def _legacy_report_mentions_package(
    report: dict[str, Any],
    *,
    ecosystem: str,
    package_name: str,
) -> bool:
    fields = [
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "evidence",
    ]
    haystack = " ".join(str(report.get(field) or "") for field in fields).lower()
    package_pattern = rf"(?<![\w@./-]){re.escape(package_name)}(?![\w@./-])"
    if re.search(package_pattern, haystack) is None:
        return False
    if not ecosystem:
        return True
    ecosystem_pattern = rf"(?<![\w@./-]){re.escape(ecosystem)}(?![\w@./-])"
    return re.search(ecosystem_pattern, haystack) is not None


def _check_dependency_duplicate(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    candidate_identity = _dependency_identity(candidate)
    if candidate_identity is None:
        return None

    cve, ecosystem, package_name = candidate_identity
    found_legacy_same_cve = False
    for report in existing_reports:
        report_identity = _dependency_identity(report)
        if report_identity is not None:
            report_cve, report_ecosystem, report_package_name = report_identity
            if (report_cve, report_package_name) != (cve, package_name):
                continue
            if report_ecosystem == ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity",
                }
            if not report_ecosystem or not ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity with missing ecosystem",
                }
            continue

        if _report_cve(report) != cve:
            continue
        found_legacy_same_cve = True
        if _legacy_report_mentions_package(
            report,
            ecosystem=ecosystem,
            package_name=package_name,
        ):
            return {
                "is_duplicate": True,
                "duplicate_id": str(report.get("id") or "")[:64],
                "confidence": 1.0,
                "reason": "Same dependency CVE/package identity in legacy report",
            }

    if found_legacy_same_cve:
        return None

    package_label = f"{ecosystem}/{package_name}" if ecosystem else package_name
    return {
        "is_duplicate": False,
        "duplicate_id": "",
        "confidence": 1.0,
        "reason": f"No existing dependency report for {cve} in {package_label}",
    }


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").lower().split())


def _dynamic_identity(report: dict[str, Any]) -> tuple[str, ...] | None:
    locations = report.get("code_locations")
    primary_location = ""
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        first = cast("dict[str, Any]", locations[0])
        primary_location = ":".join(
            [
                _normalized_text(first.get("file")),
                str(first.get("start_line") or ""),
                str(first.get("end_line") or ""),
            ]
        )
    endpoint = _normalized_text(report.get("endpoint"))
    target = _normalized_text(report.get("target"))
    if not endpoint and not primary_location:
        return None
    return (
        target,
        endpoint,
        _normalized_text(report.get("method")),
        primary_location,
        _normalized_text(report.get("cwe")),
        _normalized_text(report.get("title")),
    )


def _first_unquoted_brace(text: str) -> int:
    """Return the index of the first '{' that is not inside a JSON string."""
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            return i

    return -1


def _extract_balanced_json(text: str) -> str:
    """Return the first top-level JSON object from text, accounting for nesting."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    start = _first_unquoted_brace(text)
    if start == -1:
        raise ValueError(f"No JSON object found in dedupe response: {text[:500]}")

    brace_depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text[start:], start=start):
        if in_string:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
            if brace_depth == 0:
                return text[start : i + 1]

    raise ValueError(f"No balanced JSON object found in dedupe response: {text[:500]}")


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    """Parse and validate the dedupe model's JSON response.

    First tries strict Pydantic validation against ``DedupeJudgement``. If the
    provider returned malformed or extra-prose output (e.g. during a fallback
    path), fall back to the older lenient parser so the scan isn't blocked.
    """
    json_text = _extract_balanced_json(content)
    try:
        judgement = DedupeJudgement.model_validate_json(json_text)
    except (ValidationError, ValueError):
        logger.warning("Dedupe response failed schema validation; falling back to lenient parser")
        parsed = json.loads(json_text)
        duplicate_id = str(parsed.get("duplicate_id") or "")[:64]
        reason = str(parsed.get("reason") or "")[:500]
        try:
            confidence = float(parsed.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return {
            "is_duplicate": bool(parsed.get("is_duplicate", False)),
            "duplicate_id": duplicate_id,
            "confidence": confidence,
            "reason": reason,
        }
    return {
        "is_duplicate": judgement.is_duplicate,
        "duplicate_id": judgement.duplicate_id[:64],
        "confidence": judgement.confidence,
        "reason": judgement.reason[:500],
    }


def _extract_text(response: ModelResponse) -> str:
    parts: list[str] = []
    for item in response.output:
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(text)
    return "".join(parts)


async def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    dependency_duplicate = _check_dependency_duplicate(candidate, existing_reports)
    if dependency_duplicate is not None:
        return dependency_duplicate

    candidate_identity = _dynamic_identity(candidate)
    if candidate_identity is not None:
        for report in existing_reports:
            if _dynamic_identity(report) == candidate_identity:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Exact target, location, weakness, and title identity",
                }
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No exact deterministic report identity matched",
        }

    try:
        settings = load_settings()
        dedupe = settings.dedupe
        model_name = (dedupe.model or "").strip() or settings.llm.model
        if not model_name:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "No LLM model configured; skipping dedupe check",
            }

        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = _bound_existing_reports(
            [_prepare_report_for_comparison(r) for r in existing_reports]
        )
        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        user_msg = (
            f"Compare this candidate vulnerability against existing reports:\n\n"
            f"{json.dumps(comparison_data, indent=2)}\n\n"
            f"Respond with ONLY the JSON object described in the system prompt."
        )

        configure_sdk_model_defaults(settings)
        resolved_model = model_name.strip()
        dedupe_settings = _dedupe_model_settings(
            dedupe, resolved_model, settings.llm.timeout, settings=settings
        )
        response = await _request_dedupe_judgement(
            model=StrixProvider(settings=settings).get_model(resolved_model),
            model_name=resolved_model,
            model_settings=dedupe_settings,
            user_msg=user_msg,
        )
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.record_sdk_usage(
                agent_id="dedupe",
                agent_name="dedupe",
                model=resolved_model,
                usage=response.usage,
            )
        content = _extract_text(response)
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            "Deduplication check: is_duplicate=%s, confidence=%.2f, reason=%s",
            result["is_duplicate"],
            result["confidence"],
            result["reason"][:100],
        )

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }
    else:
        return result
