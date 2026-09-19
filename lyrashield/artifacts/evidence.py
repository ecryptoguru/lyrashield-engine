# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""run.json schema 1.1 evidence fields, artifact writers, and HTTP evidence export.

This module is the owned home of the richer evidence contract:

- :func:`evidence_v1_1_enabled` gates the whole 1.1 writer surface behind
  ``LYRASHIELD_RUN_RECORD_V1_1`` (default OFF) so compatible readers deploy
  before the engine emits the new fields.
- Finding-field normalizers (``http_exchange_ids``, ``confidence``,
  ``advisory_cvss``, ``fix_verification``) keep the finding schema additive
  and validated.
- :func:`build_coverage_document` / :func:`write_coverage_artifact` emit the
  bounded ``coverage.json`` of model-declared investigation coverage.
- :func:`build_threat_model_document` / :func:`write_threat_model_artifact`
  emit the versioned, scan-bound ``threat_model.json``.
- :func:`export_http_exchange_evidence` writes the durable, redacted,
  checksummed ``http_exchanges.json`` before sandbox teardown. A failed
  export records explicit incomplete evidence — never a verification receipt.
- :func:`build_result_manifest` binds every emitted artifact to the run by
  checksum so the run record is an immutable result manifest.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lyrashield.artifacts.writer import _atomic_write_text
from lyrashield.utils.redaction import is_sensitive_key, redact_text, redact_url
from strix.core.paths import runtime_state_dir


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema versions and the 1.1 writer gate
# ---------------------------------------------------------------------------

RUN_RECORD_SCHEMA_VERSION_1_0 = "1.0"
RUN_RECORD_SCHEMA_VERSION_1_1 = "1.1"
SUPPORTED_RUN_RECORD_SCHEMA_VERSIONS = frozenset(
    {RUN_RECORD_SCHEMA_VERSION_1_0, RUN_RECORD_SCHEMA_VERSION_1_1}
)

# Feature flag for the whole schema-1.1 writer surface: new finding fields,
# update_vulnerability_report, coverage/threat-model artifacts, and the HTTP
# exchange evidence export. Default OFF — readers deploy before writers.
EVIDENCE_V1_1_ENV = "LYRASHIELD_RUN_RECORD_V1_1"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def evidence_v1_1_enabled() -> bool:
    """Return whether the schema-1.1 writer surface is enabled."""
    return os.environ.get(EVIDENCE_V1_1_ENV, "").strip().lower() in _TRUE_VALUES


def run_record_schema_version() -> str:
    """Schema version stamped on a *new* run record.

    A resumed run keeps the version it was created with — the record's own
    ``schema_version`` governs what its artifacts may carry, so a run's
    contract never changes mid-flight.
    """
    if evidence_v1_1_enabled():
        return RUN_RECORD_SCHEMA_VERSION_1_1
    return RUN_RECORD_SCHEMA_VERSION_1_0


def record_supports_evidence_v1_1(run_record: dict[str, Any]) -> bool:
    """True when this record's declared schema version is 1.1."""
    return run_record.get("schema_version") == RUN_RECORD_SCHEMA_VERSION_1_1


# ---------------------------------------------------------------------------
# Finding-field budgets and normalizers (schema 1.1 additions)
# ---------------------------------------------------------------------------

# http_exchange_ids: at most 10 distinct numeric ASCII proxy request ids,
# each at most 128 characters. They are *references* — the durable evidence is
# the exported, checksummed exchange in http_exchanges.json.
MAX_HTTP_EXCHANGE_IDS = 10
MAX_HTTP_EXCHANGE_ID_CHARS = 128

# Bounded append-only revision history per finding.
MAX_UPDATE_HISTORY_ENTRIES = 50
MAX_UPDATE_REASON_CHARS = 500

# Per-field text bounds for the new evidence fields.
MAX_EVIDENCE_FIELD_CHARS = 10_000
MAX_METRIC_REASONING_CHARS = 4_000

VALID_CONFIDENCE = frozenset({"high", "medium", "low"})

# A fix_verification object is an *engine attestation* of what the filing agent
# checked — it is NOT a verification receipt and NOT proof a fix works. The
# ``kind`` marker makes that explicit for every downstream reader.
FIX_VERIFICATION_KIND = "engine_attestation"

# Content a revision may replace. Identity (id, timestamp, finding_class) and
# original authorship (agent_id, agent_name) are creation-time invariants and
# can never be revised. ``dependency_metadata`` is replaced whole.
UPDATABLE_REPORT_FIELDS = frozenset(
    {
        "title",
        "dependency_metadata",
        "severity",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "poc_script_code",
        "remediation_steps",
        "evidence",
        "assumptions",
        "counterevidence",
        "confidence",
        "confidence_rationale",
        "severity_change_conditions",
        "fix_effort",
        "cvss",
        "cvss_breakdown",
        "endpoint",
        "method",
        "cve",
        "cwe",
        "code_locations",
        "http_exchange_ids",
        "fix_verification",
        "fix_pr_body",
        "advisory_cvss",
        "contextual_cvss_reasoning",
        "evidence_warnings",
    }
)

# Fields that only describe another field. A revision may raise a rating or
# replace locations without restating the reasoning behind the old values; the
# stale annotation is dropped rather than left contradicting the finding.
DEPENDENT_REPORT_FIELDS: dict[str, tuple[str, ...]] = {
    "confidence": ("confidence_rationale",),
    "severity": ("severity_change_conditions",),
    "cvss": ("cvss_breakdown",),
    "code_locations": ("fix_verification",),
}

# Fields every finding must still satisfy after a revision — the creation-time
# invariants applied to updates.
_IMMUTABLE_FINDING_FIELDS = frozenset(
    {"id", "timestamp", "finding_class", "agent_id", "agent_name"}
)
_VALID_SEVERITIES = frozenset(
    {"critical", "high", "medium", "low", "info", "informational", "none"}
)


def validate_revised_finding(revised: dict[str, Any], original: dict[str, Any]) -> list[str]:
    """Check a revised finding still satisfies creation-time invariants.

    Identity and authorship cannot move, the title must stay a non-empty
    string, and the severity must stay a known label. Returns a list of
    violations; empty means the revision is structurally valid.
    """
    errors: list[str] = [
        f"revision cannot change creation-time field {field!r}"
        for field in sorted(_IMMUTABLE_FINDING_FIELDS)
        if revised.get(field) != original.get(field)
    ]
    title = revised.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("revision leaves 'title' empty")
    severity = revised.get("severity")
    if not isinstance(severity, str) or severity.lower() not in _VALID_SEVERITIES:
        errors.append(f"revision leaves 'severity' invalid: {severity!r}")
    history = revised.get("update_history")
    if not isinstance(history, list) or len(history) > MAX_UPDATE_HISTORY_ENTRIES:
        errors.append("revision history missing or exceeds its bound")
    return errors


def normalize_http_exchange_ids(raw: Any) -> tuple[list[str] | None, list[str]]:
    """Return distinct proxy exchange ids in their original order.

    ``(None, errors)`` for a malformed value, ``(ids, [])`` for a valid one
    (``[]`` when the caller passed an empty list — an explicit "detach all").
    """
    if raw is None:
        return None, []
    if not isinstance(raw, list):
        return None, ["http_exchange_ids must be a list of proxy request ids"]

    normalized: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        if not isinstance(value, str):
            errors.append(f"http_exchange_ids[{index}] must be a string")
            continue
        request_id = value.strip()
        if not request_id:
            errors.append(f"http_exchange_ids[{index}] cannot be empty")
            continue
        if len(request_id) > MAX_HTTP_EXCHANGE_ID_CHARS:
            errors.append(
                f"http_exchange_ids[{index}] must be {MAX_HTTP_EXCHANGE_ID_CHARS} "
                "characters or fewer"
            )
            continue
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in request_id):
            errors.append(f"http_exchange_ids[{index}] must contain only visible ASCII characters")
            continue
        if not request_id.isdigit():
            errors.append(f"http_exchange_ids[{index}] must be a numeric proxy request id")
            continue
        if request_id not in seen:
            seen.add(request_id)
            normalized.append(request_id)
            if len(normalized) > MAX_HTTP_EXCHANGE_IDS:
                errors.append(
                    f"http_exchange_ids can contain at most "
                    f"{MAX_HTTP_EXCHANGE_IDS} distinct request ids"
                )
                break
    return normalized, errors


_CVSS_VECTOR_RE = re.compile(r"^CVSS:[34]\.\d/([A-Z]{1,3}:[NLHARCUPM]/*)+$")


def normalize_confidence(raw: Any) -> tuple[str | None, list[str]]:
    """Validate an optional confidence label."""
    if raw is None:
        return None, []
    if not isinstance(raw, str):
        return None, ["confidence must be a string"]
    value = raw.strip().lower()
    if value not in VALID_CONFIDENCE:
        return None, [f"Invalid confidence: {raw!r}. Must be one of: {sorted(VALID_CONFIDENCE)}"]
    return value, []


def normalize_advisory_cvss(raw: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Normalize the structured ``advisory_cvss`` evidence object.

    Schema 1.1 carries the advisory score with its vector and metric reasoning,
    not a bare number: ``{score, vector, source, metric_reasoning}``. A bare
    numeric value is accepted and wrapped so older callers stay valid.
    """
    if raw is None:
        return None, []
    if isinstance(raw, bool):
        return None, ["advisory_cvss must be an object or a 0-10 score"]
    if isinstance(raw, int | float):
        if not 0.0 <= float(raw) <= 10.0:
            return None, [f"advisory_cvss score must be between 0.0 and 10.0, got {raw}"]
        return {"score": float(raw)}, []
    if not isinstance(raw, dict):
        return None, ["advisory_cvss must be an object {score, vector, metric_reasoning}"]

    errors: list[str] = []
    result: dict[str, Any] = {}
    score = raw.get("score")
    if isinstance(score, bool) or not isinstance(score, int | float):
        errors.append("advisory_cvss.score is required and must be a number")
    elif not 0.0 <= float(score) <= 10.0:
        errors.append(f"advisory_cvss.score must be between 0.0 and 10.0, got {score}")
    else:
        result["score"] = float(score)

    vector = raw.get("vector")
    if vector is not None:
        if not isinstance(vector, str) or not _CVSS_VECTOR_RE.match(vector.strip()):
            errors.append(
                "advisory_cvss.vector must be a CVSS vector string (e.g. 'CVSS:3.1/AV:N/AC:L/...')"
            )
        else:
            result["vector"] = vector.strip()

    for key in ("source", "metric_reasoning"):
        value = raw.get(key)
        if value is not None:
            if not isinstance(value, str):
                errors.append(f"advisory_cvss.{key} must be a string")
            elif value.strip():
                result[key] = value.strip()[:MAX_METRIC_REASONING_CHARS]
    return (None if errors else result), errors


def normalize_fix_verification(raw: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Normalize ``fix_verification`` into the engine-attested object.

    Accepts a string statement (wrapped) or an object with ``statement``,
    optional ``method`` and bounded ``evidence_refs``. The stored object always
    carries ``kind: engine_attestation`` — the engine attests the filing agent
    ran a check; it is not a verification receipt and not proof of a fix.
    """
    if raw is None:
        return None, []
    if isinstance(raw, str):
        statement = raw.strip()
        if not statement:
            return None, ["fix_verification cannot be an empty string"]
        raw = {"statement": statement}
    if not isinstance(raw, dict):
        return None, ["fix_verification must be an object or a statement string"]

    errors: list[str] = []
    statement_value = raw.get("statement")
    if not isinstance(statement_value, str) or not statement_value.strip():
        errors.append("fix_verification.statement is required and cannot be empty")
    method = raw.get("method")
    if method is not None and not isinstance(method, str):
        errors.append("fix_verification.method must be a string")

    refs = raw.get("evidence_refs")
    normalized_refs: list[str] = []
    if refs is not None:
        if not isinstance(refs, list):
            errors.append("fix_verification.evidence_refs must be a list")
        else:
            for index, value in enumerate(refs[:MAX_HTTP_EXCHANGE_IDS]):
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"fix_verification.evidence_refs[{index}] must be a string")
                    continue
                normalized_refs.append(value.strip()[:MAX_HTTP_EXCHANGE_ID_CHARS])
            if isinstance(refs, list) and len(refs) > MAX_HTTP_EXCHANGE_IDS:
                errors.append(
                    f"fix_verification.evidence_refs is bounded to {MAX_HTTP_EXCHANGE_IDS} entries"
                )

    if errors:
        return None, errors
    result: dict[str, Any] = {
        "kind": FIX_VERIFICATION_KIND,
        "statement": str(statement_value).strip()[:MAX_EVIDENCE_FIELD_CHARS],
    }
    if isinstance(method, str) and method.strip():
        result["method"] = method.strip()[:256]
    if normalized_refs:
        result["evidence_refs"] = normalized_refs
    return result, []


# ---------------------------------------------------------------------------
# coverage.json — model-declared investigation coverage
# ---------------------------------------------------------------------------

COVERAGE_FILENAME = "coverage.json"
COVERAGE_ENTRY_LIMIT = 500
_COVERAGE_EVIDENCE_CHARS = 2_000


def build_coverage_document(
    *,
    run_record: dict[str, Any],
    agent_graph: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    exit_reason: str | None = None,
) -> dict[str, Any]:
    """Assemble the owned ``coverage.json`` document.

    Entries are *model-declared* investigation coverage — an agent's own
    account of what it assessed — kept strictly separate from machine-observed
    facts and deterministic control outcomes. Work that was never selected,
    was blocked, or was truncated stays ``unassessed``: it appears only under
    ``gaps``, never as a coverage claim. The substrate gap/completeness
    analysis is reused unchanged.
    """
    from strix.report.coverage import build_coverage_document as _build_substrate
    from strix.tools.coverage.tools import get_coverage_entries

    entries = get_coverage_entries()
    dropped = 0
    if len(entries) > COVERAGE_ENTRY_LIMIT:
        dropped = len(entries) - COVERAGE_ENTRY_LIMIT
        entries = entries[:COVERAGE_ENTRY_LIMIT]
        logger.warning(
            "coverage entries exceed budget %d; dropping %d",
            COVERAGE_ENTRY_LIMIT,
            dropped,
        )

    document = _build_substrate(
        run_record=run_record,
        entries=entries,
        agent_graph=agent_graph,
        vulnerability_reports=vulnerability_reports,
        exit_reason=exit_reason,
    )

    # Overlay the contract fields the worker consumes: stable id, subject,
    # investigation status, reason, and evidence references on every entry.
    bounded_entries: list[dict[str, Any]] = []
    for raw, rendered in zip(entries, document.get("entries", []), strict=True):
        entry = dict(rendered)
        entry["id"] = str(raw.get("entry_id", ""))
        entry["subject"] = entry.get("surface", "")
        entry["investigation_status"] = entry.get("outcome", "")
        entry["reason"] = str(entry.get("evidence") or "")[:_COVERAGE_EVIDENCE_CHARS]
        refs = raw.get("evidence_refs")
        entry["evidence_refs"] = (
            [str(ref)[:MAX_HTTP_EXCHANGE_ID_CHARS] for ref in refs[:MAX_HTTP_EXCHANGE_IDS]]
            if isinstance(refs, list)
            else []
        )
        entry["source"] = "model_declared"
        bounded_entries.append(entry)
    document["entries"] = bounded_entries
    if dropped:
        document["truncated"] = {"entries_dropped": dropped, "entry_limit": COVERAGE_ENTRY_LIMIT}
    return document


def write_coverage_artifact(run_dir: Path, document: dict[str, Any]) -> Path:
    """Write ``coverage.json`` into the run directory and return its path."""
    path = run_dir / COVERAGE_FILENAME
    _atomic_write_text(path, json.dumps(document, ensure_ascii=False, indent=2, default=str))
    logger.info(
        "Saved coverage record to: %s (%d entries)",
        path,
        len(document.get("entries", [])),
    )
    return path


# ---------------------------------------------------------------------------
# threat_model.json — versioned, scan-bound threat model
# ---------------------------------------------------------------------------

THREAT_MODEL_FILENAME = "threat_model.json"
THREAT_MODEL_SCHEMA = "lyrashield-threat-model/1.0"
THREAT_MODEL_MIRROR = "threat_models.json"
_MAX_MODELS = 20
_MAX_MODEL_CONTENT_CHARS = 64_000
_MAX_AMENDMENTS_PER_MODEL = 40
_MAX_AMENDMENT_CHARS = 8_000


def build_threat_model_document(
    run_dir: Path,
    run_record: dict[str, Any],
) -> dict[str, Any] | None:
    """Assemble the versioned ``threat_model.json`` document, or None.

    Reads the run's threat-model mirror (``.state/threat_models.json``) — the
    store the scan's agents actually wrote. Assets, trust boundaries, entry
    points and assumptions live in the model content; this artifact binds them
    to the scan. A threat model is not proof its attack paths were tested.
    """
    mirror = runtime_state_dir(run_dir) / THREAT_MODEL_MIRROR
    if not mirror.is_file():
        return None
    try:
        data = json.loads(mirror.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("threat model mirror at %s is unreadable", mirror, exc_info=True)
        return {
            "schema_version": THREAT_MODEL_SCHEMA,
            "run_id": run_record.get("run_id"),
            "models": [],
            "error": "threat model mirror unreadable",
        }
    if not isinstance(data, dict):
        return None

    models: list[dict[str, Any]] = []
    truncated = False
    for identity, model in list(data.items())[: _MAX_MODELS + 1]:
        if len(models) >= _MAX_MODELS:
            truncated = True
            break
        if not isinstance(model, dict):
            continue
        content = str(model.get("content") or "")
        amendments = model.get("amendments")
        bounded_amendments: list[dict[str, Any]] = []
        if isinstance(amendments, list):
            for amendment in amendments[:_MAX_AMENDMENTS_PER_MODEL]:
                if not isinstance(amendment, dict):
                    continue
                bounded_amendments.append(
                    {
                        "by": str(amendment.get("by") or ""),
                        "at": str(amendment.get("at") or ""),
                        "content": str(amendment.get("content") or "")[:_MAX_AMENDMENT_CHARS],
                    }
                )
        model_truncated = len(content) > _MAX_MODEL_CONTENT_CHARS or (
            isinstance(amendments, list) and len(amendments) > _MAX_AMENDMENTS_PER_MODEL
        )
        truncated = truncated or model_truncated
        models.append(
            {
                "target": str(model.get("target") or identity),
                "written_at": model.get("written_at"),
                "written_by": model.get("written_by"),
                "content": content[:_MAX_MODEL_CONTENT_CHARS],
                "amendments": bounded_amendments,
            }
        )

    document: dict[str, Any] = {
        "schema_version": THREAT_MODEL_SCHEMA,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "run_id": run_record.get("run_id"),
        "run_name": run_record.get("run_name"),
        "models": models,
        "note": (
            "The threat model records the scan's declared assets, trust "
            "boundaries, entry points and assumptions. It is not proof that "
            "its attack paths were tested."
        ),
    }
    if truncated:
        document["truncated"] = True
    return document


def write_threat_model_artifact(run_dir: Path, document: dict[str, Any]) -> Path:
    """Write ``threat_model.json`` into the run directory and return its path."""
    path = run_dir / THREAT_MODEL_FILENAME
    _atomic_write_text(path, json.dumps(document, ensure_ascii=False, indent=2, default=str))
    logger.info("Saved threat model record to: %s", path)
    return path


# ---------------------------------------------------------------------------
# http_exchanges.json — durable redacted HTTP evidence export
# ---------------------------------------------------------------------------

HTTP_EXCHANGES_FILENAME = "http_exchanges.json"
HTTP_EXCHANGES_SCHEMA = "lyrashield-http-exchanges/1.0"

# Per-artifact budgets: bounded exchange count, bounded body samples, bounded
# total size. Exceeding any limit records truncation rather than writing an
# unbounded artifact.
MAX_EXPORT_EXCHANGES = 64
MAX_EXPORT_BODY_SAMPLE_BYTES = 4096
MAX_EXPORT_TOTAL_BYTES = 1_048_576

# Headers that are always credentials/secret-bearing; never exported.
_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "proxy-authenticate",
        "www-authenticate",
    }
)


def _raw_bytes(raw: bytes | str | None) -> bytes | None:
    """Normalize a Caido ``raw`` payload to bytes."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return bytes(raw)


def _decode_bounded(raw: bytes | str | None, limit: int) -> tuple[str, bool, int]:
    """Decode a body sample under the byte cap. Returns (text, truncated, size)."""
    blob = _raw_bytes(raw)
    if not blob:
        return "", False, 0
    size = len(blob)
    truncated = size > limit
    sample = blob[:limit] if truncated else blob
    return sample.decode("utf-8", errors="replace"), truncated, size


def _body_of(raw: bytes | str | None) -> bytes | None:
    """Return the message body — never the header block.

    Credentials live in headers (Authorization, Cookie, Set-Cookie); sampling
    them as if they were body would leak them past the header redaction.
    """
    blob = _raw_bytes(raw)
    if not blob:
        return None
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in blob:
            return blob.split(sep, 1)[1]
    # No header terminator: treat the payload as body (chunked/streamed).
    return blob


def _parse_headers(raw: bytes | str | None) -> dict[str, str]:
    """Parse HTTP header lines from a raw message head, redacting secrets."""
    headers: dict[str, str] = {}
    blob = _raw_bytes(raw)
    if not blob:
        return headers
    head = blob.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    for line in head.decode("iso-8859-1", errors="replace").splitlines()[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip()
        lowered = key.lower()
        if lowered in _SECRET_HEADERS or is_sensitive_key(key):
            headers[key] = "[REDACTED]"
        else:
            headers[key] = redact_text(value.strip(), include_internal_paths=True)[:512]
    return headers


def _export_one_exchange(request_id: str, result: Any) -> dict[str, Any]:
    """Build one redacted, checksummed exchange entry from a Caido result."""
    request = getattr(result, "request", None)
    response = getattr(result, "response", None)

    entry: dict[str, Any] = {"proxy_request_id": str(request_id)}
    if request is not None:
        req_raw = _raw_bytes(getattr(request, "raw", None))
        query = str(getattr(request, "query", "") or "")
        path = str(getattr(request, "path", "") or "")
        target = f"{path}?{query}" if query else path
        body, body_truncated, body_size = _decode_bounded(
            _body_of(req_raw), MAX_EXPORT_BODY_SAMPLE_BYTES
        )
        entry["request"] = {
            "method": str(getattr(request, "method", "") or ""),
            "host": str(getattr(request, "host", "") or ""),
            "port": getattr(request, "port", None),
            "path": redact_text(path, include_internal_paths=True)[:2048],
            "target": redact_url(target)[:2048],
            "is_tls": bool(getattr(request, "is_tls", False)),
            "created_at": str(getattr(request, "created_at", "") or ""),
            "headers": _parse_headers(req_raw),
            "body_sample": redact_text(body, include_internal_paths=True),
            "body_truncated": body_truncated,
            "body_bytes": body_size,
            "sha256": hashlib.sha256(req_raw).hexdigest() if req_raw else None,
        }
    if response is not None:
        resp_raw = _raw_bytes(getattr(response, "raw", None))
        body, body_truncated, body_size = _decode_bounded(
            _body_of(resp_raw), MAX_EXPORT_BODY_SAMPLE_BYTES
        )
        entry["response"] = {
            "status_code": getattr(response, "status_code", None),
            "length": getattr(response, "length", None),
            "roundtrip_ms": getattr(response, "roundtrip_time", None),
            "created_at": str(getattr(response, "created_at", "") or ""),
            "headers": _parse_headers(resp_raw),
            "body_sample": redact_text(body, include_internal_paths=True),
            "body_truncated": body_truncated,
            "body_bytes": body_size,
            "sha256": hashlib.sha256(resp_raw).hexdigest() if resp_raw else None,
        }
    return entry


async def export_http_exchange_evidence(
    client: Any,
    run_dir: Path,
    *,
    run_record: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Export cited HTTP exchanges as durable redacted evidence.

    Runs before sandbox teardown while the proxy project is still reachable.
    Every exchange a finding cites via ``http_exchange_ids`` is fetched,
    redacted (authorization/cookie/secret material never leaves the proxy),
    checksummed, and bound to the scan, workspace, target and finding
    revision. Opaque proxy request ids stay correlation keys only — the
    durable evidence is the exported content and its digest.

    Returns a status dict the caller persists on the run record:
    ``exported`` / ``skipped`` (nothing cited / no proxy) / ``partial`` /
    ``failed``. A non-exported status is an explicit incomplete-evidence
    marker, never a verification receipt.
    """
    from lyrashield.tools.proxy import caido_api

    cited: dict[str, list[str]] = {}
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        ids = finding.get("http_exchange_ids")
        if not finding_id or not isinstance(ids, list):
            continue
        valid = [str(v) for v in ids if isinstance(v, str) and v.strip()]
        if valid:
            cited[finding_id] = valid[:MAX_HTTP_EXCHANGE_IDS]

    requested_ids: list[str] = []
    for ids in cited.values():
        for request_id in ids:
            if request_id not in requested_ids:
                requested_ids.append(request_id)

    if not requested_ids:
        return {"status": "skipped", "reason": "no http_exchange_ids cited", "exchanges": 0}
    if client is None:
        return {
            "status": "failed",
            "reason": "proxy client unavailable; cited exchanges were not exported",
            "exchanges": 0,
            "missing_request_ids": requested_ids,
        }

    from lyrashield.tools.proxy.tools import _call as _serialized_call

    entries: list[dict[str, Any]] = []
    missing: list[str] = []
    truncated_ids: list[str] = []
    for request_id in requested_ids:
        if len(entries) >= MAX_EXPORT_EXCHANGES:
            truncated_ids.append(request_id)
            continue
        try:
            result = await _serialized_call(
                client,
                functools.partial(caido_api.get_request_with_client, request_id=request_id),
            )
        except Exception:  # noqa: BLE001 — any proxy failure degrades to partial
            logger.warning("http evidence export: fetch of %s failed", request_id)
            missing.append(request_id)
            continue
        if result is None:
            missing.append(request_id)
            continue
        entries.append(_export_one_exchange(request_id, result))

    document: dict[str, Any] = {
        "schema_version": HTTP_EXCHANGES_SCHEMA,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "binding": {
            "run_id": run_record.get("run_id"),
            "run_name": run_record.get("run_name"),
            "targets": run_record.get("targets_info") or [],
            "report_artifacts_revision": run_record.get("report_artifacts_revision"),
            "findings": cited,
        },
        "exchanges": entries,
    }
    if missing:
        document["missing_request_ids"] = missing
    if truncated_ids:
        document["truncated"] = {
            "exchange_limit": MAX_EXPORT_EXCHANGES,
            "omitted_request_ids": truncated_ids,
        }

    payload = json.dumps(document, ensure_ascii=False, indent=2, default=str)
    if len(payload.encode("utf-8")) > MAX_EXPORT_TOTAL_BYTES:
        # Last-line budget defense: drop body samples entirely rather than
        # write an oversized artifact. Metadata + checksums still export.
        for entry in entries:
            for side in ("request", "response"):
                block = entry.get(side)
                if isinstance(block, dict):
                    block["body_sample"] = ""
                    block["body_truncated"] = True
        payload = json.dumps(document, ensure_ascii=False, indent=2, default=str)
        prior_truncated = document.get("truncated")
        document["truncated"] = {
            **(prior_truncated if isinstance(prior_truncated, dict) else {}),
            "body_samples_dropped": True,
        }
        payload = json.dumps(document, ensure_ascii=False, indent=2, default=str)

    try:
        _atomic_write_text(run_dir / HTTP_EXCHANGES_FILENAME, payload)
    except (OSError, RuntimeError) as exc:
        logger.exception("http evidence export write failed")
        return {
            "status": "failed",
            "reason": f"http_exchanges.json write failed: {exc}",
            "exchanges": 0,
            "missing_request_ids": requested_ids,
        }

    if not entries:
        # Every cited exchange failed to fetch — nothing was exported, so the
        # marker must read failed (explicit incomplete evidence), never a
        # partial-success veneer.
        status = "failed"
    else:
        status = "exported" if not (missing or truncated_ids) else "partial"
    outcome: dict[str, Any] = {
        "status": status,
        "exchanges": len(entries),
        "artifact": HTTP_EXCHANGES_FILENAME,
        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }
    if missing:
        outcome["missing_request_ids"] = missing
    if truncated_ids:
        outcome["truncated"] = True
    return outcome


# ---------------------------------------------------------------------------
# Result manifest — the immutable binding of emitted artifacts to the run
# ---------------------------------------------------------------------------

_MANIFEST_ARTIFACTS = (
    "vulnerabilities.json",
    "vulnerabilities.csv",
    "findings.sarif",
    "penetration_test_report.md",
    COVERAGE_FILENAME,
    THREAT_MODEL_FILENAME,
    HTTP_EXCHANGES_FILENAME,
)


def build_result_manifest(run_dir: Path) -> dict[str, Any]:
    """Checksum every emitted artifact into the run's result manifest.

    The manifest lives inside run.json so one read binds artifact name →
    path → sha256 → bytes for the exact revision the worker ingests.
    """
    artifacts: dict[str, Any] = {}
    for name in _MANIFEST_ARTIFACTS:
        path = run_dir / name
        if not path.is_file():
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        artifacts[name] = {
            "path": name,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "bytes": len(blob),
        }
    vuln_dir = run_dir / "vulnerabilities"
    if vuln_dir.is_dir():
        entries: dict[str, Any] = {}
        for md in sorted(vuln_dir.glob("*.md")):
            try:
                blob = md.read_bytes()
            except OSError:
                continue
            entries[md.name] = hashlib.sha256(blob).hexdigest()
        if entries:
            artifacts["vulnerabilities/"] = {"files": entries}
    return {"schema_version": 1, "artifacts": artifacts}


__all__ = [
    "COVERAGE_FILENAME",
    "DEPENDENT_REPORT_FIELDS",
    "EVIDENCE_V1_1_ENV",
    "FIX_VERIFICATION_KIND",
    "HTTP_EXCHANGES_FILENAME",
    "MAX_HTTP_EXCHANGE_IDS",
    "MAX_HTTP_EXCHANGE_ID_CHARS",
    "MAX_UPDATE_HISTORY_ENTRIES",
    "RUN_RECORD_SCHEMA_VERSION_1_0",
    "RUN_RECORD_SCHEMA_VERSION_1_1",
    "SUPPORTED_RUN_RECORD_SCHEMA_VERSIONS",
    "THREAT_MODEL_FILENAME",
    "UPDATABLE_REPORT_FIELDS",
    "VALID_CONFIDENCE",
    "build_coverage_document",
    "build_result_manifest",
    "build_threat_model_document",
    "evidence_v1_1_enabled",
    "export_http_exchange_evidence",
    "normalize_advisory_cvss",
    "normalize_confidence",
    "normalize_fix_verification",
    "normalize_http_exchange_ids",
    "record_supports_evidence_v1_1",
    "run_record_schema_version",
    "validate_revised_finding",
    "write_coverage_artifact",
    "write_threat_model_artifact",
]
