from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from lyrashield.artifacts import evidence as _evidence
from lyrashield.telemetry import posthog, scarf
from lyrashield.utils.redaction import is_sensitive_key, redact_text, redact_url


logger = logging.getLogger("lyrashield.artifacts.state")

if TYPE_CHECKING:
    from lyrashield.artifacts.state import ReportState

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _clean_title(title: str) -> str:
    """Return a single-line finding title.

    A title quotes text from the scanned target, so it can carry newlines, tabs or
    other control characters. Those break every artifact that renders the title on
    one line, such as the markdown heading, the CSV cell and the TUI list. Control
    characters become spaces and runs of whitespace collapse to one space.
    """
    return " ".join(_CONTROL_CHARS.sub(" ", title).split())


_FINDING_TEXT_FIELDS = (
    "title",
    "description",
    "impact",
    "technical_analysis",
    "poc_description",
    "remediation_steps",
    "evidence",
    "assumptions",
    "fix_pr_body",
    "agent_name",
)

_FINDING_URL_FIELDS = ("target", "endpoint")

_V1_1_FINDING_TEXT_FIELDS = frozenset(
    {
        "counterevidence",
        "confidence_rationale",
        "severity_change_conditions",
        "contextual_cvss_reasoning",
        "updated_at",
    }
)

_V1_1_FINDING_STRUCT_FIELDS = frozenset({"advisory_cvss", "fix_verification", "update_history"})

_V1_1_FINDING_FIELDS = (
    _V1_1_FINDING_TEXT_FIELDS
    | _V1_1_FINDING_STRUCT_FIELDS
    | frozenset(
        {
            "confidence",
            "http_exchange_ids",
            "evidence_warnings",
            "evidence_contract_version",
            "verification_state",
        }
    )
)

_MAX_TEXT_LENGTH = 10_000

_MAX_COLLECTION_SIZE = 1_000

_MAX_METADATA_DEPTH = 10

_MAX_FINDING_SERIALIZED_SIZE = 1_000_000


def _truncate_text(value: str, max_length: int = _MAX_TEXT_LENGTH) -> str:
    """Deterministically truncate a string to ``max_length`` chars."""
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."


def _bound_collection(items: list[Any], max_size: int = _MAX_COLLECTION_SIZE) -> list[Any]:
    """Deterministically bound a collection to ``max_size`` items."""
    if len(items) <= max_size:
        return items
    return items[:max_size]


def _recursive_sanitize_unknown(value: Any, *, include_internal_paths: bool, depth: int = 0) -> Any:
    """Recursively sanitize unknown dict/list/string values from model-controlled fields.

    Every string leaf is redacted; nested dicts/lists are descended up to
    ``_MAX_METADATA_DEPTH``; collections are bounded to ``_MAX_COLLECTION_SIZE``.
    """
    if depth > _MAX_METADATA_DEPTH:
        return "[truncated:depth]"
    if isinstance(value, str):
        return _truncate_text(redact_text(value, include_internal_paths=include_internal_paths))
    if isinstance(value, dict):
        bounded = list(value.items())[:_MAX_COLLECTION_SIZE]
        return {
            str(k): (
                "[SECRET]"
                if is_sensitive_key(k)
                else _recursive_sanitize_unknown(
                    v, include_internal_paths=include_internal_paths, depth=depth + 1
                )
            )
            for k, v in bounded
        }
    if isinstance(value, list):
        bounded = value[:_MAX_COLLECTION_SIZE]
        return [
            _recursive_sanitize_unknown(
                item, include_internal_paths=include_internal_paths, depth=depth + 1
            )
            for item in bounded
        ]
    return value


def sanitize_finding(
    report: dict[str, Any],
    *,
    include_internal_paths: bool,
    schema_version: str = "1.0",
) -> dict[str, Any]:
    """Return the immutable sanitized snapshot of one finding.

    Built once at the artifact persistence boundary; every durable/public
    projection (vulnerabilities JSON/MD/CSV, SARIF, viewer, sync) consumes
    only this snapshot, never the raw in-memory report. Schema-1.1 evidence
    fields are emitted only for a 1.1 record — a 1.0 run keeps its original
    contract even if the writer flag was toggled mid-run.
    """
    is_v1_1 = schema_version == _evidence.RUN_RECORD_SCHEMA_VERSION_1_1
    snapshot: dict[str, Any] = {}
    for key, value in report.items():
        if not is_v1_1 and key in _V1_1_FINDING_FIELDS:
            continue
        if is_sensitive_key(key):
            snapshot[key] = "[SECRET]"
        elif key in _FINDING_TEXT_FIELDS and isinstance(value, str):
            snapshot[key] = _truncate_text(
                redact_text(value, include_internal_paths=include_internal_paths)
            )
        elif key in _FINDING_URL_FIELDS and isinstance(value, str):
            snapshot[key] = redact_url(redact_text(value, include_internal_paths=False))
        elif key == "poc_script_code" and isinstance(value, str):
            # The weaponized payload stays a local artifact, but its copy in
            # the durable snapshot is stripped of secrets and host identity;
            # sandbox-internal workspace paths are preserved by policy.
            snapshot[key] = _truncate_text(redact_text(value, include_internal_paths=False))
        elif key == "code_locations" and isinstance(value, list):
            snapshot[key] = _bound_collection(
                _sanitize_code_locations(value, include_internal_paths)
            )
        elif key == "dependency_metadata" and isinstance(value, dict):
            snapshot[key] = {
                str(k): (
                    "[SECRET]"
                    if is_sensitive_key(k)
                    else _truncate_text(
                        redact_text(str(v), include_internal_paths=include_internal_paths)
                    )
                    if isinstance(v, str)
                    else _recursive_sanitize_unknown(
                        v, include_internal_paths=include_internal_paths
                    )
                )
                for k, v in value.items()
            }
        elif key == "cvss_breakdown" and isinstance(value, dict):
            snapshot[key] = {
                str(k): (
                    "[SECRET]"
                    if is_sensitive_key(k)
                    else redact_text(str(v), include_internal_paths=False)
                )
                for k, v in value.items()
            }
        elif is_v1_1 and key in _V1_1_FINDING_TEXT_FIELDS and isinstance(value, str):
            snapshot[key] = _truncate_text(
                redact_text(value, include_internal_paths=include_internal_paths)
            )
        elif is_v1_1 and key == "http_exchange_ids" and isinstance(value, list):
            # Proxy request ids are correlation references only; they are
            # validated numeric ASCII at intake and bounded again here.
            ids, _errors = _evidence.normalize_http_exchange_ids(value)
            snapshot[key] = ids if isinstance(ids, list) else []
        elif is_v1_1 and key == "update_history" and isinstance(value, list):
            # Append-only revision history, bounded; entries are small dicts
            # of metadata sanitized recursively like other structured fields.
            snapshot[key] = _recursive_sanitize_unknown(
                value[: _evidence.MAX_UPDATE_HISTORY_ENTRIES],
                include_internal_paths=include_internal_paths,
            )
        elif is_v1_1 and key in _V1_1_FINDING_STRUCT_FIELDS:
            snapshot[key] = _recursive_sanitize_unknown(
                value, include_internal_paths=include_internal_paths
            )
        else:
            # Unknown fields: recursively sanitize so model-controlled nested
            # metadata cannot leak secrets through the catch-all branch.
            snapshot[key] = _recursive_sanitize_unknown(
                value, include_internal_paths=include_internal_paths
            )

    if is_v1_1:
        # Schema-1.1 contract stamps. ``verification_state`` is honest about
        # provenance: a filed finding is agent-asserted, and nothing here —
        # including a successful HTTP export — upgrades it to verified. An
        # engine verification path may stamp a stronger value upstream.
        snapshot["evidence_contract_version"] = _evidence.RUN_RECORD_SCHEMA_VERSION_1_1
        snapshot.setdefault("verification_state", "unverified")

    # E4: enforce the total serialized finding size bound as a last-line
    # defense. The per-field limits above are the primary guard; this catch
    # prevents a combination of many bounded fields from producing a single
    # oversized record. If the snapshot still exceeds the bound, fall back to
    # a minimal safe finding so persistence never writes an unbounded object.
    try:
        serialized = json.dumps(snapshot)
    except (TypeError, ValueError):
        serialized = ""
    if len(serialized) > _MAX_FINDING_SERIALIZED_SIZE:
        return {
            "id": report.get("id", ""),
            "title": redact_text(
                _truncate_text(str(report.get("title", ""))),
                include_internal_paths=include_internal_paths,
            ),
            "severity": str(report.get("severity", "info")).lower().strip() or "info",
            "timestamp": report.get("timestamp", ""),
            "error": (
                "Finding exceeded the maximum serialized size and was reduced "
                "to a safe stub. The original report could not be persisted."
            ),
        }
    return snapshot


def _sanitize_code_locations(
    locations: list[Any], include_internal_paths: bool
) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for location in locations:
        if not isinstance(location, dict):
            continue
        entry: dict[str, Any] = {}
        for key, value in location.items():
            if isinstance(value, str):
                if key == "file":
                    # Keep repo-relative paths; strip any host-absolute or
                    # home-directory prefix that leaked into a location.
                    entry[key] = redact_text(value, include_internal_paths=include_internal_paths)
                else:  # snippet, fix_before, fix_after, label
                    entry[key] = redact_text(value, include_internal_paths=include_internal_paths)
            else:
                entry[key] = value
        sanitized.append(entry)
    return sanitized


def add_vulnerability_report(
    self: ReportState,
    title: str,
    severity: str,
    description: str | None = None,
    impact: str | None = None,
    target: str | None = None,
    technical_analysis: str | None = None,
    poc_description: str | None = None,
    poc_script_code: str | None = None,
    remediation_steps: str | None = None,
    evidence: str | None = None,
    assumptions: str | None = None,
    fix_effort: str | None = None,
    cvss: float | None = None,
    cvss_breakdown: dict[str, str] | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    fix_pr_body: str | None = None,
    finding_class: str | None = None,
    dependency_metadata: dict[str, Any] | None = None,
    control_ids: list[int] | None = None,
    counterevidence: str | None = None,
    confidence: str | None = None,
    confidence_rationale: str | None = None,
    severity_change_conditions: str | None = None,
    fix_verification: dict[str, Any] | str | None = None,
    advisory_cvss: dict[str, Any] | float | None = None,
    http_exchange_ids: list[str] | None = None,
    evidence_warnings: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> str:
    report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

    report: dict[str, Any] = {
        "id": report_id,
        "title": _clean_title(title),
        "severity": severity.lower().strip(),
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    _redact_paths = not self._is_whitebox
    if description:
        report["description"] = redact_text(
            description.strip(), include_internal_paths=_redact_paths
        )
    if impact:
        report["impact"] = redact_text(impact.strip(), include_internal_paths=_redact_paths)
    if target:
        report["target"] = target.strip()
    if technical_analysis:
        report["technical_analysis"] = redact_text(
            technical_analysis.strip(), include_internal_paths=_redact_paths
        )
    if poc_description:
        report["poc_description"] = redact_text(
            poc_description.strip(), include_internal_paths=_redact_paths
        )
    if poc_script_code:
        report["poc_script_code"] = redact_text(
            poc_script_code.strip(), include_internal_paths=False
        )
    if remediation_steps:
        report["remediation_steps"] = redact_text(
            remediation_steps.strip(), include_internal_paths=_redact_paths
        )
    if evidence:
        report["evidence"] = redact_text(evidence.strip(), include_internal_paths=_redact_paths)
    if assumptions:
        report["assumptions"] = redact_text(
            assumptions.strip(), include_internal_paths=_redact_paths
        )
    if fix_effort:
        report["fix_effort"] = fix_effort.strip().lower()
    if cvss is not None:
        report["cvss"] = cvss
    if cvss_breakdown:
        report["cvss_breakdown"] = cvss_breakdown
    if endpoint:
        report["endpoint"] = endpoint.strip()
    if method:
        report["method"] = method.strip()
    if cve:
        report["cve"] = cve.strip()
    if cwe:
        report["cwe"] = cwe.strip()
    if code_locations:
        report["code_locations"] = code_locations
    if fix_pr_body:
        report["fix_pr_body"] = redact_text(
            fix_pr_body.strip(), include_internal_paths=_redact_paths
        )
    report["finding_class"] = (finding_class or "dynamic").strip().lower()
    if dependency_metadata:
        report["dependency_metadata"] = dependency_metadata
    if control_ids:
        report["control_ids"] = sorted(set(control_ids))
    # Schema-1.1 evidence fields. Values arrive already normalized by the
    # reporting tool; they are sanitized again at the persistence boundary
    # and only emitted when the record's declared version is 1.1.
    if counterevidence:
        report["counterevidence"] = redact_text(
            counterevidence.strip(), include_internal_paths=_redact_paths
        )
    if confidence:
        normalized_confidence, confidence_errors = _evidence.normalize_confidence(confidence)
        if normalized_confidence is None:
            raise ValueError(f"confidence rejected: {'; '.join(confidence_errors)}")
        report["confidence"] = normalized_confidence
    if confidence_rationale:
        report["confidence_rationale"] = redact_text(
            confidence_rationale.strip(), include_internal_paths=_redact_paths
        )
    if severity_change_conditions:
        report["severity_change_conditions"] = redact_text(
            severity_change_conditions.strip(), include_internal_paths=_redact_paths
        )
    if fix_verification is not None:
        normalized_fv, fv_errors = _evidence.normalize_fix_verification(fix_verification)
        if normalized_fv is None:
            raise ValueError(f"fix_verification rejected: {'; '.join(fv_errors)}")
        normalized_fv["recorded_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        report["fix_verification"] = normalized_fv
    if advisory_cvss is not None:
        normalized_adv, adv_errors = _evidence.normalize_advisory_cvss(advisory_cvss)
        if normalized_adv is None:
            raise ValueError(f"advisory_cvss rejected: {'; '.join(adv_errors)}")
        report["advisory_cvss"] = normalized_adv
    if http_exchange_ids:
        normalized_ids, id_errors = _evidence.normalize_http_exchange_ids(http_exchange_ids)
        if id_errors or normalized_ids is None:
            raise ValueError(f"http_exchange_ids rejected: {'; '.join(id_errors)}")
        report["http_exchange_ids"] = normalized_ids
    if evidence_warnings:
        report["evidence_warnings"] = [
            redact_text(str(w).strip(), include_internal_paths=_redact_paths)[:500]
            for w in evidence_warnings[:10]
            if str(w).strip()
        ]
    if agent_id:
        report["agent_id"] = agent_id
    if agent_name:
        report["agent_name"] = agent_name

    self.vulnerability_reports.append(report)
    self._report_artifacts_revision += 1
    logger.info(f"Added vulnerability report: {report_id} - {title}")
    posthog.finding(severity, cwe=cwe, is_cve=bool(cve))
    scarf.finding(severity, cwe=cwe, is_cve=bool(cve))

    if self.vulnerability_found_callback:
        # E4: callback receives the sanitized snapshot, not the raw report,
        # so live CLI/TUI displays never show secrets or host paths.
        sanitized = sanitize_finding(
            report,
            include_internal_paths=not _redact_paths,
            schema_version=str(self.run_record.get("schema_version", "1.0")),
        )
        self.vulnerability_found_callback(sanitized)

    self._set_phase("running")
    persisted = self.save_run_data()
    if not persisted:
        # The report was broadcast to the callback but not durably
        # persisted. Remove the in-memory report and the durable ID marker
        # so the next report does not reuse the same ID or skip its
        # Markdown artifact (comment #16).
        self.vulnerability_reports.pop()
        self._saved_vuln_ids.discard(report_id)
        raise RuntimeError(
            f"Vulnerability report {report_id} was not durably persisted; "
            "artifact write failed and the report has been rolled back."
        )
    return report_id


def update_vulnerability_report(
    self: ReportState,
    report_id: str,
    fields: dict[str, Any],
    *,
    update_reason: str | None = None,
    updated_by_agent_id: str | None = None,
    updated_by_agent_name: str | None = None,
) -> dict[str, Any] | None:
    """Apply a revision to an existing report, keeping its identity.

    Invariants enforced here:

    - Creation-time identity never moves: ``id``, ``timestamp``,
      ``finding_class`` and the original author stay put.
    - The append-only ``update_history`` gains exactly one bounded entry
      per persisted revision; invalid updates leave prior evidence
      untouched.
    - Persistence precedes the in-memory change: the revised projections
      are written to disk first, and a failed write rolls the in-memory
      list back so the original evidence survives.
    - Dependent fields are dropped when the field they describe is
      superseded (severity/conclusion changes invalidate the projections
      that restate them), and all projections regenerate in one pass.
    - A sealed run (status ``completed``) is immutable: late revisions
      cannot mutate evidence a report was already rendered from.

    Returns the revised report dict, or ``None`` when the id is unknown or
    nothing in ``fields`` changes it. Raises ``RuntimeError`` when the
    revision cannot be durably persisted.
    """
    with self._report_artifacts_lock:
        index = next(
            (i for i, r in enumerate(self.vulnerability_reports) if r.get("id") == report_id),
            None,
        )
        if index is None:
            logger.warning("cannot update unknown vulnerability report %s", report_id)
            return None
        original = self.vulnerability_reports[index]

        if not _evidence.record_supports_evidence_v1_1(self.run_record):
            # A 1.0 record strips the evidence fields a revision adds
            # (update_history, updated_at, ...), so revising it would lose
            # attribution on disk. The record's version is fixed at
            # creation; this run cannot be retroactively upgraded.
            raise RuntimeError(
                f"Vulnerability report {report_id} belongs to a schema-1.0 "
                "record; revisions require the 1.1 writer "
                "(LYRASHIELD_RUN_RECORD_V1_1 at scan start)."
            )
        if self.run_record.get("status") == "completed":
            raise RuntimeError(
                f"Vulnerability report {report_id} belongs to a sealed "
                "(completed) run; the report is immutable."
            )

        changed: dict[str, Any] = {}
        for key, raw_value in fields.items():
            if key not in _evidence.UPDATABLE_REPORT_FIELDS or raw_value is None:
                continue
            value = raw_value
            if isinstance(value, str):
                value = _clean_title(value) if key == "title" else value.strip()
                if key in {"severity", "confidence", "fix_effort"}:
                    value = value.lower()
                if not value:
                    continue
            if key == "fix_verification":
                normalized_fv, fv_errors = _evidence.normalize_fix_verification(value)
                if normalized_fv is None:
                    raise ValueError(f"fix_verification rejected: {'; '.join(fv_errors)}")
                normalized_fv["recorded_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
                value = normalized_fv
            elif key == "advisory_cvss":
                normalized_adv, adv_errors = _evidence.normalize_advisory_cvss(value)
                if normalized_adv is None:
                    raise ValueError(f"advisory_cvss rejected: {'; '.join(adv_errors)}")
                value = normalized_adv
            elif key == "http_exchange_ids":
                normalized_ids, id_errors = _evidence.normalize_http_exchange_ids(value)
                if id_errors or normalized_ids is None:
                    raise ValueError(f"http_exchange_ids rejected: {'; '.join(id_errors)}")
                value = normalized_ids
            if original.get(key) == value:
                continue
            changed[key] = value

        superseded = {
            dependent
            for primary, dependents in _evidence.DEPENDENT_REPORT_FIELDS.items()
            if primary in changed
            for dependent in dependents
            if dependent not in changed and original.get(dependent) not in (None, "", [], {})
        }

        if not changed and not superseded:
            logger.info("update for %s carried no new content; keeping it as is", report_id)
            return None

        raw_history = original.get("update_history")
        history: list[dict[str, Any]] = (
            [e for e in raw_history if isinstance(e, dict)] if isinstance(raw_history, list) else []
        )
        if len(history) >= _evidence.MAX_UPDATE_HISTORY_ENTRIES:
            raise RuntimeError(
                f"Vulnerability report {report_id} reached the revision "
                f"history bound ({_evidence.MAX_UPDATE_HISTORY_ENTRIES}); "
                "further revisions would drop attribution. File a new "
                "finding instead of rewriting this one."
            )

        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "fields": sorted(changed),
        }
        if superseded:
            entry["dropped_fields"] = sorted(superseded)
        if update_reason and update_reason.strip():
            entry["reason"] = update_reason.strip()[: _evidence.MAX_UPDATE_REASON_CHARS]
        if updated_by_agent_id:
            entry["agent_id"] = updated_by_agent_id
        if updated_by_agent_name:
            entry["agent_name"] = updated_by_agent_name
        for key in ("severity", "cvss", "confidence"):
            if key in changed and original.get(key) is not None:
                entry[f"previous_{key}"] = original[key]
        history.append(entry)

        revised = {**original, **changed}
        for dependent in superseded:
            revised.pop(dependent, None)
        revised["update_history"] = history
        revised["updated_at"] = entry["timestamp"]

        violations = _evidence.validate_revised_finding(revised, original)
        if violations:
            raise RuntimeError(
                f"Vulnerability report {report_id} revision violates "
                f"creation-time invariants: {'; '.join(violations)}. "
                "Original evidence unchanged."
            )

        # Persist the revised projections BEFORE the in-memory report is
        # replaced, so a failed write leaves the original evidence
        # untouched. The markdown is re-rendered in the same pass (the id
        # is discarded from the saved set first) so on-disk evidence can
        # never carry the superseded statement next to the new verdict.
        candidate = list(self.vulnerability_reports)
        candidate[index] = revised
        saved_ids = set(self._saved_vuln_ids)
        saved_ids.discard(report_id)
        try:
            self._write_report_projections(candidate, saved_ids)
        except (OSError, RuntimeError):
            logger.exception(
                "revision of %s failed to persist; original evidence kept",
                report_id,
            )
            raise

        self.vulnerability_reports[index] = revised
        self._saved_vuln_ids = saved_ids
        self._report_artifacts_revision += 1
        persisted = self.save_run_data()
        if not persisted:
            # run.json could not be written even though the finding
            # projections were. The evidence itself is durable; roll back
            # the in-memory swap so a later save retries the full record.
            self.vulnerability_reports[index] = original
            self._report_artifacts_revision -= 1
            raise RuntimeError(
                f"Vulnerability report {report_id} revision could not be "
                "recorded in run.json; rolled back."
            )

        logger.info(
            "Updated vulnerability report %s (%s)",
            report_id,
            ", ".join(entry["fields"]) or "no field replaced",
        )
        if self.vulnerability_updated_callback:
            sanitized = sanitize_finding(
                revised,
                include_internal_paths=not self._is_whitebox,
                schema_version=str(self.run_record.get("schema_version", "1.0")),
            )
            self.vulnerability_updated_callback(sanitized)
        return revised
