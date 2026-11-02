"""Stage, validate and commit HTTP evidence through one revision boundary."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import json
import logging
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lyrashield.artifacts import evidence
from lyrashield.artifacts.state_projection import sanitize_targets_info
from lyrashield.artifacts.writer import (
    _atomic_write_bytes,
    read_run_record,
    restore_revision_artifacts,
    snapshot_revision_artifacts,
)


logger = logging.getLogger(__name__)
_LATE_EXPORTS: set[asyncio.Task[Any]] = set()


if TYPE_CHECKING:
    from collections.abc import Callable

    from lyrashield.artifacts.state import ReportState


def _require_manifest(run_dir: Path, manifest: Any, *, require_http: bool) -> dict[str, Any]:
    """Verify the original assertion, including every mandatory entry."""
    evidence.verify_result_manifest(run_dir, manifest)
    if not isinstance(manifest, dict):
        raise TypeError("HTTP export manifest is missing")
    names = ["vulnerabilities.json"]
    if require_http:
        names.append(evidence.HTTP_EXCHANGES_FILENAME)
    artifacts = manifest.get("artifacts")
    for name in names:
        entry = artifacts.get(name) if isinstance(artifacts, dict) else None
        if (
            not isinstance(entry, dict)
            or entry.get("path") != name
            or not isinstance(entry.get("bytes"), int)
            or isinstance(entry.get("bytes"), bool)
        ):
            raise RuntimeError("HTTP export mandatory manifest entry is missing or malformed")
    return manifest


def _read_document(run_dir: Path, outcome: dict[str, Any]) -> dict[str, Any]:
    path = run_dir / evidence.HTTP_EXCHANGES_FILENAME
    if path.stat().st_size > evidence.MAX_EXPORT_TOTAL_BYTES:
        raise RuntimeError("HTTP export exceeds its byte budget")
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != outcome.get("sha256"):
        raise RuntimeError("HTTP export checksum does not match its outcome")
    document = json.loads(payload.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("HTTP export must be an object")
    return document


def _bound_export_ids(
    document: dict[str, Any],
    record: dict[str, Any],
    findings: list[dict[str, Any]],
    outcome: dict[str, Any],
) -> dict[str, list[str]]:
    """Validate membership, identity, revision, availability and capture shape."""
    binding = document.get("binding")
    if document.get("schema_version") != evidence.HTTP_EXCHANGES_SCHEMA or not isinstance(
        binding, dict
    ):
        raise RuntimeError("HTTP export binding is missing")
    revision = binding.get("report_artifacts_revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        raise TypeError("HTTP export report revision is invalid")
    if any(
        binding.get(field) != record.get(field)
        for field in ("run_id", "run_name", "report_artifacts_revision")
    ):
        raise RuntimeError("HTTP export has a foreign or stale run revision")
    revisions, cited = binding.get("finding_revisions"), binding.get("findings")
    if not isinstance(revisions, dict) or not isinstance(cited, dict):
        raise TypeError("HTTP export finding revision binding is missing")
    entries = document.get("exchanges")
    if not isinstance(entries, list) or len(entries) > evidence.MAX_EXPORT_EXCHANGES:
        raise TypeError("HTTP export exchanges are invalid")
    index = {entry.get("proxy_request_id"): entry for entry in entries if isinstance(entry, dict)}
    if len(index) != len(entries):
        raise RuntimeError("HTTP export exchange identities are invalid")
    positive = (
        outcome.get("status") in {"exported", "partial"}
        and outcome.get("artifact") == evidence.HTTP_EXCHANGES_FILENAME
        and not isinstance(outcome.get("exchanges"), bool)
        and outcome.get("exchanges") == len(entries)
        and bool(entries)
    )
    if entries and not positive:
        raise RuntimeError("HTTP export outcome does not describe its captured exchanges")
    unavailable: set[str] = set()
    for source in (document, outcome):
        for key in ("missing_request_ids", "capacity_omitted_request_ids"):
            values = source.get(key, [])
            if not evidence.valid_http_omission_ids(values):
                raise RuntimeError("HTTP export unavailability metadata is invalid")
            unavailable.update(values)
    truncated = document.get("truncated")
    if isinstance(truncated, dict):
        values = truncated.get("omitted_request_ids", [])
        if not evidence.valid_http_omission_ids(values):
            raise RuntimeError("HTTP export truncation metadata is invalid")
        unavailable.update(values)
    verified: dict[str, list[str]] = {}
    for finding in findings:
        finding_id = str(finding["id"])
        claims, _overflow = evidence.select_http_export_ids(finding)
        if not claims:
            continue
        bound, errors = evidence.normalize_http_exchange_ids(cited.get(finding_id))
        if (
            errors
            or bound is None
            or len(bound) != len(cited.get(finding_id) or [])
            or set(bound) != set(claims)
            or isinstance(revisions.get(finding_id), bool)
            or revisions.get(finding_id) != len(finding.get("update_history") or [])
        ):
            raise RuntimeError("HTTP export belongs to a different finding revision")
        valid = []
        for request_id in claims:
            exported = index.get(request_id)
            request = exported.get("request") if isinstance(exported, dict) else None
            if (
                positive
                and request_id not in unavailable
                and isinstance(request, dict)
                and isinstance(request.get("sha256"), str)
                and re.fullmatch(r"[a-f0-9]{64}", request["sha256"])
                and evidence._exchange_matches_finding(
                    str(request.get("host") or "").lower().rstrip("."), finding
                )
            ):
                valid.append(request_id)
        verified[finding_id] = valid
    return verified


def _prior_durable_export(
    run_dir: Path,
    record: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    outcome = record.get("evidence_export")
    if (
        not any(finding.get("http_exchange_ids") for finding in findings)
        or record.get("receipt_persisted") is not True
        or not isinstance(outcome, dict)
        or outcome.get("status") not in {"exported", "partial"}
    ):
        return None
    try:
        manifest = _require_manifest(run_dir, record.get("result_manifest"), require_http=True)
        if manifest["artifacts"][evidence.HTTP_EXCHANGES_FILENAME]["sha256"] != outcome.get(
            "sha256"
        ):
            return None
        document = _read_document(run_dir, outcome)
        verified = _bound_export_ids(document, record, findings, outcome)
    except (OSError, RuntimeError, TypeError, ValueError):
        # An incomplete or stale receipt is never reconstructed from today's
        # files. Fresh captures may replace it; offline claims stay unavailable.
        return None
    allowed = {
        value
        for finding in findings
        for value in finding.get("http_exchange_ids") or []
        if value in verified.get(str(finding["id"]), [])
    }
    document["exchanges"] = [
        entry for entry in document["exchanges"] if entry["proxy_request_id"] in allowed
    ]
    return document if document["exchanges"] else None


def _document_for(record: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    cited = {
        str(finding["id"]): evidence.select_http_export_ids(finding)[0] for finding in findings
    }
    cited = {key: value for key, value in cited.items() if value}
    return {
        "schema_version": evidence.HTTP_EXCHANGES_SCHEMA,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "binding": {
            "run_id": record.get("run_id"),
            "run_name": record.get("run_name"),
            "report_artifacts_revision": record["report_artifacts_revision"],
            "targets": sanitize_targets_info(record.get("targets_info") or []),
            "findings": cited,
            "finding_revisions": {
                str(finding["id"]): len(finding.get("update_history") or [])
                for finding in findings
                if str(finding["id"]) in cited
            },
        },
        "exchanges": [],
    }


def _combine_exports(
    record: dict[str, Any],
    findings: list[dict[str, Any]],
    fresh: dict[str, Any],
    prior: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build availability from retained captures, never from stale omission flags."""
    document = _document_for(record, findings)
    fresh_index = {entry["proxy_request_id"]: entry for entry in fresh["exchanges"]}
    previous = prior["exchanges"] if prior else []
    reused = {
        entry["proxy_request_id"]
        for entry in previous
        if entry["proxy_request_id"] not in fresh_index
    }
    entries = [fresh_index.pop(entry["proxy_request_id"], entry) for entry in previous]
    entries.extend(fresh_index.values())
    omitted = [entry["proxy_request_id"] for entry in entries[evidence.MAX_EXPORT_EXCHANGES :]]
    document["exchanges"] = entries[: evidence.MAX_EXPORT_EXCHANGES]
    present = {entry["proxy_request_id"] for entry in document["exchanges"]}
    requested = {value for values in document["binding"]["findings"].values() for value in values}
    document["missing_request_ids"] = sorted(requested - present)
    capacity = {
        value for finding in findings for value in evidence.select_http_export_ids(finding)[1]
    } - requested
    if capacity:
        document["capacity_omitted_request_ids"] = sorted(capacity)
    if omitted:
        document["truncated"] = {
            "exchange_limit": evidence.MAX_EXPORT_EXCHANGES,
            "omitted_request_ids": omitted,
        }
    if reused.intersection(present):
        document["reused_durable_exchanges"] = len(reused.intersection(present))
    return document


def _candidate_findings(
    findings: list[dict[str, Any]], verified: dict[str, list[str]]
) -> list[dict[str, Any]] | None:
    candidate = copy.deepcopy(findings)
    for finding in candidate:
        finding_id = str(finding["id"])
        claims = list(
            dict.fromkeys(
                list(finding.get("http_exchange_ids") or [])
                + list(finding.get("pending_http_exchange_ids") or [])
            )
        )
        if not claims:
            continue
        available = verified.get(finding_id, [])
        pending = [value for value in claims if value not in available]
        if len(pending) > evidence.MAX_HTTP_EXCHANGE_IDS:
            return None
        finding["http_exchange_ids"] = available
        finding["pending_http_exchange_ids"] = pending
        finding.setdefault("verification_state", "unverified")
    return candidate


def _outcome(
    document: dict[str, Any], payload: bytes | None, *, reason: str | None, pending: bool
) -> dict[str, Any]:
    entries = document["exchanges"] if payload is not None else []
    status = "failed" if not entries else "partial" if pending else "exported"
    if not document["binding"]["findings"] and not entries:
        status = "skipped"
    result: dict[str, Any] = {"status": status, "exchanges": len(entries)}
    if reason and status == "failed":
        result["reason"] = reason
    for field in (
        "missing_request_ids",
        "capacity_omitted_request_ids",
        "reused_durable_exchanges",
    ):
        value = document.get(field)
        if value and (
            (field == "reused_durable_exchanges" and payload is not None)
            or (field != "reused_durable_exchanges" and evidence.valid_http_omission_ids(value))
        ):
            result[field] = value
    if payload is not None:
        result.update(
            artifact=evidence.HTTP_EXCHANGES_FILENAME, sha256=hashlib.sha256(payload).hexdigest()
        )
    if document.get("truncated"):
        result["truncated"] = True
    return result


def _discard_late_export(task: asyncio.Task[Any], owner: tempfile.TemporaryDirectory[str]) -> None:
    """Consume the ignored result, then delete its privately owned stage."""
    _LATE_EXPORTS.discard(task)
    with contextlib.suppress(asyncio.CancelledError, Exception):
        task.result()
    try:
        owner.cleanup()
    except OSError:
        logger.warning("Late HTTP evidence stage cleanup failed", exc_info=True)


async def _stage_fresh_export(
    run_dir: Path,
    exporter: Callable[..., Any],
    client: Any,
    record: dict[str, Any],
    findings: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], str | None, bool]:
    """Race a deadline without waiting for a dependency to accept cancellation.

    An interrupted task owns its quarantined directory until it actually
    settles. Its callback then removes the stage. This prevents late writes
    racing deletion or ever replacing committed run artifacts.
    """
    owner = tempfile.TemporaryDirectory(prefix=".http-export-", dir=run_dir)
    stage = Path(owner.name)
    quarantined = False
    cancelled = False
    reason = None
    outcome: dict[str, Any] = {"status": "failed", "exchanges": 0}
    try:
        task = asyncio.create_task(
            exporter(
                client,
                stage,
                run_record=copy.deepcopy(record),
                findings=copy.deepcopy(findings),
            )
        )
        done: set[asyncio.Task[Any]] = set()
        try:
            done, _pending = await asyncio.wait(
                {task},
                timeout=evidence.HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            cancelled, reason = True, "export_cancelled"
        if task not in done:
            reason = reason or "export_timeout"
            quarantined = True
            _LATE_EXPORTS.add(task)
            task.add_done_callback(lambda settled: _discard_late_export(settled, owner))
            task.cancel()
        else:
            try:
                outcome = task.result()
            except asyncio.CancelledError:
                cancelled, reason = True, "export_cancelled"
            except Exception:  # noqa: BLE001 — record unavailability without raw proxy errors
                reason = "export_failed"
        fresh = _document_for(record, findings)
        if reason is None and (stage / evidence.HTTP_EXCHANGES_FILENAME).is_file():
            fresh = _read_document(stage, outcome)
            eligible = _bound_export_ids(fresh, record, findings, outcome)
            eligible_ids = {value for values in eligible.values() for value in values}
            # A fetched entry explicitly marked missing/omitted is unavailable.
            # Only a separately qualified prior capture can restore that ID.
            fresh["exchanges"] = [
                entry for entry in fresh["exchanges"] if entry["proxy_request_id"] in eligible_ids
            ]
        return fresh, outcome, reason, cancelled
    finally:
        if not quarantined:
            owner.cleanup()


async def reconcile_http_exchange_evidence(
    state: ReportState,
    client: Any,
    *,
    exporter: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Stage without locks across awaits; commit every result under one CAS.

    The run record is written last. Caught failures restore prior artifacts;
    process interruption is detected by the manifest on resume/ingest.
    """
    if not evidence.record_supports_pending_http_evidence(state.run_record):
        raise RuntimeError("Pending HTTP reconciliation requires a schema-1.2 run")
    exporter = exporter or evidence.export_http_exchange_evidence
    run_dir = state.get_run_dir()
    with state._report_artifacts_lock:
        revision = state._report_artifacts_revision
        findings, record = (
            copy.deepcopy(state.vulnerability_reports),
            copy.deepcopy(state.run_record),
        )
        resumed_unnamed = record.get("run_name") is None and record.get("run_id") == state.run_name
        if record.get("run_id") != state.run_id or (
            record.get("run_name") != state.run_name and not resumed_unnamed
        ):
            raise RuntimeError("HTTP export source run identity does not match this run")
        prior = _prior_durable_export(run_dir, record, findings)
    record["report_artifacts_revision"] = revision + 1
    fresh, fresh_outcome, reason, cancelled = await _stage_fresh_export(
        run_dir,
        exporter,
        client,
        record,
        findings,
    )
    reason = reason or fresh_outcome.get("reason")
    document = _combine_exports(record, findings, fresh, prior)
    payload = evidence.encode_http_exchange_document(document)
    provisional = _outcome(document, payload, reason=reason, pending=True)
    verified = (
        _bound_export_ids(document, record, findings, provisional) if payload is not None else {}
    )
    candidate = _candidate_findings(findings, verified)
    if candidate is None:
        # The two independently bounded arrays cannot always be demoted
        # into one pending array. Preserve every claim and artifact; record
        # failure through the same revision guard, never a lossy projection.
        candidate, payload = findings, None
        outcome = {"status": "failed", "exchanges": 0, "reason": "pending_capacity_exceeded"}
        preserve_artifacts = True
    else:
        preserve_artifacts = False
        if payload is None:
            reason = "export_size_exceeded"
        outcome = _outcome(
            document,
            payload,
            reason=reason,
            pending=any(finding.get("pending_http_exchange_ids") for finding in candidate),
        )
    try:
        _commit_revision(
            state, revision, candidate, payload, outcome, preserve_artifacts=preserve_artifacts
        )
    finally:
        if cancelled:
            raise asyncio.CancelledError
    return outcome


def _commit_revision(
    state: ReportState,
    revision: int,
    findings: list[dict[str, Any]],
    payload: bytes | None,
    outcome: dict[str, Any],
    *,
    preserve_artifacts: bool,
) -> None:
    with state._report_artifacts_lock:
        if state._report_artifacts_revision != revision:
            raise RuntimeError("Finding revision changed while HTTP export was staged")
        run_dir = state.get_run_dir()
        prior_artifacts = snapshot_revision_artifacts(run_dir)
        prior_record, prior_findings = copy.deepcopy(state.run_record), state.vulnerability_reports
        prior_saved = set(state._saved_vuln_ids)
        prior_persisted = state._persisted_report_artifacts_revision
        prior_counters = state._save_seq, state._turn_count
        prior_scope = state._scope_violations_seen, state._scope_dropped_seen
        prior_receipt = state.receipt_persisted
        try:
            if payload is not None:
                _atomic_write_bytes(run_dir / evidence.HTTP_EXCHANGES_FILENAME, payload)
            if not preserve_artifacts:
                saved: set[str] = set()
                state._write_report_projections(findings, saved, require_sarif=True)
                state._saved_vuln_ids = saved
                state.vulnerability_reports = findings
            state._report_artifacts_revision = revision + 1
            state._persisted_report_artifacts_revision = revision + 1
            state.set_evidence_export_outcome(outcome)
            _persist_bound_revision(state, run_dir, revision + 1, require_http=payload is not None)
        except Exception:
            state.vulnerability_reports = prior_findings
            state.run_record.clear()
            state.run_record.update(prior_record)
            state._saved_vuln_ids = prior_saved
            state._report_artifacts_revision = revision
            state._persisted_report_artifacts_revision = prior_persisted
            state._save_seq, state._turn_count = prior_counters
            state._scope_violations_seen, state._scope_dropped_seen = prior_scope
            state.receipt_persisted = prior_receipt
            try:
                restore_revision_artifacts(run_dir, prior_artifacts)
            except Exception as recovery_error:
                state.receipt_persisted = False
                state.run_record["receipt_persisted"] = False
                raise RuntimeError("HTTP evidence revision recovery failed") from recovery_error
            raise


def _persist_bound_revision(
    state: ReportState, run_dir: Path, revision: int, *, require_http: bool
) -> None:
    if not state.save_run_data():
        raise RuntimeError("HTTP evidence revision receipt could not be persisted")
    persisted = read_run_record(run_dir)
    if not isinstance(persisted, dict):
        raise TypeError("HTTP evidence revision receipt is missing")
    manifest = _require_manifest(
        run_dir, persisted.get("result_manifest"), require_http=require_http
    )
    if (
        persisted.get("report_artifacts_revision") != revision
        or persisted.get("receipt_persisted") is not True
        or manifest != state.run_record.get("result_manifest")
    ):
        raise RuntimeError("HTTP evidence revision receipt is stale")
