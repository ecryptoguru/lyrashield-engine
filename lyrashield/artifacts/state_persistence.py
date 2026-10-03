from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from lyrashield.artifacts import evidence as _evidence
from lyrashield.artifacts.usage import LLMUsageLedger
from lyrashield.artifacts.writer import validate_finding_id


if TYPE_CHECKING:
    from lyrashield.artifacts.state import ReportState

logger = logging.getLogger("lyrashield.artifacts.state")

RUN_RECORD_SCHEMA_VERSION = _evidence.RUN_RECORD_SCHEMA_VERSION_1_0

REQUIRED_RUN_RECORD_FIELDS: tuple[str, ...] = (
    "schema_version",
    "run_id",
    "run_name",
    "start_time",
    "end_time",
    "status",
    "phase",
    "auth_mode",
    "targets_info",
    "llm_usage",
    "seq",
    "turn_count",
)


def validate_run_record(record: dict[str, Any]) -> None:
    """Raise when ``record`` is not a complete versioned worker contract."""
    missing = [field for field in REQUIRED_RUN_RECORD_FIELDS if field not in record]
    if missing:
        raise RuntimeError(f"run.json contract incomplete, missing fields: {missing}")
    if record.get("schema_version") not in _evidence.SUPPORTED_RUN_RECORD_SCHEMA_VERSIONS:
        raise RuntimeError(
            f"run.json contract carries unsupported schema_version: "
            f"{record.get('schema_version')!r} (expected one of "
            f"{sorted(_evidence.SUPPORTED_RUN_RECORD_SCHEMA_VERSIONS)!r})"
        )


def initial_run_record(
    run_name: str | None,
    *,
    auth_mode: str,
    targets_info: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical first run record (the only constructor of it).

    Both the CLI's pre-scan persistence and :class:`ReportState` build the
    record here, so the first observable run.json is already a complete
    versioned worker contract — never a partial hand-rolled dict.

    ``targets_info`` is a required contract field and is accepted as an
    explicit parameter so it is never dropped by the ``extra`` filter that
    protects required fields from caller override (comment #6).
    """
    record: dict[str, Any] = {
        "schema_version": _evidence.run_record_schema_version(),
        "run_id": run_name or f"run-{uuid4().hex[:8]}",
        "run_name": run_name,
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "status": "running",
        "phase": "setup",
        "auth_mode": auth_mode,
        "targets_info": targets_info if isinstance(targets_info, list) else [],
        "llm_usage": LLMUsageLedger().to_record(),
        "seq": 0,
        "turn_count": 0,
    }
    if record["schema_version"] == _evidence.RUN_RECORD_SCHEMA_VERSION_1_1:
        record["evidence_format"] = _evidence.RUN_RECORD_SCHEMA_VERSION_1_1
    if extra:
        # Required contract fields are immutable here: extra must not
        # overwrite them. A caller cannot forge status, schema_version,
        # run_id, or any other field the worker contract depends on.
        record.update({k: v for k, v in extra.items() if k not in REQUIRED_RUN_RECORD_FIELDS})
    return record


def get_run_dir(self: ReportState, *, run_dir_for: Callable[[str], Path]) -> Path:
    if self._run_dir is None:
        run_dir_name = self.run_name if self.run_name else self.run_id
        self._run_dir = run_dir_for(run_dir_name)
        self._run_dir.mkdir(parents=True, exist_ok=True)

    return self._run_dir


def hydrate_from_run_dir(
    self: ReportState,
    *,
    read_run_record: Callable[[Path], dict[str, Any] | None],
    int_or_zero: Callable[[Any], int],
    clean_title: Callable[[str], str],
    logger: logging.Logger,
) -> None:
    """Reload prior-scan state from ``{run_dir}/`` for resume.

    Restores:

    - ``vulnerability_reports`` from ``vulnerabilities.json`` so
      :meth:`add_vulnerability_report` doesn't allocate a colliding
      ``vuln-0001`` and overwrite the prior on-disk MD.
    - ``run_record`` from ``run.json`` so timestamps, run inputs,
      status, and final report state have one public source of truth.

    Idempotent on missing files (fresh runs land here too via the
    same code path). **Raises on corruption** — silently swallowing
    a corrupt ``vulnerabilities.json`` would let the next vuln
    allocate ``vuln-0001`` and overwrite the prior MD on disk
    (data loss). Caller is expected to fail the run loud and let
    the user inspect ``{run_dir}`` or pick a fresh ``--run-name``.
    """
    run_dir = self.get_run_dir()

    data = read_run_record(run_dir)
    if data is not None and "result_manifest" in data:
        _evidence.verify_result_manifest(run_dir, data["result_manifest"])

    json_path = run_dir / "vulnerabilities.json"
    vuln_data: list[Any] | None = None
    if json_path.exists():
        try:
            parsed_vuln_data = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"vulnerabilities.json at {json_path} is corrupt ({exc}); "
                f"refusing to start fresh — that would overwrite prior "
                f"vulnerability MDs on disk. Inspect or delete the run dir.",
            ) from exc
        if not isinstance(parsed_vuln_data, list):
            raise RuntimeError(f"vulnerabilities.json at {json_path} is not a list")
        if any(not isinstance(report, dict) for report in parsed_vuln_data):
            raise RuntimeError(f"vulnerabilities.json at {json_path} contains a non-object finding")
        vuln_data = parsed_vuln_data
        finding_ids: set[str] = set()
        for report in vuln_data:
            try:
                finding_id = validate_finding_id(report.get("id"))
            except ValueError as exc:
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} contains an invalid finding id"
                ) from exc
            if finding_id in finding_ids:
                raise RuntimeError(
                    "vulnerabilities.json at "
                    f"{json_path} contains duplicate finding id {finding_id!r}"
                )
            finding_ids.add(finding_id)

    persisted_report_revision: int | None = None
    if data:
        self.run_record.update(data)
        if isinstance(data.get("start_time"), str):
            self.start_time = data["start_time"]
        if isinstance(data.get("end_time"), str):
            self.end_time = data["end_time"]
        scan_results = data.get("scan_results")
        if isinstance(scan_results, dict):
            scan_results = cast("dict[str, Any]", scan_results)
            self.scan_results = scan_results
            self.final_scan_result = self._format_final_scan_result(scan_results)
        self._hydrate_llm_usage(data.get("llm_usage"))
        self._save_seq = max(self._save_seq, int_or_zero(data.get("seq")))
        self._turn_count = max(self._turn_count, int_or_zero(data.get("turn_count")))
        self.run_record["seq"] = self._save_seq
        self.run_record["turn_count"] = self._turn_count
        revision = data.get("report_artifacts_revision")
        if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0:
            persisted_report_revision = revision
        logger.info("report state hydrated run.json from %s", run_dir)

    if vuln_data is not None:
        self.vulnerability_reports = [cast("dict[str, Any]", report) for report in vuln_data]
        for r in self.vulnerability_reports:
            # A finding written before the class was persisted still carries the
            # metadata of its class, so name the class it always had.
            if not r.get("finding_class"):
                r["finding_class"] = "dependency_cve" if r.get("dependency_metadata") else "dynamic"
            title = r.get("title")
            stale_md = False
            if isinstance(title, str):
                r["title"] = clean_title(title)
                stale_md = r["title"] != title
            rid = r.get("id")
            # A finding already on disk keeps its markdown, unless cleaning
            # changed the title: the heading on disk then needs a rewrite.
            if isinstance(rid, str) and not stale_md:
                self._saved_vuln_ids.add(rid)
        logger.info(
            "report state hydrated %d vulnerability report(s)",
            len(self.vulnerability_reports),
        )

    if data and json_path.exists():
        # Legacy records predate the durable revision and are revision 0.
        # Both counters must agree so usage-only resume saves do not rewrite
        # unchanged report projections.
        restored_revision = persisted_report_revision or 0
        self._report_artifacts_revision = restored_revision
        self._persisted_report_artifacts_revision = restored_revision

    # Same-process resume: the caido ledger may still hold entries already
    # merged into the persisted record. Seed both offsets from the live
    # snapshot so _sync_scope_decisions() only processes new denials —
    # never re-appends entries or re-adds previously counted overflow.
    try:
        from lyrashield.tools.proxy import caido_api

        snapshot = caido_api.get_scope_decisions()
    except ImportError:
        snapshot = None
    if isinstance(snapshot, dict):
        violations = snapshot.get("violations")
        if isinstance(violations, list):
            self._scope_violations_seen = max(self._scope_violations_seen, len(violations))
        dropped = snapshot.get("dropped")
        if isinstance(dropped, int) and not isinstance(dropped, bool):
            self._scope_dropped_seen = max(self._scope_dropped_seen, dropped)


def save_run_data(
    self: ReportState,
    mark_complete: bool = False,
    status: str | None = None,
) -> bool:
    with self._report_artifacts_lock:
        return self._save_run_data_locked(mark_complete=mark_complete, status=status)


def save_run_data_locked(
    self: ReportState,
    mark_complete: bool = False,
    status: str | None = None,
) -> bool:
    """Persist scan artifacts and return whether all required writes
    succeeded.

    When ``mark_complete=True`` and the required receipt cannot be
    persisted, the in-memory completion fields are reverted so a later
    incidental save cannot persist a completed record without a durable
    receipt.
    """
    # Snapshot pre-completion state so a failed receipt write can revert
    # in-memory completion eligibility — a failed persistence must not
    # leave the lifecycle marked completed (E3 monotonic fail-closed).
    prev_status = self.run_record.get("status")
    prev_end_time = self.end_time

    if mark_complete:
        self.end_time = datetime.now(UTC).isoformat()
        self.run_record["end_time"] = self.end_time
        self.run_record["status"] = "completed"
        self._set_phase("completed")
    elif status and self.run_record.get("status") != "completed":
        current_status = self.run_record.get("status")
        if status == "stopped" and current_status in {"failed", "interrupted"}:
            status = str(current_status)
        if self.end_time is None:
            self.end_time = datetime.now(UTC).isoformat()
        self.run_record["end_time"] = self.end_time
        self.run_record["status"] = status
        self._set_phase(status)

    self._sync_progress()
    self._sync_llm_usage_record()
    persisted = self._save_artifacts()

    # If the receipt write failed and we had marked complete, revert the
    # in-memory completion so a later incidental save cannot persist a
    # completed record without a durable receipt. Keep receipt_persisted
    # as False — the write actually failed.
    if mark_complete and not self.receipt_persisted:
        self.run_record["status"] = prev_status
        self.run_record["end_time"] = prev_end_time
        self.end_time = prev_end_time
        if prev_status != "completed":
            self._set_phase(str(prev_status or "running"))
    return persisted


def save_artifacts(
    self: ReportState,
    *,
    evidence: Any,
    quality: Any,
    runtime_state_dir: Callable[[Path], Path],
    read_agent_graph: Callable[[Path], dict[str, Any]],
    coverage_ledger_entries: Callable[[], list[dict[str, Any]]],
    write_executive_report_fn: Callable[..., None],
    validate_run_record_fn: Callable[[dict[str, Any]], None],
    write_run_record_fn: Callable[..., None],
    write_resume_record_fn: Callable[..., None],
    logger: logging.Logger,
) -> bool:
    """Write scan artifacts under ``run_dir``.

    Returns ``True`` only when every required artifact (vulnerabilities,
    run record) is successfully persisted. Non-fatal artifacts (executive
    report, SARIF) may fail and be logged, but they do not make this
    return ``False``. Callers that must know whether durability succeeded
    (e.g. vulnerability report tools) should act on the return value.
    """
    run_dir = self.get_run_dir()
    run_dir.mkdir(parents=True, exist_ok=True)

    evidence_v1_1 = evidence.record_supports_evidence_v1_1(self.run_record)

    report_artifacts_revision = self._report_artifacts_revision
    write_report_artifacts = self._persisted_report_artifacts_revision != report_artifacts_revision
    report_artifacts_persisted = not write_report_artifacts
    if write_report_artifacts:
        # Each artifact is isolated so a failure in one cannot skip the others;
        # run.json is the billing/cost receipt and is written last.
        optional_artifacts_persisted = True
        if self.final_scan_result:
            try:
                write_executive_report_fn(run_dir, self.final_scan_result)
            except (OSError, RuntimeError):
                optional_artifacts_persisted = False
                logger.exception("Executive report write failed (non-fatal)")

        # The worker must distinguish a clean scan from missing output. Always
        # write this artifact after a content change, including for a valid
        # zero-finding result. Failure makes the whole save fail.
        try:
            projections_persisted = self._write_report_projections(
                self.vulnerability_reports, self._saved_vuln_ids
            )
        except (OSError, RuntimeError):
            logger.exception("Vulnerabilities artifact write failed (required)")
            self.receipt_persisted = False
            self.run_record["receipt_persisted"] = False
            return False
        if not projections_persisted:
            optional_artifacts_persisted = False
        report_artifacts_persisted = optional_artifacts_persisted

    if evidence_v1_1:
        # Coverage and the threat model change independently of the
        # finding projections (agents record coverage entries without
        # touching findings), so they refresh on every save.
        if not self._write_evidence_artifacts(run_dir):
            report_artifacts_persisted = False
        # Replay-guard denials and the honest quality ledger are derived
        # from observed activity only — unexercised surfaces stay
        # unassessed, never smoothed into a coverage number.
        admitted_hosts: dict[str, int] = {}
        try:
            admitted_hosts = self._sync_scope_decisions()
        except Exception:
            logger.exception("scope_violations sync failed (non-fatal)")
        try:
            recorded = self.run_record.get("scope_violations")
            recorded = recorded if isinstance(recorded, dict) else {}
            self.run_record["scan_quality"] = quality.build_scan_quality(
                run_record=self.run_record,
                agent_graph=read_agent_graph(runtime_state_dir(run_dir)),
                coverage_entries=coverage_ledger_entries(),
                vulnerability_reports=self.vulnerability_reports,
                scope_decisions={
                    "violations": recorded.get("entries") or [],
                    "dropped": recorded.get("dropped") or 0,
                    "admitted_hosts": admitted_hosts,
                },
            )
        except Exception:
            report_artifacts_persisted = False
            logger.exception("scan_quality build failed (non-fatal)")
        # The result manifest binds every emitted artifact to this record
        # by checksum — the immutable link the worker verifies against.
        try:
            self.run_record["result_manifest"] = evidence.build_result_manifest(run_dir)
        except Exception:
            logger.exception("result manifest build failed (non-fatal)")

    persisted_report_revision = self._persisted_report_artifacts_revision
    if report_artifacts_persisted:
        persisted_report_revision = report_artifacts_revision
    self.run_record["report_artifacts_revision"] = persisted_report_revision
    persisted_report_revision = self._persisted_report_artifacts_revision
    if report_artifacts_persisted:
        persisted_report_revision = report_artifacts_revision
    self.run_record["report_artifacts_revision"] = persisted_report_revision

    try:
        # Validate the full worker contract before any write: the first
        # observable run.json must already be complete and versioned.
        validate_run_record_fn(self.run_record)
        # Snapshot claims persistence optimistically so the durable record
        # carries receipt_persisted=true the moment it lands on disk; a
        # failed write reverts both the record flag and in-memory state.
        self.receipt_persisted = True
        self.run_record["receipt_persisted"] = True
        write_run_record_fn(run_dir, self.run_record)
    except (OSError, RuntimeError):
        # The run record carries the cost receipt the worker reconciles
        # against the provider total; a silent skip here mis-bills the
        # scan as if it cost nothing. Flag it, never swallow it.
        self.receipt_persisted = False
        self.run_record["receipt_persisted"] = False
        logger.exception("run.json receipt persist FAILED — cost receipt not written")
        return False

    # Write the private resume record with unsanitized execution fields so
    # a resumed scan can recover cloned_repo_path / source_path values that
    # the public run.json intentionally redacts (comment #5). This is
    # non-fatal to the receipt; a missing resume file can still be recovered
    # from the public record (resume will just lose host paths).
    if write_report_artifacts:
        try:
            write_resume_record_fn(
                run_dir,
                targets_info=self._raw_targets_info,
                local_sources=self._raw_local_sources,
            )
        except (OSError, RuntimeError):
            report_artifacts_persisted = False
            logger.exception("Resume record write failed (non-fatal)")

    if report_artifacts_persisted:
        self._persisted_report_artifacts_revision = persisted_report_revision

    logger.info("Essential scan data saved to: %s", run_dir)
    return True
