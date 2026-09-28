# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
# Controlled subprocess boundary: provenance lookup resolves Git and uses shell=False.
# Same-name aliases below are explicit re-exports for strict mypy compatibility.
# ruff: noqa: PLC0414
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Optional, cast

from agents.usage import Usage

from lyrashield.artifacts import evidence as _evidence
from lyrashield.artifacts import quality as _quality
from lyrashield.artifacts.repo_context import (
    _derive_repository_context as _derive_repository_context,
)
from lyrashield.artifacts.repo_context import (
    _git_head as _git_head,
)
from lyrashield.artifacts.repo_context import (
    _parse_repo_full_name as _parse_repo_full_name,
)
from lyrashield.artifacts.repo_context import (
    _sarif_repository_context as _sarif_repository_context,
)
from lyrashield.artifacts.sarif import write_sarif
from lyrashield.artifacts.state_findings import (
    _CONTROL_CHARS as _CONTROL_CHARS,
)
from lyrashield.artifacts.state_findings import (
    _FINDING_TEXT_FIELDS as _FINDING_TEXT_FIELDS,
)
from lyrashield.artifacts.state_findings import (
    _FINDING_URL_FIELDS as _FINDING_URL_FIELDS,
)
from lyrashield.artifacts.state_findings import (
    _MAX_COLLECTION_SIZE as _MAX_COLLECTION_SIZE,
)
from lyrashield.artifacts.state_findings import (
    _MAX_FINDING_SERIALIZED_SIZE as _MAX_FINDING_SERIALIZED_SIZE,
)
from lyrashield.artifacts.state_findings import (
    _MAX_METADATA_DEPTH as _MAX_METADATA_DEPTH,
)
from lyrashield.artifacts.state_findings import (
    _MAX_TEXT_LENGTH as _MAX_TEXT_LENGTH,
)
from lyrashield.artifacts.state_findings import (
    _V1_1_FINDING_FIELDS as _V1_1_FINDING_FIELDS,
)
from lyrashield.artifacts.state_findings import (
    _V1_1_FINDING_STRUCT_FIELDS as _V1_1_FINDING_STRUCT_FIELDS,
)
from lyrashield.artifacts.state_findings import (
    _V1_1_FINDING_TEXT_FIELDS as _V1_1_FINDING_TEXT_FIELDS,
)
from lyrashield.artifacts.state_findings import (
    _bound_collection as _bound_collection,
)
from lyrashield.artifacts.state_findings import (
    _clean_title as _clean_title,
)
from lyrashield.artifacts.state_findings import (
    _recursive_sanitize_unknown as _recursive_sanitize_unknown,
)
from lyrashield.artifacts.state_findings import (
    _sanitize_code_locations as _sanitize_code_locations,
)
from lyrashield.artifacts.state_findings import (
    _truncate_text as _truncate_text,
)
from lyrashield.artifacts.state_findings import (
    add_vulnerability_report as _add_vulnerability_report,
)
from lyrashield.artifacts.state_findings import (
    sanitize_finding as sanitize_finding,
)
from lyrashield.artifacts.state_findings import (
    update_vulnerability_report as _update_vulnerability_report,
)
from lyrashield.artifacts.state_persistence import (
    REQUIRED_RUN_RECORD_FIELDS as REQUIRED_RUN_RECORD_FIELDS,
)
from lyrashield.artifacts.state_persistence import (
    RUN_RECORD_SCHEMA_VERSION as RUN_RECORD_SCHEMA_VERSION,
)
from lyrashield.artifacts.state_persistence import (
    get_run_dir as _get_run_dir,
)
from lyrashield.artifacts.state_persistence import (
    hydrate_from_run_dir as _hydrate_from_run_dir,
)
from lyrashield.artifacts.state_persistence import (
    initial_run_record as initial_run_record,
)
from lyrashield.artifacts.state_persistence import (
    save_artifacts as _persist_artifacts,
)
from lyrashield.artifacts.state_persistence import (
    save_run_data as _save_run_data,
)
from lyrashield.artifacts.state_persistence import (
    save_run_data_locked as _persist_run_data_locked,
)
from lyrashield.artifacts.state_persistence import (
    validate_run_record as validate_run_record,
)
from lyrashield.artifacts.state_projection import (
    _coverage_ledger_entries as _coverage_ledger_entries,
)
from lyrashield.artifacts.state_projection import (
    _read_agent_graph as _read_agent_graph,
)
from lyrashield.artifacts.state_projection import (
    format_final_scan_result as _format_scan_result,
)
from lyrashield.artifacts.state_projection import (
    sanitize_attachments as sanitize_attachments,
)
from lyrashield.artifacts.state_projection import (
    sanitize_local_sources as sanitize_local_sources,
)
from lyrashield.artifacts.state_projection import (
    sanitize_targets_info as sanitize_targets_info,
)
from lyrashield.artifacts.state_projection import (
    write_evidence_artifacts as _project_evidence_artifacts,
)
from lyrashield.artifacts.state_projection import (
    write_report_projections as _project_report_projections,
)
from lyrashield.artifacts.usage import (
    _METERED_USD_PER_MILLION,
    LLMUsageLedger,
    _int_or_zero,
    _round_cost,
    extract_provider_usage,
)
from lyrashield.artifacts.writer import (
    read_run_record,
    write_executive_report,
    write_resume_record,
    write_run_record,
    write_vulnerabilities,
)
from lyrashield.runtime.session_manager import CLEANUP_FAILED, CLEANUP_REMOVED
from lyrashield.telemetry import posthog, scarf
from lyrashield.utils.redaction import redact_text
from strix.config import codex
from strix.config.loader import load_settings
from strix.core.paths import run_dir_for, runtime_state_dir


logger = logging.getLogger(__name__)


_global_report_state: Optional["ReportState"] = None

_ALLOWED_PHASES = frozenset({"setup", "running", "finalizing", "completed", "stopped"})

# Schema version for run.json.
#
# run.json is a cross-repo contract: the LyraShield worker parses it to decide a
# scan's terminal status, cost, and coverage. Until now it carried no version, so
# a consumer had no way to detect an incompatible producer other than by probing
# for individual fields.
#
# Bump the MAJOR component for a breaking change (a field removed, renamed, or
# given new semantics) and the MINOR component for additive, backward-compatible
# fields. The worker's zod schema uses `.strip()`, so unknown keys are ignored —
# additive changes are safe to ship ahead of a worker update.


# Schema 1.1 adds per-finding evidence (counterevidence, confidence rationale,
# structured advisory_cvss, severity_change_conditions, engine-attested
# fix_verification, bounded http_exchange_ids, append-only revision history)
# plus coverage.json, threat_model.json, http_exchanges.json and an inline
# result manifest. Task-12 additions: ``scope_violations`` (bounded replay-guard
# denial evidence) and ``scan_quality`` (per-surface observed-vs-declared
# accounting). ``sandbox_capabilities`` — the probed backend capability record —
# is unconditional run provenance, not part of the gated evidence surface. The
# whole surface is gated on ``LYRASHIELD_RUN_RECORD_V1_1`` (default off) so
# readers deploy before writers; a run keeps the version it was created with.

# Fields every run.json write must carry from its first observable appearance
# (the worker parses this contract at any point in the run, not just at the
# end). Writers validate against this list before persisting.


def _strix_version() -> str | None:
    """Best-effort package version for the SARIF tool.driver.version field."""
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        return None


def get_global_report_state() -> Optional["ReportState"]:
    return _global_report_state


# Finding fields sanitized as free text at the persistence boundary. Fields
# not listed here (id, severity, timestamp, cvss, cve, cwe, method,
# finding_class, control_ids, agent_id) are structural identifiers copied
# verbatim — they carry no operator or target-derived secrets.

# Schema-1.1 finding fields sanitized as free text when the record carries
# them. A 1.0 record must not emit them at all (readers deploy first).
# Schema-1.1 structured fields: validated at intake, recursively sanitized
# here so nested model-controlled strings still pass through redaction.

# Deterministic bounds for artifact fields (E4): unbounded model-controlled
# text could exhaust disk/memory or smuggle payloads through projections.
# Persisted scope-violation entries bound (ledger bound is lower; this caps
# the durable list merged across saves).
_MAX_SCOPE_VIOLATION_ENTRIES = 500


def set_global_report_state(report_state: Optional["ReportState"]) -> None:
    global _global_report_state  # noqa: PLW0603
    _global_report_state = report_state
    # New run: drop any streamed-cost entries a prior run left unconsumed.
    streamed_openrouter_costs.clear()


class ReportState:
    """Per-scan product artifact state plus artifact writer.

    The Agents SDK owns model/tool execution, tracing, and conversation
    persistence. This store keeps only Strix-owned scan artifacts and
    report metadata. Live UI projections belong to the interface layer.

    It does not consume SDK tracing processors.
    """

    def __init__(self, run_name: str | None = None):
        self.run_name = run_name

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        # Raw (unsanitized) targets and local sources are kept for SARIF
        # provenance and for the private resume.json file. They are never
        # written to the public worker contract (run.json).
        self._repo_context_targets: list[dict[str, Any]] = []
        self._raw_targets_info: list[dict[str, Any]] = []
        self._raw_local_sources: list[dict[str, Any]] = []
        self._llm_usage = LLMUsageLedger()
        self._provider_usage_receipts: dict[str, dict[str, Any]] = {}
        configured_model = load_settings().llm.model
        auth_mode = codex.auth_mode(configured_model)
        if auth_mode == "subscription":
            self._llm_usage.set_zero_cost_model(configured_model)
        self.run_record = initial_run_record(run_name, auth_mode=auth_mode)
        # initial_run_record generated the run_id; adopt it on the instance.
        self.run_id = str(self.run_record["run_id"])
        self.start_time = str(self.run_record["start_time"])
        self.end_time: str | None = None
        self._run_dir: Path | None = None
        self._saved_vuln_ids: set[str] = set()
        self._save_seq = 0
        self._turn_count = 0
        # Finding/report projections are much larger than run.json and do not
        # change on an LLM usage update. Write them once per content change;
        # run.json still persists every usage/cost update for billing safety.
        self._report_artifacts_revision = 0
        self._persisted_report_artifacts_revision = -1
        self._report_artifacts_lock = threading.RLock()
        self.receipt_persisted: bool = True

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None
        # Invoked with the sanitized revised snapshot after a revision has been
        # durably persisted — the UI projection refresh point.
        self.vulnerability_updated_callback: Callable[[dict[str, Any]], None] | None = None

        # Concurrency-safe web-search reservation boundary (I20): the scan's
        # count/cost limits are checked and reserved atomically, so concurrent
        # tool calls cannot overspend either limit. Process-local is the real
        # boundary today — one engine process owns a scan's budget.
        self._web_search_lock = threading.Lock()
        self._web_search_inflight = 0
        self._web_search_reserved_cost = 0.0

        self._sarif_repo_ctx: dict[str, Any] | None = None
        self._sarif_repo_ctx_ready: bool = False

        self.posthog_scan_ended_sent: bool = False
        self.scarf_scan_ended_sent: bool = False
        self.scan_ended_exit_reason: str | None = None
        # How many scope-violation ledger entries have already been merged
        # into run_record["scope_violations"]["entries"], and how much of the
        # process-cumulative ledger overflow has already been accounted into
        # the persisted ``dropped`` count.
        self._scope_violations_seen = 0
        self._scope_dropped_seen = 0

    def get_run_dir(self) -> Path:
        return _get_run_dir(self, run_dir_for=run_dir_for)

    def hydrate_from_run_dir(self) -> None:
        _hydrate_from_run_dir(
            self,
            read_run_record=read_run_record,
            int_or_zero=_int_or_zero,
            clean_title=_clean_title,
            logger=logger,
        )

    add_vulnerability_report = _add_vulnerability_report

    update_vulnerability_report = _update_vulnerability_report

    def set_sandbox_capabilities(self, capabilities: dict[str, Any]) -> None:
        """Record the probed sandbox capability set as run provenance.

        The record comes from the post-start capability probe — only
        capabilities the backend verifiably delivered are marked
        ``supported``; ``unprobed`` entries carry named preflight
        degradations so a missing guarantee is never silent.
        """
        if isinstance(capabilities, dict):
            self.run_record["sandbox_capabilities"] = capabilities

    def _sync_scope_decisions(self) -> dict[str, int]:
        """Merge new replay-guard denials into the run record (bounded).

        Violations arrive from the process-local ledger in
        ``lyrashield.tools.proxy.caido_api`` — every denied request the
        replay guard saw. The persisted list is capped; overflow is counted
        in ``dropped`` so the record stays honest about truncation. Returns
        the per-host admitted-request counts for quality accounting.
        """
        from lyrashield.tools.proxy import caido_api

        snapshot = caido_api.get_scope_decisions()
        violations = snapshot["violations"]
        new_entries = violations[self._scope_violations_seen :]
        self._scope_violations_seen = len(violations)

        persisted = self.run_record.get("scope_violations")
        existing: list[dict[str, Any]] = []
        # snapshot["dropped"] is process-cumulative; add only the new overflow
        # so repeated saves cannot inflate the persisted count.
        ledger_dropped = int(snapshot["dropped"])
        dropped = ledger_dropped - self._scope_dropped_seen
        self._scope_dropped_seen = ledger_dropped
        if isinstance(persisted, dict):
            raw_entries = persisted.get("entries")
            if isinstance(raw_entries, list):
                existing = [e for e in raw_entries if isinstance(e, dict)]
            dropped += int(persisted.get("dropped") or 0)

        keep = _MAX_SCOPE_VIOLATION_ENTRIES - len(existing)
        if len(new_entries) > keep:
            dropped += len(new_entries) - max(0, keep)
            new_entries = new_entries[: max(0, keep)]
        existing.extend(new_entries)
        self.run_record["scope_violations"] = {
            "entries": existing,
            "dropped": dropped,
            "total": len(existing) + dropped,
        }
        return cast("dict[str, int]", snapshot["admitted_hosts"])

    def set_evidence_export_outcome(self, outcome: dict[str, Any]) -> None:
        """Record the HTTP exchange evidence export result on the run record.

        ``outcome`` is the status dict from
        :func:`lyrashield.artifacts.evidence.export_http_exchange_evidence` —
        ``exported``/``partial``/``skipped``/``failed``. It is evidence-status
        metadata only: a failed or partial export is an explicit
        incomplete-evidence marker, never a verification receipt.
        """
        self.run_record["evidence_export"] = dict(outcome)

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        # E4: return sanitized snapshots so dedupe and other consumers never
        # see raw secrets or host paths from the in-memory reports.
        return [
            sanitize_finding(
                report,
                include_internal_paths=not self._is_whitebox,
                schema_version=str(self.run_record.get("schema_version", "1.0")),
            )
            for report in self.vulnerability_reports
        ]

    def record_sdk_usage(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
        response_id: str | None = None,
    ) -> None:
        """Record SDK-native token usage for one completed model run/cycle."""
        self._llm_usage.record(
            agent_id=agent_id,
            agent_name=agent_name,
            model=model,
            usage=usage,
            provider_receipt=self._provider_usage_receipts.pop(response_id, None)
            if response_id
            else None,
        )
        self._turn_count += 1
        self._set_phase("running")
        self.save_run_data()

    def capture_provider_usage(self, response: Any) -> None:
        """Capture raw numeric buckets before the SDK fills absent fields with zero."""
        receipt = extract_provider_usage(response)
        if receipt is not None:
            self._provider_usage_receipts[receipt["response_id"]] = receipt

    def provider_usage_receipt(self, response_id: str | None) -> dict[str, Any] | None:
        return self._provider_usage_receipts.get(response_id) if response_id else None

    def record_observed_llm_cost(
        self,
        cost: float,
        *,
        model: str | None = None,
        response_id: str | None = None,
    ) -> None:
        self._llm_usage.record_observed_cost(cost, model=model, response_id=response_id)

    def get_total_llm_usage(self) -> dict[str, Any]:
        return dict(self.run_record.get("llm_usage") or self._build_llm_usage_record())

    def get_total_llm_cost(self) -> float:
        """Live accumulated LLM cost, independent of the persisted run-record snapshot."""
        return self._llm_usage.total_cost

    def reserve_web_search_slot(
        self,
        estimated_cost: float,
        *,
        max_calls: int,
        budget_usd: float,
    ) -> str | None:
        """Atomically reserve one web-search call slot and its max charge.

        Returns an error string when the call would exceed the scan's
        call-count or web-search cost limit (counting in-flight calls and
        reserved charges), or None when the slot is reserved. Pair with
        :meth:`commit_web_search_call` on success or
        :meth:`release_web_search_reservation` on failure/cancellation.
        """
        with self._web_search_lock:
            committed_count, committed_cost = self.get_web_search_stats()
            if max_calls > 0 and committed_count + self._web_search_inflight >= max_calls:
                return (
                    f"Web search call limit reached "
                    f"({committed_count + self._web_search_inflight}/{max_calls})."
                )
            if (
                budget_usd > 0
                and committed_cost + self._web_search_reserved_cost + estimated_cost > budget_usd
            ):
                return (
                    f"Web search budget exceeded "
                    f"(${committed_cost + self._web_search_reserved_cost:.4f}/${budget_usd:.2f})."
                )
            self._web_search_inflight += 1
            self._web_search_reserved_cost += max(0.0, estimated_cost)
            return None

    def release_web_search_reservation(self, estimated_cost: float) -> None:
        """Roll back an uncommitted web-search reservation."""
        with self._web_search_lock:
            self._web_search_inflight = max(0, self._web_search_inflight - 1)
            self._web_search_reserved_cost = max(
                0.0, self._web_search_reserved_cost - max(0.0, estimated_cost)
            )

    def commit_web_search_call(
        self,
        cost: float,
        *,
        query: str,
        mode: str,
        provider: str = "parallel",
        estimated_cost: float = 0.0,
    ) -> None:
        """Commit a reserved web-search call at its actual charge."""
        with self._web_search_lock:
            self._web_search_inflight = max(0, self._web_search_inflight - 1)
            self._web_search_reserved_cost = max(
                0.0, self._web_search_reserved_cost - max(0.0, estimated_cost)
            )
        self.record_web_search_cost(cost, query=query, mode=mode, provider=provider)

    def record_web_search_cost(
        self,
        cost: float,
        *,
        query: str,
        mode: str,
        provider: str = "parallel",
    ) -> None:
        """Record a web search call's cost and append it to the run record."""
        if cost > 0:
            # Ancillary provider charge: stays metered even when the model
            # tokens ride a subscription (I19).
            self._llm_usage.record_ancillary_cost("web_search", cost)
        entry: dict[str, Any] = {
            "provider": provider,
            "mode": mode,
            "query": query,
            "cost": _round_cost(cost),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.run_record.setdefault("web_search_usage", []).append(entry)
        self.save_run_data()

    def get_web_search_stats(self) -> tuple[int, float]:
        """Return (call_count, total_cost) for web search in this run."""
        entries = self.run_record.get("web_search_usage", [])
        if not isinstance(entries, list):
            return 0, 0.0
        total_cost = sum(float(e.get("cost", 0.0)) for e in entries)
        return len(entries), total_cost

    def update_scan_final_fields(
        self,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> None:
        _redact_paths = not self._is_whitebox
        self.scan_results = {
            "scan_completed": True,
            "executive_summary": redact_text(
                executive_summary.strip(), include_internal_paths=_redact_paths
            ),
            "methodology": redact_text(methodology.strip(), include_internal_paths=_redact_paths),
            "technical_analysis": redact_text(
                technical_analysis.strip(), include_internal_paths=_redact_paths
            ),
            "recommendations": redact_text(
                recommendations.strip(), include_internal_paths=_redact_paths
            ),
            "success": True,
        }

        self.final_scan_result = self._format_final_scan_result(self.scan_results)
        self.run_record["scan_results"] = self.scan_results
        self.run_record.pop("terminal_reason", None)
        self._report_artifacts_revision += 1

        logger.info("Updated scan final fields")
        self._set_phase("finalizing")
        self.save_run_data()
        self.save_run_data(mark_complete=True)
        posthog.end(self, exit_reason="finished_by_tool")
        scarf.end(self, exit_reason="finished_by_tool")

    @property
    def _is_whitebox(self) -> bool:
        """True if any target is a local source tree (whitebox / source-aware)."""
        if not self.scan_config:
            return False
        targets = self.scan_config.get("targets") or []
        return any(isinstance(t, dict) and t.get("type") == "local_code" for t in targets)

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_record["status"] = "running"
        self.run_record["end_time"] = None
        self.run_record.pop("scan_results", None)
        self.run_record.pop("terminal_reason", None)
        self.end_time = None
        self.scan_results = None
        self.final_scan_result = None
        targets = [t for t in (config.get("targets") or []) if isinstance(t, dict)]
        # Keep raw target and local-source details in memory only. The durable
        # record carries sanitized forms; the private resume.json carries the
        # originals for resume/SARIF provenance (comment #5).
        self._repo_context_targets = [dict(t) for t in targets if t.get("type") == "repository"]
        self._raw_targets_info = [dict(t) for t in targets]
        self._raw_local_sources = [
            dict(s) for s in config.get("local_sources", []) if isinstance(s, dict)
        ]
        self._report_artifacts_revision += 1
        instruction = str(config.get("user_instructions") or "")
        self.run_record.update(
            {
                "targets_info": sanitize_targets_info(targets),
                # Raw instructions are private execution configuration: the
                # durable receipt records only that one existed and its size.
                "instruction": None,
                "instruction_chars": len(instruction),
                "scan_mode": config.get("scan_mode", "deep"),
                "diff_scope": config.get("diff_scope", {"active": False}),
                "non_interactive": bool(config.get("non_interactive", False)),
                "local_sources": sanitize_local_sources(config.get("local_sources", [])),
                "attachments": sanitize_attachments(config.get("attachments", [])),
                "scope_mode": config.get("scope_mode", "auto"),
                "diff_base": config.get("diff_base"),
                "diff_head": config.get("diff_head"),
                "repository_revision": config.get("repository_revision"),
            }
        )
        self._set_phase("running")

    save_run_data = _save_run_data

    def _save_run_data_locked(
        self,
        mark_complete: bool = False,
        status: str | None = None,
    ) -> bool:
        return _persist_run_data_locked(
            self,
            mark_complete=mark_complete,
            status=status,
        )

    def set_terminal_reason(self, reason: str) -> None:
        """Record a machine-readable non-completion reason for worker callers."""
        if self.run_record.get("status") != "completed":
            self.run_record["terminal_reason"] = reason

    def set_sandbox_cleanup_status(self, sandbox_removed: bool) -> None:
        """Backward-compatible boolean wrapper around :meth:`set_cleanup_outcome`."""
        self.set_cleanup_outcome(CLEANUP_REMOVED if sandbox_removed else CLEANUP_FAILED)

    def set_cleanup_outcome(
        self,
        outcome: str,
        *,
        last_error: str | None = None,
    ) -> None:
        """Persist the sandbox cleanup outcome monotonically.

        ``removed`` is terminal; ``failed`` stays failed (optionally with a
        fresher error) until a confirmed removal supersedes it; a later
        ``not_found`` (cache miss) can never erase a recorded failure or
        removal. ``sandbox_removed`` stays in the record for worker
        backward-readability.
        """
        current = self.run_record.get("cleanup")
        prior: dict[str, Any] = current if isinstance(current, dict) else {}
        prior_status = prior.get("status")
        if prior_status == CLEANUP_REMOVED:
            return
        if prior_status == CLEANUP_FAILED and outcome != CLEANUP_REMOVED:
            outcome = CLEANUP_FAILED
        record: dict[str, Any] = {
            "status": outcome,
            "sandbox_removed": outcome == CLEANUP_REMOVED,
        }
        if last_error is not None:
            record["last_error"] = last_error
        elif prior.get("last_error"):
            record["last_error"] = prior["last_error"]
        if prior.get("attempts"):
            record["attempts"] = prior["attempts"]
        self.run_record["cleanup"] = record
        self.save_run_data()

    def cleanup(self, status: str = "stopped") -> None:
        self.save_run_data(status=status)

    _format_final_scan_result = staticmethod(_format_scan_result)

    def _write_report_projections(
        self,
        reports: list[dict[str, Any]],
        saved_vuln_ids: set[str],
    ) -> bool:
        return _project_report_projections(
            self,
            reports,
            saved_vuln_ids,
            write_vulnerabilities=write_vulnerabilities,
            write_sarif=write_sarif,
            tool_version=_strix_version(),
            logger=logger,
        )

    def _write_evidence_artifacts(self, run_dir: Path) -> bool:
        return _project_evidence_artifacts(
            self,
            run_dir,
            evidence=_evidence,
            runtime_state_dir=runtime_state_dir,
            read_agent_graph=_read_agent_graph,
            logger=logger,
        )

    def _save_artifacts(self) -> bool:
        return _persist_artifacts(
            self,
            evidence=_evidence,
            quality=_quality,
            runtime_state_dir=runtime_state_dir,
            read_agent_graph=_read_agent_graph,
            coverage_ledger_entries=_coverage_ledger_entries,
            write_executive_report_fn=write_executive_report,
            validate_run_record_fn=validate_run_record,
            write_run_record_fn=write_run_record,
            write_resume_record_fn=write_resume_record,
            logger=logger,
        )

    _sarif_repository_context = _sarif_repository_context

    _derive_repository_context = _derive_repository_context

    def _sync_llm_usage_record(self) -> None:
        self.run_record["llm_usage"] = self._build_llm_usage_record()

    def _set_phase(self, phase: str) -> None:
        """Set a coarse, stable phase label on the run record."""
        if phase not in _ALLOWED_PHASES:
            phase = "stopped"
        self.run_record["phase"] = phase

    def _sync_progress(self) -> None:
        """Advance the monotonic save sequence and copy live progress counters."""
        self._save_seq += 1
        self.run_record["seq"] = self._save_seq
        self.run_record["turn_count"] = self._turn_count

    def _build_llm_usage_record(self) -> dict[str, Any]:
        return self._llm_usage.to_record()

    def _hydrate_llm_usage(self, raw_usage: Any) -> None:
        self._llm_usage.hydrate(raw_usage)
        self._sync_llm_usage_record()


def _as_dict(obj: Any) -> dict[str, Any] | None:
    """Return *obj* as a str-keyed dict, or None if it isn't a mapping."""
    if isinstance(obj, dict):
        return cast("dict[str, Any]", obj)
    return None


def openrouter_stream_cost(usage: Any) -> float | None:
    """Total OpenRouter-reported cost from a raw stream ``usage`` block, or None.

    Non-BYOK responses bill everything to ``usage.cost``. BYOK responses put the
    OpenRouter fee in ``usage.cost`` (often 0) and the provider charge in
    ``usage.cost_details.upstream_inference_cost``, so BYOK totals sum the two.
    """
    if not isinstance(usage, dict):
        return None
    total = 0.0
    cost = usage.get("cost")
    if isinstance(cost, int | float) and cost > 0:
        total += float(cost)
    if bool(usage.get("is_byok")):
        details = usage.get("cost_details")
        upstream = details.get("upstream_inference_cost") if isinstance(details, dict) else None
        if isinstance(upstream, int | float) and upstream > 0:
            total += float(upstream)
    return total if total > 0 else None


def _response_id(completion_response: Any) -> str | None:
    response_id = getattr(completion_response, "id", None)
    if response_id is None and isinstance(completion_response, dict):
        response_id = cast("dict[str, Any]", completion_response).get("id")
    return response_id if isinstance(response_id, str) and response_id else None


class StreamedOpenRouterCosts:
    """Correlates OpenRouter's per-stream cost from the parser to the cost callback.

    LiteLLM rebuilds streamed responses from token-only chunks and drops the
    ``usage.cost`` OpenRouter reports in its final stream chunk (its non-streamed
    path preserves it; streaming snapshots hidden params at stream start). Every
    scan streams, so the OpenRouter streaming handler (see strix.config.models)
    records the cost here keyed by response id, and the callback takes it back out
    for the matching rebuilt response. Entries are removed on read; ``clear()``
    runs per scan so nothing accumulates across runs.
    """

    def __init__(self) -> None:
        self._costs: dict[str, float] = {}
        self._lock = threading.Lock()

    def remember(self, response_id: Any, usage: Any) -> None:
        cost = openrouter_stream_cost(usage)
        if cost is None or not (isinstance(response_id, str) and response_id):
            return
        with self._lock:
            self._costs[response_id] = cost

    def take(self, completion_response: Any) -> float | None:
        response_id = _response_id(completion_response)
        if response_id is None:
            return None
        with self._lock:
            return self._costs.pop(response_id, None)

    def clear(self) -> None:
        with self._lock:
            self._costs.clear()


streamed_openrouter_costs = StreamedOpenRouterCosts()


def litellm_cost_callback(
    kwargs: Any,
    completion_response: Any,
    _start_time: Any = None,
    _end_time: Any = None,
) -> None:
    """LiteLLM ``success_callback`` adapter; forwards observed cost to the active scan."""
    kwargs_dict = _as_dict(kwargs)
    model = kwargs_dict.get("model") if kwargs_dict is not None else None
    if isinstance(model, str) and model.strip().lower().split("/")[-1] in _METERED_USD_PER_MILLION:
        # Azure's LiteLLM response_cost can be stale for GPT-6. The usage
        # ledger prices the provider token receipt with the pinned rate card.
        return
    cost: float | None = None
    if kwargs_dict is not None:
        raw = kwargs_dict.get("response_cost")
        if isinstance(raw, int | float) and raw > 0:
            cost = float(raw)

    if cost is None:
        hidden = _as_dict(getattr(completion_response, "_hidden_params", None))
        if hidden is not None:
            candidate = hidden.get("response_cost")
            if isinstance(candidate, int | float) and candidate > 0:
                cost = float(candidate)
            else:
                headers = _as_dict(hidden.get("additional_headers"))
                if headers is not None:
                    raw = headers.get("llm_provider-x-litellm-response-cost")
                    try:
                        value = float(raw) if raw is not None else None
                    except (TypeError, ValueError):
                        value = None
                    if value is not None and value > 0:
                        cost = value

    if cost is None:
        cost = _usage_reported_cost(completion_response)

    # Recover the exact OpenRouter cost the streaming handler stashed for this
    # response — LiteLLM drops it from streamed usage, so nothing above sees it.
    if cost is None:
        cost = streamed_openrouter_costs.take(completion_response)

    if cost is None:
        cost = _estimate_response_cost(kwargs, completion_response)

    if cost is None or cost <= 0:
        return
    report_state = get_global_report_state()
    if report_state is None:
        return
    try:
        report_state.record_observed_llm_cost(
            cost,
            model=model if isinstance(model, str) else None,
            response_id=_response_id(completion_response),
        )
    except Exception:
        logger.exception("Failed to record observed LiteLLM cost")


def _usage_reported_cost(completion_response: Any) -> float | None:
    """Provider-reported cost from the ``usage`` block (e.g. OpenRouter).

    Non-BYOK responses charge everything to ``usage.cost``. BYOK responses
    charge only the OpenRouter fee to ``usage.cost`` (often 0) and report the
    provider charge in ``usage.cost_details.upstream_inference_cost``, so the
    true BYOK total is the sum of the two.
    """
    usage: Any = getattr(completion_response, "usage", None)
    if usage is None and isinstance(completion_response, dict):
        usage = cast("dict[str, Any]", completion_response).get("usage")
    if usage is None:
        return None

    def _field(container: Any, name: str) -> Any:
        if isinstance(container, dict):
            return cast("dict[str, Any]", container).get(name)
        return getattr(container, name, None)

    total = 0.0
    usage_cost = _field(usage, "cost")
    if isinstance(usage_cost, int | float) and usage_cost > 0:
        total += float(usage_cost)

    if bool(_field(usage, "is_byok")):
        upstream = _field(_field(usage, "cost_details"), "upstream_inference_cost")
        if isinstance(upstream, int | float) and upstream > 0:
            total += float(upstream)

    return total if total > 0 else None


def _estimate_response_cost(kwargs: Any, completion_response: Any) -> float | None:
    """Best-effort LiteLLM cost-map estimate when no provider-reported cost exists.

    LiteLLM strips provider cost fields when rebuilding streamed responses and
    returns no ``response_cost`` for models missing from its cost map, so try
    the provider-prefixed name, the raw name, and the bare model name.
    """
    from litellm import completion_cost

    kwargs_dict = _as_dict(kwargs)
    model = kwargs_dict.get("model") if kwargs_dict is not None else None
    if not isinstance(model, str) or not model:
        completion_response_dict = _as_dict(completion_response)
        if completion_response_dict is not None:
            model = completion_response_dict.get("model")
        else:
            model = getattr(completion_response, "model", None)
    if not isinstance(model, str) or not model:
        return None

    provider = None
    if kwargs_dict is not None:
        litellm_params = _as_dict(kwargs_dict.get("litellm_params"))
        if litellm_params is not None:
            provider = litellm_params.get("custom_llm_provider")

    usage_payload = _usage_payload(completion_response)
    if usage_payload is None:
        return None

    candidates: list[str] = []
    if isinstance(provider, str) and provider and not model.startswith(f"{provider}/"):
        candidates.append(f"{provider}/{model}")
    candidates.append(model)
    if "/" in model:
        candidates.append(model.rsplit("/", 1)[-1])

    for candidate in candidates:
        try:
            value = completion_cost(
                completion_response={"model": candidate, "usage": usage_payload},
                model=candidate,
            )
            numeric_value = float(value)
        except Exception:  # nosec B112  # noqa: BLE001, S112
            continue
        if numeric_value > 0:
            return numeric_value
    return None


def _usage_payload(completion_response: Any) -> dict[str, Any] | None:
    """Token counts as a plain dict, detached from the response's provider metadata."""
    usage: Any = getattr(completion_response, "usage", None)
    if usage is None and isinstance(completion_response, dict):
        usage = cast("dict[str, Any]", completion_response).get("usage")
    if usage is None:
        return None
    if hasattr(usage, "model_dump"):
        usage = usage.model_dump()
    if not isinstance(usage, dict):
        return None
    payload = cast("dict[str, Any]", usage)
    if not payload.get("total_tokens") and not (
        payload.get("prompt_tokens") or payload.get("completion_tokens")
    ):
        return None
    return payload
