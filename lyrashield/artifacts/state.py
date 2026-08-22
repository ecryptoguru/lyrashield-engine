# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
# Controlled subprocess boundary: provenance lookup resolves Git and uses shell=False.
import json
import logging
import shutil
import subprocess  # nosec B404
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Optional, cast
from uuid import uuid4

from agents.usage import Usage

from lyrashield.artifacts.sarif import write_sarif
from lyrashield.artifacts.usage import LLMUsageLedger, _int_or_zero, _round_cost
from lyrashield.artifacts.writer import (
    read_run_record,
    write_executive_report,
    write_run_record,
    write_vulnerabilities,
)
from lyrashield.runtime.session_manager import CLEANUP_FAILED, CLEANUP_REMOVED
from lyrashield.telemetry import posthog, scarf
from lyrashield.utils.redaction import redact_text, redact_url
from strix.config import codex
from strix.config.loader import load_settings
from strix.core.paths import run_dir_for


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
RUN_RECORD_SCHEMA_VERSION = "1.0"

# Fields every run.json write must carry from its first observable appearance
# (the worker parses this contract at any point in the run, not just at the
# end). Writers validate against this list before persisting.
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
    if record.get("schema_version") != RUN_RECORD_SCHEMA_VERSION:
        raise RuntimeError(
            f"run.json contract carries unsupported schema_version: "
            f"{record.get('schema_version')!r} (expected {RUN_RECORD_SCHEMA_VERSION!r})"
        )


def initial_run_record(
    run_name: str | None,
    *,
    auth_mode: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical first run record (the only constructor of it).

    Both the CLI's pre-scan persistence and :class:`ReportState` build the
    record here, so the first observable run.json is already a complete
    versioned worker contract — never a partial hand-rolled dict.
    """
    record: dict[str, Any] = {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "run_id": run_name or f"run-{uuid4().hex[:8]}",
        "run_name": run_name,
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "status": "running",
        "phase": "setup",
        "auth_mode": auth_mode,
        "targets_info": [],
        "llm_usage": LLMUsageLedger().to_record(),
        "seq": 0,
        "turn_count": 0,
    }
    if extra:
        record.update(extra)
    return record


def _strix_version() -> str | None:
    """Best-effort package version for the SARIF tool.driver.version field."""
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        return None


def _parse_repo_full_name(uri: str) -> str | None:
    """Extract ``owner/repo`` from a git URL or slug, else None."""
    text = uri.strip().removesuffix(".git")
    if not text:
        return None
    if "@" in text and ":" in text.split("@", 1)[1]:
        # scp-style: git@host:owner/repo
        text = text.split("@", 1)[1].split(":", 1)[1]
    elif "://" in text:
        # https://host/owner/repo
        host_and_path = text.split("://", 1)[1]
        text = host_and_path.split("/", 1)[1] if "/" in host_and_path else host_and_path
    parts = [p for p in text.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return None


def _git_head(repo_path: str) -> tuple[str | None, str | None]:
    """Best-effort ``(commit_sha, branch)`` for a cloned repo, or ``(None, None)``.

    Used to populate SARIF versionControlProvenance. Failures (missing git,
    non-repo path, detached HEAD, timeout) degrade to None so the SARIF
    emit is never blocked by a provenance lookup.
    """
    path = Path(repo_path)
    if not path.is_dir():
        return None, None

    git_executable = shutil.which("git")
    if git_executable is None:
        return None, None

    def _run(args: list[str]) -> str | None:
        try:
            # Controlled subprocess boundary: Git path is resolved and shell is disabled.
            result = subprocess.run(  # noqa: S603  # nosec B603
                [git_executable, "-C", str(path), *args],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None

    commit = _run(["rev-parse", "HEAD"])
    branch = _run(["rev-parse", "--abbrev-ref", "HEAD"])
    if branch == "HEAD":  # detached HEAD carries no branch name
        branch = None
    return commit, branch


def get_global_report_state() -> Optional["ReportState"]:
    return _global_report_state


# Finding fields sanitized as free text at the persistence boundary. Fields
# not listed here (id, severity, timestamp, cvss, cve, cwe, method,
# finding_class, control_ids, agent_id) are structural identifiers copied
# verbatim — they carry no operator or target-derived secrets.
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


def sanitize_finding(report: dict[str, Any], *, include_internal_paths: bool) -> dict[str, Any]:
    """Return the immutable sanitized snapshot of one finding.

    Built once at the artifact persistence boundary; every durable/public
    projection (vulnerabilities JSON/MD/CSV, SARIF, viewer, sync) consumes
    only this snapshot, never the raw in-memory report.
    """
    snapshot: dict[str, Any] = {}
    for key, value in report.items():
        if key in _FINDING_TEXT_FIELDS and isinstance(value, str):
            snapshot[key] = redact_text(value, include_internal_paths=include_internal_paths)
        elif key in _FINDING_URL_FIELDS and isinstance(value, str):
            snapshot[key] = redact_url(redact_text(value, include_internal_paths=False))
        elif key == "poc_script_code" and isinstance(value, str):
            # The weaponized payload stays a local artifact, but its copy in
            # the durable snapshot is stripped of secrets and host identity;
            # sandbox-internal workspace paths are preserved by policy.
            snapshot[key] = redact_text(value, include_internal_paths=False)
        elif key == "code_locations" and isinstance(value, list):
            snapshot[key] = _sanitize_code_locations(value, include_internal_paths)
        elif key == "dependency_metadata" and isinstance(value, dict):
            snapshot[key] = {
                str(k): redact_text(str(v), include_internal_paths=include_internal_paths)
                if isinstance(v, str)
                else v
                for k, v in value.items()
            }
        elif key == "cvss_breakdown" and isinstance(value, dict):
            snapshot[key] = {
                str(k): redact_text(str(v), include_internal_paths=False) for k, v in value.items()
            }
        else:
            snapshot[key] = value
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


def sanitize_targets_info(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitized target identifiers for the durable run receipt.

    URLs keep scheme/host/path shape but lose credentials and sensitive query
    values; repository URLs get the same URL treatment; host filesystem paths
    reduce to their basename; cloned host paths are dropped entirely.
    """
    sanitized: list[dict[str, Any]] = []
    for target in targets:
        entry: dict[str, Any] = {"type": target.get("type")}
        details = target.get("details")
        if isinstance(details, dict):
            clean_details: dict[str, Any] = {}
            for key, value in details.items():
                if key == "cloned_repo_path":
                    continue  # host path; private execution configuration
                if isinstance(value, str) and value:
                    if key in {"target_url", "target_repo"}:
                        clean_details[key] = redact_url(
                            redact_text(value, include_internal_paths=False)
                        )
                    else:
                        clean_details[key] = redact_text(value, include_internal_paths=True)
                elif value is not None:
                    clean_details[key] = value
            entry["details"] = clean_details
        sanitized.append(entry)
    return sanitized


def sanitize_local_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Local source entries without host filesystem paths."""
    sanitized: list[dict[str, Any]] = []
    for source in sources:
        entry: dict[str, Any] = {}
        for key in ("workspace_subdir", "mount"):
            if key in source:
                entry[key] = source[key]
        sanitized.append(entry)
    return sanitized


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
        self._llm_usage = LLMUsageLedger()
        auth_mode = codex.auth_mode(load_settings().llm.model)
        self._llm_usage.zero_cost = auth_mode == "subscription"
        self.run_record = initial_run_record(run_name, auth_mode=auth_mode)
        # initial_run_record generated the run_id; adopt it on the instance.
        self.run_id = str(self.run_record["run_id"])
        self.start_time = str(self.run_record["start_time"])
        self.end_time: str | None = None
        self._run_dir: Path | None = None
        self._saved_vuln_ids: set[str] = set()
        self._save_seq = 0
        self._turn_count = 0
        self.receipt_persisted: bool = True

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

        self._sarif_repo_ctx: dict[str, Any] | None = None
        self._sarif_repo_ctx_ready: bool = False

        self.posthog_scan_ended_sent: bool = False
        self.scarf_scan_ended_sent: bool = False
        self.scan_ended_exit_reason: str | None = None

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = run_dir_for(run_dir_name)
            self._run_dir.mkdir(parents=True, exist_ok=True)

        return self._run_dir

    def hydrate_from_run_dir(self) -> None:
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
            self._save_seq = max(self._save_seq, _int_or_zero(data.get("seq")))
            self._turn_count = max(self._turn_count, _int_or_zero(data.get("turn_count")))
            self.run_record["seq"] = self._save_seq
            self.run_record["turn_count"] = self._turn_count
            logger.info("report state hydrated run.json from %s", run_dir)

        json_path = run_dir / "vulnerabilities.json"
        if json_path.exists():
            try:
                vuln_data = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is corrupt ({exc}); "
                    f"refusing to start fresh — that would overwrite prior "
                    f"vulnerability MDs on disk. Inspect or delete the run dir.",
                ) from exc
            if not isinstance(vuln_data, list):
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is not a list",
                )
            self.vulnerability_reports = [
                cast("dict[str, Any]", r) for r in vuln_data if isinstance(r, dict)
            ]
            for r in self.vulnerability_reports:
                rid = r.get("id")
                if isinstance(rid, str):
                    self._saved_vuln_ids.add(rid)
            logger.info(
                "report state hydrated %d vulnerability report(s)",
                len(self.vulnerability_reports),
            )

    def add_vulnerability_report(
        self,
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
        dependency_metadata: dict[str, str] | None = None,
        control_ids: list[int] | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> str:
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report: dict[str, Any] = {
            "id": report_id,
            "title": title.strip(),
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
        if agent_id:
            report["agent_id"] = agent_id
        if agent_name:
            report["agent_name"] = agent_name

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")
        posthog.finding(severity, cwe=cwe, is_cve=bool(cve))
        scarf.finding(severity, cwe=cwe, is_cve=bool(cve))

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(report)

        self._set_phase("running")
        self.save_run_data()
        return report_id

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(self.vulnerability_reports)

    def record_sdk_usage(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
    ) -> None:
        """Record SDK-native token usage for one completed model run/cycle."""
        self._llm_usage.record(
            agent_id=agent_id,
            agent_name=agent_name,
            model=model,
            usage=usage,
        )
        self._turn_count += 1
        self._set_phase("running")
        self.save_run_data()

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
            self._llm_usage.record_observed_cost(cost)
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
        # Keep raw repository target details in memory only (SARIF provenance
        # needs the cloned path); the durable record carries sanitized forms.
        self._repo_context_targets = [dict(t) for t in targets if t.get("type") == "repository"]
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
                "scope_mode": config.get("scope_mode", "auto"),
                "diff_base": config.get("diff_base"),
            }
        )
        self._set_phase("running")

    def save_run_data(self, mark_complete: bool = False, status: str | None = None) -> None:
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
        self._save_artifacts()

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

    def _format_final_scan_result(self, scan_results: dict[str, Any]) -> str:
        return f"""# Executive Summary

{str(scan_results.get("executive_summary", "")).strip()}

# Methodology

{str(scan_results.get("methodology", "")).strip()}

# Technical Analysis

{str(scan_results.get("technical_analysis", "")).strip()}

# Recommendations

{str(scan_results.get("recommendations", "")).strip()}
"""

    def _save_artifacts(self) -> None:
        """Write scan artifacts under ``run_dir``."""
        run_dir = self.get_run_dir()
        run_dir.mkdir(parents=True, exist_ok=True)

        # One immutable sanitized snapshot feeds every durable/public
        # projection; the raw in-memory reports never reach disk.
        include_internal_paths = not self._is_whitebox
        snapshot = [
            sanitize_finding(report, include_internal_paths=include_internal_paths)
            for report in self.vulnerability_reports
        ]

        # Each artifact is isolated so a failure in one cannot skip the others;
        # run.json is the billing/cost receipt and is written last.
        if self.final_scan_result:
            try:
                write_executive_report(run_dir, self.final_scan_result)
            except (OSError, RuntimeError):
                logger.exception("Executive report write failed (non-fatal)")

        # The worker must distinguish a clean scan from missing output. Always
        # write this artifact, including for a valid zero-finding result.
        try:
            write_vulnerabilities(run_dir, snapshot, self._saved_vuln_ids)
        except (OSError, RuntimeError):
            logger.exception("Vulnerabilities artifact write failed (non-fatal)")

        # SARIF is an integration artifact; it must not hide a successful core
        # receipt when an optional formatter has a problem.
        try:
            write_sarif(
                run_dir,
                snapshot,
                tool_version=_strix_version(),
                repository_context=self._sarif_repository_context(),
            )
        except Exception:
            logger.exception("SARIF emit failed (non-fatal; core receipt unaffected)")

        try:
            # Validate the full worker contract before any write: the first
            # observable run.json must already be complete and versioned.
            validate_run_record(self.run_record)
            # Snapshot claims persistence optimistically so the durable record
            # carries receipt_persisted=true the moment it lands on disk; a
            # failed write reverts both the record flag and in-memory state.
            self.receipt_persisted = True
            self.run_record["receipt_persisted"] = True
            write_run_record(run_dir, self.run_record)
        except (OSError, RuntimeError):
            # The run record carries the cost receipt the worker reconciles
            # against the provider total; a silent skip here mis-bills the
            # scan as if it cost nothing. Flag it, never swallow it.
            self.receipt_persisted = False
            self.run_record["receipt_persisted"] = False
            logger.exception("run.json receipt persist FAILED — cost receipt not written")
        logger.info("Essential scan data saved to: %s", run_dir)

    def _sarif_repository_context(self) -> dict[str, Any] | None:
        """Repo/commit/branch context for SARIF provenance (repo scans only).

        Cached after first derivation — ``_save_artifacts`` runs on every
        state save, and the git lookup only needs to happen once per run.
        Returns None for URL / IP (DAST) targets that have no repository.
        """
        if not self._sarif_repo_ctx_ready:
            self._sarif_repo_ctx = self._derive_repository_context()
            self._sarif_repo_ctx_ready = True
        return self._sarif_repo_ctx

    def _derive_repository_context(self) -> dict[str, Any] | None:
        # Prefer the in-memory raw repository targets; the durable record's
        # targets_info is sanitized and carries no cloned paths.
        raw_targets = getattr(self, "_repo_context_targets", None)
        if raw_targets is None:
            targets = self.run_record.get("targets_info")
            if not isinstance(targets, list):
                return None
            repo_targets = [
                cast("dict[str, Any]", t)
                for t in targets
                if isinstance(t, dict) and t.get("type") == "repository"
            ]
        else:
            repo_targets = [cast("dict[str, Any]", t) for t in raw_targets]
        if len(repo_targets) != 1:
            return None
        target = repo_targets[0]
        details = target.get("details")
        if not isinstance(details, dict):
            return None
        details = cast("dict[str, Any]", details)

        uri = details.get("target_repo")
        if not isinstance(uri, str) or not uri.strip():
            return None

        # Public SARIF provenance: URL shape without credentials/query tokens.
        context: dict[str, Any] = {"repositoryUri": redact_url(uri.strip())}
        full_name = _parse_repo_full_name(uri)
        if full_name:
            context["repositoryFullName"] = full_name
        cloned = details.get("cloned_repo_path")
        if isinstance(cloned, str) and cloned.strip():
            commit, branch = _git_head(cloned.strip())
            if commit:
                context["commitSha"] = commit
            if branch:
                context["branch"] = branch
                context["ref"] = f"refs/heads/{branch}"
        return context

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
    if isinstance(model, str) and model.strip().lower().split("/")[-1] in {
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    }:
        # Azure's LiteLLM response_cost can be stale for GPT-5.6. The usage
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
