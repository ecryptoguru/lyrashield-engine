# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
# Controlled subprocess boundary: provenance lookup resolves Git and uses shell=False.
import json
import logging
import re
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

from lyrashield.artifacts import evidence as _evidence
from lyrashield.artifacts import quality as _quality
from lyrashield.artifacts.sarif import write_sarif
from lyrashield.artifacts.usage import (
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
from lyrashield.runtime.attachments import public_manifest
from lyrashield.runtime.session_manager import CLEANUP_FAILED, CLEANUP_REMOVED
from lyrashield.telemetry import posthog, scarf
from lyrashield.utils.redaction import is_sensitive_key, redact_text, redact_url
from strix.config import codex
from strix.config.loader import load_settings
from strix.core.paths import run_dir_for, runtime_state_dir


logger = logging.getLogger(__name__)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _clean_title(title: str) -> str:
    """Return a single-line finding title.

    A title quotes text from the scanned target, so it can carry newlines, tabs or
    other control characters. Those break every artifact that renders the title on
    one line, such as the markdown heading, the CSV cell and the TUI list. Control
    characters become spaces and runs of whitespace collapse to one space.
    """
    return " ".join(_CONTROL_CHARS.sub(" ", title).split())


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

RUN_RECORD_SCHEMA_VERSION = _evidence.RUN_RECORD_SCHEMA_VERSION_1_0

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

# Schema-1.1 finding fields sanitized as free text when the record carries
# them. A 1.0 record must not emit them at all (readers deploy first).
_V1_1_FINDING_TEXT_FIELDS = frozenset(
    {
        "counterevidence",
        "confidence_rationale",
        "severity_change_conditions",
        "contextual_cvss_reasoning",
        "updated_at",
    }
)
# Schema-1.1 structured fields: validated at intake, recursively sanitized
# here so nested model-controlled strings still pass through redaction.
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

# Deterministic bounds for artifact fields (E4): unbounded model-controlled
# text could exhaust disk/memory or smuggle payloads through projections.
_MAX_TEXT_LENGTH = 10_000
_MAX_COLLECTION_SIZE = 1_000
_MAX_METADATA_DEPTH = 10
_MAX_FINDING_SERIALIZED_SIZE = 1_000_000
# Persisted scope-violation entries bound (ledger bound is lower; this caps
# the durable list merged across saves).
_MAX_SCOPE_VIOLATION_ENTRIES = 500


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


def sanitize_attachments(attachments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attachment manifest entries without host filesystem paths.

    The durable run record carries each staged original's ``name``,
    ``sha256``, ``size``, declared ``content_type``, and in-sandbox
    ``container_path`` — never the host ``source_path``.
    """
    return public_manifest([a for a in attachments if isinstance(a, dict)])


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
            self._save_seq = max(self._save_seq, _int_or_zero(data.get("seq")))
            self._turn_count = max(self._turn_count, _int_or_zero(data.get("turn_count")))
            self.run_record["seq"] = self._save_seq
            self.run_record["turn_count"] = self._turn_count
            revision = data.get("report_artifacts_revision")
            if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0:
                persisted_report_revision = revision
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
                # A finding written before the class was persisted still carries the
                # metadata of its class, so name the class it always had.
                if not r.get("finding_class"):
                    r["finding_class"] = (
                        "dependency_cve" if r.get("dependency_metadata") else "dynamic"
                    )
                title = r.get("title")
                stale_md = False
                if isinstance(title, str):
                    r["title"] = _clean_title(title)
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
        self,
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
                    normalized_fv["recorded_at"] = datetime.now(UTC).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
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
                [e for e in raw_history if isinstance(e, dict)]
                if isinstance(raw_history, list)
                else []
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

    def save_run_data(self, mark_complete: bool = False, status: str | None = None) -> bool:
        with self._report_artifacts_lock:
            return self._save_run_data_locked(mark_complete=mark_complete, status=status)

    def _save_run_data_locked(self, mark_complete: bool = False, status: str | None = None) -> bool:
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

    def _write_report_projections(
        self,
        reports: list[dict[str, Any]],
        saved_vuln_ids: set[str],
    ) -> bool:
        """Write the finding projections (JSON/CSV/MD + SARIF) for ``reports``.

        The vulnerabilities write is required — its failure raises so callers
        that must roll back (finding revisions) can. SARIF is best-effort:
        its failure is logged and returns ``False`` without raising.
        """
        run_dir = self.get_run_dir()
        include_internal_paths = not self._is_whitebox
        schema_version = str(self.run_record.get("schema_version", "1.0"))
        # One immutable sanitized snapshot feeds every durable/public
        # projection; the raw in-memory reports never reach disk.
        snapshot = [
            sanitize_finding(
                report,
                include_internal_paths=include_internal_paths,
                schema_version=schema_version,
            )
            for report in reports
        ]
        write_vulnerabilities(run_dir, snapshot, saved_vuln_ids)
        try:
            write_sarif(
                run_dir,
                snapshot,
                tool_version=_strix_version(),
                repository_context=self._sarif_repository_context(),
            )
        except Exception:
            logger.exception("SARIF emit failed (non-fatal; core receipt unaffected)")
            return False
        return True

    def _write_evidence_artifacts(self, run_dir: Path) -> bool:
        """Write the schema-1.1 companion artifacts (coverage, threat model).

        Both are bounded and best-effort: failures are logged and reported as
        ``False`` so the persisted revision stays honest, but they never block
        the required receipt.
        """
        persisted = True
        try:
            coverage = _evidence.build_coverage_document(
                run_record=self.run_record,
                agent_graph=_read_agent_graph(runtime_state_dir(run_dir)),
                vulnerability_reports=self.vulnerability_reports,
                exit_reason=self.scan_ended_exit_reason,
            )
            _evidence.write_coverage_artifact(run_dir, coverage)
        except Exception:
            persisted = False
            logger.exception("coverage.json write failed (non-fatal)")
        try:
            threat_model = _evidence.build_threat_model_document(run_dir, self.run_record)
            if threat_model is not None:
                _evidence.write_threat_model_artifact(run_dir, threat_model)
        except Exception:
            persisted = False
            logger.exception("threat_model.json write failed (non-fatal)")
        return persisted

    def _save_artifacts(self) -> bool:
        """Write scan artifacts under ``run_dir``.

        Returns ``True`` only when every required artifact (vulnerabilities,
        run record) is successfully persisted. Non-fatal artifacts (executive
        report, SARIF) may fail and be logged, but they do not make this
        return ``False``. Callers that must know whether durability succeeded
        (e.g. vulnerability report tools) should act on the return value.
        """
        run_dir = self.get_run_dir()
        run_dir.mkdir(parents=True, exist_ok=True)

        evidence_v1_1 = _evidence.record_supports_evidence_v1_1(self.run_record)

        report_artifacts_revision = self._report_artifacts_revision
        write_report_artifacts = (
            self._persisted_report_artifacts_revision != report_artifacts_revision
        )
        report_artifacts_persisted = not write_report_artifacts
        if write_report_artifacts:
            # Each artifact is isolated so a failure in one cannot skip the others;
            # run.json is the billing/cost receipt and is written last.
            optional_artifacts_persisted = True
            if self.final_scan_result:
                try:
                    write_executive_report(run_dir, self.final_scan_result)
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
                self.run_record["scan_quality"] = _quality.build_scan_quality(
                    run_record=self.run_record,
                    agent_graph=_read_agent_graph(runtime_state_dir(run_dir)),
                    coverage_entries=_coverage_ledger_entries(),
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
                self.run_record["result_manifest"] = _evidence.build_result_manifest(run_dir)
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
            return False

        # Write the private resume record with unsanitized execution fields so
        # a resumed scan can recover cloned_repo_path / source_path values that
        # the public run.json intentionally redacts (comment #5). This is
        # non-fatal to the receipt; a missing resume file can still be recovered
        # from the public record (resume will just lose host paths).
        if write_report_artifacts:
            try:
                write_resume_record(
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
        # targets_info is sanitized and carries no cloned paths. An empty
        # in-memory list means set_scan_config was never called, so fall back
        # to the run record (e.g. tests that set it directly).
        raw_targets = getattr(self, "_repo_context_targets", None) or []
        if raw_targets:
            repo_targets = [cast("dict[str, Any]", t) for t in raw_targets]
        else:
            targets = self.run_record.get("targets_info")
            if not isinstance(targets, list):
                return None
            repo_targets = [
                cast("dict[str, Any]", t)
                for t in targets
                if isinstance(t, dict) and t.get("type") == "repository"
            ]
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


def _read_agent_graph(state_dir: Path) -> dict[str, Any]:
    """Lazy wrapper so the substrate coverage module loads only on demand."""
    from strix.report.coverage import read_agent_graph

    return read_agent_graph(state_dir)


def _coverage_ledger_entries() -> list[dict[str, Any]]:
    """Lazy wrapper for the model-declared coverage ledger store."""
    from strix.tools.coverage.tools import get_coverage_entries

    return cast("list[dict[str, Any]]", get_coverage_entries())


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
