from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from lyrashield.artifacts.state_findings import sanitize_finding
from lyrashield.runtime.attachments import public_manifest
from lyrashield.utils.redaction import redact_text, redact_url


if TYPE_CHECKING:
    from lyrashield.artifacts.state import ReportState


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


def format_final_scan_result(scan_results: dict[str, Any]) -> str:
    return f"""# Executive Summary

{str(scan_results.get("executive_summary", "")).strip()}

# Methodology

{str(scan_results.get("methodology", "")).strip()}

# Technical Analysis

{str(scan_results.get("technical_analysis", "")).strip()}

# Recommendations

{str(scan_results.get("recommendations", "")).strip()}
"""


def write_report_projections(
    self: ReportState,
    reports: list[dict[str, Any]],
    saved_vuln_ids: set[str],
    *,
    require_sarif: bool = False,
    write_vulnerabilities: Callable[..., Any],
    write_sarif: Callable[..., Any],
    tool_version: str | None,
    logger: logging.Logger,
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
            tool_version=tool_version,
            repository_context=self._sarif_repository_context(),
        )
    except Exception:
        logger.exception("SARIF emit failed (non-fatal; core receipt unaffected)")
        if require_sarif:
            raise
        return False
    return True


def write_evidence_artifacts(
    self: ReportState,
    run_dir: Path,
    *,
    evidence: Any,
    runtime_state_dir: Callable[[Path], Path],
    read_agent_graph: Callable[[Path], dict[str, Any]],
    logger: logging.Logger,
) -> bool:
    """Write the schema-1.1 companion artifacts (coverage, threat model).

    Both are bounded and best-effort: failures are logged and reported as
    ``False`` so the persisted revision stays honest, but they never block
    the required receipt.
    """
    persisted = True
    try:
        from lyrashield.artifacts.quality import effective_agent_graph

        coverage = evidence.build_coverage_document(
            run_record=self.run_record,
            agent_graph=effective_agent_graph(
                self.run_record, read_agent_graph(runtime_state_dir(run_dir))
            ),
            vulnerability_reports=self.vulnerability_reports,
            exit_reason=self.scan_ended_exit_reason,
        )
        evidence.write_coverage_artifact(run_dir, coverage)
    except Exception:
        persisted = False
        logger.exception("coverage.json write failed (non-fatal)")
    try:
        threat_model = evidence.build_threat_model_document(run_dir, self.run_record)
        if threat_model is not None:
            evidence.write_threat_model_artifact(run_dir, threat_model)
    except Exception:
        persisted = False
        logger.exception("threat_model.json write failed (non-fatal)")
    return persisted


def _read_agent_graph(state_dir: Path) -> dict[str, Any]:
    """Lazy wrapper so the substrate coverage module loads only on demand."""
    from strix.report.coverage import read_agent_graph

    return read_agent_graph(state_dir)


def _coverage_ledger_entries() -> list[dict[str, Any]]:
    """Lazy wrapper for the model-declared coverage ledger store."""
    from strix.tools.coverage.tools import get_coverage_entries

    return cast("list[dict[str, Any]]", get_coverage_entries())


read_agent_graph = _read_agent_graph
coverage_ledger_entries = _coverage_ledger_entries
