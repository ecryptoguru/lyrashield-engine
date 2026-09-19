"""``scan_quality`` — honest per-surface accounting for run.json schema 1.1.

This block answers "what was actually exercised versus merely declared".
Every number here derives from activity the runtime observed (agent graph,
filed findings, web-search metering, replay admission decisions, probed
sandbox capabilities) or from the model-declared coverage ledger — always
labeled ``declared``. Nothing is estimated and no coverage percentage is
invented: a surface with no observed or declared activity stays
``unassessed``, and capability gaps surface as named degradations rather
than being smoothed into a score.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from strix.report.coverage import agents_from_graph


logger = logging.getLogger(__name__)

SCAN_QUALITY_SCHEMA = "lyrashield-scan-quality/1.0"

_MAX_SURFACES = 200
_MAX_SURFACE_CHARS = 200
_MAX_UNASSESSED = 100

# Agent graph statuses that mean the agent did not finish cleanly.
_INCOMPLETE_AGENT_STATUSES = frozenset({"crashed", "stopped", "running", "waiting"})


def _surface_key(value: Any) -> str | None:
    """Normalize a surface reference to a host or bounded free-text key."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()[:_MAX_SURFACE_CHARS]
    candidate = text if "://" in text else f"//{text.split('/')[0]}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return text
    host = parsed.hostname
    if host:
        return host.lower().rstrip(".")
    return text


def _authorized_scope_hosts(run_record: dict[str, Any]) -> list[str]:
    """The recorded authorized host set — probed capability record first."""
    caps = run_record.get("sandbox_capabilities")
    if isinstance(caps, dict):
        hosts = caps.get("authorized_hosts")
        if isinstance(hosts, list):
            return sorted({str(h) for h in hosts if isinstance(h, str) and h})
    scope = run_record.get("proxy_default_scope")
    if isinstance(scope, dict):
        allowlist = scope.get("allowlist")
        if isinstance(allowlist, list):
            return sorted(
                {str(p).lstrip("*.") for p in allowlist if isinstance(p, str) and p.strip("*.")}
            )
    return []


def _sandbox_summary(run_record: dict[str, Any]) -> dict[str, Any] | None:
    """Compact capability/preflight provenance for the quality block."""
    caps = run_record.get("sandbox_capabilities")
    if not isinstance(caps, dict):
        return None
    probed = caps.get("capabilities")
    statuses = (
        {
            str(name): str(entry.get("status"))
            for name, entry in probed.items()
            if isinstance(entry, dict)
        }
        if isinstance(probed, dict)
        else {}
    )
    preflight = caps.get("preflight")
    degradations: list[str] = []
    failures: list[str] = []
    if isinstance(preflight, dict):
        degradations.extend(
            str(item["control"])
            for item in preflight.get("degradations") or []
            if isinstance(item, dict) and item.get("control")
        )
        failures.extend(
            str(item["control"])
            for item in preflight.get("failures") or []
            if isinstance(item, dict) and item.get("control")
        )
    summary: dict[str, Any] = {
        "backend": caps.get("backend"),
        "capabilities": statuses,
        "preflight_degradations": sorted(degradations),
        "preflight_failures": sorted(failures),
    }
    return summary


def _surface_row() -> dict[str, Any]:
    return {
        "origins": set(),
        "declared": 0,
        "findings": 0,
        "admitted_requests": 0,
        "denied_requests": 0,
    }


def _assessment(row: dict[str, Any]) -> str:
    """Honest per-surface verdict — observed beats declared beats nothing."""
    if row["findings"] > 0 or row["admitted_requests"] > 0:
        return "observed"
    if row["declared"] > 0:
        return "declared"
    if row["denied_requests"] > 0:
        return "denied"
    return "unassessed"


def build_scan_quality(
    *,
    run_record: dict[str, Any],
    agent_graph: dict[str, Any],
    coverage_entries: list[dict[str, Any]],
    vulnerability_reports: list[dict[str, Any]],
    scope_decisions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the ``scan_quality`` run-record block.

    All inputs are already-observed run data; this function derives counts
    and per-surface verdicts only. It never estimates coverage, never
    upgrades a model-declared claim to an observation, and leaves every
    unexercised surface explicitly ``unassessed``.
    """
    agents = agents_from_graph(agent_graph)
    agents_incomplete = sum(
        1 for agent in agents if agent.get("status") in _INCOMPLETE_AGENT_STATUSES
    )

    decisions = scope_decisions if isinstance(scope_decisions, dict) else {}
    violations = [v for v in decisions.get("violations") or [] if isinstance(v, dict)]
    dropped_violations = int(decisions.get("dropped") or 0)
    admitted_hosts = {
        str(host): int(count)
        for host, count in (decisions.get("admitted_hosts") or {}).items()
        if isinstance(count, int) and count > 0
    }

    surfaces: dict[str, dict[str, Any]] = {}

    def _row(key: str | None) -> dict[str, Any] | None:
        if not key:
            return None
        if key not in surfaces and len(surfaces) < _MAX_SURFACES:
            surfaces[key] = _surface_row()
        return surfaces.get(key)

    for host in _authorized_scope_hosts(run_record):
        row = _row(host)
        if row is not None:
            row["origins"].add("authorized_scope")

    declared_outcomes: dict[str, int] = {}
    for entry in coverage_entries:
        outcome = str(entry.get("outcome") or "")
        if outcome:
            declared_outcomes[outcome] = declared_outcomes.get(outcome, 0) + 1
        row = _row(_surface_key(entry.get("surface")))
        if row is not None:
            row["declared"] += 1
            row["origins"].add("declared")

    for report in vulnerability_reports:
        key = _surface_key(report.get("endpoint")) or _surface_key(report.get("target"))
        row = _row(key)
        if row is not None:
            row["findings"] += 1
            row["origins"].add("finding")

    for host, count in admitted_hosts.items():
        row = _row(host)
        if row is not None:
            row["admitted_requests"] += count
            row["origins"].add("egress_admitted")

    for violation in violations:
        row = _row(str(violation.get("host") or "") or None)
        if row is not None:
            row["denied_requests"] += 1
            row["origins"].add("egress_denied")

    surface_rows: list[dict[str, Any]] = []
    unassessed: list[str] = []
    for key in sorted(surfaces):
        row = surfaces[key]
        verdict = _assessment(row)
        surface_rows.append(
            {
                "surface": key,
                "origins": sorted(row["origins"]),
                "declared_coverage_entries": row["declared"],
                "findings": row["findings"],
                "admitted_requests": row["admitted_requests"],
                "denied_requests": row["denied_requests"],
                "assessment": verdict,
            }
        )
        if verdict == "unassessed" and len(unassessed) < _MAX_UNASSESSED:
            unassessed.append(key)

    web_search_usage = run_record.get("web_search_usage")
    export = run_record.get("evidence_export")
    document: dict[str, Any] = {
        "schema": SCAN_QUALITY_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": run_record.get("run_id"),
        "observed": {
            "agents_total": len(agents),
            "agents_finished": len(agents) - agents_incomplete,
            "agents_incomplete": agents_incomplete,
            "findings_filed": len(vulnerability_reports),
            "web_search_calls": len(web_search_usage) if isinstance(web_search_usage, list) else 0,
            "proxy_requests_admitted": sum(admitted_hosts.values()),
            "proxy_requests_denied": len(violations) + dropped_violations,
            "evidence_export": export.get("status") if isinstance(export, dict) else None,
            "sandbox": _sandbox_summary(run_record),
            "scan_status": run_record.get("status"),
            "terminal_reason": run_record.get("terminal_reason"),
        },
        "declared": {
            "coverage_entries": len(coverage_entries),
            "outcomes": declared_outcomes,
        },
        "surfaces": surface_rows,
        "unassessed": unassessed,
        "note": (
            "Counts derive only from observed runtime activity and the "
            "model-declared coverage ledger. 'declared' surfaces are "
            "agent-reported, not machine-verified; 'unassessed' surfaces "
            "were in scope but have no recorded exercise."
        ),
    }
    if dropped_violations:
        document["observed"]["scope_violations_dropped"] = dropped_violations
    return document


__all__ = [
    "SCAN_QUALITY_SCHEMA",
    "build_scan_quality",
]
