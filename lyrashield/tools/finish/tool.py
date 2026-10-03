"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from lyrashield.lifecycle.agents import coordinator_from_context


logger = logging.getLogger(__name__)


def _finish_assessment(
    *,
    report_state: Any,
    agent_graph: dict[str, Any],
) -> dict[str, Any]:
    """Derive finish caveats from observed graph, coverage and scan records."""
    from lyrashield.artifacts import evidence, quality
    from lyrashield.artifacts import state as state_module

    candidate_record = dict(report_state.run_record)
    candidate_record["status"] = "completed"
    candidate_record["receipt_persisted"] = True
    candidate_record["scan_results"] = {"success": True, "scan_completed": True}
    graph = quality.effective_agent_graph(candidate_record, agent_graph)
    coverage = evidence.build_coverage_document(
        run_record=candidate_record,
        agent_graph=graph,
        vulnerability_reports=report_state.vulnerability_reports,
    )
    violations = candidate_record.get("scope_violations")
    violations = violations if isinstance(violations, dict) else {}
    quality_record = quality.build_scan_quality(
        run_record=candidate_record,
        agent_graph=graph,
        coverage_entries=state_module._coverage_ledger_entries(),
        vulnerability_reports=report_state.vulnerability_reports,
        scope_decisions={
            "violations": violations.get("entries") or [],
            "dropped": violations.get("dropped") or 0,
        },
    )

    observed = coverage.get("machine_observed")
    raw_agents = observed.get("agents") if isinstance(observed, dict) else []
    incomplete_agents = [
        {"agent_name": agent.get("agent_name", "unknown"), "status": agent.get("status", "unknown")}
        for agent in raw_agents or []
        if isinstance(agent, dict) and agent.get("status") != "completed"
    ]
    coverage_gaps = coverage.get("gaps")
    coverage_gaps = coverage_gaps if isinstance(coverage_gaps, list) else []
    completeness = coverage.get("completeness")
    coverage_complete = bool(
        isinstance(completeness, dict)
        and completeness.get("complete") is True
        and not coverage_gaps
    )
    reasons = {
        str(reason)
        for reason in quality_record.get("assessment_reasons", [])
        if isinstance(reason, str)
    }
    if coverage_gaps:
        reasons.add("coverage_gaps_present")
    if not coverage_complete:
        reasons.add("coverage_incomplete")
    ordered_reasons = sorted(reasons)
    return {
        "assessment": "inconclusive" if ordered_reasons else "findings_recorded",
        "assessment_reasons": ordered_reasons,
        "coverage_complete": coverage_complete,
        "coverage_gaps": coverage_gaps,
        "incomplete_agents": incomplete_agents,
    }


def _assessment_note(*, assessment: dict[str, Any], report_section: str) -> str:
    """Keep limitations visible in the customer-facing final report."""
    details: list[str] = []
    if "no_findings_recorded" in assessment["assessment_reasons"]:
        details.append(
            "No vulnerabilities were filed. This does not demonstrate that the target is secure."
        )
    incomplete = assessment["incomplete_agents"]
    if incomplete:
        statuses: dict[str, int] = {}
        for agent in incomplete:
            status = str(agent.get("status") or "unknown")
            statuses[status] = statuses.get(status, 0) + 1
        details.append(
            "Incomplete agent work: "
            + ", ".join(f"{count} {status}" for status, count in sorted(statuses.items()))
            + "."
        )
    if assessment["coverage_gaps"]:
        details.append(
            f"Coverage has {len(assessment['coverage_gaps'])} unresolved gap(s); "
            "see the coverage record."
        )
    if not assessment["coverage_complete"]:
        details.append(
            "Coverage or finalization is incomplete; unresolved work remains inconclusive."
        )
    details = [line for line in details if line.casefold() not in report_section.casefold()]
    if not details:
        return report_section
    heading = (
        "" if "### Assessment limitations" in report_section else "### Assessment limitations\n\n"
    )
    return f"{report_section.rstrip()}\n\n{heading}" + "\n".join(f"- {line}" for line in details)


def _final_evidence_is_durable(report_state: Any) -> bool:
    """Confirm the successful finish and its companion artifacts are durable."""
    from lyrashield.artifacts import evidence
    from lyrashield.artifacts.quality import SCAN_QUALITY_SCHEMA
    from lyrashield.artifacts.writer import read_run_record

    current_revision = getattr(report_state, "_report_artifacts_revision", None)
    if (
        not isinstance(current_revision, int)
        or isinstance(current_revision, bool)
        or report_state.receipt_persisted is not True
        or report_state.run_record.get("report_artifacts_revision") != current_revision
    ):
        return False
    try:
        run_dir = report_state.get_run_dir()
        persisted = read_run_record(run_dir)
    except Exception:
        logger.exception("finish_scan: unable to read persisted final evidence")
        return False
    results = persisted.get("scan_results") if isinstance(persisted, dict) else None
    if (
        not isinstance(persisted, dict)
        or persisted.get("status") != "completed"
        or persisted.get("receipt_persisted") is not True
        or persisted.get("report_artifacts_revision") != current_revision
        or not isinstance(results, dict)
        or results.get("success") is not True
        or results.get("scan_completed") is not True
    ):
        return False
    if not evidence.record_supports_evidence_v1_1(persisted):
        return True

    quality_record = persisted.get("scan_quality")
    if (
        not isinstance(quality_record, dict)
        or quality_record.get("schema") != SCAN_QUALITY_SCHEMA
        or quality_record.get("run_id") != persisted.get("run_id")
        or quality_record.get("assessment") not in {"inconclusive", "findings_recorded"}
        or not isinstance(quality_record.get("assessment_reasons"), list)
    ):
        return False
    try:
        coverage_bytes = (run_dir / "coverage.json").read_bytes()
        coverage = json.loads(coverage_bytes)
    except (OSError, json.JSONDecodeError):
        return False
    if (
        not isinstance(coverage, dict)
        or coverage.get("run_id") != persisted.get("run_id")
        or not isinstance(coverage.get("completeness"), dict)
        or coverage["completeness"].get("scan_status") != "completed"
    ):
        return False
    manifest = persisted.get("result_manifest")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    coverage_manifest = artifacts.get("coverage.json") if isinstance(artifacts, dict) else None
    if (
        not isinstance(coverage_manifest, dict)
        or coverage_manifest.get("path") != "coverage.json"
        or coverage_manifest.get("bytes") != len(coverage_bytes)
        or coverage_manifest.get("sha256") != hashlib.sha256(coverage_bytes).hexdigest()
    ):
        return False
    try:
        evidence.verify_result_manifest(run_dir, manifest)
    except Exception:
        logger.exception("finish_scan: persisted result manifest verification failed")
        return False
    return True


def _leave_finish_unresolved(report_state: Any) -> None:
    """Persist a retryable state after final evidence fails verification."""
    results = report_state.run_record.get("scan_results")
    results = dict(results) if isinstance(results, dict) else {}
    results.update(success=False, scan_completed=False)
    report_state.scan_results = results
    report_state.run_record["scan_results"] = results
    report_state.run_record["status"] = "running"
    report_state.run_record["phase"] = "finalizing"
    report_state.run_record["end_time"] = None
    report_state.run_record["terminal_reason"] = "final_evidence_not_persisted"
    report_state.end_time = None
    try:
        if not report_state.save_run_data():
            logger.error("finish_scan: unresolved state receipt did not persist")
    except Exception:
        logger.exception("finish_scan: failed to persist unresolved finalization state")


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from lyrashield.artifacts.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            # Fail closed (I22): without report state there is no durable
            # record of completion, so the scan must not report success.
            logger.error("No global report state; finish_scan refused")
            return {
                "success": False,
                "scan_completed": False,
                "assessment": "inconclusive",
                "assessment_reasons": ["report_state_unavailable"],
                "coverage_complete": False,
                "coverage_gaps": [],
                "incomplete_agents": [],
                "error": (
                    "Scan completion not persisted: report state unavailable. "
                    "The scan was NOT finalized."
                ),
            }
        assessment = _finish_assessment(
            report_state=report_state,
            agent_graph=agent_graph or {},
        )
        report_state.update_scan_final_fields(
            executive_summary=_assessment_note(
                assessment=assessment,
                report_section=executive_summary.strip(),
            ),
            methodology=methodology.strip(),
            technical_analysis=_assessment_note(
                assessment=assessment,
                report_section=technical_analysis.strip(),
            ),
            recommendations=recommendations.strip(),
        )
        if not report_state.receipt_persisted:
            # The completion receipt never reached disk; claiming success
            # would finalize a lifecycle with no durable report state.
            logger.error("finish_scan: run.json receipt did not persist; not finalizing")
            return {
                "success": False,
                "scan_completed": False,
                **assessment,
                "assessment": "inconclusive",
                "assessment_reasons": sorted(
                    {*assessment["assessment_reasons"], "finalization_not_persisted"}
                ),
                "coverage_complete": False,
                "error": (
                    "Scan completion could not be persisted (run.json write failed); "
                    "the scan was NOT finalized. Retry finish_scan."
                ),
            }
        if not _final_evidence_is_durable(report_state):
            logger.error("finish_scan: final quality and coverage evidence is not durable")
            _leave_finish_unresolved(report_state)
            return {
                "success": False,
                "scan_completed": False,
                **assessment,
                "assessment": "inconclusive",
                "assessment_reasons": sorted(
                    {*assessment["assessment_reasons"], "final_evidence_not_persisted"}
                ),
                "coverage_complete": False,
                "error": (
                    "Final quality or coverage evidence was not durably persisted; "
                    "the scan was NOT finalized. Retry finish_scan."
                ),
            }
        vuln_count = len(report_state.vulnerability_reports)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
            **assessment,
        }


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **This is a terminal action, not a status probe.** Whatever you pass
    is persisted VERBATIM as the final, customer-facing report and then
    execution stops. There is no draft mode and no second chance: never
    submit placeholder, provisional, or "checking if done" text in any
    field, and never call ``finish_scan`` to poll whether subagents are
    done (use ``view_agent_graph`` / ``wait_for_agents`` for that).
    Call it exactly ONCE, only when every field holds genuine, finished
    assessment prose.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_agents`` (block until their report arrives),
       or ``stop_agent`` (graceful cancel). Only ``completed`` agents
       count as finished. Failed, crashed, stopped, budget-paused,
       unknown, or missing statuses remain incomplete and must be disclosed;
       they do not justify a positive security conclusion.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. It's a good idea to call ``list_reports`` before finishing to
       review every finding filed in this scan (use ``get_report`` for
       full detail on any of them) so your ``executive_summary`` /
       ``technical_analysis`` are grounded in what was actually reported
       — don't invent or omit findings. All vulnerabilities you found are
       filed via ``create_vulnerability_report`` — or, for known-CVE
       dependency findings, ``create_dependency_report`` (un-reported
       findings are not tracked and not credited). A dependency CVE
       already filed via ``create_dependency_report`` counts as reported;
       it does NOT need re-filing here and does NOT block finishing.
    3. Don't double-report — one report per distinct vulnerability.
    4. **Attack-chaining gate.** Do NOT finish until you have genuinely
       considered chaining the confirmed findings into higher-impact,
       end-to-end attack paths. Test materially related combinations when
       scope, evidence, and remaining budget allow; record unresolved chains
       as unverified rather than extending the run indefinitely. You may rule
       out combinations you can confidently call unrelated. Any
       validated chain must already be filed via
       ``create_vulnerability_report`` — a demonstrated end-to-end chain
       is a PoC-backed vulnerability, so it uses that tool even when one
       link is a dependency CVE (the standalone CVE stays in its own
       ``create_dependency_report``) — and surfaced prominently in
       ``executive_summary`` / ``technical_analysis``. Finding no real
       chain after a serious attempt is acceptable; skipping the
       chaining reasoning is not.

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Report output rules** (this content may be rendered into generated
    reports):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
      Never leak internal identifiers (proxy request IDs, internal
      vulnerability report IDs, or any system-generated IDs) into any
      field.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    - **Formatting — use markdown in every field.** These fields may be
      rendered into generated reports, so structure them clearly: lead
      each section with a short ``# Heading``, use ``**bold**`` for labels/emphasis,
      ``inline code`` for identifiers/paths/parameters, bullet or
      numbered lists for enumerations, and fenced code blocks
      (```` ```language ````) for any code/payload excerpts. Never emit
      one flat wall of prose or leave code unformatted.
    - If **zero** vulnerabilities were filed, say so plainly. Do not
      characterize the target as secure or clean from that result alone;
      the runtime appends an assessment limitation and returns unresolved
      coverage and incomplete agent work.

    Example (abbreviated — mirror this structure, not the wording)::

        executive_summary:
            # Executive Summary

            An external assessment of the **Acme Customer Portal**
            identified multiple weaknesses that could lead to
            unauthorized access to customer data.

            **Overall risk posture:** Elevated.

            **Key findings**
            - Confirmed SSRF in a URL-preview feature reaching internal
              network ranges.
            - Broken tenant isolation enabling cross-tenant data access.

            **Business impact**
            - Potential exposure of customer records across tenants.

        methodology:
            # Methodology

            Conducted per the **OWASP WSTG**.

            **Engagement type:** Gray-box external test.
            **Scope:** `https://app.acme.example`, `.../api/v1/`.

            **Activities:** recon, authn/session review, authorization
            and tenant-isolation testing, input/SSRF testing.

        technical_analysis:
            # Technical Analysis

            **Severity model** reflects exploitability x impact.

            1. **SSRF in URL preview** (Critical) — insufficient
               destination validation; reaches link-local addresses.
            2. **Broken tenant isolation** (High) — object identifiers
               accepted without ownership checks.

            **Systemic themes:** authorization enforced inconsistently;
            no deny-by-default egress policy.

        recommendations:
            # Recommendations

            **Immediate**
            1. Remediate SSRF: enforce a destination allowlist,
               deny-by-default, re-validate on every redirect hop.

            **Short-term**
            2. Centralize authorization with deny-by-default middleware.

            **Retest & validation:** re-test immediate items to confirm
            SSRF and tenant-isolation controls hold.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
        if active_agents and coordinator.reserve_stopped:
            active_agents = []
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    agent_graph = await coordinator.snapshot() if coordinator is not None else {}
    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        agent_graph=agent_graph,
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)
