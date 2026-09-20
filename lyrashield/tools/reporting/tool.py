# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Reporting tools — file vuln findings (with dedup + CVSS) and read them back.

``create_vulnerability_report`` / ``create_dependency_report`` file findings;
``list_reports`` / ``get_report`` let any agent (notably the root orchestrator)
review what's been filed so far across the whole scan.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from lyrashield.artifacts import evidence as _evidence
from strix.tools.nullish import clean_optional


if TYPE_CHECKING:
    from lyrashield.artifacts.state import ReportState

logger = logging.getLogger(__name__)


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


_CODE_LOCATION_FIELDS = (
    "file",
    "start_line",
    "end_line",
    "snippet",
    "label",
    "fix_before",
    "fix_after",
)


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _normalize_code_locations(
    raw: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    cleaned: list[dict[str, Any]] = []
    for loc in raw:
        normalized: dict[str, Any] = {}
        for field in _CODE_LOCATION_FIELDS:
            if field not in loc or loc[field] is None:
                continue
            value = loc[field]
            if field in ("start_line", "end_line"):
                try:
                    normalized[field] = int(value)
                except (TypeError, ValueError):
                    continue
            else:
                text = (
                    str(value).strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else str(value).strip()
                )
                if text:
                    normalized[field] = text
        if normalized.get("file") and normalized.get("start_line") is not None:
            cleaned.append(normalized)
    return cleaned or None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def _calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
            f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
            f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
            f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
        )
        c = CVSS3(vector)
        score = c.scores()[0]
        severity = c.severities()[0].lower()
    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "Title cannot be empty",
    "description": "Description cannot be empty",
    "impact": "Impact cannot be empty",
    "target": "Target cannot be empty",
    "technical_analysis": "Technical analysis cannot be empty",
    "poc_description": "PoC description cannot be empty",
    "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    "remediation_steps": "Remediation steps cannot be empty",
    "evidence": "Evidence cannot be empty - provide concrete proof of the finding",
    "assumptions": "Assumptions cannot be empty - state exploitability prerequisites",
}

_VALID_FIX_EFFORT = frozenset({"trivial", "low", "medium", "high"})


def _normalize_control_ids(control_ids: list[int] | None) -> tuple[list[int], list[str]]:
    if control_ids is None:
        return [], []
    normalized: list[int] = []
    for value in control_ids:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 50:
            return [], ["control_ids must contain only integer ranks from 1 to 50"]
        if value not in normalized:
            normalized.append(value)
    return normalized, []


_VALID_CONFIDENCE = _evidence.VALID_CONFIDENCE
_MAX_CONTEXTUAL_REASONING_CHARS = 4_000

_HTTP_EXCHANGE_DROPPED_WARNING = (
    "http_exchange_ids were not stored: the proxy project could not be reached to "
    "verify them. Attach them with update_vulnerability_report when the proxy "
    "responds again — the finding carries no verified exchange evidence until then."
)


def _validate_analysis_fields(
    *,
    confidence: str | None,
    confidence_rationale: str | None,
) -> list[str]:
    """Schema-1.1 analysis fields — additive: all optional, validated when given.

    ``confidence_rationale`` is required whenever confidence is set below
    ``high``, so a lowered rating always carries its reasoning.
    """
    errors: list[str] = []
    if confidence is not None:
        normalized, confidence_errors = _evidence.normalize_confidence(confidence)
        errors.extend(confidence_errors)
        if (
            normalized is not None
            and normalized != "high"
            and not str(confidence_rationale or "").strip()
        ):
            errors.append(
                "confidence_rationale is required when confidence is not 'high' - "
                "explain what lowers certainty"
            )
    return errors


def _validate_fix_verification(
    locations: list[dict[str, Any]] | None,
    fix_verification: Any,
) -> list[str]:
    """A location carrying a ``fix_after`` diff needs a verification statement.

    The object records the engine's attestation of the check the filing agent
    ran — it is not a verification receipt. A ``fix_before``/``fix_after``
    suggestion without it would ship a patch nobody checked.
    """
    errors: list[str] = []
    if (
        locations
        and any(loc.get("fix_after") for loc in locations)
        and (
            fix_verification is None
            or (isinstance(fix_verification, str) and not fix_verification.strip())
        )
    ):
        errors.append(
            "fix_verification is required when any code_location carries "
            "fix_after: state the check that proves the suggestion works"
        )
    if fix_verification is not None:
        _normalized, fv_errors = _evidence.normalize_fix_verification(fix_verification)
        errors.extend(fv_errors)
    return errors


async def _verify_http_exchange_ids(
    ctx: RunContextWrapper | None,
    raw: Any,
) -> tuple[list[str] | None, list[str], str | None]:
    """Verify cited proxy exchange ids against the current Caido project.

    Ids the project does not know fail validation. When the proxy itself
    cannot be queried the ids are dropped and a warning is returned instead,
    so a proxy outage never blocks a finding and unverified ids are never
    recorded as evidence.
    """
    request_ids, errors = _evidence.normalize_http_exchange_ids(raw)
    if request_ids is None or errors or not request_ids:
        return request_ids, errors, None
    if ctx is None:
        return None, [], _HTTP_EXCHANGE_DROPPED_WARNING

    try:
        from lyrashield.tools.proxy.tools import existing_request_ids

        existing, lookup_error = await existing_request_ids(ctx, request_ids)
    except Exception:  # noqa: BLE001
        logger.warning(
            "Could not verify HTTP exchange IDs against the current Caido project",
            exc_info=True,
        )
        return None, [], _HTTP_EXCHANGE_DROPPED_WARNING

    if existing is None:
        # Proxy unreachable: drop the ids, keep the finding, warn the caller.
        return None, [], lookup_error or _HTTP_EXCHANGE_DROPPED_WARNING
    missing_ids = [request_id for request_id in request_ids if request_id not in existing]
    if missing_ids:
        return (
            None,
            [
                "http_exchange_ids do not exist in the current proxy project: "
                + ", ".join(missing_ids)
            ],
            None,
        )
    return request_ids, [], None


def _with_warning(result: dict[str, Any], warning: str | None) -> dict[str, Any]:
    if warning and result.get("success"):
        result["warning"] = warning
    return result


def _finding_class_of(report: dict[str, Any]) -> str:
    raw = report.get("finding_class")
    if isinstance(raw, str) and raw.strip():
        return raw.strip().lower()
    return "dependency_cve" if report.get("dependency_metadata") else "dynamic"


async def _do_create(  # noqa: PLR0912, PLR0915
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: list[dict[str, Any]] | None,
    control_ids: list[int] | None = None,
    fix_pr_body: str | None = None,
    counterevidence: str | None = None,
    confidence: str | None = None,
    confidence_rationale: str | None = None,
    severity_change_conditions: str | None = None,
    fix_verification: dict[str, Any] | str | None = None,
    http_exchange_ids: list[str] | None = None,
    evidence_warnings: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
    }
    for name, msg in _REQUIRED_FIELDS.items():
        if not str(fields.get(name) or "").strip():
            errors.append(msg)

    errors.extend(
        _validate_analysis_fields(
            confidence=confidence,
            confidence_rationale=confidence_rationale,
        )
    )

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    if not isinstance(cvss_breakdown, dict) or not cvss_breakdown:
        errors.append("cvss_breakdown: must be an object with the 8 CVSS metrics")
        cvss_breakdown = {}
    else:
        for name, valid in _CVSS_VALID.items():
            value = cvss_breakdown.get(name)
            if value not in valid:
                errors.append(f"Invalid {name}: {value}. Must be one of: {valid}")

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    errors.extend(_validate_fix_verification(parsed_locations, fix_verification))
    normalized_exchange_ids, exchange_id_errors = _evidence.normalize_http_exchange_ids(
        http_exchange_ids
    )
    errors.extend(exchange_id_errors)
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)
    normalized_control_ids, control_errors = _normalize_control_ids(control_ids)
    errors.extend(control_errors)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)

    try:
        from lyrashield.artifacts.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            # Fail closed: a finding that cannot be persisted must never be
            # reported as filed — the run record is the only durable record.
            logger.error("No global report state; vulnerability report rejected")
            return {
                "success": False,
                "error": (
                    "Vulnerability report not persisted: report state unavailable. "
                    "The finding was NOT recorded — do not treat it as filed."
                ),
            }

        from lyrashield.artifacts.dedupe import check_duplicate

        existing = report_state.get_existing_vulnerabilities()
        candidate = {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "endpoint": endpoint,
            "method": method,
            "cwe": cwe,
            "code_locations": parsed_locations,
        }
        dedupe = await check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            duplicate_id = dedupe.get("duplicate_id", "")
            duplicate_title = next(
                (r.get("title", "Unknown") for r in existing if r.get("id") == duplicate_id),
                "",
            )
            return {
                "success": False,
                "error": (
                    f"Potential duplicate of '{duplicate_title}' "
                    f"(id={duplicate_id[:8]}...) — do not re-report the same vulnerability"
                ),
                "duplicate_of": duplicate_id,
                "duplicate_title": duplicate_title,
                "confidence": dedupe.get("confidence", 0.0),
                "reason": dedupe.get("reason", ""),
            }

        report_id = report_state.add_vulnerability_report(
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            evidence=evidence,
            assumptions=assumptions,
            fix_effort=fix_effort,
            cvss=cvss_score,
            cvss_breakdown=cvss_breakdown,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=parsed_locations,
            control_ids=normalized_control_ids,
            fix_pr_body=fix_pr_body,
            counterevidence=counterevidence,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            severity_change_conditions=severity_change_conditions,
            fix_verification=fix_verification,
            http_exchange_ids=normalized_exchange_ids or None,
            evidence_warnings=evidence_warnings,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )
    except (ImportError, AttributeError, RuntimeError, OSError, ValueError) as e:
        logger.exception("create_vulnerability_report persistence failed")
        return {"success": False, "error": f"Failed to create vulnerability report: {e!s}"}
    else:
        logger.info(
            "Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",
            report_id,
            severity,
            cvss_score,
            title,
        )
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cvss_score": cvss_score,
        }


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    """Return the (agent_id, agent_name) of the agent invoking this tool."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None
    return agent_id, agent_name


@function_tool(timeout=180, strict_mode=False)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    control_ids: list[int] | None = None,
    fix_pr_body: str | None = None,
    counterevidence: str | None = None,
    confidence: str | None = None,
    confidence_rationale: str | None = None,
    severity_change_conditions: str | None = None,
    fix_verification: str | None = None,
    http_exchange_ids: list[str] | None = None,
) -> str:
    """File a vulnerability report — one report per fully-verified finding.

    **When to file**: you have a concrete vulnerability with a working
    proof-of-concept and you're 100% sure it's a real issue.

    **When NOT to file**:

    - General security observations without a specific vulnerability.
    - Suspicions you haven't confirmed with a PoC.
    - Tracking multiple vulnerabilities at once — one report per vuln.
    - Re-reporting something you (or another agent) already filed.
    - Known-CVE dependency / supply-chain findings that can't be
      dynamically PoC'd — a vulnerable dependency version pinned in a
      lockfile/manifest that matches a published advisory. File those
      with ``create_dependency_report`` instead, never with this tool.

    Automatic LLM-based **deduplication** rejects reports that describe
    the same root cause on the same asset as an existing report. If you
    get a ``duplicate_of`` response, do NOT retry — move on to other
    areas.

    **Report output rules** (this content may be rendered into generated
    reports):

    - No internal/system details: never mention paths like
      ``/workspace``, internal tools, agents, sandboxes, models, system
      prompts, internal errors / stack traces, or tester environment.
      Never leak internal identifiers (proxy request IDs, internal
      report IDs) into any field. Proxy request IDs are the one exception:
      they belong only in the dedicated ``http_exchange_ids`` argument,
      never inside ``evidence`` or other report text.
    - Tone: formal, objective, third-person, vendor-neutral, concise.
      Avoid internal-guidance headings like "QUICK", "Approach", or
      "Techniques" that read like an engineering runbook rather than a
      client deliverable.
    - **Use markdown in every text field**: ``**bold**`` for emphasis,
      ``inline code`` for identifiers/values/parameters, and fenced
      code blocks (```` ```language ````) for any code/payload/HTTP
      excerpt. Never leave code bare/unformatted. When referencing a
      file, annotate the fence, e.g.
      ```` ```python title=app.py startLineNumber=42 endLineNumber=50 ````.
    - Field discipline: ``poc_description`` is steps only — NO code (all
      code goes in ``poc_script_code``); ``remediation_steps`` is prose
      only — NO code/diffs (code fixes go in ``code_locations``).
    - Numbered steps allowed only in PoC and Remediation sections.
    - Avoid hedging language; be precise and non-vague.
    - Follow a standard pentest report structure across the fields:
      (1) overview (``description``), (2) severity & CVSS vector
      (``cvss_breakdown``), (3) affected asset(s) (``target`` /
      ``endpoint``), (4) technical details (``technical_analysis``),
      (5) proof of concept (``poc_description`` + ``poc_script_code``),
      (6) impact (``impact``), (7) evidence (``evidence``), and
      (8) remediation (``remediation_steps``).

    **White-box requirement**: when source is available, you MUST
    populate ``code_locations``. See the ``code_locations`` arg below
    for the full rules around ``fix_before`` / ``fix_after``,
    multi-part fixes, and informational-vs-actionable entries.

    **CVSS breakdown** is an object with all 8 metrics (each a single
    uppercase letter):

    - ``attack_vector``: ``N`` (Network), ``A`` (Adjacent), ``L``
      (Local), ``P`` (Physical)
    - ``attack_complexity``: ``L`` / ``H``
    - ``privileges_required``: ``N`` / ``L`` / ``H``
    - ``user_interaction``: ``N`` / ``R``
    - ``scope``: ``U`` (Unchanged) / ``C`` (Changed)
    - ``confidentiality`` / ``integrity`` / ``availability``: ``N`` /
      ``L`` / ``H``

    Example::

        {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H"
        }

    **CVSS calibration** — score the weakness you actually proved, not a
    hypothetical worst case. Most over-rating comes from these mistakes:

    - **Don't presuppose a separate compromise.** If exploitation
      requires the attacker to already hold a victim secret (a stolen
      session cookie/token, a leaked one-time link, intercepted traffic),
      that acquisition is not free. Do not score it as
      ``privileges_required:N`` with ``attack_complexity:L`` as if
      directly reachable, and do not rate a replay-of-captured-secret
      issue High/Critical unless the *same* finding demonstrates a
      concrete way to obtain that secret. Issues like a session that
      survives logout or a replayable link are session-management /
      defense-in-depth weaknesses — usually Low/Medium on their own.
    - **Reserve ``H`` impact for demonstrated broad impact.** ``C:H`` /
      ``I:H`` require proof of wide or systemic read/write. A single
      user's data, a read-only information leak, or merely confirming
      that an account / domain / software version *exists* (enumeration)
      is ``C:L`` (often ``I:N``) — not ``C:H``.
    - **Model required position and interaction honestly.** An
      adversary-in-the-middle prerequisite (e.g. cleartext transmission)
      or a required victim action is not guaranteed — reflect it in
      ``attack_complexity`` / ``user_interaction`` instead of assuming the
      ideal condition always holds.

    **CVE / CWE rules**: pass the bare ID only (``CVE-2024-1234``,
    ``CWE-89``) — no name, no parenthetical. Be 100% certain; if
    unsure, omit the field rather than guessing
    the field entirely. Always prefer the most specific child CWE over
    a broad parent (CWE-89 not CWE-74; CWE-78 not CWE-77). Do NOT use
    broad/parent CWEs like CWE-74, CWE-20, CWE-200, CWE-284, or
    CWE-693.

    Common CWE references (use the ID only — names are listed here
    just for your lookup):

    - **Injection**: CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command
      Injection, CWE-94 Code Injection, CWE-77 Command Injection.
    - **Auth / Access**: CWE-287 Improper Authentication, CWE-862
      Missing Authorization, CWE-863 Incorrect Authorization, CWE-306
      Missing Auth for Critical Function, CWE-639 Authz Bypass via
      User-Controlled Key.
    - **Web**: CWE-352 CSRF, CWE-918 SSRF, CWE-601 Open Redirect,
      CWE-434 Unrestricted File Upload.
    - **Memory**: CWE-787 OOB Write, CWE-125 OOB Read, CWE-416 UAF,
      CWE-120 Classic Buffer Overflow.
    - **Data**: CWE-502 Deserialization of Untrusted Data, CWE-22
      Path Traversal, CWE-611 XXE.
    - **Crypto / Config**: CWE-798 Hard-coded Credentials, CWE-327
      Broken / Risky Crypto, CWE-311 Missing Encryption, CWE-916 Weak
      Password Hashing.

    Args:
        title: Specific finding title (e.g.
            ``"SQL Injection in /api/users login parameter"``). Don't
            include the CVE number in the title.
        description: Concise, non-technical TL;DR of the vulnerability
            (1-3 sentences) — it appears first in the report. Deep
            technical detail and root-cause analysis belong in
            ``technical_analysis``, not here.
        impact: What an attacker achieves; business risk; data at risk.
        target: Affected URL / domain / repository.
        technical_analysis: The mechanism and root cause.
        poc_description: Step-by-step reproduction (steps only, no code).
        poc_script_code: Working PoC (Python preferred).
        remediation_steps: Specific, actionable fix (prose, no code).
        evidence: Concrete proof the issue is real and exploitable —
            request/response excerpts, observed behavior, tool output.
            Use fenced code blocks; no internal identifiers/paths.
        assumptions: Short note on the assumptions/prerequisites that
            make this finding impactful or exploitable (e.g. "assumes an
            authenticated low-privilege user").
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: 8-metric object per the format above.
        endpoint: API path / Git path (e.g. ``/api/login``).
        method: HTTP method when relevant.
        cve: ``CVE-YYYY-NNNNN`` if certain, else omit.
        cwe: ``CWE-NNN`` (most specific child) if certain, else omit.
        code_locations: White-box findings — list of location objects.
        control_ids: Applicable LyraShield Vibe Security 50 ranks (1-50).

            **How ``fix_before`` / ``fix_after`` work**: they're used as
            literal GitHub/GitLab PR suggestion blocks. When a reviewer
            accepts the suggestion, the platform replaces the **exact
            lines from ``start_line`` to ``end_line``** with
            ``fix_after``. Therefore:

            1. ``fix_before`` must be a **VERBATIM** copy of the source
               at those lines — same whitespace, indentation, line
               breaks. If it doesn't match character-for-character, the
               suggestion will corrupt the code when accepted.
            2. ``fix_after`` is the COMPLETE replacement for that
               entire block (may be more or fewer lines).
            3. ``start_line`` / ``end_line`` must precisely cover the
               lines in ``fix_before`` — no more, no less.

            **Multi-part fixes**: many fixes touch multiple
            non-contiguous parts of a file (e.g. add an import at the
            top AND change code lower down). Since each
            ``fix_before`` / ``fix_after`` pair covers ONE contiguous
            block, create **separate location entries** for each
            non-contiguous part. Use ``label`` to describe each part's
            role (``"Add escape helper import"``, ``"Sanitize input
            before SQL"``). Order primary fix first, supporting
            changes (imports, config) after.

            **Informational vs actionable**:
            - With ``fix_before`` / ``fix_after``: actionable fix
              (renders as a PR suggestion block).
            - Without them: informational context (e.g. showing the
              source of tainted data, or a sink that doesn't need
              direct editing).

            **Per-location fields**:
            - ``file`` (REQUIRED): path **relative** to repo root. No
              leading slash, no ``..``, no ``/workspace/`` prefix.
              Right: ``"src/db/queries.ts"``. Wrong:
              ``"/workspace/repo/src/db/queries.ts"``, ``"./src/x.py"``,
              ``"../../etc/passwd"``.
            - ``start_line`` (REQUIRED): 1-based; positive integer.
              Verify against the actual file — do NOT guess.
            - ``end_line`` (REQUIRED): 1-based; ``>= start_line``.
              Only equal to ``start_line`` when the block truly is one
              line.
            - ``snippet`` (optional): verbatim source at this range.
            - ``label`` (optional): short role description; especially
              important for multi-part fixes.
            - ``fix_before`` (optional): verbatim copy of the
              vulnerable code, lines ``start_line``-``end_line``.
            - ``fix_after`` (optional): complete replacement for that
              block; syntactically valid.

            **Common mistakes to avoid**:
            - Guessing line numbers instead of reading the file.
            - Paraphrasing / reformatting code in ``fix_before``.
            - Setting ``start_line == end_line`` when the vulnerable
              code spans multiple lines.
            - Bundling an import addition and a far-away code change
              into one location — split them.
            - Padding ``fix_before`` with surrounding context lines
              that aren't part of the fix.
            - Duplicating the same change across multiple locations.
        fix_pr_body: Optional. When source is available and you have a
            concrete fix, a markdown PR-description body proposing the
            fix (summary + rationale). Prose/markdown only — the code
            change itself belongs in ``code_locations``. Omit for
            black-box findings.

    Example (abbreviated — mirror this structure)::

        title: "Reflected XSS in /search q parameter"
        description:
            The **`q`** parameter of `/search` reflects user input into
            the HTML response without encoding, allowing script
            injection.
        technical_analysis:
            The handler interpolates `q` directly into the page body:

            ```python title=views.py startLineNumber=42 endLineNumber=44
            html = f"<h2>Results for {q}</h2>"
            return HttpResponse(html)
            ```

            No output encoding is applied, so `<script>` executes.
        poc_description:
            1. Navigate to `/search?q=<payload>`.
            2. Observe the payload executes in the victim's browser.
        poc_script_code:
            ```
            GET /search?q=<script>alert(document.domain)</script>
            ```
        evidence:
            Response echoes the payload verbatim:

            ```html
            <h2>Results for <script>alert(document.domain)</script></h2>
            ```
        assumptions:
            Assumes a victim can be induced to open a crafted link.
        remediation_steps:
            Context-encode all user input rendered into HTML; prefer the
            template engine's auto-escaping over string interpolation.
        fix_effort: "low"
        counterevidence: The strongest case *against* this finding after
            actively looking for it — the guard you might have missed, the
            deployment constraint, the precondition. Say what you checked,
            not just "none".
        confidence: ``high`` / ``medium`` / ``low`` — your calibrated
            confidence that this is a real, exploitable issue.
        confidence_rationale: Required when ``confidence`` is not ``high``.
            Name the specific gap (e.g. "static-only trace, could not stand
            up the service to reproduce").
        severity_change_conditions: One concrete sentence on what single
            piece of additional evidence would raise or lower the severity.
        fix_verification: How you verified the suggested fix works (required
            when any ``code_locations`` entry carries ``fix_after``). Stored
            as an engine attestation of your check — not a verification
            receipt.
        http_exchange_ids: Proxy request IDs that prove this finding. Copy
            them exactly from ``list_requests``/``view_request`` — the
            exploit exchange plus the baseline/control it differs from. Omit
            only when no HTTP was captured at all; never invent IDs. If the
            result warns the IDs could not be verified, they were dropped —
            attach them with ``update_vulnerability_report`` when the proxy
            responds.
    """
    (
        verified_exchange_ids,
        exchange_errors,
        exchange_warning,
    ) = await _verify_http_exchange_ids(ctx, http_exchange_ids)
    if exchange_errors:
        return json.dumps(
            {"success": False, "error": "Validation failed", "errors": exchange_errors},
            ensure_ascii=False,
            default=str,
        )

    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        evidence=evidence,
        assumptions=assumptions,
        fix_effort=fix_effort,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
        control_ids=control_ids,
        fix_pr_body=fix_pr_body,
        counterevidence=counterevidence,
        confidence=confidence,
        confidence_rationale=confidence_rationale,
        severity_change_conditions=severity_change_conditions,
        fix_verification=fix_verification,
        http_exchange_ids=verified_exchange_ids,
        evidence_warnings=[exchange_warning] if exchange_warning else None,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(_with_warning(result, exchange_warning), ensure_ascii=False, default=str)


_DEP_SEVERITY_FROM_CVSS = {
    (9.0, 10.0): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (0.0, 4.0): "low",
}


def _dependency_severity(advisory_cvss: float | None) -> tuple[float, str]:
    if advisory_cvss is None:
        return 0.0, "info"
    score = max(0.0, min(10.0, advisory_cvss))
    for (lo, hi), label in _DEP_SEVERITY_FROM_CVSS.items():
        if lo <= score < hi or (hi == 10.0 and score == 10.0):
            return score, label
    return score, "none"


def _build_dependency_metadata(
    *,
    package_name: str,
    installed_version: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "package_name": package_name.strip(),
        "installed_version": installed_version.strip(),
    }
    if package_ecosystem and package_ecosystem.strip():
        metadata["package_ecosystem"] = package_ecosystem.strip()
    if fixed_version and fixed_version.strip():
        metadata["fixed_version"] = fixed_version.strip()
    return metadata


def _build_dependency_evidence(
    *,
    cve: str,
    package_name: str,
    installed_version: str,
    fixed_version: str | None,
) -> str:
    evidence = (
        f"**Advisory evidence:** `{cve}` applies to `{package_name}` "
        f"at installed version `{installed_version}`."
    )
    if fixed_version and fixed_version.strip():
        evidence += f" The advisory is fixed in `{fixed_version.strip()}`."
    return evidence


async def _do_create_dependency(  # noqa: PLR0912, PLR0915
    *,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    cwe: str | None,
    advisory_cvss: float | None,
    technical_analysis: str | None,
    fix_effort: str,
    control_ids: list[int] | None = None,
    advisory_cvss_vector: str | None = None,
    advisory_cvss_metric_reasoning: str | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_reasoning: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = {
        "title": title,
        "description": description,
        "target": target,
        "package_name": package_name,
        "installed_version": installed_version,
        "package_ecosystem": package_ecosystem,
        "impact": impact,
        "remediation_steps": remediation_steps,
        "assumptions": assumptions,
    }
    for name, value in required.items():
        if not str(value or "").strip():
            errors.append(f"{name} cannot be empty")

    parsed_cve = _extract_cve(cve or "")
    cve_err = _validate_cve(parsed_cve)
    if cve_err:
        errors.append(cve_err)

    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)
    normalized_control_ids, control_errors = _normalize_control_ids(control_ids)
    errors.extend(control_errors)

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    if advisory_cvss is None:
        errors.append(
            "advisory_cvss is required: read the published advisory base score "
            "(0.0-10.0) off the advisory (trivy CVSS / NVD / GHSA). Severity is "
            "derived solely from it — do not omit it or the finding cannot be rated."
        )
    elif not 0.0 <= advisory_cvss <= 10.0:
        errors.append(f"advisory_cvss must be between 0.0 and 10.0, got {advisory_cvss}")

    # Structured advisory_cvss evidence (schema 1.1): the published score with
    # its vector and metric reasoning, not a bare number.
    advisory_evidence, advisory_evidence_errors = _evidence.normalize_advisory_cvss(
        {
            "score": advisory_cvss,
            "vector": advisory_cvss_vector,
            "source": "published advisory",
            "metric_reasoning": advisory_cvss_metric_reasoning,
        }
        if advisory_cvss is not None
        else None
    )
    errors.extend(advisory_evidence_errors)

    # A contextual breakdown rates the CVE as observed in this codebase; the
    # advisory score stays the published reference inside dependency_metadata.
    if contextual_cvss_breakdown is not None or contextual_cvss_reasoning is not None:
        if not contextual_cvss_breakdown:
            errors.append(
                "contextual_cvss_breakdown is required: rate the CVE in this codebase "
                "with all 8 CVSS v3.1 metrics when you restate the rating"
            )
        else:
            for name, valid in _CVSS_VALID.items():
                value = contextual_cvss_breakdown.get(name)
                if value not in valid:
                    errors.append(
                        f"Invalid contextual_cvss_breakdown {name}: {value}. "
                        f"Must be one of: {valid}"
                    )
        if not str(contextual_cvss_reasoning or "").strip():
            errors.append(
                "contextual_cvss_reasoning is required: state what you observed in "
                "this codebase that justifies the contextual rating"
            )

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    cvss_score, severity = _dependency_severity(advisory_cvss)
    dependency_metadata = _build_dependency_metadata(
        package_name=package_name,
        installed_version=installed_version,
        package_ecosystem=package_ecosystem or "",
        fixed_version=fixed_version,
    )
    if contextual_cvss_breakdown:
        ctx_score, ctx_severity, ctx_vector = _calculate_cvss(contextual_cvss_breakdown)
        cvss_score, severity = ctx_score, ctx_severity
        dependency_metadata["contextual_cvss_breakdown"] = contextual_cvss_breakdown
        dependency_metadata["contextual_cvss_score"] = ctx_score
        dependency_metadata["contextual_cvss_vector"] = ctx_vector
        dependency_metadata["contextual_cvss_reasoning"] = str(
            contextual_cvss_reasoning or ""
        ).strip()[:_MAX_CONTEXTUAL_REASONING_CHARS]
    evidence = _build_dependency_evidence(
        cve=parsed_cve,
        package_name=package_name.strip(),
        installed_version=installed_version.strip(),
        fixed_version=fixed_version,
    )

    try:
        from lyrashield.artifacts.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            # Fail closed (I6): an unpersisted dependency finding must never
            # be reported as filed.
            logger.error("No global report state; dependency report rejected")
            return {
                "success": False,
                "error": (
                    "Dependency report not persisted: report state unavailable. "
                    "The finding was NOT recorded — do not treat it as filed."
                ),
            }

        from lyrashield.artifacts.dedupe import check_duplicate

        existing = report_state.get_existing_vulnerabilities()
        candidate = {
            "title": title,
            "description": description,
            "target": target,
            "cve": parsed_cve,
            "dependency_metadata": dependency_metadata,
            "technical_analysis": technical_analysis,
        }
        dedupe = await check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            duplicate_id = dedupe.get("duplicate_id", "")
            return {
                "success": False,
                "error": (
                    f"Potential duplicate (id={duplicate_id[:8]}...) — "
                    "do not re-report the same dependency finding"
                ),
                "duplicate_of": duplicate_id,
                "confidence": dedupe.get("confidence", 0.0),
                "reason": dedupe.get("reason", ""),
            }

        report_id = report_state.add_vulnerability_report(
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            remediation_steps=remediation_steps,
            evidence=evidence,
            assumptions=assumptions,
            fix_effort=fix_effort,
            cvss=cvss_score if advisory_cvss is not None else None,
            cve=parsed_cve,
            cwe=cwe,
            finding_class="dependency_cve",
            dependency_metadata=dependency_metadata,
            control_ids=normalized_control_ids,
            advisory_cvss=advisory_evidence,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )
    except (ImportError, AttributeError, RuntimeError, OSError, ValueError) as e:
        logger.exception("create_dependency_report persistence failed")
        return {"success": False, "error": f"Failed to create dependency report: {e!s}"}
    else:
        logger.info(
            "Dependency report created: id=%s cve=%s package=%s severity=%s",
            report_id,
            parsed_cve,
            package_name,
            severity,
        )
        return {
            "success": True,
            "message": f"Dependency finding '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cve": parsed_cve,
        }


@function_tool(timeout=180, strict_mode=False)
async def create_dependency_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    advisory_cvss: float,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str,
    fixed_version: str | None = None,
    cwe: str | None = None,
    technical_analysis: str | None = None,
    fix_effort: str = "low",
    control_ids: list[int] | None = None,
    advisory_cvss_vector: str | None = None,
    advisory_cvss_metric_reasoning: str | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> str:
    """File a known-CVE dependency (SCA) finding — one report per CVE x package.

    Use this instead of ``create_vulnerability_report`` when the finding
    is a **known-CVE supply-chain issue**: a vulnerable third-party
    package/version identified from a lockfile, manifest, or SBOM. Unlike
    a dynamic finding, you do NOT need to trigger the vulnerability with a
    live PoC — a verified advisory + the affected installed version is the
    evidence.

    **When to file**:

    - A dependency is pinned to a version covered by a published CVE.
    - You have verified the CVE ID and the installed version falls in the
      affected range from local scanner/advisory evidence.

    **When NOT to file**:

    - Dynamically-proven vulnerabilities → use
      ``create_vulnerability_report`` (``finding_class`` dynamic).
    - Outdated-but-not-vulnerable dependencies with no CVE.
    - Re-reporting the same CVE/package already filed.

    **Reachability**: do NOT silently downgrade or suppress a finding
    because the vulnerable code path may be unreachable — instead state
    reachability as an ``assumptions`` / confidence factor. Report the
    finding; let the reader weigh exploitability.

    **Formatting**: use markdown in text fields (``**bold**``, ``inline
    code`` for package/version identifiers, fenced code blocks for
    manifest excerpts). No internal paths/tooling/agent references.

    Args:
        title: e.g. ``"CVE-2024-1234 in lodash 4.17.20 (prototype pollution)"``.
        description: What the CVE is and why the pinned version is affected.
        target: Affected repository / project / manifest.
        cve: ``CVE-YYYY-NNNNN`` — required and must be verified.
        package_name: Affected package name (e.g. ``lodash``).
        installed_version: The version currently pinned/installed.
        impact: What the CVE enables; business risk in this context.
        remediation_steps: How to fix (usually upgrade to a fixed version).
        assumptions: Exploitability/reachability assumptions & confidence.
        package_ecosystem: e.g. ``npm`` / ``pypi`` / ``maven`` / ``go``.
        fixed_version: First non-vulnerable version, if known.
        cwe: ``CWE-NNN`` (most specific) if certain, else omit.
        advisory_cvss: **Required.** Published advisory base score
            (0.0-10.0) — read it off the advisory (trivy CVSS / NVD / GHSA).
            Severity is derived solely from this score, so it must be the
            real published value; do not guess or omit it.
        technical_analysis: Optional deeper mechanism/root-cause detail.
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``
            (dependency upgrades are usually ``trivial``/``low``).
        control_ids: Applicable LyraShield Vibe Security 50 ranks (1-50).
        advisory_cvss_vector: The published CVSS vector string
            (e.g. ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``) when the
            advisory carries one — stored beside the score.
        advisory_cvss_metric_reasoning: Why the published vector's metrics
            are what they are, when the advisory states it.
        contextual_cvss_breakdown: All 8 CVSS metrics as observed in THIS
            codebase — when your trace changes the published rating. Requires
            ``contextual_cvss_reasoning``; the advisory score stays the
            published reference.
        contextual_cvss_reasoning: What you observed in this codebase that
            justifies the contextual rating.
    """
    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_create_dependency(
        title=title,
        description=description,
        target=target,
        cve=cve,
        package_name=package_name,
        installed_version=installed_version,
        impact=impact,
        remediation_steps=remediation_steps,
        assumptions=assumptions,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
        cwe=cwe,
        advisory_cvss=advisory_cvss,
        technical_analysis=technical_analysis,
        fix_effort=fix_effort,
        control_ids=control_ids,
        advisory_cvss_vector=advisory_cvss_vector,
        advisory_cvss_metric_reasoning=advisory_cvss_metric_reasoning,
        contextual_cvss_breakdown=contextual_cvss_breakdown,
        contextual_cvss_reasoning=contextual_cvss_reasoning,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "none": 5,
}
_VALID_SEVERITIES = frozenset(_SEVERITY_ORDER)
_VALID_FINDING_CLASSES = frozenset({"dynamic", "dependency_cve"})
_REPORT_DESCRIPTION_PREVIEW_CHARS = 280

# Compact, listing-safe fields — no full bodies / PoC code / evidence.
_REPORT_SUMMARY_FIELDS = (
    "id",
    "title",
    "severity",
    "cvss",
    "finding_class",
    "cve",
    "cwe",
    "target",
    "endpoint",
    "method",
    "fix_effort",
    "agent_name",
    "timestamp",
)


def _report_severity_rank(report: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(report.get("severity", "")).lower(), 99)


def _report_matches_filters(
    report: dict[str, Any],
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
) -> bool:
    if severity and str(report.get("severity", "")).lower() != severity:
        return False
    if finding_class and str(report.get("finding_class", "dynamic")).lower() != finding_class:
        return False
    if target:
        target_lower = target.lower()
        haystack = f"{report.get('target', '')} {report.get('endpoint', '')}".lower()
        if target_lower not in haystack:
            return False
    if search:
        search_lower = search.lower()
        title_match = search_lower in str(report.get("title", "")).lower()
        desc_match = search_lower in str(report.get("description", "")).lower()
        if not (title_match or desc_match):
            return False
    return True


def _mark_authorship(
    entry: dict[str, Any], report: dict[str, Any], caller_agent_id: str | None
) -> dict[str, Any]:
    """Flag whether ``report`` was filed by the agent making this call."""
    if caller_agent_id is not None and report.get("agent_id") == caller_agent_id:
        entry["by_you"] = True
    return entry


def _to_report_summary_entry(
    report: dict[str, Any], caller_agent_id: str | None = None
) -> dict[str, Any]:
    entry = {
        field: report[field] for field in _REPORT_SUMMARY_FIELDS if report.get(field) is not None
    }
    description = str(report.get("description", "")).strip()
    if description:
        if len(description) > _REPORT_DESCRIPTION_PREVIEW_CHARS:
            entry["description_preview"] = (
                f"{description[:_REPORT_DESCRIPTION_PREVIEW_CHARS].rstrip()}..."
            )
        else:
            entry["description_preview"] = description
    return _mark_authorship(entry, report, caller_agent_id)


def _severity_counts(reports: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for report in reports:
        sev = str(report.get("severity", "")).lower() or "none"
        counts[sev] = counts.get(sev, 0) + 1
    return {sev: counts[sev] for sev in _SEVERITY_ORDER if sev in counts}


async def _run_report_reader(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except (ImportError, AttributeError) as e:
        logger.exception("report reader failed")
        return {"success": False, "error": f"Failed to read reports: {e!s}"}


def _do_list_reports(
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
    include_details: bool,
    caller_agent_id: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    severity = (clean_optional(severity) or "").lower() or None
    if severity and severity not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: {severity!r}. Must be one of: {sorted(_VALID_SEVERITIES)}"
        )
    finding_class = (clean_optional(finding_class) or "").lower() or None
    if finding_class and finding_class not in _VALID_FINDING_CLASSES:
        errors.append(
            f"Invalid finding_class: {finding_class!r}. "
            f"Must be one of: {sorted(_VALID_FINDING_CLASSES)}"
        )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    from lyrashield.artifacts.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": True,
            "reports": [],
            "filtered_count": 0,
            "total_count": 0,
            "severity_counts": {},
            "warning": "Report state unavailable - no reports have been filed yet",
        }

    all_reports = report_state.get_existing_vulnerabilities()
    matched = [
        r
        for r in all_reports
        if _report_matches_filters(
            r,
            severity=severity,
            finding_class=finding_class,
            target=clean_optional(target),
            search=clean_optional(search),
        )
    ]
    matched.sort(key=lambda r: (_report_severity_rank(r), str(r.get("id", ""))))

    reports = [
        _mark_authorship(dict(r), r, caller_agent_id)
        if include_details
        else _to_report_summary_entry(r, caller_agent_id)
        for r in matched
    ]
    return {
        "success": True,
        "reports": reports,
        "filtered_count": len(reports),
        "total_count": len(all_reports),
        "severity_counts": _severity_counts(all_reports),
    }


def _do_get_report(report_id: str, caller_agent_id: str | None = None) -> dict[str, Any]:
    report_id = (report_id or "").strip()
    if not report_id:
        return {"success": False, "error": "report_id cannot be empty", "report": None}

    from lyrashield.artifacts.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
            "report": None,
        }

    for report in report_state.get_existing_vulnerabilities():
        if report.get("id") == report_id:
            return {
                "success": True,
                "report": _mark_authorship(dict(report), report, caller_agent_id),
            }
    return {
        "success": False,
        "error": f"Report with id '{report_id}' not found",
        "report": None,
    }


@function_tool(timeout=30)
async def list_reports(
    ctx: RunContextWrapper,
    severity: str | None = None,
    finding_class: str | None = None,
    target: str | None = None,
    search: str | None = None,
    include_details: bool = False,
) -> str:
    """List vulnerability reports filed so far in this scan — metadata-first.

    **For the orchestrator / root agent.** This is an orchestration tool
    for tracking scan-wide coverage and assembling the final report — leaf
    / specialist agents do their own testing and file findings; they should
    NOT call this. If you are a subagent, ignore it and focus on your task.

    Reports are shared across **every** agent in the scan, so this returns
    findings filed by any agent (root or child), not just your own. As the
    root agent, use it to track progress, avoid dispatching work on
    already-covered ground, reason about attack-chaining across confirmed
    findings, and build the ``finish_scan`` executive summary.

    By default each entry is compact: ``id``, ``title``, ``severity``,
    ``cvss``, ``finding_class``, ``cve`` / ``cwe``, ``target`` /
    ``endpoint``, ``fix_effort``, ``agent_name`` (who filed it), ``timestamp``,
    plus a 280-char ``description_preview``. Entries you filed yourself are
    flagged ``by_you: true``. The response also carries
    ``total_count`` and ``severity_counts`` (counts per severity across all
    reports, ignoring filters). Set ``include_details=True`` for full report
    bodies (PoC, evidence, remediation, code_locations) — token-expensive;
    prefer ``get_report`` to drill into a single finding.

    Filters compose (all must match): ``severity`` and ``finding_class``
    match exactly, ``target`` is a substring match against target/endpoint,
    and ``search`` is a substring match against title/description. Results
    are ordered by severity (critical -> info), then report id.

    This is read-only — it never files or dedupes anything.

    Args:
        severity: Filter to one of ``critical`` / ``high`` / ``medium`` /
            ``low`` / ``info`` / ``none``.
        finding_class: Filter to ``dynamic`` (PoC-backed) or
            ``dependency_cve`` (known-CVE supply-chain).
        target: Substring match against a report's target / endpoint.
        search: Substring match against title and description.
        include_details: When False (default) entries are compact; when
            True full report bodies are returned.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(
            _do_list_reports,
            severity=severity,
            finding_class=finding_class,
            target=target,
            search=search,
            include_details=include_details,
            caller_agent_id=caller_agent_id,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_report(ctx: RunContextWrapper, report_id: str) -> str:
    """Fetch one vulnerability report by its id (e.g. ``vuln-0001``).

    Returns the full report body — description, impact, technical analysis,
    PoC, evidence, remediation, CVSS breakdown, and any ``code_locations``.
    Use ``list_reports`` first to find ids; this is the cheap way to read a
    single finding in full without pulling every body.

    Read-only.

    Args:
        report_id: Report id from ``list_reports`` or a
            ``create_vulnerability_report`` / ``create_dependency_report``
            response (format ``vuln-NNNN``).
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(_do_get_report, report_id, caller_agent_id),
        ensure_ascii=False,
        default=str,
    )


# ---------------------------------------------------------------------------
# update_vulnerability_report — bounded, append-only finding revisions
# ---------------------------------------------------------------------------

# Free-text fields a revision may replace (validated against the same rules
# as creation; see state.UPDATABLE_REPORT_FIELDS for the full set).
_UPDATE_TEXT_FIELDS = (
    "title",
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
    "confidence_rationale",
    "severity_change_conditions",
    "endpoint",
    "method",
    "fix_pr_body",
    "contextual_cvss_reasoning",
)


def _validate_cvss_breakdown(breakdown: Any) -> list[str]:
    """Check the 8 CVSS metrics are all present with legal values."""
    if not isinstance(breakdown, dict) or not breakdown:
        return ["cvss_breakdown: must be an object with the 8 CVSS metrics"]
    errors: list[str] = []
    for name, valid in _CVSS_VALID.items():
        value = breakdown.get(name)
        if value not in valid:
            errors.append(f"Invalid {name}: {value}. Must be one of: {valid}")
    return errors


def _collect_update_changes(fields: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:  # noqa: PLR0912, PLR0915
    """Validate the fields a revision replaces and return them with any errors."""
    errors: list[str] = []
    changes: dict[str, Any] = {}

    for name in _UPDATE_TEXT_FIELDS:
        value = clean_optional(fields.get(name))
        if value is not None:
            changes[name] = value

    confidence = clean_optional(fields.get("confidence"))
    if confidence is not None:
        confidence = confidence.lower()
        if confidence not in _VALID_CONFIDENCE:
            errors.append(
                f"Invalid confidence: {confidence!r}. Must be one of: {sorted(_VALID_CONFIDENCE)}"
            )
        else:
            changes["confidence"] = confidence

    fix_effort = clean_optional(fields.get("fix_effort"))
    if fix_effort is not None:
        fix_effort = fix_effort.lower()
        if fix_effort not in _VALID_FIX_EFFORT:
            errors.append(
                f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
            )
        else:
            changes["fix_effort"] = fix_effort

    breakdown = fields.get("cvss_breakdown")
    if breakdown is not None:
        breakdown_errors = _validate_cvss_breakdown(breakdown)
        errors.extend(breakdown_errors)
        if not breakdown_errors:
            cvss_score, severity, _vector = _calculate_cvss(breakdown)
            # The rating belongs to the vector, so a revised vector carries
            # its own score and severity rather than leaving the old ones.
            changes["cvss_breakdown"] = breakdown
            changes["cvss"] = cvss_score
            changes["severity"] = severity

    raw_locations = fields.get("code_locations")
    locations = _normalize_code_locations(raw_locations)
    if locations:
        errors.extend(_validate_code_locations(locations))
        errors.extend(_validate_fix_verification(locations, fields.get("fix_verification")))
        changes["code_locations"] = locations
    elif raw_locations:
        errors.append(
            "code_locations were dropped as unusable - every location needs a relative "
            "'file' and an integer 'start_line'"
        )

    cve = clean_optional(fields.get("cve"))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
        else:
            changes["cve"] = cve
    cwe = clean_optional(fields.get("cwe"))
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)
        else:
            changes["cwe"] = cwe

    if fields.get("fix_verification") is not None:
        normalized_fv, fv_errors = _evidence.normalize_fix_verification(fields["fix_verification"])
        errors.extend(fv_errors)
        if normalized_fv is not None:
            changes["fix_verification"] = normalized_fv

    advisory = fields.get("advisory_cvss")
    if advisory is not None:
        normalized_adv, adv_errors = _evidence.normalize_advisory_cvss(advisory)
        errors.extend(adv_errors)
        if normalized_adv is not None:
            changes["advisory_cvss"] = normalized_adv

    exchange_ids = fields.get("http_exchange_ids")
    if exchange_ids is not None:
        normalized_ids, id_errors = _evidence.normalize_http_exchange_ids(exchange_ids)
        errors.extend(id_errors)
        if normalized_ids is not None:
            changes["http_exchange_ids"] = normalized_ids

    warnings_in = fields.get("evidence_warnings")
    if isinstance(warnings_in, list):
        changes["evidence_warnings"] = [str(w).strip()[:500] for w in warnings_in if str(w).strip()]

    return changes, errors


# Evidence that only a dynamic finding carries. A dependency finding describes
# a package, not a request against an endpoint.
_DYNAMIC_ONLY_UPDATE_FIELDS = (
    "endpoint",
    "method",
    "poc_description",
    "poc_script_code",
    "http_exchange_ids",
)

# A dependency finding is rated in the context of the codebase that pins it,
# and that rating is only shown with the reasoning behind it.
_DEPENDENCY_ONLY_UPDATE_FIELDS = ("contextual_cvss_reasoning",)


def _reject_cross_class_revision(
    report_id: str,
    matched_class: str,
    offending: list[str],
) -> dict[str, Any]:
    logger.info(
        "Revision of %s carries fields (%s) a %s finding does not hold; rejecting",
        report_id,
        ", ".join(offending),
        matched_class,
    )
    return {
        "success": False,
        "error": (
            f"Report '{report_id}' is a {matched_class} finding, so it cannot carry "
            f"{', '.join(offending)}. File your proof as its own vulnerability report "
            "instead of writing it onto this one."
        ),
        "report_id": report_id,
        "finding_class": matched_class,
        "rejected_fields": offending,
    }


def _rate_dependency_revision(
    report_id: str,
    matched: dict[str, Any],
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """Turn a replacement ``cvss_breakdown`` into the contextual rating.

    A dependency record keeps its rating as ``cvss``/``severity`` plus the
    contextual breakdown, vector and reasoning inside ``dependency_metadata``.
    The package identity in that metadata is copied over untouched. A new
    breakdown needs its own reasoning; the reasoning alone can be corrected
    when the record already carries the breakdown it explains.
    """
    breakdown = changes.pop("cvss_breakdown", None)
    reasoning = changes.pop("contextual_cvss_reasoning", None)
    if breakdown is None and reasoning is None:
        return None

    metadata = dict(matched.get("dependency_metadata") or {})
    if breakdown is None and not metadata.get("contextual_cvss_breakdown"):
        return {
            "success": False,
            "error": "Validation failed",
            "errors": [
                "cvss_breakdown is required: this dependency finding carries no "
                "contextual rating yet, so contextual_cvss_reasoning has nothing to explain"
            ],
            "report_id": report_id,
        }
    if reasoning is None:
        return {
            "success": False,
            "error": "Validation failed",
            "errors": [
                "contextual_cvss_reasoning is required: a dependency finding is re-rated "
                "with the cvss_breakdown observed in this codebase together with the "
                "reasoning a reader can check"
            ],
            "report_id": report_id,
        }

    if breakdown is not None:
        score, _severity, vector = _calculate_cvss(breakdown)
        metadata["contextual_cvss_breakdown"] = breakdown
        metadata["contextual_cvss_score"] = score
        metadata["contextual_cvss_vector"] = vector
    metadata["contextual_cvss_reasoning"] = reasoning[:_MAX_CONTEXTUAL_REASONING_CHARS]
    changes["dependency_metadata"] = metadata
    # The contextual rating replaces the headline rating too.
    if breakdown is not None:
        changes["cvss"] = score
        changes["severity"] = _severity
    return None


def _fit_revision_to_class(
    report_state: ReportState,
    report_id: str,
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """Keep a revision inside the class of the finding it names."""
    matched = next(
        (r for r in report_state.get_existing_vulnerabilities() if r.get("id") == report_id),
        None,
    )
    if matched is None:
        return None

    matched_class = _finding_class_of(matched)
    foreign = (
        _DEPENDENCY_ONLY_UPDATE_FIELDS
        if matched_class == "dynamic"
        else _DYNAMIC_ONLY_UPDATE_FIELDS
    )
    offending = [name for name in foreign if name in changes]
    if offending:
        return _reject_cross_class_revision(report_id, matched_class, offending)
    if matched_class == "dynamic":
        return None
    return _rate_dependency_revision(report_id, matched, changes)


def _read_revision(
    report_id: str, update_reason: str, fields: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return the changes a revision asks for, or the reason it cannot be acted on."""
    if not report_id or not str(update_reason or "").strip():
        missing = "report_id" if not report_id else "update_reason"
        return {}, {
            "success": False,
            "error": (
                f"{missing} cannot be empty - name the report you are revising and state "
                "what you learned that it does not yet carry"
            ),
        }

    changes, errors = _collect_update_changes(fields)
    if errors:
        return {}, {"success": False, "error": "Validation failed", "errors": errors}
    if not changes:
        return {}, {
            "success": False,
            "error": "No fields to update - pass at least one field you want to replace",
        }
    return changes, None


async def _do_update(
    *,
    report_id: str,
    update_reason: str,
    fields: dict[str, Any],
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Apply an agent's own revision to a report it can name.

    Editing a finding is its own operation and the only way a filed finding
    changes. Deduplication never reaches this path: it only decides whether a
    new candidate is a finding already on file.
    """
    report_id = (report_id or "").strip()
    changes, rejection = _read_revision(report_id, update_reason, fields)
    if rejection is not None:
        return rejection

    from lyrashield.artifacts.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
        }

    class_error = _fit_revision_to_class(report_state, report_id, changes)
    if class_error is not None:
        return class_error

    if "evidence_warnings" in changes:
        # Warnings append rather than replace — a dropped-evidence note from an
        # earlier revision must survive a later one.
        matched = next(
            (r for r in report_state.get_existing_vulnerabilities() if r.get("id") == report_id),
            None,
        )
        prior = matched.get("evidence_warnings") if matched else None
        merged = [
            *(prior if isinstance(prior, list) else []),
            *changes["evidence_warnings"],
        ]
        deduped = list(dict.fromkeys(str(w) for w in merged))
        changes["evidence_warnings"] = deduped[:20]

    try:
        updated = report_state.update_vulnerability_report(
            report_id,
            changes,
            update_reason=update_reason,
            updated_by_agent_id=agent_id,
            updated_by_agent_name=agent_name,
        )
    except (RuntimeError, ValueError) as exc:
        # Sealed run, schema-1.0 record, bound overflow, or a failed
        # persistence — the original evidence is untouched either way.
        return {
            "success": False,
            "error": str(exc),
            "report_id": report_id,
        }
    if updated is None:
        known = [r.get("id") for r in report_state.get_existing_vulnerabilities()]
        if report_id not in known:
            error = f"Report with id '{report_id}' not found"
        else:
            error = f"Report '{report_id}' already says this - nothing in your update changes it"
        return {"success": False, "error": error, "report_id": report_id}

    logger.info(
        "Vulnerability report %s revised by its author: severity=%s cvss=%s fields=%s",
        report_id,
        updated.get("severity"),
        updated.get("cvss"),
        ", ".join(sorted(changes)),
    )
    return {
        "success": True,
        "action": "updated",
        "message": f"Report '{report_id}' now carries your revision. Do not file it again.",
        "report_id": report_id,
        "updated_fields": sorted(changes),
        "severity": updated.get("severity"),
        "cvss_score": updated.get("cvss"),
    }


@function_tool(timeout=60, strict_mode=False)
async def update_vulnerability_report(
    ctx: RunContextWrapper,
    report_id: str,
    update_reason: str,
    title: str | None = None,
    description: str | None = None,
    impact: str | None = None,
    target: str | None = None,
    technical_analysis: str | None = None,
    poc_description: str | None = None,
    poc_script_code: str | None = None,
    remediation_steps: str | None = None,
    evidence: str | None = None,
    assumptions: str | None = None,
    counterevidence: str | None = None,
    confidence: str | None = None,
    confidence_rationale: str | None = None,
    severity_change_conditions: str | None = None,
    fix_effort: str | None = None,
    cvss_breakdown: dict[str, str] | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    http_exchange_ids: list[str] | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> str:
    """Revise a vulnerability report you (or another agent) already filed.

    Use this when you learn something a filed finding does not yet carry —
    you built the PoC after filing it, a chain raised its impact, further
    testing weakened it, or its counterevidence/remediation/code locations
    were wrong. The finding keeps its id and gains a revision entry; nothing
    is silently rewritten.

    Read the finding first with ``get_report`` and pass only the fields that
    change. ``update_reason`` is required: state what you learned.

    Args:
        report_id: Report id (``vuln-NNNN``) from ``list_reports``.
        update_reason: What you learned that the filed report does not carry.
        title: Replacement title.
        description: Replacement description.
        impact: Replacement impact narrative.
        target: Replacement affected asset.
        technical_analysis: Replacement technical details.
        poc_description: Replacement PoC steps (no code).
        poc_script_code: Replacement exploit script or payload.
        remediation_steps: Replacement remediation prose (no code).
        evidence: Replacement evidence.
        assumptions: Replacement exploitability prerequisites.
        counterevidence: Replacement case against the finding.
        confidence: ``high`` / ``medium`` / ``low``.
        confidence_rationale: The gap behind a confidence below ``high``.
        severity_change_conditions: What would move the severity now.
        fix_effort: ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: All 8 CVSS metrics. Replaces the score and severity too.
        endpoint: Replacement endpoint.
        method: Replacement HTTP method.
        cve: Replacement CVE id.
        cwe: Replacement CWE id.
        code_locations: Replacement code locations.
        http_exchange_ids: Replacement proxy request ids — verified against the
            live proxy project. Pass an empty list to remove all linked
            exchanges.
        fix_verification: Verification statement for an applyable fix.
        fix_pr_body: Replacement fix PR body.
        contextual_cvss_reasoning: Dependency findings only. What you observed
            in this codebase that justifies the contextual ``cvss_breakdown``.
    """
    (
        verified_exchange_ids,
        exchange_errors,
        exchange_warning,
    ) = await _verify_http_exchange_ids(ctx, http_exchange_ids)
    if exchange_errors:
        return json.dumps(
            {"success": False, "error": "Validation failed", "errors": exchange_errors},
            ensure_ascii=False,
            default=str,
        )

    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
        "counterevidence": counterevidence,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "severity_change_conditions": severity_change_conditions,
        "fix_effort": fix_effort,
        "cvss_breakdown": cvss_breakdown,
        "endpoint": endpoint,
        "method": method,
        "cve": cve,
        "cwe": cwe,
        "code_locations": code_locations,
        "http_exchange_ids": verified_exchange_ids,
        "fix_verification": fix_verification,
        "fix_pr_body": fix_pr_body,
        "contextual_cvss_reasoning": contextual_cvss_reasoning,
    }
    if exchange_warning:
        # The proxy dropped the ids — the revision still applies, but the
        # finding records the unverified-evidence warning so a reader sees
        # the gap instead of a silent omission.
        warnings = [exchange_warning]
        fields["evidence_warnings"] = warnings
        if all(value is None for key, value in fields.items() if key != "evidence_warnings"):
            return json.dumps(
                {"success": False, "error": exchange_warning, "report_id": report_id},
                ensure_ascii=False,
                default=str,
            )

    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_update(
        report_id=report_id,
        update_reason=update_reason,
        fields=fields,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(_with_warning(result, exchange_warning), ensure_ascii=False, default=str)
