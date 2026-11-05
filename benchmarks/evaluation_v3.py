"""One-to-one scoring and claim-readiness contracts for evaluation v3."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from benchmarks.corpus.v3.validate import validate as validate_corpus_v3
from benchmarks.score import (
    bind_findings_to_runs,
    case_matches,
    corpus_matches_receipt,
    engine_receipt_valid,
    engine_stability,
    load_findings,
    path_profile_evidence_valid,
    receipt_version_state,
    run_set_complete,
    source_identity_complete,
)


if TYPE_CHECKING:
    from pathlib import Path


V3_SCHEMA = "lyrashield-evaluation-corpus/3.0.0"
RESULT_SCHEMA = "lyrashield-evaluation-result/3.0.0"
IDENTITY_FIELDS = (
    "scanId",
    "caseId",
    "variant",
    "runIndex",
    "scanner",
    "id",
    "file",
    "startLine",
    "title",
    "cwe",
)


def finding_identity(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the stable fields covered by adjudication and duplicate policy."""
    return {field: finding.get(field) for field in IDENTITY_FIELDS}


def finding_fingerprint(finding: dict[str, Any]) -> str:
    encoded = json.dumps(
        finding_identity(finding),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def wilson_interval(successes: int, total: int) -> dict[str, float] | None:
    """Return the two-sided 95% Wilson interval for a binomial proportion."""
    if total <= 0 or successes < 0 or successes > total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return {
        "confidence": 0.95,
        "lower": round(max(0.0, centre - margin), 6),
        "upper": round(min(1.0, centre + margin), 6),
    }


def corpus_contract_hashes(corpus_dir: Path, corpus: dict[str, Any]) -> dict[str, str]:
    return {
        name: hashlib.sha256((corpus_dir / contract["path"]).resolve().read_bytes()).hexdigest()
        for name, contract in corpus["contracts"].items()
    }


def _adjudication_decisions(corpus_dir: Path) -> dict[str, dict[str, Any]]:
    validate_corpus_v3(corpus_dir)
    record = json.loads((corpus_dir / "adjudications.json").read_text(encoding="utf-8"))
    decisions = record["decisions"]
    return {decision["findingSha256"]: decision for decision in decisions}


def _finding_ref(finding: dict[str, Any]) -> dict[str, Any]:
    ref = finding_identity(finding)
    ref["findingSha256"] = finding_fingerprint(finding)
    return ref


def _model_route_complete(manifest: dict[str, Any]) -> bool:
    route = manifest.get("modelRoute")
    return (
        isinstance(route, dict)
        and isinstance(route.get("provider"), str)
        and bool(route["provider"].strip())
        and isinstance(route.get("model"), str)
        and bool(route["model"].strip())
        and isinstance(route.get("receiptSha256"), str)
        and len(route["receiptSha256"]) == 64
        and all(character in "0123456789abcdef" for character in route["receiptSha256"])
    )


def _apply_decision(
    finding: dict[str, Any], decisions: dict[str, dict[str, Any]]
) -> tuple[str, dict[str, Any] | None]:
    decision = decisions.get(finding_fingerprint(finding))
    if decision is None:
        return "unclassified_extra", None
    return str(decision["outcome"]), decision


def _metric(successes: int, denominator: int, reasons: list[str]) -> dict[str, Any]:
    reportable = not reasons
    return {
        "status": "REPORTABLE" if reportable else "NOT_REPORTABLE",
        "raw": {"numerator": successes, "denominator": denominator},
        "value": round(successes / denominator, 6) if reportable and denominator else None,
        "wilson95": wilson_interval(successes, denominator) if reportable else None,
        "reasons": reasons,
    }


def score_v3(  # noqa: PLR0912, PLR0915 - the category ledger is intentionally exhaustive
    results_dir: Path,
    corpus_dir: Path,
    corpus: dict[str, Any],
    *,
    write_results: bool = True,
) -> dict[str, Any]:
    """Score v3 with one-to-one matching and explicit unresolved categories."""
    validate_corpus_v3(corpus_dir)
    findings_bytes = (results_dir / "findings.jsonl").read_bytes()
    findings = load_findings(findings_bytes)
    manifest = json.loads((results_dir / "run-manifest.json").read_text(encoding="utf-8"))
    decisions = _adjudication_decisions(corpus_dir)

    legacy, _supports_records, findings_digest_valid = receipt_version_state(
        manifest, findings_bytes
    )
    bound_findings, unbound_findings, incomplete_records = bind_findings_to_runs(
        findings, manifest["runs"]
    )
    scan_findings = [
        finding
        for finding in bound_findings
        if finding.get("scanner") not in {"__discovery__", "__coverage__"}
        and not finding.get("error")
    ]
    failure_findings = [
        finding
        for finding in bound_findings
        if finding.get("error") or finding.get("coverageIssues")
    ]

    by_case = {case["id"]: case for case in corpus["pairs"]}
    profile_id = manifest.get("pathProfile")
    expected_selected_ids = [
        case["id"] for case in corpus["pairs"] if profile_id in case["supportedProfiles"]
    ]
    selected_ids = manifest.get("selectedCaseIds")
    selected_cases_match = selected_ids == expected_selected_ids
    selected_cases = [by_case[case_id] for case_id in selected_ids or [] if case_id in by_case]
    scan_runs = {
        run["scanId"]: run
        for run in manifest["runs"]
        if isinstance(run.get("scanId"), str) and run["scanId"]
    }
    marker_cache: dict[str, int | None] = {}
    groups: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
    ambiguous: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    adjudicated_true_positives: list[dict[str, Any]] = []
    adjudicated_false_positives: list[dict[str, Any]] = []
    adjudicated_ambiguous: list[dict[str, Any]] = []
    adjudicated_unreachable: list[dict[str, Any]] = []
    adjudicated_incomplete: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []

    incomplete.extend(
        {"category": "unbound_record", "record": _finding_ref(finding)}
        for finding in unbound_findings
    )
    incomplete.extend(
        {"category": "failed_or_coverage_issue", "record": _finding_ref(finding)}
        for finding in failure_findings
    )

    for finding in scan_findings:
        run = scan_runs[finding["scanId"]]
        key = (
            finding["caseId"],
            run["detector"],
            int(run.get("runIndex", 0)),
            finding["variant"],
        )
        if finding["variant"] == "clean":
            groups[key].append(finding)
            continue
        case = by_case.get(finding["caseId"])
        if case is None:
            incomplete.append({"category": "unknown_case", "record": _finding_ref(finding)})
            continue
        candidate_cases = [
            candidate
            for candidate in corpus["pairs"]
            if candidate["id"] == case["id"]
            or (
                finding.get("caseId") is None
                and case_matches(candidate, finding, corpus_dir, marker_cache)
            )
        ]
        matching_cases = [
            candidate
            for candidate in candidate_cases
            if case_matches(candidate, finding, corpus_dir, marker_cache)
        ]
        if not matching_cases:
            outcome, decision = _apply_decision(finding, decisions)
            if outcome == "true_positive":
                adjudicated_true_positives.append(_finding_ref(finding))
            elif outcome == "false_positive":
                adjudicated_false_positives.append(_finding_ref(finding))
            elif outcome == "ambiguous":
                adjudicated_ambiguous.append(
                    {
                        **_finding_ref(finding),
                        "rationale": decision.get("rationale") if decision else None,
                    }
                )
            elif outcome == "unreachable":
                adjudicated_unreachable.append(
                    {
                        **_finding_ref(finding),
                        "rationale": decision.get("rationale") if decision else None,
                    }
                )
            elif outcome == "incomplete":
                adjudicated_incomplete.append(
                    {
                        **_finding_ref(finding),
                        "rationale": decision.get("rationale") if decision else None,
                    }
                )
            elif outcome == "false_negative":
                adjudicated_incomplete.append(_finding_ref(finding))
            else:
                unclassified.append(_finding_ref(finding))
            continue
        if len(matching_cases) > 1:
            ambiguous.append(
                {
                    **_finding_ref(finding),
                    "detector": run["detector"],
                    "candidateCaseIds": sorted(case["id"] for case in matching_cases),
                }
            )
            continue
        groups[key].append(finding)

    true_positives: list[dict[str, Any]] = []
    matched_groups: set[tuple[str, str, int, str]] = set()
    for key in sorted(groups):
        case_id, detector, run_index, variant = key
        case = by_case[case_id]
        candidates = sorted(groups[key], key=finding_fingerprint)
        if variant == "clean":
            seen: set[str] = set()
            for finding in candidates:
                fingerprint = finding_fingerprint(finding)
                if fingerprint in seen:
                    duplicates.append(_finding_ref(finding))
                    continue
                seen.add(fingerprint)
                false_positives.append(
                    {**_finding_ref(finding), "basis": "known-negative clean projection"}
                )
            continue

        seen = set()
        unique = []
        for finding in candidates:
            fingerprint = finding_fingerprint(finding)
            if fingerprint in seen:
                duplicates.append(_finding_ref(finding))
                continue
            seen.add(fingerprint)
            unique.append(finding)
        if not unique:
            continue
        matched_groups.add(key)
        true_positives.append(_finding_ref(unique[0]))
        for finding in unique[1:]:
            outcome, decision = _apply_decision(finding, decisions)
            if outcome == "true_positive":
                adjudicated_true_positives.append(_finding_ref(finding))
            elif outcome == "false_positive":
                adjudicated_false_positives.append(_finding_ref(finding))
            elif outcome == "ambiguous":
                adjudicated_ambiguous.append(
                    {
                        **_finding_ref(finding),
                        "rationale": decision.get("rationale") if decision else None,
                    }
                )
            elif outcome == "unreachable":
                adjudicated_unreachable.append(
                    {
                        **_finding_ref(finding),
                        "rationale": decision.get("rationale") if decision else None,
                    }
                )
            elif outcome in {"incomplete", "false_negative"}:
                adjudicated_incomplete.append(_finding_ref(finding))
            else:
                unclassified.append(_finding_ref(finding))

    expected_groups = [
        (run["case"], run["detector"], int(run.get("runIndex", 0)), run["variant"])
        for run in manifest["runs"]
    ]
    false_negatives: list[dict[str, Any]] = []
    for key in expected_groups:
        case_id, detector, run_index, variant = key
        if variant != "vulnerable" or key in matched_groups:
            continue
        related_ambiguous = any(
            item["caseId"] == case_id
            and item["detector"] == detector
            and item["runIndex"] == run_index
            for item in ambiguous
        )
        if related_ambiguous:
            continue
        false_negatives.append(
            {
                "caseId": case_id,
                "class": by_case[case_id]["class"],
                "detector": detector,
                "runIndex": run_index,
            }
        )

    failed_runs = [
        run for run in manifest["runs"] if run.get("returncode") != 0 or run.get("errors")
    ]
    incomplete.extend(
        {"category": "failed_run", "scanId": run.get("scanId")} for run in failed_runs
    )
    if incomplete_records:
        incomplete.append({"category": "record_count_or_receipt_mismatch"})

    contracts_match = manifest.get("corpusContractsSha256") == corpus_contract_hashes(
        corpus_dir, corpus
    )
    if not contracts_match:
        incomplete.append({"category": "corpus_contract_checksum_mismatch"})
    if not selected_cases_match or not selected_cases:
        incomplete.append({"category": "path_profile_case_scope_mismatch"})

    engine_runs = [run for run in manifest["runs"] if run.get("detector") == "engine"]
    invalid_engine_receipts = [run for run in engine_runs if not engine_receipt_valid(run)]
    if invalid_engine_receipts:
        incomplete.append({"category": "invalid_engine_run_receipt"})
    if engine_runs and not _model_route_complete(manifest):
        incomplete.append({"category": "missing_or_invalid_model_route"})

    complete_run_set = run_set_complete(manifest, {"pairs": selected_cases})
    if not complete_run_set:
        incomplete.append({"category": "incomplete_run_set"})

    if not source_identity_complete(manifest):
        incomplete.append({"category": "source_identity_incomplete"})
    if not path_profile_evidence_valid(manifest):
        incomplete.append({"category": "path_profile_detector_mismatch"})
    if findings_digest_valid is not True:
        incomplete.append({"category": "findings_digest_mismatch"})
    if not corpus_matches_receipt(manifest, corpus, corpus_dir):
        incomplete.append({"category": "corpus_or_fixture_checksum_mismatch"})

    status = "LEGACY_UNVALIDATED" if legacy else "INCOMPLETE" if incomplete else "COMPLETE"
    review = json.loads((corpus_dir / "adjudications.json").read_text(encoding="utf-8"))["review"]
    scenarios = [scenario for scenario in corpus["scenarios"] if scenario["profile"] == profile_id]
    unreachable_scenarios = [
        scenario for scenario in scenarios if scenario["expectedCategory"] == "unreachable"
    ]
    ambiguous_scenarios = [
        scenario for scenario in scenarios if scenario["expectedCategory"] == "ambiguous"
    ]
    incomplete_scenarios = [
        scenario for scenario in scenarios if scenario["expectedCategory"] == "incomplete"
    ]

    true_positive_count = len(true_positives) + len(adjudicated_true_positives)
    false_positive_count = len(false_positives) + len(adjudicated_false_positives)
    false_negative_count = len(false_negatives)
    ambiguous_count = len(ambiguous) + len(adjudicated_ambiguous) + len(ambiguous_scenarios)
    unreachable_count = len(adjudicated_unreachable) + len(unreachable_scenarios)
    incomplete_count = len(incomplete) + len(adjudicated_incomplete) + len(incomplete_scenarios)
    duplicate_count = len(duplicates)
    unclassified_count = len(unclassified)

    independent_review = review["status"] == "INDEPENDENTLY_REVIEWED"
    profile_contract = (corpus.get("contracts") or {}).get("pathProfiles") or {}
    profile_path = (corpus_dir / str(profile_contract.get("path", ""))).resolve()
    profile_records = json.loads(profile_path.read_text(encoding="utf-8")).get("profiles") or []
    profile_status = next(
        (profile.get("status") for profile in profile_records if profile.get("id") == profile_id),
        None,
    )
    common_reasons = [
        reason
        for reason in (
            "Independent adjudication is NOT_INDEPENDENTLY_REVIEWED."
            if not independent_review
            else "",
            f"{unclassified_count} vulnerable-fixture finding(s) remain unclassified."
            if unclassified_count
            else "",
            f"{ambiguous_count} finding(s) or scenario(s) remain ambiguous."
            if ambiguous_count
            else "",
            f"{unreachable_count} finding(s) or scenario(s) remain unreachable."
            if unreachable_count
            else "",
            f"{incomplete_count} finding(s), run(s), or contract(s) are incomplete."
            if incomplete_count
            else "",
            f"Path profile {profile_id} is {profile_status or 'UNKNOWN'}; quality is not measured."
            if profile_status != "MEASURED"
            else "",
        )
        if reason
    ]
    if status != "COMPLETE":
        common_reasons.append(f"Harness status is {status}; raw counts are diagnostics only.")

    precision_denominator = true_positive_count + false_positive_count
    recall_denominator = true_positive_count + false_negative_count
    precision = _metric(true_positive_count, precision_denominator, list(common_reasons))
    recall = _metric(true_positive_count, recall_denominator, list(common_reasons))

    classes = sorted({case["class"] for case in corpus["pairs"]})
    per_class: dict[str, dict[str, int]] = {}
    for class_name in classes:
        case_ids = {case["id"] for case in corpus["pairs"] if case["class"] == class_name}
        per_class[class_name] = {
            "truePositiveExecutions": sum(
                item["caseId"] in case_ids for item in true_positives + adjudicated_true_positives
            ),
            "falseNegativeExecutions": sum(item["caseId"] in case_ids for item in false_negatives),
            "falsePositiveExecutions": sum(
                item["caseId"] in case_ids for item in false_positives + adjudicated_false_positives
            ),
        }

    detected_for_stability: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in true_positives:
        if item["scanner"] == "engine":
            detected_for_stability[item["caseId"]].append(item)
    stability = engine_stability(manifest, detected_for_stability) if status == "COMPLETE" else None

    summary: dict[str, Any] = {
        "schemaVersion": RESULT_SCHEMA,
        "status": status,
        "claimStatus": "NOT_REPORTABLE" if common_reasons else "REPORTABLE",
        "corpus": corpus["name"],
        "corpusRevision": corpus["revision"],
        "corpusSha256": hashlib.sha256((corpus_dir / "corpus.json").read_bytes()).hexdigest(),
        "corpusContractsSha256": corpus_contract_hashes(corpus_dir, corpus),
        "pathProfile": manifest.get("pathProfile"),
        "pathProfileStatus": profile_status,
        "adjudicationStatus": review["status"],
        "heldOutStatus": json.loads((corpus_dir / "held-out.json").read_text(encoding="utf-8"))[
            "status"
        ],
        "counts": {
            "truePositive": true_positive_count,
            "falsePositive": false_positive_count,
            "falseNegative": false_negative_count,
            "ambiguous": ambiguous_count,
            "unreachable": unreachable_count,
            "unclassifiedExtra": unclassified_count,
            "duplicate": duplicate_count,
            "incomplete": incomplete_count,
        },
        "categories": {
            "truePositive": true_positives + adjudicated_true_positives,
            "falsePositive": false_positives + adjudicated_false_positives,
            "falseNegative": false_negatives,
            "ambiguous": ambiguous + adjudicated_ambiguous + ambiguous_scenarios,
            "unreachable": adjudicated_unreachable + unreachable_scenarios,
            "unclassifiedExtra": unclassified,
            "duplicate": duplicates,
            "incomplete": incomplete + adjudicated_incomplete + incomplete_scenarios,
        },
        "precision": precision,
        "recall": recall,
        "perClass": per_class,
        "engineStability": stability,
        "unboundRecords": len(unbound_findings),
        "findingsDigestMatches": findings_digest_valid,
        "failedRuns": len(failed_runs),
        "totalRuntimeMs": sum(run.get("runtimeMs", 0) for run in manifest["runs"]),
        "observedCostUsd": manifest.get("observedCostUsd"),
    }
    if write_results:
        (results_dir / "results.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        _write_results_markdown(results_dir, summary)
    return summary


def _write_results_markdown(results_dir: Path, summary: dict[str, Any]) -> None:
    counts = summary["counts"]
    lines = [
        f"# Evaluation v3 results — {summary['corpus']}@{summary['corpusRevision']}",
        "",
        f"- harness status: {summary['status']}",
        f"- claim status: {summary['claimStatus']}",
        f"- path profile: {summary['pathProfile']}",
        f"- path profile status: {summary['pathProfileStatus']}",
        f"- adjudication: {summary['adjudicationStatus']}",
        f"- held-out contract: {summary['heldOutStatus']}",
        "",
        "| Category | Raw count |",
        "|---|---:|",
    ]
    for name, count in counts.items():
        lines.append(f"| {name} | {count} |")
    for metric_name in ("precision", "recall"):
        metric = summary[metric_name]
        raw = metric["raw"]
        lines.extend(
            [
                "",
                f"- {metric_name}: {metric['status']} ({raw['numerator']}/{raw['denominator']})",
            ]
        )
        if metric["wilson95"] is not None:
            interval = metric["wilson95"]
            lines.append(
                f"- {metric_name} 95% Wilson interval: {interval['lower']}-{interval['upper']}"
            )
        lines.extend(f"- {metric_name} unavailable: {reason}" for reason in metric["reasons"])
    lines.extend(
        [
            "",
            "| Class | True positives | False negatives | False positives |",
            "|---|---:|---:|---:|",
        ]
    )
    for class_name, row in summary["perClass"].items():
        lines.append(
            f"| {class_name} | {row['truePositiveExecutions']} | "
            f"{row['falseNegativeExecutions']} | {row['falsePositiveExecutions']} |"
        )
    (results_dir / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
