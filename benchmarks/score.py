"""
Benchmark scorer — findings.jsonl x corpus.json → per-class metrics.

  uv run python benchmarks/score.py --corpus v2 --results benchmarks/results/<ts>

Matching: a finding labels a case when all declared locators agree —
  - file: finding.file ends with the case's fixture filename (or matchFile)
  - markerLine: exact CASE marker unless explicit rule identity allows tolerance
  - rulePrefixes: finding.id starts with any listed prefix, when present

Metrics: per-class recall (detected/expected), precision proxy (clean-fixture
findings = false positives), duplicate rate, run stability (engine: same case
detected in all runs), runtime, and discovery-bounds receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


BENCH_ROOT = Path(__file__).resolve().parent
LINE_TOLERANCE = 3


def load_findings(raw: bytes) -> list[dict[str, Any]]:
    records = []
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return [{}]
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            value = None
        records.append(value if isinstance(value, dict) else {})
    return records


def derive_marker_line(
    case: dict[str, Any], corpus_dir: Path, cache: dict[str, int | None]
) -> int | None:
    """A case without an explicit markerLine locates itself by its `CASE:<id>`
    comment in the vulnerable fixture — without it, any finding on the file
    would match every case that shares the file."""
    if case.get("markerLine") is not None:
        return int(case["markerLine"])
    case_id = case["id"]
    if case_id not in cache:
        fixture = corpus_dir / case["vulnerable"]
        cache[case_id] = None
        if fixture.is_file():
            needle = f"CASE:{case_id}"
            for lineno, line in enumerate(fixture.read_text(encoding="utf-8").splitlines(), 1):
                if needle in line:
                    cache[case_id] = lineno
                    break
    return cache[case_id]


def case_matches(
    case: dict[str, Any],
    finding: dict[str, Any],
    corpus_dir: Path,
    marker_cache: dict[str, int | None],
) -> bool:
    file_name = case.get("matchFile") or Path(case["vulnerable"]).name
    finding_file = finding.get("file") or ""
    if Path(finding_file).name != Path(file_name).name:
        return False
    prefixes = case.get("rulePrefixes")
    if prefixes and not any((finding.get("id") or "").startswith(prefix) for prefix in prefixes):
        return False
    # Only corpus-declared absence controls may skip line matching; a
    # detector's identifier alone cannot widen the expected case scope.
    line_exempt = case.get("absence")
    marker = derive_marker_line(case, corpus_dir, marker_cache)
    if marker is not None and not line_exempt:
        start = finding.get("startLine")
        tolerance = LINE_TOLERANCE if prefixes else 0
        if not isinstance(start, int) or abs(start - marker) > tolerance:
            return False
    return marker is not None or bool(line_exempt and prefixes)


def engine_stability(
    manifest: dict[str, Any], detected: dict[str, list[dict[str, Any]]]
) -> float | None:
    # Include every declared engine run, including runs with no detections.
    engine_runs = [
        r
        for r in manifest["runs"]
        if r["detector"] == "engine" and r.get("variant", "vulnerable") == "vulnerable"
    ]
    indices = {r.get("runIndex", 0) for r in engine_runs}
    stability = None
    if len(indices) > 1:
        per_run_hits: dict[int, set[str]] = {index: set() for index in indices}
        for case_id, hits in detected.items():
            for finding in hits:
                if finding.get("scanner") != "engine":
                    continue
                index = finding.get("runIndex")
                if index is None:
                    index = int(str(finding["scanId"]).rsplit("-", 1)[-1])
                if index in per_run_hits:
                    per_run_hits[index].add(case_id)
        common = set.intersection(*per_run_hits.values())
        union = set.union(*per_run_hits.values())
        stability = round(len(common) / len(union), 4) if union else None

    return stability


def run_set_complete(manifest: dict[str, Any], corpus: dict[str, Any]) -> bool:
    scan_ids = [run.get("scanId") for run in manifest["runs"]]
    if not all(isinstance(scan_id, str) and scan_id.strip() for scan_id in scan_ids):
        return False
    if len(set(scan_ids)) != len(scan_ids):
        return False
    detectors = (
        {"engine", "deterministic"} if manifest["detectors"] == "all" else {manifest["detectors"]}
    )
    indices = {r.get("runIndex", 0) for r in manifest["runs"] if r["detector"] == "engine"} or {0}
    expected = {
        (case["id"], detector, variant, index)
        for case in corpus["pairs"]
        for detector in detectors
        for variant in ("vulnerable", "clean")
        for index in (indices if detector == "engine" else {0})
    }
    actual = {
        (r.get("case"), r["detector"], r.get("variant"), r.get("runIndex", 0))
        for r in manifest["runs"]
    }
    return actual == expected and len(actual) == len(manifest["runs"])


def corpus_matches_receipt(
    manifest: dict[str, Any], corpus: dict[str, Any], corpus_dir: Path
) -> bool:
    if (
        manifest.get("corpus") != corpus["name"]
        or manifest.get("corpusRevision") != corpus["revision"]
    ):
        return False
    checksum = hashlib.sha256((corpus_dir / "corpus.json").read_bytes()).hexdigest()
    if manifest.get("corpusSha256") != checksum:
        return False
    expected = {case[variant] for case in corpus["pairs"] for variant in ("vulnerable", "clean")}
    hashes = manifest.get("fixtureSha256", {})
    return set(hashes) == expected and all(
        (corpus_dir / path).is_file()
        and hashlib.sha256((corpus_dir / path).read_bytes()).hexdigest() == hashes[path]
        for path in expected
    )


def bind_findings_to_runs(
    findings: list[dict[str, Any]], runs: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    bound, unbound = [], []
    counts: dict[str, int] = defaultdict(int)
    sentinels: dict[tuple[str, str], int] = defaultdict(int)
    deterministic = {"secrets", "sast", "iac", "agent_config", "ml_supply_chain"}
    for finding in findings:
        scanner = finding.get("scanner")
        detector = "engine" if scanner == "engine" else "deterministic"
        matching_runs = [
            run
            for run in runs
            if isinstance(run.get("scanId"), str)
            and run["scanId"]
            and run["scanId"] == finding.get("scanId")
        ]
        if (
            len(matching_runs) != 1
            or not isinstance(scanner, str)
            or scanner not in deterministic | {"engine", "__discovery__", "__coverage__"}
            or (scanner == "__discovery__" and not isinstance(finding.get("discovery"), dict))
            or (scanner == "__coverage__" and not isinstance(finding.get("coverageIssues"), list))
            or not isinstance(finding.get("caseId"), str)
            or not finding["caseId"]
            or finding.get("variant") not in ("vulnerable", "clean")
            or type(finding.get("runIndex")) is not int
            or matching_runs[0].get("detector") != detector
            or matching_runs[0].get("case") != finding.get("caseId")
            or matching_runs[0].get("variant") != finding.get("variant")
            or matching_runs[0].get("runIndex", 0) != finding.get("runIndex")
        ):
            unbound.append(finding)
        else:
            bound.append(finding)
            scan_id = matching_runs[0]["scanId"]
            counts[scan_id] += 1
            if scanner in {"__discovery__", "__coverage__"}:
                sentinels[(scan_id, scanner)] += 1
    incomplete = any(
        not isinstance(run.get("scanId"), str)
        or not run["scanId"]
        or type(run.get("emitted")) is not int
        or run["emitted"] < 0
        or counts.get(run.get("scanId"), 0) != run["emitted"]
        or (
            run.get("detector") == "deterministic"
            and any(
                sentinels.get((run.get("scanId"), name), 0) != 1
                for name in ("__discovery__", "__coverage__")
            )
        )
        for run in runs
    )
    return bound, unbound, incomplete


def receipt_version_state(
    manifest: dict[str, Any], findings_bytes: bytes
) -> tuple[bool, bool, bool | None]:
    version = manifest.get("harnessVersion", 1)
    legacy = type(version) is int and version < 3
    supports_records = type(version) is int and version >= 2
    digest_valid = (
        hashlib.sha256(findings_bytes).hexdigest() == manifest.get("findingsSha256")
        if type(version) is int and version == 3
        else None
    )
    return legacy, supports_records, digest_valid


def source_identity_complete(manifest: dict[str, Any]) -> bool:
    sources = manifest.get("sources")
    if manifest.get("sourcesChangedDuringRun") is not False or not isinstance(sources, dict):
        return False
    clean_diff = hashlib.sha256(b"").hexdigest()
    for name in ("engine", "product"):
        source = sources.get(name)
        if (
            not isinstance(source, dict)
            or not isinstance(source.get("revision"), str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"])
            or source.get("dirty") is not False
            or source.get("trackedDiffSha256") != clean_diff
        ):
            return False
    return (
        manifest.get("detectors") not in ("engine", "all")
        or manifest.get("engineRevision") == sources["engine"]["revision"]
    )


def engine_receipt_valid(run: dict[str, Any]) -> bool:
    receipt = run.get("runReceipt")
    if (
        not isinstance(receipt, dict)
        or "error" in receipt
        or receipt.get("schemaVersion") not in ("1.0", "1.1", "1.2")
        or not isinstance(run.get("scanId"), str)
        or not run["scanId"].strip()
        or receipt.get("runId") != run.get("scanId")
        or receipt.get("status") != "completed"
        or receipt.get("phase") != "completed"
    ):
        return False
    caps = receipt.get("sandboxCapabilities")
    if not isinstance(caps, dict):
        return False
    statuses = caps.get("statuses")
    probed_at = caps.get("probedAt")
    if (
        caps.get("schema") != "lyrashield-sandbox-capabilities/1.0"
        or not isinstance(caps.get("backend"), str)
        or not caps["backend"].strip()
        or not isinstance(statuses, dict)
        or not statuses
        or not all(
            isinstance(name, str)
            and bool(name.strip())
            and status in ("supported", "absent", "unprobed")
            for name, status in statuses.items()
        )
        or not isinstance(probed_at, str)
        or not isinstance(caps.get("preflightDegradations"), list)
        or not all(isinstance(item, str) and item for item in caps["preflightDegradations"])
        or caps.get("preflightFailures") != []
    ):
        return False
    try:
        return datetime.fromisoformat(probed_at).utcoffset() is not None
    except ValueError:
        return False


def engine_receipts_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    engine_runs = [run for run in runs if run.get("detector") == "engine"]
    receipts = [run["runReceipt"] for run in engine_runs if engine_receipt_valid(run)]
    return {
        "total": len(engine_runs),
        "withReceipt": len(receipts),
        "invalid": len(engine_runs) - len(receipts),
        "schemaVersions": sorted({receipt["schemaVersion"] for receipt in receipts}),
        "capabilityStatuses": sorted(
            {
                f"{name}={status}"
                for receipt in receipts
                for name, status in receipt["sandboxCapabilities"]["statuses"].items()
            }
        ),
    }


def ambiguous_case_match(
    case: dict[str, Any],
    finding: dict[str, Any],
    cases: list[dict[str, Any]],
    corpus_dir: Path,
    marker_cache: dict[str, int | None],
) -> bool:
    return any(
        sibling["id"] != case["id"]
        and sibling["vulnerable"] == case["vulnerable"]
        and case_matches(sibling, finding, corpus_dir, marker_cache)
        for sibling in cases
    )


def classify_scan_findings(
    findings: list[dict[str, Any]], cases: list[dict[str, Any]], corpus_dir: Path
) -> tuple[
    dict[str, list[dict[str, Any]]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    detected: dict[str, list[dict[str, Any]]] = defaultdict(list)
    clean, unmatched, ambiguous = [], [], []
    marker_cache: dict[str, int | None] = {}
    for finding in findings:
        if finding.get("variant") == "clean":
            clean.append(finding)
            continue
        matched = False
        for case in cases:
            # Each projection contains a whole shared file: credit only the
            # case/run actually executed, never sibling cases or clean controls.
            case_id = finding.get("caseId")
            if case_id is not None and case_id != case["id"]:
                continue
            if case_id is None and not str(finding.get("scanId", "")).startswith(case["id"] + "-"):
                continue
            if case_matches(case, finding, corpus_dir, marker_cache):
                if ambiguous_case_match(case, finding, cases, corpus_dir, marker_cache):
                    ambiguous.append(finding)
                else:
                    detected[case["id"]].append(finding)
                matched = True
        if not matched:
            unmatched.append(finding)
    return detected, clean, unmatched, ambiguous


def score(results_dir: Path, corpus_dir: Path) -> dict[str, Any]:
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    findings_bytes = (results_dir / "findings.jsonl").read_bytes()
    findings = load_findings(findings_bytes)
    manifest = json.loads((results_dir / "run-manifest.json").read_text(encoding="utf-8"))

    legacy, supports_records, findings_digest_valid = receipt_version_state(
        manifest, findings_bytes
    )
    unbound_findings, incomplete_records = [], False
    if supports_records:
        findings, unbound_findings, incomplete_records = bind_findings_to_runs(
            findings, manifest["runs"]
        )
    discovery_receipts = [f for f in findings if f.get("scanner") == "__discovery__"]

    scan_findings = [
        f
        for f in findings
        if isinstance(f.get("scanner"), str)
        and f.get("scanner") not in ("__discovery__", "__coverage__")
        and not f.get("error")
    ]
    detected, clean_fps, unmatched, ambiguous = classify_scan_findings(
        scan_findings, corpus["pairs"], corpus_dir
    )

    per_class: dict[str, dict[str, Any]] = {}
    classes = {c["class"] for c in corpus["pairs"]}
    for cls in sorted(classes):
        cases = [c for c in corpus["pairs"] if c["class"] == cls]
        hits = sum(1 for c in cases if detected[c["id"]])
        per_class[cls] = {
            "cases": len(cases),
            "detected": hits,
            "recall": round(hits / len(cases), 4),
        }

    stability = engine_stability(manifest, detected)

    duplicate_count = 0
    for finding_list in detected.values():
        per_execution: dict[tuple[object, object], int] = defaultdict(int)
        for finding in finding_list:
            per_execution[(finding.get("scanId"), finding.get("scanner"))] += 1
        duplicate_count += sum(max(0, count - 1) for count in per_execution.values())
    failures = [r for r in manifest["runs"] if r.get("returncode") != 0 or r.get("errors")]
    coverage_issues = [f for f in findings if f.get("error") or f.get("coverageIssues")]
    engine_receipts = engine_receipts_summary(manifest["runs"])
    status = (
        "LEGACY_UNVALIDATED"
        if legacy
        else "INCOMPLETE"
        if failures
        or ambiguous
        or engine_receipts["invalid"]
        or findings_digest_valid is not True
        or unbound_findings
        or incomplete_records
        or coverage_issues
        or not run_set_complete(manifest, corpus)
        or not corpus_matches_receipt(manifest, corpus, corpus_dir)
        or not source_identity_complete(manifest)
        else "COMPLETE"
    )
    clean_runs = [r for r in manifest["runs"] if r.get("variant") == "clean"]

    summary = {
        "status": status,
        "failedRuns": len(failures),
        "coverageIssueReceipts": len(coverage_issues),
        "cleanRuns": len(clean_runs),
        "cleanFindings": len(clean_fps) if clean_runs else None,
        "corpus": corpus["name"],
        "corpusRevision": corpus["revision"],
        "detectors": manifest["detectors"],
        "totalCases": len(corpus["pairs"]),
        "detectedCases": sum(1 for c in corpus["pairs"] if detected[c["id"]]),
        "recall": round(
            sum(1 for c in corpus["pairs"] if detected[c["id"]]) / len(corpus["pairs"]), 4
        ),
        "unmatchedFindings": len(unmatched),
        "ambiguousFindings": len(ambiguous),
        "unboundRecords": len(unbound_findings) if supports_records else None,
        "recordIntegrityIncomplete": incomplete_records if supports_records else None,
        "findingsDigestMatches": findings_digest_valid,
        "duplicateRate": round(
            duplicate_count / max(1, sum(len(hits) for hits in detected.values())),
            4,
        ),
        "perClass": per_class,
        "engineStability": stability,
        "totalRuntimeMs": sum(r.get("runtimeMs", 0) for r in manifest["runs"]),
        "discoveryReceipts": len(discovery_receipts),
        "engineReceipts": engine_receipts,
        "engineRevision": manifest.get("engineRevision"),
    }
    (results_dir / "results.json").write_text(json.dumps(summary, indent=2))

    lines = [
        f"# Benchmark results — {corpus['name']}@{corpus['revision']}",
        "",
        f"- status: {status}",
        f"- detectors: {manifest['detectors']}",
        f"- engine revision: {manifest.get('engineRevision') or 'n/a'}",
        f"- recall: {summary['recall']} ({summary['detectedCases']}/{summary['totalCases']})",
        "- unmatched vulnerable-fixture findings (not false positives): "
        f"{summary['unmatchedFindings']}",
        f"- findings matching overlapping case locators: {summary['ambiguousFindings']}",
        f"- records not bound to a recorded run: {summary['unboundRecords']}",
        f"- record counts or scanner receipts incomplete: {summary['recordIntegrityIncomplete']}",
        f"- findings digest matches: {summary['findingsDigestMatches']}",
        f"- clean-fixture findings: {summary['cleanFindings']}",
        f"- duplicate rate: {summary['duplicateRate']}",
        f"- engine stability: {stability if stability is not None else 'n/a (single/det)'}",
        "",
        "| class | detected | cases | recall |",
        "|---|---|---|---|",
    ]
    for cls, row in per_class.items():
        lines.append(f"| {cls} | {row['detected']} | {row['cases']} | {row['recall']} |")
    (results_dir / "RESULTS.md").write_text("\n".join(lines) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="v2")
    parser.add_argument("--results", required=True)
    args = parser.parse_args()
    summary = score(Path(args.results), BENCH_ROOT / "corpus" / args.corpus)
    print(json.dumps(summary, indent=2))
    return 0 if summary["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    sys.exit(main())
