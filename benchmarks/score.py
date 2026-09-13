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
import json
import sys
from collections import defaultdict
from pathlib import Path


BENCH_ROOT = Path(__file__).resolve().parent
LINE_TOLERANCE = 3


def load_findings(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("{")
    ]


def derive_marker_line(case: dict, corpus_dir: Path, cache: dict[str, int | None]) -> int | None:
    """A case without an explicit markerLine locates itself by its `CASE:<id>`
    comment in the vulnerable fixture — without it, any finding on the file
    would match every case that shares the file."""
    if case.get("markerLine") is not None:
        return case["markerLine"]
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
    case: dict, finding: dict, corpus_dir: Path, marker_cache: dict[str, int | None]
) -> bool:
    file_name = case.get("matchFile") or Path(case["vulnerable"]).name
    finding_file = finding.get("file") or ""
    if Path(finding_file).name != Path(file_name).name:
        return False
    prefixes = case.get("rulePrefixes")
    if prefixes and not any((finding.get("id") or "").startswith(prefix) for prefix in prefixes):
        return False
    # Absence cases ("no USER directive") have no offending line — the marker
    # constraint can't apply to them or to findings reported as -absent.
    line_exempt = case.get("absence")
    marker = derive_marker_line(case, corpus_dir, marker_cache)
    if marker is not None and not line_exempt:
        start = finding.get("startLine")
        tolerance = LINE_TOLERANCE if prefixes else 0
        if not isinstance(start, int) or abs(start - marker) > tolerance:
            return False
    return marker is not None or bool(line_exempt and prefixes)


def engine_stability(manifest: dict, detected: dict) -> float | None:
    # Include every declared engine run, including runs with no detections.
    engine_runs = [
        r
        for r in manifest["runs"]
        if r["detector"] == "engine" and r.get("variant", "vulnerable") == "vulnerable"
    ]
    indices = {r.get("runIndex", 0) for r in engine_runs}
    stability = None
    if len(indices) > 1:
        per_run_hits = {index: set() for index in indices}
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


def run_set_complete(manifest: dict, corpus: dict) -> bool:
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


def score(results_dir: Path, corpus_dir: Path) -> dict:
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    findings = load_findings(results_dir / "findings.jsonl")
    manifest = json.loads((results_dir / "run-manifest.json").read_text(encoding="utf-8"))

    detected: dict[str, list[dict]] = defaultdict(list)
    clean_fps: list[dict] = []
    unmatched: list[dict] = []
    marker_cache: dict[str, int | None] = {}
    discovery_receipts = [f for f in findings if f.get("scanner") == "__discovery__"]

    scan_findings = [
        f
        for f in findings
        if isinstance(f.get("scanner"), str)
        and f.get("scanner") not in ("__discovery__", "__coverage__")
        and not f.get("error")
    ]
    for finding in scan_findings:
        if finding.get("variant") == "clean":
            clean_fps.append(finding)
            continue
        matched = False
        for case in corpus["pairs"]:
            # Each projection contains a whole shared file: credit only the
            # case/run actually executed, never sibling cases or clean controls.
            case_id = finding.get("caseId")
            if case_id is not None and case_id != case["id"]:
                continue
            if case_id is None and not str(finding.get("scanId", "")).startswith(case["id"] + "-"):
                continue
            if case_matches(case, finding, corpus_dir, marker_cache):
                detected[case["id"]].append(finding)
                matched = True
        if not matched:
            unmatched.append(finding)

    per_class: dict[str, dict] = {}
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
    for hits in detected.values():
        per_execution: dict[tuple, int] = defaultdict(int)
        for finding in hits:
            per_execution[(finding.get("scanId"), finding.get("scanner"))] += 1
        duplicate_count += sum(max(0, count - 1) for count in per_execution.values())
    failures = [r for r in manifest["runs"] if r.get("returncode") != 0 or r.get("errors")]
    coverage_issues = [f for f in findings if f.get("error") or f.get("coverageIssues")]
    legacy = manifest.get("harnessVersion", 1) < 2
    status = (
        "LEGACY_UNVALIDATED"
        if legacy
        else "INCOMPLETE"
        if failures
        or coverage_issues
        or not run_set_complete(manifest, corpus)
        or manifest.get("sourcesChangedDuringRun")
        or any(source.get("dirty") for source in manifest.get("sources", {}).values())
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
        "duplicateRate": round(
            duplicate_count / max(1, sum(len(hits) for hits in detected.values())),
            4,
        ),
        "perClass": per_class,
        "engineStability": stability,
        "totalRuntimeMs": sum(r.get("runtimeMs", 0) for r in manifest["runs"]),
        "discoveryReceipts": len(discovery_receipts),
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
