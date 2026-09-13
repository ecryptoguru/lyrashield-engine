"""
Benchmark scorer — findings.jsonl × corpus.json → per-class metrics.

  uv run python benchmarks/score.py --corpus v2 --results benchmarks/results/<ts>

Matching: a finding labels a case when all declared locators agree —
  - file: finding.file ends with the case's fixture filename (or matchFile)
  - markerLine: |finding.startLine - markerLine| <= 3, when present
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
    if not finding_file.endswith(file_name):
        return False
    prefixes = case.get("rulePrefixes")
    if prefixes and not any(
        (finding.get("id") or "").startswith(prefix) for prefix in prefixes
    ):
        return False
    # Absence cases ("no USER directive") have no offending line — the marker
    # constraint can't apply to them or to findings reported as -absent.
    line_exempt = case.get("absence") or str(finding.get("id") or "").endswith("-absent")
    marker = derive_marker_line(case, corpus_dir, marker_cache)
    if marker is not None and not line_exempt:
        start = finding.get("startLine")
        if not isinstance(start, int) or abs(start - marker) > LINE_TOLERANCE:
            return False
    return True


def score(results_dir: Path, corpus_dir: Path) -> dict:
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    findings = load_findings(results_dir / "findings.jsonl")
    manifest = json.loads((results_dir / "run-manifest.json").read_text(encoding="utf-8"))

    detected: dict[str, list[dict]] = defaultdict(list)
    clean_fps: list[dict] = []
    marker_cache: dict[str, int | None] = {}
    discovery_receipts = [f for f in findings if f.get("scanner") == "__discovery__"]

    scan_findings = [f for f in findings if f.get("scanner") not in ("__discovery__", "__coverage__")]
    for finding in scan_findings:
        matched = False
        for case in corpus["pairs"]:
            if case_matches(case, finding, corpus_dir, marker_cache):
                detected[case["id"]].append(finding)
                matched = True
        if not matched:
            clean_fps.append(finding)

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

    # Run stability for engine runs: fraction of detected cases detected in
    # every run (needs --runs > 1 to be meaningful).
    engine_runs = [r for r in manifest["runs"] if r["detector"] == "engine"]
    stability = None
    if len({r.get("runIndex") for r in engine_runs if r.get("runIndex") is not None}) > 1:
        per_run_hits: dict[int, set] = defaultdict(set)
        for f in scan_findings:
            if f.get("scanner") == "engine" and "engine-" in (f.get("scanId") or ""):
                run_index = int(str(f["scanId"]).rsplit("-", 1)[-1])
                for case in corpus["pairs"]:
                    if case_matches(case, f, corpus_dir, marker_cache):
                        per_run_hits[run_index].add(case["id"])
        if per_run_hits:
            common = set.intersection(*per_run_hits.values()) if len(per_run_hits) > 1 else set()
            union = set.union(*per_run_hits.values())
            stability = round(len(common) / len(union), 4) if union else 1.0

    summary = {
        "corpus": corpus["name"],
        "corpusRevision": corpus["revision"],
        "detectors": manifest["detectors"],
        "totalCases": len(corpus["pairs"]),
        "detectedCases": sum(1 for c in corpus["pairs"] if detected[c["id"]]),
        "recall": round(
            sum(1 for c in corpus["pairs"] if detected[c["id"]]) / len(corpus["pairs"]), 4
        ),
        "unmatchedFindings": len(clean_fps),
        "duplicateRate": round(
            sum(max(0, len(v) - 1) for v in detected.values())
            / max(1, len(scan_findings)),
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
        f"- detectors: {manifest['detectors']}",
        f"- engine revision: {manifest.get('engineRevision') or 'n/a'}",
        f"- recall: {summary['recall']} ({summary['detectedCases']}/{summary['totalCases']})",
        f"- unmatched findings (FP candidates): {summary['unmatchedFindings']}",
        f"- duplicate rate: {summary['duplicateRate']}",
        f"- engine stability: {stability if stability is not None else 'n/a (single run or deterministic only)'}",
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
