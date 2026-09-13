"""
Benchmark runner — corpus fixtures through deterministic scanners (offline,
free) and the engine CLI (founder-gated, costs model budget).

  uv run python benchmarks/run.py --corpus v2 --detectors deterministic
  uv run python benchmarks/run.py --corpus v2 --detectors all --runs 2 \
      --engine-approve "I authorize spend"

Deterministic runs invoke the sibling product repo's scanners via tsx and
cost nothing. Engine runs require --engine-approve and record the exact
engine revision + model route into results.json. Findings land in
benchmarks/results/<timestamp>/findings.jsonl for score.py.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


BENCH_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = BENCH_ROOT / "results"
DETERMINISTIC_RUNNER = BENCH_ROOT / "run_deterministics.ts"

# Sibling product repo — where the deterministic scanner sources live.
PRODUCT_REPO = Path(
    os.environ.get("LYRASHIELD_AI_DIR", BENCH_ROOT.parent.parent / "lyrashield-ai")
).resolve()


def load_corpus(corpus_dir: Path) -> dict:
    return json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))


def materialize_fixture(corpus_dir: Path, case: dict) -> Path:
    """Copy the case's vulnerable projection into a temp repo dir."""
    repo_dir = Path(tempfile.mkdtemp(prefix=f"bench-{case['id']}-"))
    src = corpus_dir / case["vulnerable"]
    dest = repo_dir / Path(case["vulnerable"]).name
    shutil.copy2(src, dest)
    return repo_dir


def run_deterministic(corpus_dir: Path, case: dict, out) -> dict:
    repo_dir = materialize_fixture(corpus_dir, case)
    scan_id = f"{case['id']}-det"
    cmd = [
        "pnpm",
        "-C",
        str(PRODUCT_REPO / "apps/worker"),
        "exec",
        "tsx",
        str(DETERMINISTIC_RUNNER),
        "--repo-root",
        str(repo_dir),
        "--scan-id",
        scan_id,
    ]
    env = {**os.environ, "LYRASHIELD_AI_DIR": str(PRODUCT_REPO)}
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
    runtime_ms = int((time.monotonic() - started) * 1000)
    emitted = 0
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("{"):
            out.write(line + "\n")
            emitted += 1
    shutil.rmtree(repo_dir, ignore_errors=True)
    return {
        "case": case["id"],
        "detector": "deterministic",
        "emitted": emitted,
        "runtimeMs": runtime_ms,
        "returncode": proc.returncode,
        "stderrTail": proc.stderr[-2000:] if proc.returncode != 0 else None,
    }


def run_engine(corpus_dir: Path, case: dict, out, run_index: int) -> dict:
    """Engine run through the engine CLI — gated by --engine-approve."""
    repo_dir = materialize_fixture(corpus_dir, case)
    scan_id = f"{case['id']}-engine-{run_index}"
    # Non-interactive runs persist findings to strix_runs/<run-name>/
    # vulnerabilities.json under the cwd — they are NOT printed to stdout.
    cmd = [
        "lyrashield",
        "--target",
        str(repo_dir),
        "--non-interactive",
        "--scan-mode",
        "quick",
        "--run-name",
        scan_id,
    ]
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, cwd=repo_dir)
    runtime_ms = int((time.monotonic() - started) * 1000)

    emitted = 0
    vuln_path = repo_dir / "strix_runs" / scan_id / "vulnerabilities.json"
    if vuln_path.is_file():
        try:
            for rec in json.loads(vuln_path.read_text(encoding="utf-8")):
                if not isinstance(rec, dict):
                    continue
                loc = (rec.get("code_locations") or [{}])[0]
                out.write(
                    json.dumps(
                        {
                            "scanId": scan_id,
                            "scanner": "engine",
                            "id": rec.get("id"),
                            "severity": rec.get("severity"),
                            "title": rec.get("title"),
                            "cwe": rec.get("cwe"),
                            "file": loc.get("file") or rec.get("target"),
                            "startLine": loc.get("start_line"),
                        }
                    )
                    + "\n"
                )
                emitted += 1
        except json.JSONDecodeError:
            pass
    shutil.rmtree(repo_dir, ignore_errors=True)
    return {
        "case": case["id"],
        "detector": "engine",
        "runIndex": run_index,
        "emitted": emitted,
        "runtimeMs": runtime_ms,
        "returncode": proc.returncode,
        "stderrTail": proc.stderr[-2000:] if proc.returncode != 0 else None,
    }


def engine_revision() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=BENCH_ROOT.parent,
        ).stdout.strip()
    except Exception:
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="v2", help="corpus dir name under benchmarks/corpus")
    parser.add_argument(
        "--detectors",
        choices=["deterministic", "engine", "all"],
        default="deterministic",
    )
    parser.add_argument("--runs", type=int, default=1, help="engine runs per case (stability)")
    parser.add_argument(
        "--engine-approve",
        metavar="PHRASE",
        help="required for engine runs; any non-empty phrase records authorization",
    )
    args = parser.parse_args()

    corpus_dir = BENCH_ROOT / "corpus" / args.corpus
    corpus = load_corpus(corpus_dir)

    wants_engine = args.detectors in ("engine", "all")
    if wants_engine and not args.engine_approve:
        print(
            "Engine runs spend model budget. Re-run with "
            '--engine-approve "I authorize spend" to proceed.',
            file=sys.stderr,
        )
        return 2

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = RESULTS_ROOT / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    findings_path = out_dir / "findings.jsonl"
    runs_meta = []
    with findings_path.open("w", encoding="utf-8") as out:
        for case in corpus["pairs"]:
            if args.detectors in ("deterministic", "all"):
                runs_meta.append(run_deterministic(corpus_dir, case, out))
            if wants_engine:
                runs_meta.extend(run_engine(corpus_dir, case, out, i) for i in range(args.runs))

    manifest = {
        "corpus": corpus["name"],
        "corpusRevision": corpus["revision"],
        "schemaVersion": corpus["schemaVersion"],
        "detectors": args.detectors,
        "engineRevision": engine_revision() if wants_engine else None,
        "engineApproved": bool(args.engine_approve) if wants_engine else None,
        "runs": runs_meta,
        "startedAt": timestamp,
    }
    (out_dir / "run-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Wrote {findings_path} ({sum(r['emitted'] for r in runs_meta)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
