"""Run security-gate mutations only inside disposable Git worktrees."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = Path(__file__).resolve().parent / "mutations" / "v1" / "probes.json"
EVIDENCE_SCHEMA = "lyrashield-mutation-evidence/1.0.0"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _worktree_path(worktree: Path, relative_path: str) -> Path:
    path = (worktree / relative_path).resolve()
    if not path.is_relative_to(worktree.resolve()):
        raise ValueError(f"mutation path must stay inside the isolated worktree: {relative_path}")
    return path


def _git(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def apply_replacement(source: Path, old: str, new: str) -> None:
    content = source.read_text(encoding="utf-8")
    count = content.count(old)
    if count != 1:
        raise ValueError(f"mutation target expected once in {source}, found {count}")
    source.write_text(content.replace(old, new, 1), encoding="utf-8")


def _run_test(worktree: Path, test: list[str], timeout: int) -> dict[str, Any]:
    env = {**os.environ, "PYTHONPATH": str(worktree), "PYTHONDONTWRITEBYTECODE": "1"}
    command = [sys.executable, "-m", "pytest", *test, "-q", "--tb=short", "-p", "no:cacheprovider"]
    started = time.monotonic()
    proc = subprocess.run(
        command,
        cwd=worktree,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "command": command,
        "returncode": proc.returncode,
        "runtimeMs": int((time.monotonic() - started) * 1000),
        "stdoutTail": proc.stdout[-4000:],
        "stderrTail": proc.stderr[-2000:],
    }


def _cleanup_worktree(temp_root: Path, worktree: Path) -> str | None:
    proc = _git(["worktree", "remove", "--force", str(worktree)], cwd=ROOT)
    shutil.rmtree(temp_root, ignore_errors=True)
    return None if proc.returncode == 0 else (proc.stderr or proc.stdout).strip()


def run_probe(spec: dict[str, Any], *, timeout: int) -> dict[str, Any]:
    temp_root = Path(tempfile.mkdtemp(prefix="lyrashield-mutation-"))
    worktree = temp_root / "repo"
    add = _git(["worktree", "add", "--detach", str(worktree), "HEAD"], cwd=ROOT)
    if add.returncode != 0:
        shutil.rmtree(temp_root, ignore_errors=True)
        return {
            "id": spec["id"],
            "gate": spec["gate"],
            "status": "ERROR",
            "error": f"git worktree add failed: {(add.stderr or add.stdout).strip()}",
        }
    result: dict[str, Any]
    try:
        source = _worktree_path(worktree, spec["sourcePath"])
        original_hash = _hash(source)
        baseline = _run_test(worktree, spec["test"], timeout)
        if baseline["returncode"] != 0:
            result = {
                "id": spec["id"],
                "gate": spec["gate"],
                "status": "ERROR",
                "error": "baseline test failed",
                "originalSha256": original_hash,
                "baseline": baseline,
            }
        else:
            apply_replacement(source, spec["old"], spec["new"])
            mutated_hash = _hash(source)
            killed = _run_test(worktree, spec["test"], timeout)
            combined_output = killed["stdoutTail"] + killed["stderrTail"]
            detected = killed["returncode"] != 0 and spec["expectedFailureText"] in combined_output
            restore = _git(["checkout", "--", spec["sourcePath"]], cwd=worktree)
            restored_hash = _hash(source)
            restored = _run_test(worktree, spec["test"], timeout)
            restored_valid = (
                restore.returncode == 0
                and restored_hash == original_hash
                and mutated_hash != original_hash
                and restored["returncode"] == 0
            )
            result = {
                "id": spec["id"],
                "gate": spec["gate"],
                "requirement": spec["requirement"],
                "status": "PASS" if detected and restored_valid else "FAIL",
                "sourcePath": spec["sourcePath"],
                "originalSha256": original_hash,
                "mutatedSha256": mutated_hash,
                "restoredSha256": restored_hash,
                "baseline": baseline,
                "killed": killed,
                "restored": restored,
            }
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result = {
            "id": spec.get("id"),
            "gate": spec.get("gate"),
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        cleanup_error = _cleanup_worktree(temp_root, worktree)
        if cleanup_error:
            result["cleanupError"] = cleanup_error
            result["status"] = "FAIL"
    return result


def run_probes(*, only: set[str] | None = None, timeout: int = 300) -> dict[str, Any]:
    root_status = _git(["status", "--porcelain"], cwd=ROOT)
    if root_status.returncode != 0:
        raise RuntimeError("unable to inspect source worktree")
    if root_status.stdout.strip():
        raise RuntimeError("source worktree must be clean before mutation probing")
    revision = _git(["rev-parse", "HEAD"], cwd=ROOT).stdout.strip()
    spec_record = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    probes = [spec for spec in spec_record["probes"] if only is None or spec["id"] in only]
    if only and {spec["id"] for spec in probes} != only:
        missing = sorted(only - {spec["id"] for spec in probes})
        raise ValueError(f"unknown probe ids: {missing}")
    results = [run_probe(spec, timeout=timeout) for spec in probes]
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "revision": revision,
        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "PASS"
        if results and all(item["status"] == "PASS" for item in results)
        else "FAIL",
        "probes": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="*", help="probe ids to run")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--output", help="write the evidence JSON to this path")
    parser.add_argument("--list", action="store_true", help="list configured gates and exit")
    args = parser.parse_args()
    if args.list:
        spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
        print(
            json.dumps(
                [{"id": item["id"], "gate": item["gate"]} for item in spec["probes"]], indent=2
            )
        )
        return 0
    evidence = run_probes(
        only=set(args.only) if args.only else None,
        timeout=args.timeout,
    )
    rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
