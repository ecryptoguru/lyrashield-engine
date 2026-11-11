"""Run a non-claimable local Composer SCA diagnostic against the product scanner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from benchmarks.corpus.v3.validate import validate
from benchmarks.run import BENCH_ROOT, PRODUCT_REPO, source_state


CORPUS = BENCH_ROOT / "corpus/v3"
FIXTURES = BENCH_ROOT / "fixtures/offline_sca/v1"
RUNNER = BENCH_ROOT / "run_offline_sca.ts"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs() -> dict[str, str]:
    paths = [
        CORPUS / "corpus.json",
        CORPUS / "advisories/frozen.json",
        RUNNER,
        Path(__file__),
        CORPUS / "adjudications.json",
        CORPUS / "held-out.json",
        BENCH_ROOT / "profiles/v1/paths.json",
    ]
    paths.extend(
        FIXTURES / variant / name
        for variant in ("vulnerable", "clean")
        for name in ("composer.json", "composer.lock")
    )
    return {str(path.relative_to(BENCH_ROOT.parent)): digest(path) for path in paths}


def execute(variant: str, advisories: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="lyrashield-offline-sca-") as directory:
        fixture = Path(directory)
        for name in ("composer.json", "composer.lock"):
            shutil.copyfile(FIXTURES / variant / name, fixture / name)
        proc = subprocess.run(
            [
                str(PRODUCT_REPO / "apps/worker/node_modules/.bin/tsx"),
                str(RUNNER),
                "--fixture",
                str(fixture),
                "--advisories",
                str(advisories),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": directory,
                "TMPDIR": os.environ.get("TMPDIR", directory),
                "LYRASHIELD_AI_DIR": str(PRODUCT_REPO),
            },
        )
    if proc.returncode != 0:
        raise RuntimeError(f"{variant} SCA execution failed: {proc.stderr[-2000:]}")
    records = [
        line.removeprefix("SCAPROBE:")
        for line in proc.stdout.splitlines()
        if line.startswith("SCAPROBE:")
    ]
    if len(records) != 1:
        raise RuntimeError(f"{variant} SCA output was incomplete")
    result = json.loads(records[0])
    if result.get("inventoryStatus") != "COMPLETE" or result.get("coverageIssues") != []:
        raise RuntimeError(f"{variant} SCA coverage was incomplete")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="new directory for retained evidence"
    )
    args = parser.parse_args()
    try:
        validate(CORPUS)
        before_inputs = inputs()
        adjudication = json.loads((CORPUS / "adjudications.json").read_text())["review"]["status"]
        held_out = json.loads((CORPUS / "held-out.json").read_text())["status"]
        profiles = json.loads((BENCH_ROOT / "profiles/v1/paths.json").read_text())["profiles"]
        profile_status = next(
            profile["status"] for profile in profiles if profile["id"] == "offline_sca"
        )
        node = shutil.which("node")
        tsx = PRODUCT_REPO / "apps/worker/node_modules/.bin/tsx"
        if not node or not tsx.is_file():
            raise RuntimeError("local runtime identity unavailable")  # noqa: TRY301
        runtime = {"nodeSha256": digest(Path(node).resolve()), "tsxShimSha256": digest(tsx)}
        sources = {"engine": source_state(BENCH_ROOT.parent), "product": source_state(PRODUCT_REPO)}
        results = {
            variant: execute(variant, CORPUS / "advisories/frozen.json")
            for variant in ("vulnerable", "clean")
        }
        after_sources = {
            "engine": source_state(BENCH_ROOT.parent),
            "product": source_state(PRODUCT_REPO),
        }
        if (
            before_inputs != inputs()
            or sources != after_sources
            or runtime != {"nodeSha256": digest(Path(node).resolve()), "tsxShimSha256": digest(tsx)}
        ):
            raise RuntimeError("inputs or source changed during the diagnostic")  # noqa: TRY301
        args.output.mkdir(parents=True, exist_ok=False)
        artifacts = {}
        for variant, result in results.items():
            path = args.output / f"{variant}.json"
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            artifacts[variant] = {"path": path.name, "sha256": digest(path)}
        receipt = {
            "schemaVersion": "lyrashield-offline-sca-diagnostic/1.0.0",
            "fixtureSet": "local-synthetic-composer-v1",
            "basedOnCaseId": "PHP-COMPOSER-01",
            "profile": "offline_sca",
            "profileStatus": profile_status,
            "diagnosticStatus": "NOT_MEASURED",
            "claimStatus": "NOT_REPORTABLE",
            "adjudicationStatus": adjudication,
            "heldOutStatus": held_out,
            "limitations": [
                "One synthetic Composer pair only; other SCA cases remain unmeasured.",
                "Local source execution has no qualified image or model route.",
                "The frozen advisory is synthetic and is not a live advisory feed.",
            ],
            "sources": sources,
            "image": None,
            "modelRoute": None,
            "runnerSha256": digest(RUNNER),
            "corpusSha256": digest(CORPUS / "corpus.json"),
            "advisorySha256": digest(CORPUS / "advisories/frozen.json"),
            "inputSha256": before_inputs,
            "runtime": runtime,
            "runs": artifacts,
        }
        (args.output / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Offline SCA diagnostic failed: {exc}", file=sys.stderr)
        return 1
    print(f"Retained offline SCA diagnostic in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
