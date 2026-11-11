"""Exercise the local SCA probe against the real product scanner."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks/corpus/v3"
FIXTURES = ROOT / "benchmarks/fixtures/offline_sca/v1"
PRODUCT = Path(os.environ.get("LYRASHIELD_AI_DIR", "/nonexistent"))
pytestmark = pytest.mark.skipif(
    not (PRODUCT / "apps/worker/node_modules/.bin/tsx").is_file(),
    reason="set LYRASHIELD_AI_DIR to an installed product checkout",
)


def test_probe_executes_real_scanner_and_binds_retained_evidence(tmp_path: Path) -> None:
    output = tmp_path / "receipt"
    proc = subprocess.run(  # noqa: S603 -- fixed local executable and test paths
        [sys.executable, "-m", "benchmarks.offline_sca_probe", "--output", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    receipt = json.loads((output / "receipt.json").read_text())
    assert receipt["profileStatus"] == "NOT_MEASURED"
    assert receipt["claimStatus"] == "NOT_REPORTABLE"
    assert receipt["fixtureSet"] == "local-synthetic-composer-v1"
    assert receipt["basedOnCaseId"] == "PHP-COMPOSER-01"
    assert receipt["adjudicationStatus"] == "NOT_INDEPENDENTLY_REVIEWED"
    assert receipt["heldOutStatus"] == "NOT_PROVIDED"
    assert receipt["modelRoute"] is None and receipt["image"] is None
    assert receipt["sources"]["product"]["revision"]
    assert receipt["sources"]["engine"]["revision"]
    assert receipt["runnerSha256"]
    for path in (
        "benchmarks/corpus/v3/adjudications.json",
        "benchmarks/corpus/v3/held-out.json",
        "benchmarks/profiles/v1/paths.json",
    ):
        assert (
            receipt["inputSha256"][path] == hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        )
    assert (
        receipt["advisorySha256"]
        == hashlib.sha256((CORPUS / "advisories/frozen.json").read_bytes()).hexdigest()
    )
    for variant in ("vulnerable", "clean"):
        artifact = output / f"{variant}.json"
        assert (
            receipt["runs"][variant]["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
        )
        result = json.loads(artifact.read_text())
        assert result["inventoryStatus"] == "COMPLETE"
        assert result["coverageIssues"] == []
    vulnerable = json.loads((output / "vulnerable.json").read_text())
    clean = json.loads((output / "clean.json").read_text())
    assert len(vulnerable["findings"]) == 1
    assert vulnerable["findings"][0]["id"] == "LYRA-FIXTURE-2026-001"
    assert vulnerable["findings"][0]["package"] == "example/legacy-router"
    assert vulnerable["findings"][0]["fixedVersion"] == "2.4.1"
    assert clean["findings"] == []


def test_probe_rejects_stale_lock_without_complete_coverage(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "composer.lock").write_bytes((FIXTURES / "vulnerable/composer.lock").read_bytes())
    manifest_path = fixture / "composer.json"
    manifest_path.write_text('{"require":{"example/legacy-router":"^9.0"}}')
    proc = subprocess.run(  # noqa: S603 -- fixed local executable and test paths
        [
            str(PRODUCT / "apps/worker/node_modules/.bin/tsx"),
            str(ROOT / "benchmarks/run_offline_sca.ts"),
            "--fixture",
            str(fixture),
            "--advisories",
            str(CORPUS / "advisories/frozen.json"),
        ],
        cwd=ROOT,
        env={**os.environ, "LYRASHIELD_AI_DIR": str(PRODUCT)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode != 0
    assert "incomplete" in proc.stderr.lower()


def test_probe_rejects_unbound_advisory_snapshot(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    for name in ("composer.json", "composer.lock"):
        (fixture / name).write_bytes((FIXTURES / "vulnerable" / name).read_bytes())
    snapshot = json.loads((CORPUS / "advisories/frozen.json").read_text())
    snapshot["advisories"][0]["fixed"] = "9.0.0"
    snapshot["advisories"][0]["affected"] = "<9.0.0"
    path = tmp_path / "altered.json"
    path.write_text(json.dumps(snapshot))
    proc = subprocess.run(  # noqa: S603 -- fixed local executable and test paths
        [
            str(PRODUCT / "apps/worker/node_modules/.bin/tsx"),
            str(ROOT / "benchmarks/run_offline_sca.ts"),
            "--fixture",
            str(fixture),
            "--advisories",
            str(path),
        ],
        cwd=ROOT,
        env={**os.environ, "LYRASHIELD_AI_DIR": str(PRODUCT)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode != 0
    assert "advisory" in proc.stderr.lower()
