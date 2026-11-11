"""Evaluation v3 category, denominator, uncertainty, and claim-gate regressions."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from benchmarks import run as benchmark_run
from benchmarks.evaluation_v3 import (
    corpus_contract_hashes,
    finding_fingerprint,
    score_v3,
    wilson_interval,
)


CORPUS_DIR = Path(__file__).resolve().parents[1] / "benchmarks" / "corpus" / "v3"


def _source() -> dict[str, Any]:
    return {
        "revision": "a" * 40,
        "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
        "dirty": False,
    }


def _finding(case: dict[str, Any], variant: str, *, extra: bool = False) -> dict[str, Any]:
    filename = Path(case[variant]).name
    marker = case.get("markerLine", 2)
    return {
        "caseId": case["id"],
        "variant": variant,
        "scanId": f"{case['id']}-{variant}-det",
        "runIndex": 0,
        "scanner": "sast",
        "id": "sast-fixture",
        "file": filename,
        "startLine": int(marker) + (2 if extra else 0),
        "title": "fixture finding",
        "cwe": "CWE-1",
    }


def _result_fixture(
    tmp_path: Path,
    extra_records: list[dict[str, Any]],
    *,
    corpus_dir: Path = CORPUS_DIR,
) -> tuple[Path, dict[str, Any]]:
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    selected_cases = [
        case for case in corpus["pairs"] if "deterministic_core" in case["supportedProfiles"]
    ]
    records_by_scan: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in selected_cases:
        for variant in ("vulnerable", "clean"):
            scan_id = f"{case['id']}-{variant}-det"
            records_by_scan[scan_id].extend(
                [
                    {
                        "caseId": case["id"],
                        "variant": variant,
                        "scanId": scan_id,
                        "runIndex": 0,
                        "scanner": "__discovery__",
                        "discovery": {},
                    },
                    {
                        "caseId": case["id"],
                        "variant": variant,
                        "scanId": scan_id,
                        "runIndex": 0,
                        "scanner": "__coverage__",
                        "coverageIssues": [],
                    },
                ]
            )
    for record in extra_records:
        records_by_scan[record["scanId"]].append(record)

    result_dir = tmp_path / "result"
    result_dir.mkdir()
    findings = [
        record
        for case in selected_cases
        for variant in ("vulnerable", "clean")
        for record in records_by_scan[f"{case['id']}-{variant}-det"]
    ]
    findings_path = result_dir / "findings.jsonl"
    findings_path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in findings) + "\n",
        encoding="utf-8",
    )
    runs = [
        {
            "case": case["id"],
            "detector": "deterministic",
            "variant": variant,
            "runIndex": 0,
            "scanId": f"{case['id']}-{variant}-det",
            "returncode": 0,
            "errors": [],
            "emitted": len(records_by_scan[f"{case['id']}-{variant}-det"]),
            "runtimeMs": 1,
        }
        for case in selected_cases
        for variant in ("vulnerable", "clean")
    ]
    manifest = {
        "harnessVersion": 4,
        "engineRuns": None,
        "detectors": "deterministic",
        "engineRevision": None,
        "pathProfile": "deterministic_core",
        "scannerContractVersion": "fixture/3",
        "selectedCaseIds": [case["id"] for case in selected_cases],
        "sources": {"engine": _source(), "product": _source()},
        "sourcesChangedDuringRun": False,
        "corpus": corpus["name"],
        "corpusRevision": corpus["revision"],
        "corpusSha256": hashlib.sha256((corpus_dir / "corpus.json").read_bytes()).hexdigest(),
        "corpusContractsSha256": corpus_contract_hashes(corpus_dir, corpus),
        "fixtureSha256": {
            path: hashlib.sha256((corpus_dir / path).read_bytes()).hexdigest()
            for path in {
                case[variant] for case in corpus["pairs"] for variant in ("vulnerable", "clean")
            }
        },
        "findingsSha256": hashlib.sha256(findings_path.read_bytes()).hexdigest(),
        "runs": runs,
    }
    (result_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return result_dir, manifest


def test_v3_scoring_is_one_to_one_and_preserves_unclassified_extras(tmp_path: Path) -> None:
    corpus = json.loads((CORPUS_DIR / "corpus.json").read_text(encoding="utf-8"))
    case = next(item for item in corpus["pairs"] if item["id"] == "SECRET-01")
    true_positive = _finding(case, "vulnerable")
    clean_false_positive = _finding(case, "clean")
    extra = _finding(case, "vulnerable", extra=True)
    result_dir, manifest = _result_fixture(
        tmp_path, [true_positive, dict(true_positive), extra, clean_false_positive]
    )

    summary = score_v3(result_dir, CORPUS_DIR, corpus)

    assert summary["status"] == "COMPLETE"
    assert summary["claimStatus"] == "NOT_REPORTABLE"
    assert summary["counts"] == {
        "truePositive": 1,
        "falsePositive": 1,
        "falseNegative": 24,
        "ambiguous": 0,
        "unreachable": 0,
        "unclassifiedExtra": 1,
        "duplicate": 1,
        "incomplete": 0,
    }
    assert summary["precision"]["status"] == "NOT_REPORTABLE"
    assert summary["precision"]["raw"] == {"numerator": 1, "denominator": 2}
    assert summary["precision"]["wilson95"] is None
    assert summary["recall"]["raw"] == {"numerator": 1, "denominator": 25}
    assert any("remain unclassified" in reason for reason in summary["precision"]["reasons"])
    assert (result_dir / "results.json").is_file()
    assert "NOT_REPORTABLE" in (result_dir / "RESULTS.md").read_text(encoding="utf-8")

    manifest["corpusContractsSha256"]["adjudications"] = "0" * 64
    (result_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert score_v3(result_dir, CORPUS_DIR, corpus)["status"] == "INCOMPLETE"


def test_wilson_interval_uses_the_raw_denominator() -> None:
    interval = wilson_interval(8, 10)
    assert interval is not None
    assert interval["confidence"] == 0.95
    assert interval["lower"] == 0.490162
    assert interval["upper"] == 0.943318
    assert wilson_interval(0, 0) is None
    assert wilson_interval(11, 10) is None


def test_ambiguous_scenarios_remain_in_the_category_ledger(tmp_path: Path) -> None:
    benchmarks = tmp_path / "benchmarks"
    corpus_dir = benchmarks / "corpus" / "v3"
    shutil.copytree(CORPUS_DIR, corpus_dir)
    shutil.copytree(CORPUS_DIR.parent / "v2", benchmarks / "corpus" / "v2")
    shutil.copytree(CORPUS_DIR.parents[1] / "profiles", benchmarks / "profiles")
    corpus_path = corpus_dir / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["scenarios"].append(
        {
            "id": "AMBIGUOUS-FIXTURE-01",
            "profile": "deterministic_core",
            "expectedCategory": "ambiguous",
            "status": "NOT_MEASURED",
        }
    )
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    result_dir, _manifest = _result_fixture(tmp_path, [], corpus_dir=corpus_dir)

    summary = score_v3(result_dir, corpus_dir, corpus)

    assert summary["counts"]["ambiguous"] == 1
    assert any(
        item.get("id") == "AMBIGUOUS-FIXTURE-01" for item in summary["categories"]["ambiguous"]
    )


@pytest.mark.parametrize("returncode", [False, 0.0, None, "0", -1])
def test_v3_scoring_requires_an_integer_zero_exit_code(tmp_path: Path, returncode: Any) -> None:
    corpus = json.loads((CORPUS_DIR / "corpus.json").read_text(encoding="utf-8"))
    result_dir, manifest = _result_fixture(tmp_path, [])
    assert score_v3(result_dir, CORPUS_DIR, corpus)["failedRuns"] == 0
    manifest["runs"][0]["returncode"] = returncode
    (result_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    summary = score_v3(result_dir, CORPUS_DIR, corpus)
    assert summary["status"] == "INCOMPLETE"
    assert summary["failedRuns"] == 1
    assert any(
        item.get("category") == "failed_run" and item.get("scanId") == manifest["runs"][0]["scanId"]
        for item in summary["categories"]["incomplete"]
    )


def test_scoring_rejects_detector_evidence_from_another_path_profile(tmp_path: Path) -> None:
    corpus = json.loads((CORPUS_DIR / "corpus.json").read_text(encoding="utf-8"))
    result_dir, manifest = _result_fixture(tmp_path, [])
    manifest["pathProfile"] = "local_engine_cli"
    (result_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    summary = score_v3(result_dir, CORPUS_DIR, corpus)

    assert summary["status"] == "INCOMPLETE"
    assert any(
        item.get("category") == "path_profile_detector_mismatch"
        for item in summary["categories"]["incomplete"]
    )


def test_runner_rejects_a_path_profile_with_incompatible_detectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmarks/run.py",
            "--corpus",
            "v3",
            "--detectors",
            "deterministic",
            "--path-profile",
            "local_engine_cli",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        benchmark_run.main()

    assert exc_info.value.code == 2


def test_runner_rejects_a_profile_without_a_dedicated_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmarks/run.py",
            "--corpus",
            "v3",
            "--detectors",
            "deterministic",
            "--path-profile",
            "offline_sca",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        benchmark_run.main()

    assert exc_info.value.code == 2


def test_adjudicated_unreachable_finding_blocks_reporting_and_stays_visible(
    tmp_path: Path,
) -> None:
    benchmarks = tmp_path / "benchmarks"
    corpus_dir = benchmarks / "corpus" / "v3"
    shutil.copytree(CORPUS_DIR, corpus_dir)
    shutil.copytree(CORPUS_DIR.parent / "v2", benchmarks / "corpus" / "v2")
    shutil.copytree(CORPUS_DIR.parents[1] / "profiles", benchmarks / "profiles")
    corpus_path = corpus_dir / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["provenance"]["independentReviewStatus"] = "INDEPENDENTLY_REVIEWED"
    profile_path = benchmarks / "profiles" / "v1" / "paths.json"
    profiles = json.loads(profile_path.read_text(encoding="utf-8"))
    for profile in profiles["profiles"]:
        if profile["id"] == "deterministic_core":
            profile["status"] = "MEASURED"
    profile_path.write_text(json.dumps(profiles), encoding="utf-8")
    corpus["contracts"]["pathProfiles"]["sha256"] = hashlib.sha256(
        profile_path.read_bytes()
    ).hexdigest()
    case = next(item for item in corpus["pairs"] if item["id"] == "SECRET-01")
    extra = _finding(case, "vulnerable", extra=True)
    adjudications_path = corpus_dir / "adjudications.json"
    adjudications = json.loads(adjudications_path.read_text(encoding="utf-8"))
    adjudications["review"].update(
        {
            "status": "INDEPENDENTLY_REVIEWED",
            "reviewers": [{"id": "reviewer-a"}, {"id": "reviewer-b"}],
            "reviewedAt": "2026-11-05T00:00:00+00:00",
        }
    )
    adjudications["decisions"] = [
        {
            "findingSha256": finding_fingerprint(extra),
            "outcome": "unreachable",
            "reviewerIds": ["reviewer-a", "reviewer-b"],
            "rationale": "The projection cannot be reached.",
        }
    ]
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")
    corpus["contracts"]["adjudications"]["sha256"] = hashlib.sha256(
        adjudications_path.read_bytes()
    ).hexdigest()
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    result_dir, _manifest = _result_fixture(tmp_path, [extra], corpus_dir=corpus_dir)

    summary = score_v3(result_dir, corpus_dir, corpus)

    assert summary["status"] == "COMPLETE"
    assert summary["claimStatus"] == "NOT_REPORTABLE"
    assert summary["counts"]["unreachable"] == 1
    assert any(
        item.get("findingSha256") == finding_fingerprint(extra)
        for item in summary["categories"]["unreachable"]
    )
    assert any("unreachable" in reason.lower() for reason in summary["precision"]["reasons"])


def test_not_measured_path_profile_blocks_reportable_metrics(tmp_path: Path) -> None:
    corpus = json.loads((CORPUS_DIR / "corpus.json").read_text(encoding="utf-8"))
    result_dir, _manifest = _result_fixture(tmp_path, [])

    summary = score_v3(result_dir, CORPUS_DIR, corpus)

    assert summary["claimStatus"] == "NOT_REPORTABLE"
    assert any(
        "Path profile deterministic_core is NOT_MEASURED" in reason
        for reason in summary["precision"]["reasons"]
    )
