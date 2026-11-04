"""Offline regressions for benchmark evidence attribution and failure states."""

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks import run
from benchmarks.score import (
    case_matches,
    corpus_matches_receipt,
    engine_receipt_valid,
    engine_stability,
    run_set_complete,
    score,
    source_identity_complete,
)


def test_marker_matching_does_not_credit_neighboring_case(tmp_path: Path) -> None:
    (tmp_path / "a.ts").write_text("bad() // CASE:A\nbad() // CASE:B\n")
    case = {"id": "B", "vulnerable": "a.ts"}
    finding = {"file": "a.ts", "startLine": 1, "id": "rule-absent"}
    assert not case_matches(case, finding, tmp_path, {})
    finding["startLine"] = 2
    assert case_matches(case, finding, tmp_path, {})
    finding["file"] = "not-a.ts"
    assert not case_matches(case, finding, tmp_path, {})


def test_overlapping_case_locators_do_not_credit_ambiguous_findings(tmp_path: Path) -> None:
    cases = [
        {
            "id": "A",
            "class": "iac",
            "vulnerable": "bad.yaml",
            "clean": "safe.yaml",
            "markerLine": 1,
            "rulePrefixes": ["iac-compose-privileged", "iac-k8s"],
        },
        {
            "id": "B",
            "class": "iac",
            "vulnerable": "bad.yaml",
            "clean": "safe.yaml",
            "markerLine": 4,
            "rulePrefixes": ["iac-k8s-hostpath"],
        },
    ]
    corpus = {"name": "test", "revision": "v1", "pairs": cases}
    (tmp_path / "corpus.json").write_text(json.dumps(corpus))
    (tmp_path / "bad.yaml").write_text("privileged: true\n\n\nhostPath: /etc\n")
    (tmp_path / "safe.yaml").write_text("safe: true\n")
    source = {
        "revision": "a" * 40,
        "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
        "dirty": False,
    }
    runs, records = [], []
    for case in cases:
        for variant in ("vulnerable", "clean"):
            case_id = case["id"]
            scan_id = f"{case_id}-{variant}-det"
            runs.append(
                {
                    "case": case_id,
                    "detector": "deterministic",
                    "variant": variant,
                    "runIndex": 0,
                    "scanId": scan_id,
                    "returncode": 0,
                    "emitted": 3 if case_id == "B" and variant == "vulnerable" else 2,
                }
            )
            for scanner, data in (
                ("__coverage__", {"coverageIssues": []}),
                ("__discovery__", {"discovery": {}}),
            ):
                records.append(
                    {
                        "caseId": case_id,
                        "variant": variant,
                        "runIndex": 0,
                        "scanId": scan_id,
                        "scanner": scanner,
                        **data,
                    }
                )
    records.append(
        {
            "caseId": "B",
            "variant": "vulnerable",
            "runIndex": 0,
            "scanId": "B-vulnerable-det",
            "scanner": "iac",
            "id": "iac-k8s-hostpath-bad.yaml-4",
            "file": "bad.yaml",
            "startLine": 4,
        }
    )
    findings = tmp_path / "findings.jsonl"
    findings.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    manifest = {
        "harnessVersion": 3,
        "detectors": "deterministic",
        "runs": runs,
        "corpus": "test",
        "corpusRevision": "v1",
        "corpusSha256": hashlib.sha256((tmp_path / "corpus.json").read_bytes()).hexdigest(),
        "fixtureSha256": {
            name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            for name in ("bad.yaml", "safe.yaml")
        },
        "findingsSha256": hashlib.sha256(findings.read_bytes()).hexdigest(),
        "sources": {"engine": source, "product": source},
        "sourcesChangedDuringRun": False,
    }
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    result = score(tmp_path, tmp_path)
    assert result["status"] == "INCOMPLETE"
    assert result["detectedCases"] == 0
    assert result["ambiguousFindings"] == 1
    # A narrowed locator restores credit to the correct case.
    cases[0]["rulePrefixes"] = ["iac-compose-privileged"]
    (tmp_path / "corpus.json").write_text(json.dumps(corpus))
    manifest["corpusSha256"] = hashlib.sha256((tmp_path / "corpus.json").read_bytes()).hexdigest()
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    result = score(tmp_path, tmp_path)
    assert result["status"] == "COMPLETE"
    assert result["detectedCases"] == 1
    assert result["ambiguousFindings"] == 0


def test_stability_includes_zero_hit_runs() -> None:
    manifest = {"runs": [{"detector": "engine", "runIndex": i} for i in range(3)]}
    detected = {"A": [{"scanner": "engine", "runIndex": i} for i in range(2)]}
    assert engine_stability(manifest, detected) == 0


@pytest.mark.parametrize("revision", [None, "b" * 40])
def test_engine_revision_must_match_source_identity(revision: str | None) -> None:
    source = {
        "revision": "a" * 40,
        "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
        "dirty": False,
    }
    manifest = {
        "detectors": "engine",
        "engineRevision": revision,
        "sources": {"engine": source, "product": source},
        "sourcesChangedDuringRun": False,
    }
    assert not source_identity_complete(manifest)
    manifest["engineRevision"] = source["revision"]
    assert source_identity_complete(manifest)


@pytest.mark.parametrize("bad_id", ["", "A-vulnerable-det", None])
def test_complete_run_set_requires_unique_nonempty_scan_ids(bad_id: str | None) -> None:
    corpus = {"pairs": [{"id": "A"}]}
    runs = [
        {
            "case": "A",
            "detector": "deterministic",
            "variant": variant,
            "runIndex": 0,
            "scanId": f"A-{variant}-det",
        }
        for variant in ("vulnerable", "clean")
    ]
    manifest = {"detectors": "deterministic", "runs": runs}
    assert run_set_complete(manifest, corpus)
    runs[1]["scanId"] = bad_id
    assert not run_set_complete(manifest, corpus)


@pytest.mark.parametrize(
    "changed",
    [
        {"scanId": "another-run"},
        {"caseId": "other-case"},
        {"variant": "unknown"},
        {"runIndex": 9},
        {"scanner": "engine"},
        {"scanner": None},
        {"scanner": "__discovery__"},
        {"scanner": "__coverage__"},
    ],
)
def test_finding_must_belong_to_the_recorded_run(tmp_path: Path, changed: dict) -> None:
    case = {"id": "A", "class": "auth", "vulnerable": "bad.ts", "clean": "safe.ts"}
    corpus = {"name": "fixture", "revision": "v1", "pairs": [case]}
    (tmp_path / "corpus.json").write_text(json.dumps(corpus))
    (tmp_path / "bad.ts").write_text("bad() // CASE:A\n")
    (tmp_path / "safe.ts").write_text("safe() // CASE:A\n")
    runs = [
        {
            "case": "A",
            "detector": "deterministic",
            "variant": variant,
            "runIndex": 0,
            "scanId": f"A-{variant}-det",
            "returncode": 0,
            "emitted": 3 if variant == "vulnerable" else 2,
        }
        for variant in ("vulnerable", "clean")
    ]
    manifest = {
        "harnessVersion": 3,
        "detectors": "deterministic",
        "runs": runs,
        "corpus": "fixture",
        "corpusRevision": "v1",
        "sourcesChangedDuringRun": False,
        "sources": {
            name: {
                "revision": "a" * 40,
                "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
                "dirty": False,
            }
            for name in ("engine", "product")
        },
        "corpusSha256": hashlib.sha256((tmp_path / "corpus.json").read_bytes()).hexdigest(),
        "fixtureSha256": {
            name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            for name in ("bad.ts", "safe.ts")
        },
    }
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    finding = {
        "caseId": "A",
        "variant": "vulnerable",
        "scanId": "A-vulnerable-det",
        "scanner": "sast",
        "file": "bad.ts",
        "startLine": 1,
        "runIndex": 0,
    }
    sentinels = [
        {
            "caseId": "A",
            "variant": variant,
            "scanId": f"A-{variant}-det",
            "runIndex": 0,
            "scanner": scanner,
            **payload,
        }
        for variant in ("vulnerable", "clean")
        for scanner, payload in (
            ("__discovery__", {"discovery": {}}),
            ("__coverage__", {"coverageIssues": []}),
        )
    ]
    path = tmp_path / "findings.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in [finding, *sentinels]) + "\n")
    manifest["findingsSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    valid = score(tmp_path, tmp_path)
    assert valid["status"] == "COMPLETE"
    assert valid["detectedCases"] == 1
    assert valid["findingsDigestMatches"] is True
    del manifest["findingsSha256"]
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    assert score(tmp_path, tmp_path)["status"] == "INCOMPLETE"
    manifest["findingsSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    # The same run identities and record count cannot hide changed finding bytes.
    changed_content = {**finding, "title": "different"}
    path.write_text(
        "\n".join(json.dumps(record) for record in [changed_content, *sentinels]) + "\n"
    )
    assert score(tmp_path, tmp_path)["status"] == "INCOMPLETE"

    # A pre-binding receipt remains readable but can no longer qualify as complete.
    manifest["harnessVersion"] = 2
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    assert score(tmp_path, tmp_path)["status"] == "LEGACY_UNVALIDATED"
    manifest["harnessVersion"] = 3
    path.write_text(
        "\n".join(json.dumps(record) for record in [{**finding, **changed}, *sentinels]) + "\n"
    )
    manifest["findingsSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    invalid = score(tmp_path, tmp_path)
    assert invalid["status"] == "INCOMPLETE"
    assert invalid["detectedCases"] == 0

    for records in (sentinels, [finding, finding, *sentinels]):
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
        manifest["findingsSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
        assert score(tmp_path, tmp_path)["status"] == "INCOMPLETE"
    path.write_text(
        "\n".join(json.dumps(record) for record in [finding, *sentinels]) + "\nnot json\n"
    )
    manifest["findingsSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    assert score(tmp_path, tmp_path)["status"] == "INCOMPLETE"


def test_clean_findings_errors_and_repeat_runs_are_separate(tmp_path: Path) -> None:
    case = {"id": "A", "class": "auth", "vulnerable": "a.ts"}
    (tmp_path / "a.ts").write_text("bad() // CASE:A\n")
    (tmp_path / "corpus.json").write_text(
        json.dumps({"name": "test", "revision": "v2", "pairs": [case]})
    )
    records = [
        {
            "caseId": "A",
            "variant": "vulnerable",
            "scanId": f"A-engine-{i}",
            "scanner": "engine",
            "file": "a.ts",
            "startLine": 1,
            "runIndex": i,
        }
        for i in range(2)
    ]
    records.extend(
        [
            {**records[0], "variant": "clean", "scanId": "A-clean-engine-0"},
            {"scanner": "sast", "error": "scanner failed"},
            {"level": "info", "message": "scanner startup", "variant": "clean"},
        ]
    )
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(rec) for rec in records))
    runs = [
        {
            "case": "A",
            "detector": "engine",
            "variant": "vulnerable",
            "runIndex": i,
            "scanId": f"A-engine-{i}",
            "returncode": 0,
        }
        for i in range(2)
    ]
    runs.append(
        {
            "case": "A",
            "detector": "engine",
            "variant": "clean",
            "runIndex": 0,
            "scanId": "A-clean-engine-0",
            "returncode": 0,
        }
    )
    (tmp_path / "run-manifest.json").write_text(
        json.dumps(
            {
                "harnessVersion": 3,
                "detectors": "engine",
                "runs": runs,
                "findingsSha256": hashlib.sha256(
                    (tmp_path / "findings.jsonl").read_bytes()
                ).hexdigest(),
            }
        )
    )
    result = score(tmp_path, tmp_path)
    assert result["detectedCases"] == 1
    assert result["cleanFindings"] == 1
    assert result["unmatchedFindings"] == 0
    assert result["duplicateRate"] == 0
    assert result["status"] == "INCOMPLETE"


def test_deterministic_runner_records_clean_polarity_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "safe.ts").write_text("safe()")
    case = {"id": "A", "vulnerable": "absent.ts", "clean": "safe.ts"}
    seen = []

    def execute(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        fixture = Path(cmd[cmd.index("--repo-root") + 1])
        assert (fixture / "safe.ts").read_text() == "safe()"
        seen.append(fixture)
        return SimpleNamespace(
            stdout='{"scanId":"A-clean-det","scanner":"sast","error":"failed"}',
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(run.subprocess, "run", execute)
    output = io.StringIO()
    receipt = run.run_deterministic(tmp_path, case, output, "clean")
    assert receipt["errors"]
    assert json.loads(output.getvalue())["variant"] == "clean"
    assert json.loads(output.getvalue())["caseId"] == "A"
    assert not seen[0].exists()


def test_runner_records_digest_of_exact_findings_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus_dir = tmp_path / "corpus" / "fixture"
    corpus_dir.mkdir(parents=True)
    case = {"id": "A", "class": "auth", "vulnerable": "bad.ts", "clean": "safe.ts"}
    corpus = {"name": "fixture", "revision": "v1", "schemaVersion": "test", "pairs": [case]}
    (corpus_dir / "corpus.json").write_text(json.dumps(corpus))
    for filename in ("bad.ts", "safe.ts"):
        (corpus_dir / filename).write_text("fixture // CASE:A\n")
    monkeypatch.setattr(run, "BENCH_ROOT", tmp_path)
    monkeypatch.setattr(run, "RESULTS_ROOT", tmp_path / "results")
    source = {
        "revision": "a" * 40,
        "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
        "dirty": False,
    }
    monkeypatch.setattr(run, "source_state", lambda _path: source.copy())
    monkeypatch.setattr(sys, "argv", ["run.py", "--corpus", "fixture"])

    def execute(_corpus_dir: Path, case: dict, out: io.TextIOBase, variant: str) -> dict:
        scan_id = f"{case['id']}-{variant}-det"
        for scanner, payload in (
            ("__discovery__", {"discovery": {}}),
            ("__coverage__", {"coverageIssues": []}),
        ):
            out.write(
                json.dumps(
                    {
                        "caseId": case["id"],
                        "variant": variant,
                        "scanId": scan_id,
                        "runIndex": 0,
                        "scanner": scanner,
                        **payload,
                    }
                )
                + "\n"
            )
        return {
            "case": case["id"],
            "variant": variant,
            "scanId": scan_id,
            "runIndex": 0,
            "detector": "deterministic",
            "emitted": 2,
            "returncode": 0,
        }

    monkeypatch.setattr(run, "run_deterministic", execute)
    assert run.main() == 0
    result_dir = next((tmp_path / "results").iterdir())
    manifest = json.loads((result_dir / "run-manifest.json").read_text())
    assert manifest["harnessVersion"] == 3
    assert (
        manifest["findingsSha256"]
        == hashlib.sha256((result_dir / "findings.jsonl").read_bytes()).hexdigest()
    )
    assert score(result_dir, corpus_dir)["status"] == "COMPLETE"
    for malformed in (
        {},
        {"engine": source},
        {"engine": source, "product": {}},
        {"engine": {**source, "revision": "unknown"}, "product": source},
        {"engine": source, "product": {**source, "dirty": None}},
    ):
        manifest["sources"] = malformed
        (result_dir / "run-manifest.json").write_text(json.dumps(manifest))
        assert score(result_dir, corpus_dir)["status"] == "INCOMPLETE"
    manifest["sources"] = {"engine": source, "product": source}
    del manifest["sourcesChangedDuringRun"]
    (result_dir / "run-manifest.json").write_text(json.dumps(manifest))
    assert score(result_dir, corpus_dir)["status"] == "INCOMPLETE"
    manifest["sourcesChangedDuringRun"] = False
    for unknown_version in (4, True, "3"):
        manifest["harnessVersion"] = unknown_version
        (result_dir / "run-manifest.json").write_text(json.dumps(manifest))
        assert score(result_dir, corpus_dir)["status"] == "INCOMPLETE"
    manifest["harnessVersion"] = 3
    findings_path = result_dir / "findings.jsonl"
    findings_path.write_bytes(b"\xff\n")
    manifest["findingsSha256"] = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    (result_dir / "run-manifest.json").write_text(json.dumps(manifest))
    assert score(result_dir, corpus_dir)["status"] == "INCOMPLETE"


def test_generated_receipts_do_not_invalidate_source_state(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603,S607 - local fixture repository

    git("init")
    source = tmp_path / "scanner.py"
    source.write_text("pass\n")
    git("add", "scanner.py")
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "-m",
        "fixture",
    )
    before = run.source_state(tmp_path)
    assert not before["dirty"]
    output = tmp_path / "benchmarks" / "results" / "run"
    output.mkdir(parents=True)
    (output / "findings.jsonl").write_text("{}\n")
    assert run.source_state(tmp_path) == before
    source.write_text("changed = True\n")
    after = run.source_state(tmp_path)
    assert after["dirty"]
    assert after["trackedDiffSha256"] != before["trackedDiffSha256"]


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        {"error": "unreadable"},
        {"schemaVersion": "2.0"},
        {"runId": "wrong"},
        {"status": "running"},
        {"phase": "finalizing"},
        {"sandboxCapabilities": None},
        {"sandboxCapabilities": {"statuses": []}},
        {"sandboxCapabilities": {"schema": "unexpected"}},
    ],
)
def test_engine_score_requires_valid_run_receipts(tmp_path: Path, invalid: object) -> None:
    case = {"id": "A", "class": "auth", "vulnerable": "bad.ts", "clean": "safe.ts"}
    corpus = {"name": "test", "revision": "v1", "pairs": [case]}
    (tmp_path / "corpus.json").write_text(json.dumps(corpus))
    for name in ("bad.ts", "safe.ts"):
        (tmp_path / name).write_text("example // CASE:A\n")
    (tmp_path / "findings.jsonl").write_bytes(b"")
    source = {
        "revision": "a" * 40,
        "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
        "dirty": False,
    }
    caps = {
        "schema": "lyrashield-sandbox-capabilities/1.0",
        "backend": "docker",
        "probedAt": "2026-11-04T00:00:00+00:00",
        "statuses": {"exec": "supported"},
        "preflightDegradations": [],
        "preflightFailures": [],
    }
    runs = [
        {
            "case": "A",
            "detector": "engine",
            "variant": variant,
            "runIndex": 0,
            "scanId": f"A-{variant}-engine-0",
            "returncode": 0,
            "emitted": 0,
            "runReceipt": {
                "schemaVersion": "1.1",
                "runId": f"A-{variant}-engine-0",
                "status": "completed",
                "phase": "completed",
                "sandboxCapabilities": caps,
            },
        }
        for variant in ("vulnerable", "clean")
    ]
    manifest = {
        "harnessVersion": 3,
        "detectors": "engine",
        "runs": runs,
        "engineRevision": source["revision"],
        "sources": {"engine": source, "product": source},
        "sourcesChangedDuringRun": False,
        "corpus": "test",
        "corpusRevision": "v1",
        "corpusSha256": hashlib.sha256((tmp_path / "corpus.json").read_bytes()).hexdigest(),
        "fixtureSha256": {
            name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            for name in ("bad.ts", "safe.ts")
        },
        "findingsSha256": hashlib.sha256(b"").hexdigest(),
    }
    path = tmp_path / "run-manifest.json"
    path.write_text(json.dumps(manifest))
    assert score(tmp_path, tmp_path)["status"] == "COMPLETE"
    runs[0]["runReceipt"] = {**runs[0]["runReceipt"], **invalid} if invalid else invalid
    path.write_text(json.dumps(manifest))
    result = score(tmp_path, tmp_path)
    assert result["status"] == "INCOMPLETE"
    assert result["engineReceipts"]["invalid"] == 1
    manifest["harnessVersion"] = 2
    path.write_text(json.dumps(manifest))
    assert score(tmp_path, tmp_path)["status"] == "LEGACY_UNVALIDATED"


def test_engine_run_receipt_surfaces_run_record_fields(tmp_path: Path) -> None:
    run_dir = tmp_path / "strix_runs" / "scan-1"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "schema_version": "1.1",
                "run_id": "scan-1",
                "status": "completed",
                "phase": "completed",
                "sandbox_capabilities": {
                    "schema": "lyrashield-sandbox-capabilities/1.0",
                    "backend": "docker",
                    "probed_at": "2026-11-04T00:00:00+00:00",
                    "capabilities": {
                        "exec": {"status": "supported"},
                        "mounts": {"status": "unprobed"},
                    },
                    "preflight": {
                        "degradations": [{"control": "egress_policy_delivery"}],
                        "failures": [{"control": "agent_exec"}],
                    },
                },
                "scan_quality": {
                    "observed": {"findings_filed": 2},
                    "declared": {"coverage_entries": 1},
                    "surfaces": [{"surface": "a"}, {"surface": "b"}],
                    "unassessed": ["c"],
                },
                "scope_violations": {"total": 4},
                "evidence_export": {"status": "exported"},
            }
        )
    )
    receipt = run.engine_run_receipt(tmp_path, "scan-1")
    assert receipt["schemaVersion"] == "1.1"
    assert receipt["runId"] == "scan-1"
    assert receipt["status"] == receipt["phase"] == "completed"
    caps = receipt["sandboxCapabilities"]
    assert caps["schema"] == "lyrashield-sandbox-capabilities/1.0"
    assert caps["probedAt"] == "2026-11-04T00:00:00+00:00"
    assert caps["backend"] == "docker"
    assert caps["statuses"] == {"exec": "supported", "mounts": "unprobed"}
    assert caps["preflightDegradations"] == ["egress_policy_delivery"]
    assert caps["preflightFailures"] == ["agent_exec"]
    assert receipt["scanQuality"]["observed"]["findings_filed"] == 2
    assert receipt["scanQuality"]["surfaces"] == 2
    assert receipt["scanQuality"]["unassessed"] == 1
    assert receipt["scopeViolations"] == 4
    assert receipt["evidenceExport"] == "exported"


def test_engine_run_receipt_missing_and_unreadable(tmp_path: Path) -> None:
    assert run.engine_run_receipt(tmp_path, "no-scan") is None
    bad = tmp_path / "strix_runs" / "bad-scan"
    bad.mkdir(parents=True)
    (bad / "run.json").write_text("{not json")
    receipt = run.engine_run_receipt(tmp_path, "bad-scan")
    assert "error" in receipt
    (bad / "run.json").write_bytes(b"\xff")
    receipt = run.engine_run_receipt(tmp_path, "bad-scan")
    assert "error" in receipt


@pytest.mark.parametrize(
    "preflight",
    [
        None,
        {},
        {"degradations": [], "failures": None},
        {"degradations": [], "failures": [42]},
        {"degradations": [], "failures": [{"control": "guard"}]},
    ],
)
def test_invalid_preflight_provenance_cannot_qualify_engine_receipt(
    tmp_path: Path, preflight: object
) -> None:
    run_dir = tmp_path / "strix_runs" / "scan-1"
    run_dir.mkdir(parents=True)
    record = {
        "schema_version": "1.1",
        "run_id": "scan-1",
        "status": "completed",
        "phase": "completed",
        "sandbox_capabilities": {
            "schema": "lyrashield-sandbox-capabilities/1.0",
            "backend": "docker",
            "probed_at": "2026-11-04T00:00:00+00:00",
            "capabilities": {"exec": {"status": "supported"}},
            "preflight": {"degradations": [], "failures": []},
        },
    }
    (run_dir / "run.json").write_text(json.dumps(record))
    receipt = run.engine_run_receipt(tmp_path, "scan-1")
    assert engine_receipt_valid({"scanId": "scan-1", "runReceipt": receipt})
    record["sandbox_capabilities"]["preflight"] = preflight
    (run_dir / "run.json").write_text(json.dumps(record))
    receipt = run.engine_run_receipt(tmp_path, "scan-1")
    assert not engine_receipt_valid({"scanId": "scan-1", "runReceipt": receipt})


@pytest.mark.parametrize(
    "change",
    [
        {"schema": "other"},
        {"backend": ""},
        {"probedAt": "not-a-time"},
        {"probedAt": "2026-11-04T00:00:00"},
        {"statuses": {}},
        {"statuses": {"exec": "unknown"}},
        {"preflightDegradations": None},
        {"preflightFailures": ["guard"]},
    ],
)
def test_engine_receipt_rejects_each_invalid_capability_field(change: dict) -> None:
    caps = {
        "schema": "lyrashield-sandbox-capabilities/1.0",
        "backend": "docker",
        "probedAt": "2026-11-04T00:00:00+00:00",
        "statuses": {"exec": "supported"},
        "preflightDegradations": [],
        "preflightFailures": [],
    }
    receipt = {
        "schemaVersion": "1.1",
        "runId": "scan-1",
        "status": "completed",
        "phase": "completed",
        "sandboxCapabilities": caps,
    }
    run_record = {"scanId": "scan-1", "runReceipt": receipt}
    assert engine_receipt_valid(run_record)
    receipt["sandboxCapabilities"] = {**caps, **change}
    assert not engine_receipt_valid(run_record)


def test_scoring_requires_original_corpus_and_fixture_bytes(tmp_path: Path) -> None:
    corpus = {
        "name": "fixture",
        "revision": "v1",
        "pairs": [{"vulnerable": "bad.ts", "clean": "safe.ts"}],
    }
    (tmp_path / "corpus.json").write_text(json.dumps(corpus))
    (tmp_path / "bad.ts").write_text("bad()")
    (tmp_path / "safe.ts").write_text("safe()")
    manifest = {
        "corpus": "fixture",
        "corpusRevision": "v1",
        "corpusSha256": hashlib.sha256((tmp_path / "corpus.json").read_bytes()).hexdigest(),
        "fixtureSha256": {
            name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            for name in ("bad.ts", "safe.ts")
        },
    }
    assert corpus_matches_receipt(manifest, corpus, tmp_path)
    (tmp_path / "bad.ts").write_text("changed()")
    assert not corpus_matches_receipt(manifest, corpus, tmp_path)
