"""Offline regressions for benchmark evidence attribution and failure states."""

import hashlib
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks import run
from benchmarks.score import case_matches, corpus_matches_receipt, engine_stability, score


def test_marker_matching_does_not_credit_neighboring_case(tmp_path: Path) -> None:
    (tmp_path / "a.ts").write_text("bad() // CASE:A\nbad() // CASE:B\n")
    case = {"id": "B", "vulnerable": "a.ts"}
    finding = {"file": "a.ts", "startLine": 1, "id": "rule-absent"}
    assert not case_matches(case, finding, tmp_path, {})
    finding["startLine"] = 2
    assert case_matches(case, finding, tmp_path, {})
    finding["file"] = "not-a.ts"
    assert not case_matches(case, finding, tmp_path, {})


def test_stability_includes_zero_hit_runs() -> None:
    manifest = {"runs": [{"detector": "engine", "runIndex": i} for i in range(3)]}
    detected = {"A": [{"scanner": "engine", "runIndex": i} for i in range(2)]}
    assert engine_stability(manifest, detected) == 0


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
            {**records[0], "variant": "clean"},
            {"scanner": "sast", "error": "scanner failed"},
            {"level": "info", "message": "scanner startup", "variant": "clean"},
        ]
    )
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(rec) for rec in records))
    runs = [{"detector": "engine", "runIndex": i, "returncode": 0} for i in range(2)]
    runs.append({"detector": "engine", "variant": "clean", "returncode": 0})
    (tmp_path / "run-manifest.json").write_text(
        json.dumps({"harnessVersion": 2, "detectors": "engine", "runs": runs})
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
