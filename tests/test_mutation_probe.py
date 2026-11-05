"""Mutation harness safety and coverage contracts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from benchmarks import mutation_probe
from benchmarks.mutation_probe import SPEC_PATH, apply_replacement


REQUIRED_GATES = {
    "authorization",
    "workspace_scope",
    "gate_identity",
    "evidence_scope",
    "cleanup_unknown",
    "billing_cap_replay",
    "cache_identity",
    "report_signature",
    "analytics_privacy",
}


def test_mutation_manifest_covers_every_required_gate() -> None:
    record = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    assert {probe["gate"] for probe in record["probes"]} == REQUIRED_GATES
    assert all(probe["expectedFailureText"] for probe in record["probes"])


def test_replacement_requires_exactly_one_match(tmp_path) -> None:
    source = tmp_path / "source.py"
    source.write_text("safe = True\n", encoding="utf-8")
    apply_replacement(source, "safe = True", "safe = False")
    assert source.read_text() == "safe = False\n"
    source.write_text("duplicate = 1\nduplicate = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="found 2"):
        apply_replacement(source, "duplicate = 1", "duplicate = 2")


def test_mutation_probe_reports_cleanup_failure_after_a_killed_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = "safe = True\n"

    def fake_git(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["worktree", "add"]:
            worktree = Path(args[3])
            worktree.mkdir(parents=True)
            (worktree / "source.py").write_text(original, encoding="utf-8")
        elif args[:1] == ["checkout"]:
            (cwd / "source.py").write_text(original, encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(mutation_probe, "_git", fake_git)
    monkeypatch.setattr(
        mutation_probe,
        "_run_test",
        lambda *_args, **_kwargs: {"returncode": 0, "stdoutTail": "", "stderrTail": ""},
    )
    monkeypatch.setattr(
        mutation_probe, "_cleanup_worktree", lambda *_args: "simulated cleanup failure"
    )

    result = mutation_probe.run_probe(
        {
            "id": "fixture",
            "gate": "cleanup_unknown",
            "sourcePath": "source.py",
            "old": "safe = True",
            "new": "safe = False",
            "test": ["tests/test_fixture.py::test_fixture"],
            "expectedFailureText": "test_fixture",
            "requirement": "fixture",
        },
        timeout=1,
    )

    assert result["status"] == "FAIL"
    assert result["cleanupError"] == "simulated cleanup failure"


def test_mutation_probe_rejects_source_paths_outside_the_isolated_worktree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_git(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["worktree", "add"]:
            worktree = Path(args[3])
            worktree.mkdir(parents=True)
            (worktree.parent / "outside.py").write_text("safe = True\n", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(mutation_probe, "_git", fake_git)
    monkeypatch.setattr(
        mutation_probe,
        "_run_test",
        lambda *_args, **_kwargs: {"returncode": 0, "stdoutTail": "", "stderrTail": ""},
    )
    monkeypatch.setattr(mutation_probe, "_cleanup_worktree", lambda *_args: None)

    result = mutation_probe.run_probe(
        {
            "id": "outside",
            "gate": "workspace_scope",
            "sourcePath": "../outside.py",
            "old": "safe = True",
            "new": "safe = False",
            "test": ["tests/test_fixture.py::test_fixture"],
            "expectedFailureText": "test_fixture",
            "requirement": "fixture",
        },
        timeout=1,
    )

    assert result["status"] == "ERROR"
    assert "inside the isolated worktree" in result["error"]
