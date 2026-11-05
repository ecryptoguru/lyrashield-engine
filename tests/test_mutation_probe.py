"""Mutation harness safety and coverage contracts."""

from __future__ import annotations

import json

import pytest

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
