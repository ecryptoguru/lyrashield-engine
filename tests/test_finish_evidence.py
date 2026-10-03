"""Finishing preserves inconclusive assessment and requires durable evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.tools.finish.tool import _do_finish


if TYPE_CHECKING:
    from pathlib import Path


def _finish(*, agent_graph: dict[str, object] | None = None) -> dict[str, object]:
    return _do_finish(
        parent_id=None,
        executive_summary="# Executive Summary\nAssessment complete.",
        methodology="# Methodology\nReviewed the in-scope application.",
        technical_analysis="# Technical Analysis\nNo confirmed findings were filed.",
        recommendations="# Recommendations\nRetest after remediation.",
        agent_graph=agent_graph,
    )


@pytest.fixture
def finish_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    state = ReportState(run_name="finish-evidence")
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: state)
    return state


def test_zero_findings_finish_is_reported_as_inconclusive(finish_state: ReportState) -> None:
    result = _finish(
        agent_graph={"statuses": {"root": "running"}, "parent_of": {"root": None}},
    )

    assert result["success"] is True
    assert result["assessment"] == "inconclusive"
    assert "no_findings_recorded" in result["assessment_reasons"]
    assert "does not demonstrate that the target is secure" in (
        finish_state.run_record["scan_results"]["executive_summary"].lower()
    )
    coverage = finish_state.get_run_dir() / "coverage.json"
    assert '"scan_status": "completed"' in coverage.read_text(encoding="utf-8")


def test_finish_refuses_to_claim_success_when_final_coverage_is_corrupted(
    finish_state: ReportState,
) -> None:
    original_update = finish_state.update_scan_final_fields

    def update_then_corrupt_coverage(*args: object, **kwargs: object) -> None:
        original_update(*args, **kwargs)
        coverage_path = finish_state.get_run_dir() / "coverage.json"
        coverage_path.write_text('{"run_id":"different-run"}', encoding="utf-8")

    finish_state.update_scan_final_fields = update_then_corrupt_coverage  # type: ignore[method-assign]

    result = _finish()

    assert result["success"] is False
    assert result["scan_completed"] is False
    assert result["assessment"] == "inconclusive"
    assert "final_evidence_not_persisted" in result["assessment_reasons"]
    assert finish_state.run_record["status"] == "running"
    assert finish_state.run_record["scan_results"]["scan_completed"] is False
