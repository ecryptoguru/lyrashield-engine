"""Regression coverage for unchanged report artifact writes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agents.usage import Usage

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_usage_only_save_does_not_rewrite_unchanged_report_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState(run_name="artifact-write-dedupe")
    state._run_dir = tmp_path

    vulnerability_writes = 0
    sarif_writes = 0

    def count_vulnerability_write(*_args: object, **_kwargs: object) -> int:
        nonlocal vulnerability_writes
        vulnerability_writes += 1
        return 0

    def count_sarif_write(*_args: object, **_kwargs: object) -> None:
        nonlocal sarif_writes
        sarif_writes += 1

    monkeypatch.setattr(state_module, "write_vulnerabilities", count_vulnerability_write)
    monkeypatch.setattr(state_module, "write_sarif", count_sarif_write)

    assert state.save_run_data()
    first_seq = state.run_record["seq"]
    state.record_sdk_usage(
        agent_id="agent-1",
        usage=Usage(requests=1, input_tokens=10, output_tokens=2, total_tokens=12),
        model="azure_ai/gpt-5.6-luna",
    )

    assert vulnerability_writes == 1
    assert sarif_writes == 1
    assert state.run_record["seq"] == first_seq + 1
    assert state.run_record["llm_usage"]["requests"] == 1


def test_new_finding_rewrites_report_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState(run_name="artifact-write-new-finding")
    state._run_dir = tmp_path

    vulnerability_writes = 0

    def count_vulnerability_write(*_args: object, **_kwargs: object) -> int:
        nonlocal vulnerability_writes
        vulnerability_writes += 1
        return 0

    monkeypatch.setattr(state_module, "write_vulnerabilities", count_vulnerability_write)

    assert state.save_run_data()
    state.add_vulnerability_report(title="SQL injection", severity="high")

    assert vulnerability_writes == 2
