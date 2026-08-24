"""Regression coverage for unchanged report artifact writes."""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING, Any

from agents.usage import Usage

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.artifacts.writer import write_vulnerabilities as write_vulnerabilities_original


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


def test_usage_only_resume_does_not_rewrite_report_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState(run_name="artifact-write-resume")
    state._run_dir = tmp_path
    assert state.save_run_data()

    resumed = ReportState(run_name="artifact-write-resume")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()

    vulnerability_writes = 0

    def count_vulnerability_write(*_args: object, **_kwargs: object) -> int:
        nonlocal vulnerability_writes
        vulnerability_writes += 1
        return 0

    monkeypatch.setattr(state_module, "write_vulnerabilities", count_vulnerability_write)
    resumed.record_sdk_usage(
        agent_id="agent-1",
        usage=Usage(requests=1, input_tokens=10, output_tokens=2, total_tokens=12),
        model="azure_ai/gpt-5.6-luna",
    )

    assert vulnerability_writes == 0


def test_concurrent_saves_leave_newest_report_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState(run_name="artifact-write-concurrent")
    state._run_dir = tmp_path
    state.vulnerability_reports = [
        {"id": "vuln-0001", "title": "Older", "severity": "low", "timestamp": "now"}
    ]
    state._report_artifacts_revision = 1

    older_write_started = threading.Event()
    release_older_write = threading.Event()
    write_count = 0

    def block_first_write(
        run_dir: Path,
        vulnerability_reports: list[dict[str, Any]],
        saved_vuln_ids: set[str],
    ) -> int:
        nonlocal write_count
        write_count += 1
        if write_count == 1:
            older_write_started.set()
            assert release_older_write.wait(timeout=5)
        return write_vulnerabilities_original(run_dir, vulnerability_reports, saved_vuln_ids)

    monkeypatch.setattr(state_module, "write_vulnerabilities", block_first_write)
    monkeypatch.setattr(state_module, "write_sarif", lambda *_args, **_kwargs: None)

    results: list[bool] = []
    older = threading.Thread(target=lambda: results.append(state.save_run_data()))
    older.start()
    assert older_write_started.wait(timeout=5)

    state.vulnerability_reports.append(
        {"id": "vuln-0002", "title": "Newer", "severity": "high", "timestamp": "now"}
    )
    state._report_artifacts_revision += 1
    newer = threading.Thread(target=lambda: results.append(state.save_run_data()))
    newer.start()
    release_older_write.set()
    older.join(timeout=5)
    newer.join(timeout=5)

    assert not older.is_alive()
    assert not newer.is_alive()
    assert results == [True, True]
    reports = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert [report["title"] for report in reports] == ["Older", "Newer"]
