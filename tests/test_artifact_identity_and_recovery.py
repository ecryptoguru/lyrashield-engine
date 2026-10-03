from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.artifacts.writer import (
    validate_finding_id,
)
from lyrashield.artifacts.writer import (
    write_vulnerabilities as write_vulnerabilities_original,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_finding_ids_skip_orphaned_markdown_artifacts(tmp_path: Path) -> None:
    (tmp_path / "vulnerabilities").mkdir()
    orphan = tmp_path / "vulnerabilities" / "vuln-0002.md"
    orphan.write_text("orphaned but retained\n", encoding="utf-8")
    state = ReportState(run_name="orphaned-finding")
    state._run_dir = tmp_path

    report_id = state.add_vulnerability_report(title="New finding", severity="high")

    assert report_id == "vuln-0003"
    assert orphan.read_text(encoding="utf-8") == "orphaned but retained\n"


@pytest.mark.parametrize("finding_id", ["vuln-0001", "vuln-10000", "vuln-99999999"])
def test_validate_finding_id_accepts_canonical_counters(finding_id: str) -> None:
    assert validate_finding_id(finding_id) == finding_id


@pytest.mark.parametrize(
    "finding_id",
    [
        "",
        "/tmp/vuln-0001",  # noqa: S108 - deliberately invalid path input
        r"C:\\temp\\vuln-0001",
        r"..\\vuln-0001",
        "vuln-12",
        "vuln-0001.md",
    ],
)
def test_validate_finding_id_rejects_paths_and_noncanonical_ids(finding_id: str) -> None:
    with pytest.raises(ValueError, match="canonical finding ID"):
        validate_finding_id(finding_id)


def test_hydration_rejects_duplicate_finding_ids(tmp_path: Path) -> None:
    state = ReportState(run_name="duplicate-finding")
    state._run_dir = tmp_path
    assert state.save_run_data()
    record = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {"id": "vuln-0001", "title": "First", "severity": "low"},
                {"id": "vuln-0001", "title": "Second", "severity": "high"},
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "run.json").write_text(json.dumps(record), encoding="utf-8")
    resumed = ReportState(run_name="duplicate-finding")
    resumed._run_dir = tmp_path

    with pytest.raises(RuntimeError, match="duplicate finding id"):
        resumed.hydrate_from_run_dir()


def test_hydration_rejects_traversal_finding_id_before_state_mutation(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state = ReportState(run_name="traversal-finding")
    state._run_dir = run_dir
    state.add_vulnerability_report(title="Original", severity="high")

    vuln_path = run_dir / "vulnerabilities.json"
    reports = json.loads(vuln_path.read_text(encoding="utf-8"))
    reports[0]["id"] = "../../outside"
    vuln_path.write_text(json.dumps(reports), encoding="utf-8")
    record_path = run_dir / "run.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record.pop("result_manifest", None)
    record_path.write_text(json.dumps(record), encoding="utf-8")

    resumed = ReportState(run_name="traversal-finding")
    resumed._run_dir = run_dir
    prior_report = {"id": "in-memory", "title": "Keep me", "severity": "low"}
    resumed.vulnerability_reports = [prior_report]
    resumed.run_record["preserve_on_failure"] = True

    with pytest.raises(RuntimeError, match="invalid finding id"):
        resumed.hydrate_from_run_dir()

    assert resumed.vulnerability_reports == [prior_report]
    assert resumed.run_record["preserve_on_failure"] is True
    assert not (tmp_path / "outside.md").exists()


def test_writer_rejects_traversal_finding_id_before_path_creation(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside_path = tmp_path / "outside.md"
    report = {
        "id": "../../outside",
        "title": "Traversal",
        "severity": "high",
        "timestamp": "2026-10-02 00:00:00 UTC",
    }

    with pytest.raises(ValueError, match="canonical finding ID"):
        write_vulnerabilities_original(run_dir, [report], set())

    assert not outside_path.exists()


@pytest.mark.parametrize("damage", ["tampered", "missing", "invalid_manifest_version"])
def test_manifest_failure_preserves_existing_resumable_state(
    damage: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    state = ReportState(run_name=f"manifest-{damage}")
    state._run_dir = tmp_path
    state.add_vulnerability_report(title="Trusted finding", severity="high")
    run_dir = state.get_run_dir()
    vulnerability_path = run_dir / "vulnerabilities.json"
    if damage == "tampered":
        payload = json.loads(vulnerability_path.read_text(encoding="utf-8"))
        payload[0]["title"] = "Tampered finding"
        vulnerability_path.write_text(json.dumps(payload), encoding="utf-8")
    elif damage == "missing":
        vulnerability_path.unlink()
    else:
        record_path = run_dir / "run.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["result_manifest"]["schema_version"] = True
        record_path.write_text(json.dumps(record), encoding="utf-8")

    resumed = ReportState(run_name=f"manifest-{damage}")
    resumed._run_dir = tmp_path
    prior_report = {"id": "in-memory", "title": "Keep me", "severity": "low"}
    resumed.vulnerability_reports = [prior_report]
    resumed.run_record["preserve_on_failure"] = True

    with pytest.raises(RuntimeError, match="result manifest"):
        resumed.hydrate_from_run_dir()

    assert resumed.vulnerability_reports == [prior_report]
    assert resumed.run_record["preserve_on_failure"] is True


def test_legacy_run_without_manifest_remains_resumable(tmp_path: Path) -> None:
    state = ReportState(run_name="legacy-manifest")
    state._run_dir = tmp_path
    report_id = state.add_vulnerability_report(title="Legacy finding", severity="low")
    record = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert "result_manifest" not in record

    resumed = ReportState(run_name="legacy-manifest")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()

    assert resumed.vulnerability_reports[0]["id"] == report_id


def test_revision_write_failure_restores_previous_artifact_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    state = ReportState(run_name="revision-rollback")
    state._run_dir = tmp_path
    report_id = state.add_vulnerability_report(title="Original title", severity="medium")
    run_dir = state.get_run_dir()
    tracked = [
        run_dir / "run.json",
        run_dir / "vulnerabilities.json",
        run_dir / "vulnerabilities.csv",
        run_dir / "findings.sarif",
        run_dir / "vulnerabilities" / f"{report_id}.md",
    ]
    prior_bytes = {path: path.read_bytes() for path in tracked if path.exists()}

    def write_then_fail(
        run_dir_arg: Path,
        reports: list[dict[str, Any]],
        saved_vuln_ids: set[str],
    ) -> int:
        write_vulnerabilities_original(run_dir_arg, reports, saved_vuln_ids)
        raise RuntimeError("injected failure after artifact replacement")

    monkeypatch.setattr(state_module, "write_vulnerabilities", write_then_fail)
    with pytest.raises(RuntimeError, match="injected failure"):
        state.update_vulnerability_report(report_id, {"title": "Revised title"})

    assert state.vulnerability_reports[0]["title"] == "Original title"
    assert {path: path.read_bytes() for path in prior_bytes} == prior_bytes
    persisted = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert persisted[0]["title"] == "Original title"


def test_add_report_unexpected_projection_error_restores_prior_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = ReportState(run_name="unexpected-projection-rollback")
    state._run_dir = tmp_path
    state.add_vulnerability_report(title="Original title", severity="medium")
    run_dir = state.get_run_dir()
    tracked = [
        run_dir / "run.json",
        run_dir / "resume.json",
        run_dir / "vulnerabilities.json",
        run_dir / "vulnerabilities.csv",
        run_dir / "findings.sarif",
        run_dir / "vulnerabilities" / "vuln-0001.md",
        run_dir / "vulnerabilities" / "vuln-0002.md",
    ]
    prior_bytes = {path: path.read_bytes() if path.exists() else None for path in tracked}
    prior_reports = copy.deepcopy(state.vulnerability_reports)
    prior_saved_ids = set(state._saved_vuln_ids)
    prior_revision = state._report_artifacts_revision
    prior_persisted_revision = state._persisted_report_artifacts_revision
    prior_record = copy.deepcopy(state.run_record)
    prior_save_seq = state._save_seq

    def write_then_raise_value_error(
        run_dir_arg: Path,
        reports: list[dict[str, Any]],
        saved_vuln_ids: set[str],
    ) -> int:
        write_vulnerabilities_original(run_dir_arg, reports, saved_vuln_ids)
        raise ValueError("injected non-I/O projection failure")

    monkeypatch.setattr(state_module, "write_vulnerabilities", write_then_raise_value_error)
    with pytest.raises(ValueError, match="injected non-I/O projection failure"):
        state.add_vulnerability_report(title="Uncommitted title", severity="high")

    assert state.vulnerability_reports == prior_reports
    assert state._saved_vuln_ids == prior_saved_ids
    assert state._report_artifacts_revision == prior_revision
    assert state._persisted_report_artifacts_revision == prior_persisted_revision
    assert state.run_record == prior_record
    assert state._save_seq == prior_save_seq
    assert {path: path.read_bytes() if path.exists() else None for path in tracked} == prior_bytes
