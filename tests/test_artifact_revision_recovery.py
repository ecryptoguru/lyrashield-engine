"""Caught write failures cannot publish a partial finding revision."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts import state_findings
from lyrashield.artifacts.state import ReportState
from lyrashield.tools.proxy import caido_api
from lyrashield.tools.reporting.tool import _do_create


if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture
def revision_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    state = ReportState(run_name="revision-recovery")
    state._run_dir = tmp_path
    assert (
        state.add_vulnerability_report(
            "SQL injection in login",
            "high",
            target="https://example.com",
            endpoint="/login",
            method="GET",
            cwe="CWE-89",
            evidence="Original evidence",
        )
        == "vuln-0001"
    )
    return state


def _durable_bytes(run_dir: Path) -> dict[Path, bytes]:
    return {p.relative_to(run_dir): p.read_bytes() for p in run_dir.rglob("*") if p.is_file()}


def _inject_replacement_failure(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    *,
    after_replace: bool = True,
    occurrence: int = 1,
) -> Callable[[], bool]:
    replace = Path.replace
    injected = False
    replacements = 0

    def fail_after_replace(source: Path, target: Path | str) -> Path:
        nonlocal injected, replacements
        if Path(target).name == filename:
            replacements += 1
        if Path(target).name == filename and replacements == occurrence and not injected:
            injected = True
            if after_replace:
                replace(source, target)
            raise OSError(f"injected {filename} replacement failure")
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_after_replace)
    return lambda: injected


@pytest.mark.asyncio
async def test_new_finding_receipt_failure_restores_prior_evidence_and_public_retry(
    revision_state: ReportState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", revision_state)
    before = _durable_bytes(tmp_path)
    original = copy.deepcopy(revision_state.vulnerability_reports)
    write_run_record = state_module.write_run_record
    injected = False
    observed_ids: list[str] = []

    def fail_after_projections(run_dir: Path, record: dict[str, Any]) -> None:
        nonlocal injected
        if not injected:
            injected = True
            observed_ids.extend(
                finding["id"]
                for finding in json.loads((run_dir / "vulnerabilities.json").read_text())
            )
            assert (run_dir / "vulnerabilities" / "vuln-0002.md").is_file()
            assert "New independent finding" in (run_dir / "vulnerabilities.csv").read_text()
            assert "New independent finding" in (run_dir / "findings.sarif").read_text()
            raise OSError("receipt failed after candidate projections were replaced")
        write_run_record(run_dir, record)

    monkeypatch.setattr(state_module, "write_run_record", fail_after_projections)
    fields: dict[str, Any] = {
        "title": "New independent finding",
        "description": "Candidate evidence",
        "impact": "Account access",
        "target": "https://example.com",
        "technical_analysis": "Independent root cause",
        "poc_description": "Request this endpoint",
        "poc_script_code": "GET /independent",
        "remediation_steps": "Validate authorization",
        "evidence": "Observed independent evidence",
        "assumptions": "Accessible endpoint",
        "fix_effort": "LOW",
        "cvss_breakdown": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "endpoint": "/independent",
        "method": "GET",
        "cwe": "CWE-862",
        "cve": None,
        "code_locations": None,
    }

    failed = await _do_create(**fields)

    assert injected
    assert observed_ids == ["vuln-0001", "vuln-0002"]
    assert failed["success"] is False
    assert revision_state.vulnerability_reports == original
    assert _durable_bytes(tmp_path) == before
    assert revision_state.save_run_data()
    assert json.loads((tmp_path / "vulnerabilities.json").read_text()) == json.loads(
        before[Path("vulnerabilities.json")]
    )

    retried = await _do_create(**fields)

    assert retried["success"] is True
    records = json.loads((tmp_path / "vulnerabilities.json").read_text())
    assert len(records) == 2
    candidate = next(record for record in records if record["title"] == fields["title"])
    assert candidate["id"] == retried["report_id"]
    assert candidate["evidence"] == fields["evidence"]
    assert {path.stem for path in (tmp_path / "vulnerabilities").glob("*.md")} == {
        record["id"] for record in records
    }
    assert fields["title"] in (tmp_path / "vulnerabilities" / f"{candidate['id']}.md").read_text()
    assert fields["title"] in (tmp_path / "vulnerabilities.csv").read_text()
    sarif_results = json.loads((tmp_path / "findings.sarif").read_text())["runs"][0]["results"]
    assert len(sarif_results) == 2
    receipt = json.loads((tmp_path / "run.json").read_text())
    assert receipt["receipt_persisted"] is True
    assert receipt["report_artifacts_revision"] == revision_state._report_artifacts_revision
    resumed = ReportState(run_name="revision-recovery")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()
    assert resumed.vulnerability_reports == records
    assert resumed.run_record["report_artifacts_revision"] == receipt["report_artifacts_revision"]


@pytest.mark.parametrize(
    "filename",
    [
        "vuln-0001.md",
        "vulnerabilities.csv",
        "vulnerabilities.json",
        "findings.sarif",
        "run.json",
    ],
)
@pytest.mark.parametrize("after_replace", [False, True])
def test_failed_revision_restores_all_prior_bytes_and_resumes_original(
    revision_state: ReportState,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    after_replace: bool,
) -> None:
    before = _durable_bytes(tmp_path)
    original = copy.deepcopy(revision_state.vulnerability_reports)
    injected = _inject_replacement_failure(monkeypatch, filename, after_replace=after_replace)
    with pytest.raises((OSError, RuntimeError)):
        revision_state.update_vulnerability_report(
            "vuln-0001",
            {"title": "Revised SQL injection", "severity": "low", "evidence": "New evidence"},
            update_reason="Independent validation",
        )
    assert injected()
    assert revision_state.vulnerability_reports == original
    assert _durable_bytes(tmp_path) == before

    resumed = ReportState(run_name="revision-recovery")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()
    assert resumed.vulnerability_reports == json.loads(before[Path("vulnerabilities.json")])
    assert (
        resumed.run_record["report_artifacts_revision"]
        == json.loads(before[Path("run.json")])["report_artifacts_revision"]
    )


@pytest.mark.parametrize(
    "filename",
    [
        "vuln-0001.md",
        "vulnerabilities.csv",
        "vulnerabilities.json",
        "findings.sarif",
        "run.json",
    ],
)
def test_save_and_revision_retry_do_not_skip_restored_finding_projections(
    revision_state: ReportState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    _inject_replacement_failure(monkeypatch, filename)
    with pytest.raises((OSError, RuntimeError)):
        revision_state.update_vulnerability_report("vuln-0001", {"title": "Revised SQL injection"})

    assert revision_state.save_run_data()
    assert "# SQL injection in login" in (tmp_path / "vulnerabilities" / "vuln-0001.md").read_text()
    assert (
        json.loads((tmp_path / "vulnerabilities.json").read_text())[0]["title"]
        == "SQL injection in login"
    )
    revised = revision_state.update_vulnerability_report(
        "vuln-0001",
        {"title": "Revised SQL injection"},
        update_reason="Retry validation",
    )
    assert revised is not None
    assert revised["title"] == "Revised SQL injection"
    assert len(revised["update_history"]) == 1
    assert "# Revised SQL injection" in (tmp_path / "vulnerabilities" / "vuln-0001.md").read_text()
    assert "Revised SQL injection" in (tmp_path / "vulnerabilities.csv").read_text()
    assert (
        json.loads((tmp_path / "vulnerabilities.json").read_text())[0]["title"]
        == "Revised SQL injection"
    )
    assert "Revised SQL injection" in (tmp_path / "findings.sarif").read_text()
    run_record: dict[str, Any] = json.loads((tmp_path / "run.json").read_text())
    assert run_record["report_artifacts_revision"] == revision_state._report_artifacts_revision
    resumed = ReportState(run_name="revision-recovery")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()
    persisted_findings = json.loads((tmp_path / "vulnerabilities.json").read_text())
    assert resumed.vulnerability_reports == persisted_findings
    assert resumed.vulnerability_reports[0]["update_history"] == revised["update_history"]


def test_blocked_rollback_fails_loudly_and_later_save_repairs_original(
    revision_state: ReportState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replace = Path.replace
    blocked = True

    def blocked_markdown_replace(source: Path, target: Path | str) -> Path:
        result = replace(source, target)
        if blocked and Path(target).name == "vuln-0001.md":
            raise OSError("filesystem remains unavailable")
        return result

    monkeypatch.setattr(Path, "replace", blocked_markdown_replace)
    with pytest.raises(RuntimeError, match=r"recovery.*failed"):
        revision_state.update_vulnerability_report("vuln-0001", {"title": "Revised SQL injection"})
    assert revision_state.receipt_persisted is False
    blocked = False
    assert revision_state.save_run_data()
    assert "# SQL injection in login" in (tmp_path / "vulnerabilities" / "vuln-0001.md").read_text()
    assert (
        json.loads((tmp_path / "vulnerabilities.json").read_text())[0]["title"]
        == "SQL injection in login"
    )


def test_failed_revision_invalidates_ids_created_while_repairing_missing_markdown(
    revision_state: ReportState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    second_id = revision_state.add_vulnerability_report("Second original finding", "medium")
    second_markdown = tmp_path / "vulnerabilities" / f"{second_id}.md"
    second_markdown.unlink()
    revision_state._saved_vuln_ids.discard(second_id)
    _inject_replacement_failure(monkeypatch, "run.json")
    with pytest.raises(RuntimeError):
        revision_state.update_vulnerability_report("vuln-0001", {"title": "Revised SQL injection"})
    assert not second_markdown.exists()
    assert revision_state.save_run_data()
    assert "# Second original finding" in second_markdown.read_text()


def test_run_record_failure_restores_prior_revision_after_single_projection_write(
    revision_state: ReportState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = _durable_bytes(tmp_path)
    _inject_replacement_failure(monkeypatch, "run.json")
    with pytest.raises(RuntimeError):
        revision_state.update_vulnerability_report("vuln-0001", {"title": "Revised SQL injection"})
    assert _durable_bytes(tmp_path) == before
    assert revision_state.vulnerability_reports[0]["title"] == "SQL injection in login"


def test_failed_revision_preserves_scope_cursor_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    decisions: dict[str, Any] = {"violations": [], "dropped": 0, "admitted_hosts": {}}
    monkeypatch.setattr(caido_api, "get_scope_decisions", lambda: decisions)
    state = ReportState(run_name="scope-revision-recovery")
    state._run_dir = tmp_path
    state.add_vulnerability_report("Original scope finding", "high")
    before = _durable_bytes(tmp_path)
    denial = {"host": "denied.example", "reason": "outside_scope"}
    decisions["violations"] = [denial]
    decisions["dropped"] = 2
    _inject_replacement_failure(monkeypatch, "run.json")

    with pytest.raises(RuntimeError):
        state.update_vulnerability_report("vuln-0001", {"title": "Revised scope finding"})

    assert _durable_bytes(tmp_path) == before
    assert state._scope_violations_seen == 0
    assert state._scope_dropped_seen == 0
    assert state.save_run_data()
    saved = json.loads((tmp_path / "run.json").read_text())["scope_violations"]
    assert saved == {"entries": [denial], "dropped": 2, "total": 3}
    assert state.save_run_data()
    assert json.loads((tmp_path / "run.json").read_text())["scope_violations"] == saved
    resumed = ReportState(run_name="scope-revision-recovery")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()
    assert resumed.run_record["scope_violations"] == saved


@pytest.mark.parametrize("error_type", [ValueError, TypeError])
@pytest.mark.parametrize("filename", ["vulnerabilities.json"])
def test_ordinary_persistence_exception_restores_prior_bytes_and_retry(
    revision_state: ReportState,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    filename: str,
) -> None:
    before = _durable_bytes(tmp_path)
    original = copy.deepcopy(revision_state.vulnerability_reports)
    replace = Path.replace
    error = error_type("ordinary persistence failure")
    injected = False

    def replace_then_fail(source: Path, target: Path | str) -> Path:
        nonlocal injected
        result = replace(source, target)
        if Path(target).name == filename and not injected:
            injected = True
            raise error
        return result

    monkeypatch.setattr(Path, "replace", replace_then_fail)
    with pytest.raises(error_type) as caught:
        revision_state.update_vulnerability_report("vuln-0001", {"title": "Revised SQL injection"})
    assert caught.value is error
    assert injected
    assert revision_state.vulnerability_reports == original
    assert _durable_bytes(tmp_path) == before
    assert revision_state.save_run_data()
    revised = revision_state.update_vulnerability_report(
        "vuln-0001", {"title": "Revised SQL injection"}
    )
    assert revised is not None
    assert len(revised["update_history"]) == 1
    resumed = ReportState(run_name="revision-recovery")
    resumed._run_dir = tmp_path
    resumed.hydrate_from_run_dir()
    assert resumed.vulnerability_reports == json.loads(
        (tmp_path / "vulnerabilities.json").read_text()
    )


def test_finding_revision_does_not_rewrite_private_resume_state(
    revision_state: ReportState,
    tmp_path: Path,
) -> None:
    resume_path = tmp_path / "resume.json"
    before_resume = resume_path.read_bytes()
    # POSIX filename decoding can produce surrogateescaped host paths. These
    # are retained only in the private resume record. A finding revision does
    # not change that record and should not need to serialize it again.
    revision_state._raw_local_sources = [{"source_path": str(tmp_path / chr(0xDCFF))}]

    revised = revision_state.update_vulnerability_report(
        "vuln-0001", {"title": "Revised SQL injection"}
    )

    assert revised is not None
    assert revision_state.vulnerability_reports[0]["title"] == "Revised SQL injection"
    assert resume_path.read_bytes() == before_resume
    assert not list(tmp_path.rglob("*.tmp"))


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, asyncio.CancelledError])
def test_base_exception_propagates_without_revision_recovery(
    revision_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    error = error_type("interrupt revision")
    recovered = False

    def interrupt(*_args: Any, **_kwargs: Any) -> None:
        raise error

    def observe_recovery(*_args: Any, **_kwargs: Any) -> None:
        nonlocal recovered
        recovered = True

    monkeypatch.setattr(revision_state, "save_run_data", interrupt)
    monkeypatch.setattr(state_findings, "restore_revision_artifacts", observe_recovery)
    with pytest.raises(error_type) as caught:
        revision_state.update_vulnerability_report("vuln-0001", {"title": "Revised SQL injection"})
    assert caught.value is error
    assert recovered is False
