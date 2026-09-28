from __future__ import annotations

from lyrashield.artifacts import repo_context, state_findings, state_persistence, state_projection
from lyrashield.artifacts import state as state_module


def test_report_state_split_modules_keep_the_legacy_facade() -> None:
    assert state_module.sanitize_finding is state_findings.sanitize_finding
    assert state_module.ReportState.add_vulnerability_report is (
        state_findings.add_vulnerability_report
    )
    assert state_module.ReportState.update_vulnerability_report is (
        state_findings.update_vulnerability_report
    )
    assert state_module.initial_run_record is state_persistence.initial_run_record
    assert state_module.validate_run_record is state_persistence.validate_run_record
    assert state_module._parse_repo_full_name is repo_context.parse_repo_full_name
    assert state_module.sanitize_targets_info is state_projection.sanitize_targets_info
