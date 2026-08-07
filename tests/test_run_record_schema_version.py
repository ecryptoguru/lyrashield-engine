"""run.json carries an explicit, well-formed schema version.

run.json is a cross-repo contract: the LyraShield worker parses it to decide a
scan's terminal status, cost, and coverage. Pinning the version here means a
change to the contract has to be a deliberate edit to this test, not an
accidental side effect of editing the record shape.
"""

from __future__ import annotations

import re

from strix.report.state import RUN_RECORD_SCHEMA_VERSION, ReportState


def test_schema_version_is_major_minor() -> None:
    assert re.fullmatch(r"\d+\.\d+", RUN_RECORD_SCHEMA_VERSION), (
        "RUN_RECORD_SCHEMA_VERSION must be MAJOR.MINOR so consumers can compare it"
    )


def test_schema_version_is_pinned() -> None:
    # Bump deliberately: MAJOR for a breaking change, MINOR for additive fields.
    assert RUN_RECORD_SCHEMA_VERSION == "1.0"


def test_new_run_record_declares_its_schema_version() -> None:
    state = ReportState(run_name="schema-version-probe")
    assert state.run_record["schema_version"] == RUN_RECORD_SCHEMA_VERSION


def test_schema_version_survives_phase_and_progress_updates() -> None:
    # The worker may read run.json at any point in the run, not just at the end,
    # so the version must not be dropped by an in-flight record mutation.
    state = ReportState(run_name="schema-version-phase")
    state._set_phase("running")
    state._sync_progress()
    assert state.run_record["schema_version"] == RUN_RECORD_SCHEMA_VERSION
    assert state.run_record["phase"] == "running"
