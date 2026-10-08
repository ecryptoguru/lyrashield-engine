"""The engine must look up its own distribution name and never raise without it.

Regression: the three legacy call sites used ``strix-agent``, a distribution
that does not exist in any build of this project, so the SARIF
``tool.driver.version`` field was silently omitted and the TUI header fell back
to ``dev``. The helper must also survive a frozen build where no distribution
metadata exists at all.
"""

from __future__ import annotations

import importlib.metadata
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest

from lyrashield.artifacts.state import ReportState, set_global_report_state
from lyrashield.version import DISTRIBUTION_NAME, engine_version


if TYPE_CHECKING:
    from pathlib import Path


def _finding() -> dict[str, Any]:
    return {
        "id": "vuln-0001",
        "title": "SQL Injection in get_user",
        "severity": "critical",
        "cwe": "CWE-89",
        "timestamp": "2026-07-02 10:00:00 UTC",
        "code_locations": [{"file": "app.py", "start_line": 4}],
    }


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


def test_distribution_name_is_the_project_name() -> None:
    assert DISTRIBUTION_NAME == "lyrashield-engine"


def test_installed_build_reports_a_concrete_version() -> None:
    # The repo .venv installs this project, so the helper must resolve a value
    # here. A None result means the distribution name is wrong again.
    assert engine_version() is not None


def test_sarif_write_path_emits_tool_driver_version(report_state: ReportState) -> None:
    """The real projection path must put a version in SARIF tool.driver.

    ``tests/test_sarif.py`` passes ``tool_version`` explicitly, so it cannot
    catch a broken lookup. This drives the production call chain instead:
    ``ReportState._write_report_projections`` resolves the version itself.
    """
    assert report_state._write_report_projections([_finding()], set()) is True

    document = json.loads(
        (report_state.get_run_dir() / "findings.sarif").read_text(encoding="utf-8")
    )
    driver = document["runs"][0]["tool"]["driver"]
    assert driver["name"] == "LyraShield"
    assert driver["version"] == engine_version()
    assert driver["version"] is not None


def test_sarif_write_path_still_omits_version_when_metadata_is_absent(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A frozen build has no metadata; the field is omitted rather than faked."""
    monkeypatch.setattr("lyrashield.version.version", Mock(return_value=None))

    assert report_state._write_report_projections([_finding()], set()) is True
    document = json.loads(
        (report_state.get_run_dir() / "findings.sarif").read_text(encoding="utf-8")
    )
    assert "version" not in document["runs"][0]["tool"]["driver"]


def test_engine_version_falls_back_when_distribution_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frozen and uninstalled builds must not raise."""

    def _raise(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr("lyrashield.version.version", _raise)

    assert engine_version() is None


def test_engine_version_survives_a_broken_metadata_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frozen loaders can fail with something other than PackageNotFoundError."""

    def _raise(_name: str) -> str:
        raise ValueError("no metadata in frozen build")

    monkeypatch.setattr("lyrashield.version.version", _raise)

    assert engine_version() is None
