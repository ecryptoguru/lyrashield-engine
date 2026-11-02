"""Owned CLI behavior in pipes, resume selection, and opt-in finding gates."""

from __future__ import annotations

import sys
from importlib import import_module
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from lyrashield.agents.prompt import render_system_prompt
from lyrashield.interface import arg_parser
from lyrashield_adapter.cli import _register_lyrashield_skills
from tests.test_finish_gate_provenance import finish_run_result


if TYPE_CHECKING:
    from pathlib import Path


main_module = import_module("lyrashield.interface.main")


def test_no_terminal_automatically_selects_headless(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["lyrashield", "-t", "https://example.test"])
    monkeypatch.setattr(arg_parser, "terminal_attached", lambda: False, raising=False)
    assert arg_parser.parse_arguments().non_interactive is True


@pytest.mark.parametrize(
    "reason",
    ["runtime_deadline", "engine_stopped", "budget_exceeded", "rate_limited", "incomplete"],
)
def test_threshold_cannot_turn_incomplete_scan_green(reason: str) -> None:
    state = SimpleNamespace(
        run_record={"status": "stopped", "terminal_reason": reason},
        vulnerability_reports=[{"severity": "low"}],
    )
    assert main_module._non_interactive_exit_code(state, fail_on="high") != 0


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("critical", 2),
        ("HIGH", 2),
        ("medium", 0),
        ("info", 0),
        ("none", 0),
        ("unknown", 2),
        (None, 2),
    ],
)
def test_opt_in_threshold_only_changes_completed_finding_exit(
    severity: str | None, expected: int
) -> None:
    state = SimpleNamespace(
        run_record={"status": "completed"}, vulnerability_reports=[{"severity": severity}]
    )
    qualified = {
        "success": True,
        "scan_completed": True,
        "coverage_complete": True,
        "assessment_reasons": [],
    }
    assert (
        main_module._non_interactive_exit_code(
            state, fail_on="high", finish_result=finish_run_result(qualified)
        )
        == expected
    )
    assert main_module._non_interactive_exit_code(state) == 2


def test_resume_picker_cancellation_stops_before_loading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["lyrashield", "-r"])
    monkeypatch.setattr(arg_parser, "terminal_attached", lambda: True, raising=False)
    picker = Mock(return_value=None)
    loader = Mock(side_effect=AssertionError("cancel must not load"))
    monkeypatch.setattr(arg_parser, "pick_run", picker, raising=False)
    monkeypatch.setattr(arg_parser, "_load_resume_state", loader)
    with pytest.raises(SystemExit) as exc:
        arg_parser.parse_arguments()
    assert exc.value.code == 0
    picker.assert_called_once()


def test_bare_resume_without_terminal_has_actionable_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["lyrashield", "-r"])
    monkeypatch.setattr(arg_parser, "terminal_attached", lambda: False, raising=False)
    with pytest.raises(SystemExit) as exc:
        arg_parser.parse_arguments()
    assert exc.value.code == 2
    assert "--resume <run_name>" in capsys.readouterr().err


@pytest.mark.parametrize(
    "reason",
    [
        "coverage_needs_follow_up",
        "agent_work_incomplete",
        "surfaces_unassessed",
        "finalization_incomplete",
    ],
)
def test_threshold_respects_known_incompleteness_in_completed_receipt(reason: str) -> None:
    state = SimpleNamespace(
        run_record={"status": "completed", "scan_quality": {"assessment_reasons": [reason]}},
        vulnerability_reports=[{"severity": "low"}],
    )
    assert main_module._non_interactive_exit_code(state, fail_on="high") == 5
    assert main_module._non_interactive_exit_code(state) == 2


def test_no_findings_alone_does_not_fabricate_incompleteness() -> None:
    state = SimpleNamespace(
        run_record={
            "status": "completed",
            "scan_quality": {"assessment_reasons": ["no_findings_recorded"]},
        },
        vulnerability_reports=[],
    )
    qualified = {
        "success": True,
        "scan_completed": True,
        "coverage_complete": True,
        "assessment_reasons": ["no_findings_recorded"],
    }
    assert (
        main_module._non_interactive_exit_code(
            state, fail_on="high", finish_result=finish_run_result(qualified)
        )
        == 0
    )


def test_picker_selection_uses_normal_resume_loader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["lyrashield", "-r", "--instruction", "new direction"])
    monkeypatch.setattr(arg_parser, "terminal_attached", lambda: True)
    monkeypatch.setattr(arg_parser, "pick_run", lambda: "safe-run")
    snapshot = tmp_path / "strix_runs" / "safe-run" / ".state" / "agents.json"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text("{}")

    def loader(args, _parser):
        assert args.resume == "safe-run"
        args.targets_info = [{"type": "web_application", "original": "https://example.test"}]
        args.attachments = []

    load = Mock(side_effect=loader)
    monkeypatch.setattr(arg_parser, "_load_resume_state", load)
    args = arg_parser.parse_arguments()
    assert args.user_explicit_instruction == "new direction"
    load.assert_called_once()


def test_owned_root_prompt_reconciles_coverage_within_limits(monkeypatch) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    _register_lyrashield_skills()
    root = render_system_prompt(is_root=True)
    child = render_system_prompt(is_root=False)
    assert "## Coverage Reconciliation" in root
    assert "`needs_follow_up`" in root
    assert "require paid" in root
    assert "Children must not delegate" in root
    assert "## Coverage Reconciliation" not in child
