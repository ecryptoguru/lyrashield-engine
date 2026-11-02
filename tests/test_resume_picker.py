"""Resume selection lists safe snapshots and never mutates scan artifacts."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from lyrashield.interface import resume_picker


if TYPE_CHECKING:
    from pathlib import Path


def test_picker_lists_only_safe_resumable_runs(tmp_path: Path) -> None:
    valid = tmp_path / "valid"
    (valid / ".state").mkdir(parents=True)
    (valid / ".state" / "agents.json").write_text("{}")
    (valid / "run.json").write_text('{"private":"untouched"}')
    (tmp_path / "link").symlink_to(valid, target_is_directory=True)
    missing = tmp_path / "no-snapshot"
    missing.mkdir()
    (missing / "run.json").write_text("{}")
    assert resume_picker.resumable_run_names(tmp_path) == ["valid"]
    assert (valid / "run.json").read_text() == '{"private":"untouched"}'


@pytest.mark.parametrize("answer", ["", "safe-run", "1"])
def test_picker_can_cancel_or_select_name_and_number(
    monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    monkeypatch.setattr(resume_picker, "terminal_attached", lambda: True)
    monkeypatch.setattr(resume_picker, "resumable_run_names", lambda: ["safe-run"])
    monkeypatch.setattr("builtins.input", Mock(return_value=answer))
    assert resume_picker.pick_run() == ("safe-run" if answer else None)


@pytest.mark.parametrize("error", [KeyboardInterrupt, EOFError])
def test_picker_interrupt_is_clean_cancellation(
    monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    monkeypatch.setattr(resume_picker, "terminal_attached", lambda: True)
    monkeypatch.setattr(resume_picker, "resumable_run_names", lambda: ["safe-run"])
    monkeypatch.setattr("builtins.input", Mock(side_effect=error))
    assert resume_picker.pick_run() is None


def test_closed_terminal_streams_are_treated_as_headless(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resume_picker.sys, "stdin", None)
    assert resume_picker.terminal_attached() is False
