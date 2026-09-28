"""Run-name and path containment checks for the owned viewer CLI."""

from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING

import pytest
from rich.console import Console

from lyrashield.interface.viewer.cli import _resolve_run_dir


if TYPE_CHECKING:
    from pathlib import Path


def _write_run_record(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": run_dir.name, "status": "completed"}), encoding="utf-8"
    )


def test_viewer_cli_resolves_a_run_under_the_runs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "strix_runs" / "run-2026"
    _write_run_record(run_dir)

    assert _resolve_run_dir("run-2026", Console(file=io.StringIO())) == run_dir


def test_viewer_cli_rejects_traversal_run_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as exc:
        _resolve_run_dir("../outside", Console(file=io.StringIO()))

    assert exc.value.code == 1


def test_viewer_cli_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside"
    _write_run_record(outside)
    runs = tmp_path / "strix_runs"
    runs.mkdir()
    (runs / "alias").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SystemExit) as exc:
        _resolve_run_dir("alias", Console(file=io.StringIO()))

    assert exc.value.code == 1
