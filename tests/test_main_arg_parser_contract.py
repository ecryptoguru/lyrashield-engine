from __future__ import annotations

import re
import sys
from importlib import import_module
from typing import Any

import pytest


main_module: Any = import_module("lyrashield.interface.main")


def test_help_preserves_scan_cli_flag_surface(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["lyrashield", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        main_module.parse_arguments()

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    options = help_text.split("options:", maxsplit=1)[1].split("Examples:", maxsplit=1)[0]
    flags = set(re.findall(r"(?<!\w)--[a-z0-9-]+", options))

    assert flags == {
        "--help",
        "--version",
        "--update",
        "--target",
        "--target-list",
        "--repository-branch",
        "--repository-revision",
        "--target-type",
        "--mount",
        "--attachment",
        "--instruction",
        "--instruction-file",
        "--non-interactive",
        "--scan-mode",
        "--scope-mode",
        "--diff-base",
        "--diff-head",
        "--config",
        "--max-budget",
        "--max-budget-usd",
        "--max-turns",
        "--runtime-budget-seconds",
        "--run-name",
        "--resume",
    }
