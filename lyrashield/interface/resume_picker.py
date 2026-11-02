"""Small terminal-only selector for resumable owned runs.

Selection is read-only. The normal resume loader validates source revisions,
attachments, and snapshots after a run is chosen.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from rich.console import Console

from lyrashield.interface.utils import validate_run_name
from strix.core.paths import runs_base_dir, runtime_state_dir


if TYPE_CHECKING:
    from pathlib import Path


class PickerUnavailableError(RuntimeError):
    """A terminal or a resumable run is unavailable."""


def terminal_attached() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, OSError, ValueError):
        return False


def resumable_run_names(base: Path | None = None) -> list[str]:
    """List safe run identifiers by most recent receipt; never repair a run."""
    base = base or runs_base_dir()
    if not base.is_dir():
        return []
    candidates: list[tuple[float, str]] = []
    for child in base.iterdir():
        try:
            validate_run_name(child.name)
            receipt = child / "run.json"
            snapshot = runtime_state_dir(child) / "agents.json"
            if (
                child.is_symlink()
                or not child.is_dir()
                or receipt.is_symlink()
                or not receipt.is_file()
                or snapshot.parent.is_symlink()
                or snapshot.is_symlink()
                or not snapshot.is_file()
            ):
                continue
            candidates.append((receipt.stat().st_mtime, child.name))
        except (OSError, argparse.ArgumentTypeError):
            continue
    return [name for _, name in sorted(candidates, reverse=True)]


def pick_run() -> str | None:
    """Choose by name or number; empty input, EOF, and Ctrl-C cancel cleanly."""
    if not terminal_attached():
        raise PickerUnavailableError("Run selection needs a terminal; pass --resume <run_name>")
    try:
        names = resumable_run_names()
    except OSError as exc:
        raise PickerUnavailableError(
            "Cannot read prior runs; pass --resume <run_name> to select one explicitly"
        ) from exc
    if not names:
        raise PickerUnavailableError("No resumable runs found; start a fresh scan with --target")
    console = Console()
    console.print("Resume a scan (newest first). Enter a run name or number; Enter cancels.")
    for index, name in enumerate(names, 1):
        console.print(f"  {index}. {name}", markup=False, highlight=False)
    while True:
        try:
            choice = input("Resume: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not choice:
            return None
        if choice in names:
            return choice
        if choice.isdecimal() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        console.print("Choose a listed name or number, or press Enter to cancel.")
