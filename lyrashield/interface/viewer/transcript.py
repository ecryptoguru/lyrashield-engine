# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Build the JSON payloads the viewer SPA consumes from a run directory."""

from __future__ import annotations

import errno
import json
import logging
import os
import stat
from typing import TYPE_CHECKING, Any, cast

from strix.core.paths import run_record_path, runtime_state_dir


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_TERMINAL_STATUSES = {"completed", "stopped", "failed", "interrupted"}

_KNOWN_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")


def severity_counts(vulns: list[Any]) -> dict[str, int]:
    """Bucket vulnerabilities into critical/high/medium/low counts.

    Mirrors the SPA's ``severityCounts``: severities are lowercased and
    trimmed, and anything outside the four known buckets (``info``,
    ``informational``, ``unknown``, missing, ...) folds into ``low`` so the
    shared UI renders cleanly.
    """
    counts: dict[str, int] = dict.fromkeys(_KNOWN_SEVERITIES, 0)
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        vuln = cast("dict[str, Any]", vuln)
        raw = vuln.get("severity")
        severity = str(raw or "").lower().strip()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


def build_run_state(run_dir: Path) -> dict[str, Any]:
    """Agent graph + full per-agent event/message stream.

    Reuses the Textual-free ``TuiLiveView`` projection so the viewer and the TUI
    share one parser for ``agents.json`` + ``agents.db`` and never drift.
    """
    _guard_transcript_state_inputs(run_dir)
    # Imported lazily so importing strix.interface.viewer does not eagerly pull the TUI.
    from lyrashield.interface.tui.live_view import TuiLiveView

    view = TuiLiveView()
    view.hydrate_from_run_dir(run_dir)
    return {"agents": list(view.agents.values()), "events": view.events}


def _guard_transcript_state_inputs(run_dir: Path) -> None:
    """Refuse linked or non-regular transcript inputs before the shared reader opens them."""
    state_dir = runtime_state_dir(run_dir)
    for path in (state_dir, state_dir / "agents.json", state_dir / "agents.db"):
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise OSError(errno.ELOOP, "refusing to read a symlinked transcript input", path)
        valid = stat.S_ISDIR(mode) if path == state_dir else stat.S_ISREG(mode)
        if not valid:
            raise OSError(errno.EINVAL, "refusing to read an invalid transcript input", path)


def read_run_summary(run_dir: Path) -> dict[str, Any]:
    """The ``run.json`` record plus a computed ``finished`` flag."""
    record = _load_json(run_record_path(run_dir), default={})
    if not isinstance(record, dict):
        record = {}
    record = cast("dict[str, Any]", record)
    status = record.get("status")
    finished = status in _TERMINAL_STATUSES and bool(record.get("end_time"))
    return {**record, "finished": finished}


def primary_target(record: dict[str, Any]) -> str | None:
    """The first target's original string from a run record, or None."""
    targets = record.get("targets_info")
    if not isinstance(targets, list):
        return None
    for entry in targets:
        if not isinstance(entry, dict):
            continue
        entry = cast("dict[str, Any]", entry)
        original = entry.get("original")
        if isinstance(original, str) and original:
            return original
    return None


def read_vulnerabilities(run_dir: Path) -> list[Any]:
    """The ``vulnerabilities.json`` list (empty until a scan writes it)."""
    path = run_dir / "vulnerabilities.json"
    try:
        text = _read_artifact_text(path)
    except FileNotFoundError as exc:
        if read_run_summary(run_dir).get("finished"):
            raise FileNotFoundError(f"Completed run has no findings artifact: {path}") from exc
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise TypeError(f"{path} is not a findings list")
    return data


def read_report_markdown(run_dir: Path) -> str:
    """The executive report markdown (empty until a scan writes it)."""
    report_path = run_dir / "penetration_test_report.md"
    try:
        return _read_artifact_text(report_path)
    except FileNotFoundError:
        return ""


def _read_artifact_text(path: Path) -> str:
    """Read one fixed-name run artifact without following a final symlink."""
    if path.is_symlink():
        raise OSError(errno.ELOOP, "refusing to read a symlinked run artifact", path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        return path.read_text(encoding="utf-8")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    with os.fdopen(descriptor, "r", encoding="utf-8") as artifact:
        return artifact.read()


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


__all__ = [
    "build_run_state",
    "primary_target",
    "read_report_markdown",
    "read_run_summary",
    "read_vulnerabilities",
    "severity_counts",
]
