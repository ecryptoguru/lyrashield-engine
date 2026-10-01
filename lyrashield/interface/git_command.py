# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Controlled Git subprocess boundary, object-id validation, deadline caps.

Every subprocess call resolves the Git executable and runs with
``shell=False``; the shared preflight error and the runtime-deadline
helpers live here so diff-scope resolution and repository cloning
interpret them identically.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from typing import TYPE_CHECKING

from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError


if TYPE_CHECKING:
    from pathlib import Path


class SourcePreflightError(ValueError):
    """Named preflight failure while pinning or diffing repository source.

    ``reason`` is a stable machine-readable identifier (e.g.
    ``"missing_revision"``) so callers and tests can distinguish a fail-closed
    preflight rejection from a generic resolution error. A Review Changes run
    that hits one of these must stop — it must never fall back to an
    unpinned snapshot.
    """

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        # The stable reason token stays visible in CLI panels and logs.
        super().__init__(f"[{reason}] {message}")


_GIT_OBJECT_ID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def _is_git_object_id(value: str) -> bool:
    """True iff *value* is a full 40- or 64-character lowercase Git object ID."""
    return bool(_GIT_OBJECT_ID_RE.fullmatch(value))


def _raise_if_deadline_exhausted(deadline: RunDeadline | None, phase: str) -> None:
    """Stop acquisition when the shared scan allowance is already spent."""
    if deadline is not None and deadline.remaining_seconds() <= 0:
        raise RunDeadlineExceededError(f"runtime allowance exhausted during {phase}")


def _bounded_timeout(deadline: RunDeadline | None, cap: float) -> float:
    """Cap a subprocess wait at both its configured bound and the allowance."""
    if deadline is None:
        return cap
    return max(0.001, min(cap, deadline.remaining_seconds()))


def validate_git_object_id(value: str) -> str:
    """argparse ``type=`` validator for ``--repository-revision``/``--diff-head``.

    Only immutable full-length object IDs are accepted: abbreviated SHAs,
    branch/tag names, ``HEAD`` expressions, and ref strings containing
    shell-meaningful or option-injection characters are all rejected, so the
    validated value is always safe to place in a Git argument array.
    """
    candidate = value.strip()
    if not _is_git_object_id(candidate):
        raise argparse.ArgumentTypeError(
            "must be a full 40- or 64-character lowercase hex Git object ID "
            "(branches, tags, abbreviated SHAs, and ref expressions are not accepted)"
        )
    return candidate


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise FileNotFoundError("Git executable not found in PATH")
    return executable


def _run_git_command(
    repo_path: Path, args: list[str], check: bool = True, timeout: float = 5
) -> subprocess.CompletedProcess[str]:
    # Controlled subprocess boundary: Git path is resolved and shell is disabled.
    return subprocess.run(  # noqa: S603
        [_git_executable(), "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


def _run_git_command_raw(
    repo_path: Path, args: list[str], check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    # Controlled subprocess boundary: Git path is resolved and shell is disabled.
    return subprocess.run(  # noqa: S603
        [_git_executable(), "-C", str(repo_path), *args],
        capture_output=True,
        check=check,
        timeout=5,
    )


def _git_ref_exists(repo_path: Path, ref: str) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--verify", "--quiet", ref], check=False)
    return result.returncode == 0


def _is_full_git_commit_sha(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value))
