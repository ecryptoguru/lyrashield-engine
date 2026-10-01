# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Repository cloning, revision pinning, and checkout assertion."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.interface.git_command import (
    SourcePreflightError,
    _bounded_timeout,
    _git_executable,
    _git_ref_exists,
    _raise_if_deadline_exhausted,
    _run_git_command,
)
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError


_GIT_CLONE_TIMEOUT_SECONDS = 900

_GIT_FETCH_TIMEOUT_SECONDS = 300

_GIT_CHECKOUT_TIMEOUT_SECONDS = 120


def _print_clone_error(console: Console, message: str) -> None:
    error_text = Text()
    error_text.append("REPOSITORY CLONE FAILED", style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(f"{message}\n", style="white")
    panel = Panel(
        error_text,
        title="[bold white]LYRASHIELD",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _is_full_git_commit_sha(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value))


def _print_source_preflight_error(console: Console, error: SourcePreflightError) -> None:
    error_text = Text()
    error_text.append("SOURCE PREFLIGHT FAILED", style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(f"{error}\n", style="white")
    panel = Panel(
        error_text,
        title="[bold white]LYRASHIELD",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _commit_available(repo_path: Path, sha: str) -> bool:
    return _git_ref_exists(repo_path, f"{sha}^{{commit}}")


def _ensure_commit_available(
    repo_path: Path, sha: str, reason: str, deadline: RunDeadline | None = None
) -> None:
    """Ensure commit *sha* exists locally; one bounded fetch, then fail closed."""
    if _commit_available(repo_path, sha):
        return
    _raise_if_deadline_exhausted(deadline, f"fetch of required commit {sha}")
    try:
        fetch = _run_git_command(
            repo_path,
            ["fetch", "origin", sha],
            check=False,
            timeout=_bounded_timeout(deadline, _GIT_FETCH_TIMEOUT_SECONDS),
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SourcePreflightError(reason, f"Fetching required commit {sha} failed: {e}") from e
    if fetch.returncode != 0 or not _commit_available(repo_path, sha):
        stderr = fetch.stderr.strip()
        raise SourcePreflightError(
            reason,
            f"Required commit {sha} is not available in '{repo_path}'"
            + (f": {stderr}" if stderr else "."),
        )


def _read_only_head_revision(repo_path: Path) -> str | None:
    """Return HEAD's commit object ID or ``None`` when it cannot be resolved.

    Unlike :func:`_assert_checkout_revision` this is purely observational:
    ``rev-parse HEAD`` never checks out, fetches or otherwise modifies the
    clone, so a possibly-altered resume cache is left exactly as found.
    """
    try:
        result = _run_git_command(repo_path, ["rev-parse", "HEAD"], check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


def _assert_checkout_revision(
    repo_path: Path, revision: str, deadline: RunDeadline | None = None
) -> None:
    """Detach the checkout at *revision* and assert HEAD's object ID matches.

    A branch name is only a fetch hint — the recorded immutable revision is
    what must end up checked out. If the commit is not advertised (e.g. a
    force-pushed or non-branch head), one bounded direct fetch is attempted
    before failing closed.
    """
    _raise_if_deadline_exhausted(deadline, f"checkout at revision {revision}")
    checkout = _run_git_command(
        repo_path,
        ["checkout", "--detach", revision],
        check=False,
        timeout=_bounded_timeout(deadline, _GIT_CHECKOUT_TIMEOUT_SECONDS),
    )
    if checkout.returncode != 0:
        _ensure_commit_available(repo_path, revision, "missing_revision", deadline)
        try:
            _run_git_command(
                repo_path,
                ["checkout", "--detach", revision],
                check=True,
                timeout=_bounded_timeout(deadline, _GIT_CHECKOUT_TIMEOUT_SECONDS),
            )
        except subprocess.CalledProcessError as e:
            detail = e.stderr.strip() if isinstance(e.stderr, str) else str(e)
            raise SourcePreflightError(
                "checkout_failed",
                f"Unable to detach '{repo_path}' at revision {revision}: {detail}",
            ) from e
    actual = _run_git_command(repo_path, ["rev-parse", "HEAD"], check=False)
    actual_sha = actual.stdout.strip() if actual.returncode == 0 else ""
    if actual_sha != revision:
        raise SourcePreflightError(
            "checkout_mismatch",
            f"Checkout assertion failed for '{repo_path}': requested {revision} "
            f"but HEAD is {actual_sha or 'unresolved'}.",
        )


def clone_repository(
    repo_url: str,
    run_name: str,
    dest_name: str | None = None,
    branch: str | None = None,
    *,
    revision: str | None = None,
    required_commits: tuple[str, ...] = (),
    deadline: RunDeadline | None = None,
) -> str:
    console = Console()

    git_executable = _git_executable()

    if dest_name:
        repo_name = dest_name
    else:
        repo_name = Path(repo_url).stem if repo_url.endswith(".git") else Path(repo_url).name

    if not repo_name or repo_name in {".", ".."} or "/" in repo_name or "\\" in repo_name:
        _print_clone_error(
            console,
            f"The repository destination name {repo_name!r} is not a safe subdirectory.",
        )
        sys.exit(1)

    # The clone shares the scan's monotonic deadline: refuse to spawn git
    # once the allowance is gone rather than starting work that can only be
    # abandoned.
    _raise_if_deadline_exhausted(deadline, "repository clone")

    base = Path(tempfile.gettempdir()) / "strix_repos"
    base.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=f"repo_{run_name}_", dir=base))
    clone_path = temp_dir / repo_name

    if clone_path.exists():
        shutil.rmtree(clone_path)

    # An explicit --repository-revision (or a full-SHA --repository-branch, the
    # legacy form) pins the checkout to an immutable commit. A branch name is
    # only a fetch hint — never the checkout source — so the pinned path clones
    # all refs with --no-checkout and detaches at the object ID afterwards.
    pinned_revision = revision or (branch if branch and _is_full_git_commit_sha(branch) else None)

    try:
        with console.status(f"[bold cyan]Cloning repository {repo_url}...", spinner="dots"):
            # Controlled subprocess boundary: Git path is resolved, shell=False,
            # and -- terminates option parsing before the user-controlled repository URL.
            clone_args = [git_executable, "clone"]
            if pinned_revision:
                # A full commit SHA is an immutable revision, not a remote branch. Clone the
                # repository normally so reachable refs are fetched, then detach at that revision.
                # ``git clone --branch <sha> --single-branch`` fails because a SHA is not an
                # advertised branch name.
                clone_args.append("--no-checkout")
            elif branch:
                clone_args.extend(["--branch", branch, "--single-branch"])
            clone_args.extend(["--", repo_url, str(clone_path)])
            subprocess.run(  # noqa: S603
                clone_args,
                capture_output=True,
                text=True,
                check=True,
                timeout=_bounded_timeout(deadline, _GIT_CLONE_TIMEOUT_SECONDS),
            )
            _raise_if_deadline_exhausted(deadline, "repository checkout")
            if pinned_revision:
                _assert_checkout_revision(clone_path, pinned_revision.lower(), deadline)
            for required in required_commits:
                _ensure_commit_available(clone_path, required, "missing_base", deadline)

        return str(clone_path.absolute())

    except SourcePreflightError as e:
        _print_source_preflight_error(console, e)
        sys.exit(1)
    except subprocess.TimeoutExpired as e:
        # A git wait that outlived the allowance is a deadline event, not a
        # clone failure — surface it as RunDeadlineExceededError so the entry
        # point can record the honest bounded terminal artifact.
        if deadline is not None and deadline.remaining_seconds() <= 0:
            raise RunDeadlineExceededError(
                f"runtime allowance exhausted during repository clone of {repo_url}"
            ) from e
        _print_clone_error(
            console,
            f"Timed out acquiring repository {repo_url}: {e}",
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        error_text = Text()
        error_text.append("REPOSITORY CLONE FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append(f"Could not clone repository: {repo_url}\n", style="white")
        error_text.append(
            f"Error: {e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}", style="dim red"
        )

        panel = Panel(
            error_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    except FileNotFoundError:
        error_text = Text()
        error_text.append("GIT NOT FOUND", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Git is not installed or not available in PATH.\n", style="white")
        error_text.append("Please install Git to clone repositories.\n", style="white")

        panel = Panel(
            error_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
