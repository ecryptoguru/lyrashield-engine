from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from lyrashield.utils.redaction import redact_url


if TYPE_CHECKING:
    from lyrashield.artifacts.state import ReportState


def _parse_repo_full_name(uri: str) -> str | None:
    """Extract ``owner/repo`` from a git URL or slug, else None."""
    text = uri.strip().removesuffix(".git")
    if not text:
        return None
    if "@" in text and ":" in text.split("@", 1)[1]:
        # scp-style: git@host:owner/repo
        text = text.split("@", 1)[1].split(":", 1)[1]
    elif "://" in text:
        # https://host/owner/repo
        host_and_path = text.split("://", 1)[1]
        text = host_and_path.split("/", 1)[1] if "/" in host_and_path else host_and_path
    parts = [p for p in text.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return None


def _git_head(repo_path: str) -> tuple[str | None, str | None]:
    """Best-effort ``(commit_sha, branch)`` for a cloned repo, or ``(None, None)``.

    Used to populate SARIF versionControlProvenance. Failures (missing git,
    non-repo path, detached HEAD, timeout) degrade to None so the SARIF
    emit is never blocked by a provenance lookup.
    """
    path = Path(repo_path)
    if not path.is_dir():
        return None, None

    git_executable = shutil.which("git")
    if git_executable is None:
        return None, None

    def _run(args: list[str]) -> str | None:
        try:
            # Controlled subprocess boundary: Git path is resolved and shell is disabled.
            result = subprocess.run(  # noqa: S603
                [git_executable, "-C", str(path), *args],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None

    commit = _run(["rev-parse", "HEAD"])
    branch = _run(["rev-parse", "--abbrev-ref", "HEAD"])
    if branch == "HEAD":  # detached HEAD carries no branch name
        branch = None
    return commit, branch


def _sarif_repository_context(self: ReportState) -> dict[str, Any] | None:
    """Repo/commit/branch context for SARIF provenance (repo scans only).

    Cached after first derivation — ``_save_artifacts`` runs on every
    state save, and the git lookup only needs to happen once per run.
    Returns None for URL / IP (DAST) targets that have no repository.
    """
    if not self._sarif_repo_ctx_ready:
        self._sarif_repo_ctx = self._derive_repository_context()
        self._sarif_repo_ctx_ready = True
    return self._sarif_repo_ctx


def _derive_repository_context(self: ReportState) -> dict[str, Any] | None:
    # Prefer the in-memory raw repository targets; the durable record's
    # targets_info is sanitized and carries no cloned paths. An empty
    # in-memory list means set_scan_config was never called, so fall back
    # to the run record (e.g. tests that set it directly).
    raw_targets = getattr(self, "_repo_context_targets", None) or []
    if raw_targets:
        repo_targets = [cast("dict[str, Any]", t) for t in raw_targets]
    else:
        targets = self.run_record.get("targets_info")
        if not isinstance(targets, list):
            return None
        repo_targets = [
            cast("dict[str, Any]", t)
            for t in targets
            if isinstance(t, dict) and t.get("type") == "repository"
        ]
    if len(repo_targets) != 1:
        return None
    target = repo_targets[0]
    details = target.get("details")
    if not isinstance(details, dict):
        return None
    details = cast("dict[str, Any]", details)

    uri = details.get("target_repo")
    if not isinstance(uri, str) or not uri.strip():
        return None

    # Public SARIF provenance: URL shape without credentials/query tokens.
    context: dict[str, Any] = {"repositoryUri": redact_url(uri.strip())}
    full_name = _parse_repo_full_name(uri)
    if full_name:
        context["repositoryFullName"] = full_name
    cloned = details.get("cloned_repo_path")
    if isinstance(cloned, str) and cloned.strip():
        commit, branch = _git_head(cloned.strip())
        if commit:
            context["commitSha"] = commit
        if branch:
            context["branch"] = branch
            context["ref"] = f"refs/heads/{branch}"
    return context


# Stable downstream facade: the public name is pinned by the artifact-state
# facade test; the underscore helpers remain the internal implementation.
parse_repo_full_name = _parse_repo_full_name
