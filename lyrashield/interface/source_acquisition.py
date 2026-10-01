# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
# Controlled subprocess boundary: all subprocess calls below resolve Git and use shell=False.
"""Repository revision acquisition and diff-scope provenance helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError


_SUPPORTED_SCOPE_MODES = {"auto", "diff", "full"}

_MAX_FILES_PER_SECTION = 120

_GIT_CLONE_TIMEOUT_SECONDS = 900

_GIT_FETCH_TIMEOUT_SECONDS = 300

_GIT_CHECKOUT_TIMEOUT_SECONDS = 120


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


@dataclass
class DiffEntry:
    status: str
    path: str
    old_path: str | None = None
    similarity: int | None = None


@dataclass
class RepoDiffScope:
    source_path: str
    workspace_subdir: str | None
    base_ref: str
    merge_base: str
    added_files: list[str]
    modified_files: list[str]
    renamed_files: list[dict[str, Any]]
    deleted_files: list[str]
    analyzable_files: list[str]
    truncated_sections: dict[str, bool] = field(default_factory=dict[str, bool])
    copied_files: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    base_revision: str | None = None
    head_revision: str | None = None
    requested_base: str | None = None
    requested_head: str | None = None
    worktree_dirty: bool | None = None
    snapshot_digest: str | None = None
    context_files: list[str] = field(default_factory=list[str])

    def to_metadata(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "workspace_subdir": self.workspace_subdir,
            "base_ref": self.base_ref,
            "base_revision": self.base_revision,
            "merge_base": self.merge_base,
            "requested_base": self.requested_base,
            "requested_head": self.requested_head,
            "head_revision": self.head_revision,
            "worktree_dirty": self.worktree_dirty,
            "snapshot_digest": self.snapshot_digest,
            "snapshot_digest_stage": "preflight" if self.snapshot_digest else None,
            "added_files": self.added_files,
            "modified_files": self.modified_files,
            "renamed_files": self.renamed_files,
            "copied_files": self.copied_files,
            "deleted_files": self.deleted_files,
            "analyzable_files": self.analyzable_files,
            "context_files": self.context_files,
            "added_files_count": len(self.added_files),
            "modified_files_count": len(self.modified_files),
            "renamed_files_count": len(self.renamed_files),
            "copied_files_count": len(self.copied_files),
            "deleted_files_count": len(self.deleted_files),
            "analyzable_files_count": len(self.analyzable_files),
            "context_files_count": len(self.context_files),
            "truncated_sections": self.truncated_sections,
        }


@dataclass
class DiffScopeResult:
    active: bool
    mode: str
    instruction_block: str = ""
    metadata: dict[str, Any] = field(default_factory=dict[str, Any])


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


def _is_ci_environment(env: dict[str, str]) -> bool:
    return any(
        env.get(key)
        for key in (
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "BUILDKITE",
            "CIRCLECI",
        )
    )


def _is_pr_environment(env: dict[str, str]) -> bool:
    return any(
        env.get(key)
        for key in (
            "GITHUB_BASE_REF",
            "GITHUB_HEAD_REF",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "GITLAB_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "SYSTEM_PULLREQUEST_TARGETBRANCH",
        )
    )


def _is_git_repo(repo_path: Path) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--is-inside-work-tree"], check=False)
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def _is_repo_shallow(repo_path: Path) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--is-shallow-repository"], check=False)
    if result.returncode == 0:
        value = result.stdout.strip().lower()
        if value in {"true", "false"}:
            return value == "true"

    git_meta = repo_path / ".git"
    if git_meta.is_dir():
        return (git_meta / "shallow").exists()
    if git_meta.is_file():
        try:
            content = git_meta.read_text(encoding="utf-8").strip()
        except OSError:
            return False
        if content.startswith("gitdir:"):
            git_dir = content.split(":", 1)[1].strip()
            resolved = (repo_path / git_dir).resolve()
            return (resolved / "shallow").exists()
    return False


def _git_ref_exists(repo_path: Path, ref: str) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--verify", "--quiet", ref], check=False)
    return result.returncode == 0


def _resolve_origin_head_ref(repo_path: Path) -> str | None:
    result = _run_git_command(
        repo_path, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], check=False
    )
    if result.returncode != 0:
        return None
    ref = result.stdout.strip()
    return ref or None


def _extract_branch_name(ref: str | None) -> str | None:
    if not ref:
        return None
    value = ref.strip()
    if not value:
        return None
    return value.split("/")[-1]


def _extract_github_base_sha(env: dict[str, str]) -> str | None:
    event_path = env.get("GITHUB_EVENT_PATH", "").strip()
    if not event_path:
        return None

    path = Path(event_path)
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    base_sha = payload.get("pull_request", {}).get("base", {}).get("sha")
    if isinstance(base_sha, str) and base_sha.strip():
        return base_sha.strip()
    return None


def _resolve_default_branch_name(repo_path: Path, env: dict[str, str]) -> str | None:
    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        return github_base_ref

    origin_head = _resolve_origin_head_ref(repo_path)
    if origin_head:
        branch = _extract_branch_name(origin_head)
        if branch:
            return branch

    if _git_ref_exists(repo_path, "refs/remotes/origin/main"):
        return "main"
    if _git_ref_exists(repo_path, "refs/remotes/origin/master"):
        return "master"

    return None


def _resolve_base_ref(repo_path: Path, diff_base: str | None, env: dict[str, str]) -> str:
    if diff_base and diff_base.strip():
        return diff_base.strip()

    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        github_candidate = f"refs/remotes/origin/{github_base_ref}"
        if _git_ref_exists(repo_path, github_candidate):
            return github_candidate

    github_base_sha = _extract_github_base_sha(env)
    if github_base_sha and _git_ref_exists(repo_path, github_base_sha):
        return github_base_sha

    origin_head = _resolve_origin_head_ref(repo_path)
    if origin_head and _git_ref_exists(repo_path, origin_head):
        return origin_head

    if _git_ref_exists(repo_path, "refs/remotes/origin/main"):
        return "refs/remotes/origin/main"

    if _git_ref_exists(repo_path, "refs/remotes/origin/master"):
        return "refs/remotes/origin/master"

    raise ValueError(
        "Unable to resolve a base ref for diff-scope. Pass --diff-base explicitly "
        "(for example: --diff-base origin/main)."
    )


def _get_current_branch_name(repo_path: Path) -> str | None:
    result = _run_git_command(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    if result.returncode != 0:
        return None
    branch_name = result.stdout.strip()
    if not branch_name or branch_name == "HEAD":
        return None
    return branch_name


def _parse_name_status_z(raw_output: bytes) -> list[DiffEntry]:
    if not raw_output:
        return []

    tokens = [
        token.decode("utf-8", errors="replace") for token in raw_output.split(b"\x00") if token
    ]
    entries: list[DiffEntry] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        status_raw = token
        status_code = status_raw[:1]
        similarity: int | None = None
        if len(status_raw) > 1 and status_raw[1:].isdigit():
            similarity = int(status_raw[1:])

        if status_code in {"R", "C"} and index + 2 < len(tokens):
            old_path = tokens[index + 1]
            new_path = tokens[index + 2]
            entries.append(
                DiffEntry(
                    status=status_code,
                    path=new_path,
                    old_path=old_path,
                    similarity=similarity,
                )
            )
            index += 3
            continue

        if index + 1 < len(tokens):
            path = tokens[index + 1]
            entries.append(DiffEntry(status=status_code, path=path, similarity=similarity))
            index += 2
            continue

        break

    return entries


def _append_unique(container: list[str], seen: set[str], path: str) -> None:
    if path and path not in seen:
        seen.add(path)
        container.append(path)


def _classify_diff_entries(entries: list[DiffEntry]) -> dict[str, Any]:
    added_files: list[str] = []
    modified_files: list[str] = []
    deleted_files: list[str] = []
    renamed_files: list[dict[str, Any]] = []
    copied_files: list[dict[str, Any]] = []
    analyzable_files: list[str] = []
    analyzable_seen: set[str] = set()
    modified_seen: set[str] = set()

    for entry in entries:
        path = entry.path
        if not path:
            continue

        if entry.status == "D":
            deleted_files.append(path)
            continue

        if entry.status == "A":
            added_files.append(path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        if entry.status == "M":
            _append_unique(modified_files, modified_seen, path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        if entry.status == "R":
            renamed_files.append(
                {
                    "old_path": entry.old_path,
                    "new_path": path,
                    "similarity": entry.similarity,
                }
            )
            _append_unique(analyzable_files, analyzable_seen, path)
            if entry.similarity is None or entry.similarity < 100:
                _append_unique(modified_files, modified_seen, path)
            continue

        if entry.status == "C":
            copied_files.append(
                {
                    "old_path": entry.old_path,
                    "new_path": path,
                    "similarity": entry.similarity,
                }
            )
            _append_unique(modified_files, modified_seen, path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        _append_unique(modified_files, modified_seen, path)
        _append_unique(analyzable_files, analyzable_seen, path)

    return {
        "added_files": added_files,
        "modified_files": modified_files,
        "deleted_files": deleted_files,
        "renamed_files": renamed_files,
        "copied_files": copied_files,
        "analyzable_files": analyzable_files,
    }


def _truncate_file_list(
    files: list[str], max_files: int = _MAX_FILES_PER_SECTION
) -> tuple[list[str], bool]:
    if len(files) <= max_files:
        return files, False
    return files[:max_files], True


def build_diff_scope_instruction(scopes: list[RepoDiffScope]) -> str:
    lines = [
        "The user is requesting a review of a Pull Request.",
        (
            "Instruction: Direct your analysis primarily at the changes in the listed files. "
            "You may reference other files in the repository for context (imports, definitions, "
            "usage), but report findings only if they relate to the listed changes."
        ),
        "For Added files, review the entire file content.",
        "For Modified files, focus primarily on the changed areas.",
    ]

    for scope in scopes:
        repo_name = scope.workspace_subdir or Path(scope.source_path).name or "repository"
        lines.append("")
        lines.append(f"Repository Scope: {repo_name}")
        lines.append(f"Base reference: {scope.base_ref}")
        if scope.base_revision and scope.base_revision != scope.base_ref:
            lines.append(f"Base revision: {scope.base_revision}")
        lines.append(f"Merge base: {scope.merge_base}")
        if scope.head_revision:
            lines.append(f"Head revision: {scope.head_revision}")
        if scope.worktree_dirty:
            lines.append(
                "Note: the worktree contains uncommitted changes "
                "and is not exactly the recorded head commit. The scan's "
                "frozen uploaded source digest is recorded in run.json."
            )

        focus_files, focus_truncated = _truncate_file_list(scope.analyzable_files)
        scope.truncated_sections["analyzable_files"] = focus_truncated
        if focus_files:
            lines.append("Primary Focus (changed files to analyze):")
            lines.extend(f"- {path}" for path in focus_files)
            if focus_truncated:
                lines.append(f"- ... ({len(scope.analyzable_files) - len(focus_files)} more files)")
        else:
            lines.append("Primary Focus: No analyzable changed files detected.")

        added_files, added_truncated = _truncate_file_list(scope.added_files)
        scope.truncated_sections["added_files"] = added_truncated
        if added_files:
            lines.append("Added files (review entire file):")
            lines.extend(f"- {path}" for path in added_files)
            if added_truncated:
                lines.append(f"- ... ({len(scope.added_files) - len(added_files)} more files)")

        modified_files, modified_truncated = _truncate_file_list(scope.modified_files)
        scope.truncated_sections["modified_files"] = modified_truncated
        if modified_files:
            lines.append("Modified files (focus on changes):")
            lines.extend(f"- {path}" for path in modified_files)
            if modified_truncated:
                lines.append(
                    f"- ... ({len(scope.modified_files) - len(modified_files)} more files)"
                )

        if scope.renamed_files:
            rename_lines: list[str] = []
            for rename in scope.renamed_files:
                old_path = str(rename.get("old_path") or "unknown")
                new_path = str(rename.get("new_path") or "unknown")
                similarity = rename.get("similarity")
                if isinstance(similarity, int):
                    rename_lines.append(f"- {old_path} -> {new_path} (similarity {similarity}%)")
                else:
                    rename_lines.append(f"- {old_path} -> {new_path}")
            lines.append("Renamed files:")
            lines.extend(rename_lines)

        if scope.copied_files:
            copy_lines = []
            for copied in scope.copied_files:
                old_path = str(copied.get("old_path") or "unknown")
                new_path = str(copied.get("new_path") or "unknown")
                similarity = copied.get("similarity")
                if isinstance(similarity, int):
                    copy_lines.append(f"- {old_path} -> {new_path} (similarity {similarity}%)")
                else:
                    copy_lines.append(f"- {old_path} -> {new_path}")
            lines.append("Copied files:")
            lines.extend(copy_lines)

        deleted_files, deleted_truncated = _truncate_file_list(scope.deleted_files)
        scope.truncated_sections["deleted_files"] = deleted_truncated
        if deleted_files:
            lines.append("Note: These files were deleted (context only, not analyzable):")
            lines.extend(f"- {path}" for path in deleted_files)
            if deleted_truncated:
                lines.append(f"- ... ({len(scope.deleted_files) - len(deleted_files)} more files)")

    return "\n".join(lines).strip()


def _resolve_commit_sha(repo_path: Path, expr: str, reason: str) -> str:
    """Resolve *expr* to a full commit object ID, or raise a named preflight error.

    Ref expressions are resolved once here; downstream ``merge-base``/``diff``
    invocations only ever receive the resolved hex object ID, so an untrusted
    ref string can never be reinterpreted as a command-line option.
    """
    if not expr or expr.startswith("-") or any(char.isspace() for char in expr):
        raise SourcePreflightError(reason, f"Unsafe or empty revision expression: {expr!r}")
    try:
        result = _run_git_command(
            repo_path, ["rev-parse", "--verify", "--quiet", f"{expr}^{{commit}}"], check=False
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SourcePreflightError(
            reason, f"Could not resolve revision '{expr}' in '{repo_path}': {e}"
        ) from e
    sha = result.stdout.strip() if result.returncode == 0 else ""
    if not _is_git_object_id(sha):
        raise SourcePreflightError(
            reason,
            f"Required commit '{expr}' is not available in '{repo_path}'. "
            "Fetch the referenced revision or provide full history; "
            "Review Changes never falls back to an unpinned snapshot.",
        )
    return sha


def _worktree_snapshot_state(repo_path: Path) -> tuple[bool | None, str | None]:
    """Return ``(worktree_dirty, snapshot_digest)`` for honest non-commit provenance.

    A dirty worktree means the analyzed content is not exactly the recorded
    head commit. The digest covers the porcelain status (which names untracked
    paths), their bytes, and the full ``HEAD`` diff of tracked content. The
    later staged-source digest is authoritative for bytes uploaded to the scan.
    """
    try:
        status = _run_git_command_raw(repo_path, ["status", "--porcelain=v1", "-z"], check=False)
    except (OSError, subprocess.SubprocessError):
        return None, None
    if status.returncode != 0:
        return None, None
    if not status.stdout.strip(b"\x00"):
        return False, None
    try:
        diff = _run_git_command_raw(repo_path, ["diff", "--binary", "HEAD", "--"], check=False)
        untracked = _run_git_command_raw(
            repo_path, ["ls-files", "--others", "--exclude-standard", "-z"], check=False
        )
    except (OSError, subprocess.SubprocessError):
        return True, None
    if diff.returncode != 0 or untracked.returncode != 0:
        return True, None
    digest = hashlib.sha256()
    digest.update(status.stdout)
    digest.update(b"\x00diff\x00")
    digest.update(diff.stdout)
    for raw_path in sorted(path for path in untracked.stdout.split(b"\x00") if path):
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            return True, None
        path = repo_path / relative
        digest.update(b"\x00untracked\x00")
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        try:
            if path.is_symlink():
                target = os.fsencode(path.readlink())
                digest.update(len(target).to_bytes(8, "big"))
                digest.update(target)
                continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                file_stat = os.fstat(fd)
                if not stat.S_ISREG(file_stat.st_mode):
                    return True, None
                digest.update(file_stat.st_size.to_bytes(8, "big"))
                with os.fdopen(fd, "rb", closefd=False) as source:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
            finally:
                os.close(fd)
        except OSError:
            return True, None
    return True, f"sha256:{digest.hexdigest()}"


def _should_activate_auto_scope(
    local_sources: list[dict[str, str]], non_interactive: bool, env: dict[str, str]
) -> bool:
    if not local_sources:
        return False
    if not non_interactive:
        return False
    if not _is_ci_environment(env):
        return False
    if _is_pr_environment(env):
        return True

    for source in local_sources:
        source_path = source.get("source_path")
        if not source_path:
            continue
        repo_path = Path(source_path)
        if not _is_git_repo(repo_path):
            continue
        current_branch = _get_current_branch_name(repo_path)
        default_branch = _resolve_default_branch_name(repo_path, env)
        if current_branch and default_branch and current_branch != default_branch:
            return True
    return False


def _resolve_repo_diff_scope(
    source: dict[str, str],
    diff_base: str | None,
    env: dict[str, str],
    diff_head: str | None = None,
) -> RepoDiffScope:
    source_path = source.get("source_path", "")
    workspace_subdir = source.get("workspace_subdir")
    repo_path = Path(source_path)

    if not _is_git_repo(repo_path):
        raise SourcePreflightError(
            "not_a_git_repo", f"Source is not a git repository: {source_path}"
        )

    if _is_repo_shallow(repo_path):
        raise SourcePreflightError(
            "insufficient_history",
            "LyraShield requires full git history for diff-scope. Please set fetch-depth: 0 "
            "in your CI config.",
        )

    # Resolve HEAD first so the asserted comparison head is checked against the
    # actual checkout — Review Changes must refuse to analyze a different
    # revision than the one it recorded.
    head_revision = _resolve_commit_sha(repo_path, "HEAD", "head_unavailable")
    requested_base = diff_base.strip() if diff_base else None
    if diff_head:
        if head_revision != diff_head:
            raise SourcePreflightError(
                "head_mismatch",
                f"Requested diff head {diff_head} does not match the checkout at "
                f"'{source_path}' (HEAD is {head_revision}). The requested immutable "
                "head must equal the checkout; refusing to analyze a different revision.",
            )
        if not requested_base:
            raise SourcePreflightError(
                "missing_base", "--diff-head requires --diff-base to compare against."
            )
        if not _is_git_object_id(requested_base):
            raise SourcePreflightError(
                "invalid_base",
                f"--diff-base '{requested_base}' must be a full Git object ID when "
                "--diff-head is set.",
            )

    base_ref = _resolve_base_ref(repo_path, diff_base, env)
    # Resolve the base once; merge-base and the diff range below only consume
    # the resolved object ID, never the raw ref expression.
    base_revision = _resolve_commit_sha(repo_path, base_ref, "missing_base")

    try:
        merge_base_result = _run_git_command(
            repo_path, ["merge-base", base_revision, head_revision], check=False
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SourcePreflightError(
            "insufficient_history",
            f"Unable to compute merge-base against '{base_ref}' for '{source_path}': {e}",
        ) from e
    if merge_base_result.returncode != 0:
        stderr = merge_base_result.stderr.strip()
        raise SourcePreflightError(
            "insufficient_history",
            f"Unable to compute merge-base against '{base_ref}' for '{source_path}'. "
            f"{stderr or 'Ensure the base branch history is fetched and reachable.'}",
        )

    merge_base = merge_base_result.stdout.strip()
    if not merge_base:
        raise SourcePreflightError(
            "insufficient_history",
            f"Unable to compute merge-base against '{base_ref}' for '{source_path}'. "
            "Ensure the base branch history is fetched and reachable.",
        )

    try:
        diff_result = _run_git_command_raw(
            repo_path,
            [
                "diff",
                "--name-status",
                "-z",
                "--find-renames",
                "--find-copies",
                f"{merge_base}...{head_revision}",
            ],
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SourcePreflightError(
            "insufficient_history",
            f"Unable to resolve changed files for '{source_path}': {e}",
        ) from e
    if diff_result.returncode != 0:
        stderr = diff_result.stderr.decode("utf-8", errors="replace").strip()
        raise SourcePreflightError(
            "insufficient_history",
            f"Unable to resolve changed files for '{source_path}'. "
            f"{stderr or 'Ensure the repository has enough history for diff-scope.'}",
        )

    entries = _parse_name_status_z(diff_result.stdout)
    classified = _classify_diff_entries(entries)

    worktree_dirty, snapshot_digest = _worktree_snapshot_state(repo_path)
    if diff_head and worktree_dirty is not False:
        raise SourcePreflightError(
            "dirty_asserted_head",
            "The asserted diff head is immutable, but the local checkout is "
            "dirty or could not be confirmed clean. Confirm a clean checkout "
            "before scanning this recorded comparison.",
        )

    context_files: list[str] = []
    context_seen: set[str] = set()
    for deleted in classified["deleted_files"]:
        _append_unique(context_files, context_seen, deleted)
    for rename in classified["renamed_files"]:
        old_path = rename.get("old_path")
        if isinstance(old_path, str):
            _append_unique(context_files, context_seen, old_path)
    for copied in classified["copied_files"]:
        old_path = copied.get("old_path")
        if isinstance(old_path, str):
            _append_unique(context_files, context_seen, old_path)

    return RepoDiffScope(
        source_path=source_path,
        workspace_subdir=workspace_subdir,
        base_ref=base_ref,
        merge_base=merge_base,
        added_files=classified["added_files"],
        modified_files=classified["modified_files"],
        renamed_files=classified["renamed_files"],
        deleted_files=classified["deleted_files"],
        analyzable_files=classified["analyzable_files"],
        copied_files=classified["copied_files"],
        base_revision=base_revision,
        head_revision=head_revision,
        requested_base=requested_base,
        requested_head=diff_head,
        worktree_dirty=worktree_dirty,
        snapshot_digest=snapshot_digest,
        context_files=context_files,
    )


def resolve_diff_scope_context(
    local_sources: list[dict[str, str]],
    scope_mode: str,
    diff_base: str | None,
    non_interactive: bool,
    env: dict[str, str] | None = None,
    diff_head: str | None = None,
) -> DiffScopeResult:
    if scope_mode not in _SUPPORTED_SCOPE_MODES:
        raise ValueError(f"Unsupported scope mode: {scope_mode}")

    env_map = dict(os.environ if env is None else env)

    if scope_mode == "full":
        repos: list[dict[str, Any]] = []
        for source in local_sources:
            source_path = source.get("source_path")
            if not source_path:
                continue
            repo_path = Path(source_path)
            dirty: bool | None = None
            digest: str | None = None
            head: str | None = None
            if _is_git_repo(repo_path):
                dirty, digest = _worktree_snapshot_state(repo_path)
                try:
                    result = _run_git_command(repo_path, ["rev-parse", "HEAD"], check=False)
                    if result.returncode == 0:
                        head = result.stdout.strip() or None
                except (OSError, subprocess.SubprocessError):
                    pass
            repos.append(
                {
                    "workspace_subdir": source.get("workspace_subdir"),
                    "head_revision": head,
                    "worktree_dirty": dirty,
                    "snapshot_digest": digest,
                    "snapshot_digest_stage": "preflight" if digest else None,
                }
            )
        return DiffScopeResult(
            active=False,
            mode=scope_mode,
            metadata={"active": False, "mode": scope_mode, "repos": repos},
        )

    if scope_mode == "auto":
        should_activate = _should_activate_auto_scope(local_sources, non_interactive, env_map)
        if not should_activate:
            return DiffScopeResult(
                active=False,
                mode=scope_mode,
                metadata={"active": False, "mode": scope_mode},
            )

    if not local_sources:
        raise ValueError("Diff-scope is active, but no local repository targets were provided.")

    repo_scopes: list[RepoDiffScope] = []
    skipped_non_git: list[str] = []
    skipped_diff_scope: list[str] = []
    for source in local_sources:
        source_path = source.get("source_path")
        if not source_path:
            continue
        if not _is_git_repo(Path(source_path)):
            skipped_non_git.append(source_path)
            continue
        try:
            repo_scopes.append(_resolve_repo_diff_scope(source, diff_base, env_map, diff_head))
        except ValueError as e:
            # Auto-mode may degrade to a full snapshot for heuristic inputs —
            # but never when an immutable head was asserted. An explicit
            # Review Changes comparison fails closed instead of silently
            # analyzing the wrong revision.
            if scope_mode == "auto" and diff_head is None:
                skipped_diff_scope.append(f"{source_path} (diff-scope skipped: {e})")
                continue
            raise

    if not repo_scopes:
        if scope_mode == "auto" and diff_head is None:
            metadata: dict[str, Any] = {"active": False, "mode": scope_mode}
            if skipped_non_git:
                metadata["skipped_non_git_sources"] = skipped_non_git
            if skipped_diff_scope:
                metadata["skipped_diff_scope_sources"] = skipped_diff_scope
            return DiffScopeResult(active=False, mode=scope_mode, metadata=metadata)

        raise ValueError(
            "Diff-scope is active, but no Git repositories were found. "
            "Use --scope-mode full to disable diff-scope for this run."
        )

    instruction_block = build_diff_scope_instruction(repo_scopes)
    total_analyzable = sum(len(scope.analyzable_files) for scope in repo_scopes)
    total_deleted = sum(len(scope.deleted_files) for scope in repo_scopes)
    # Modified already includes copies and low-similarity renames.
    total_changed = sum(
        len(scope.analyzable_files) + len(scope.deleted_files) for scope in repo_scopes
    )
    metadata = {
        "active": True,
        "mode": scope_mode,
        "requested_base": diff_base,
        "requested_head": diff_head,
        "repos": [scope.to_metadata() for scope in repo_scopes],
        "total_repositories": len(repo_scopes),
        "total_analyzable_files": total_analyzable,
        "total_deleted_files": total_deleted,
        "total_changed_files": total_changed,
        "limits": {"max_files_per_section": _MAX_FILES_PER_SECTION},
    }
    if total_analyzable == 0:
        # Explicit applicability accounting: an empty analyzable diff is a
        # no-change receipt (no provider calls), and deleted-only diffs record
        # the deleted paths as context-only rather than silently scanning.
        metadata["no_change"] = True
        metadata["no_change_reason"] = "empty_diff" if total_changed == 0 else "no_analyzable_files"
    if skipped_non_git:
        metadata["skipped_non_git_sources"] = skipped_non_git
    if skipped_diff_scope:
        metadata["skipped_diff_scope_sources"] = skipped_diff_scope

    return DiffScopeResult(
        active=True,
        mode=scope_mode,
        instruction_block=instruction_block,
        metadata=metadata,
    )


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
