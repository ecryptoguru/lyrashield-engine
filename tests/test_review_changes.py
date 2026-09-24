"""Review Changes: immutable revision acquisition and diff-scope provenance.

Coverage for the engine half of the Review Changes workflow:

- ``--repository-revision``/``--diff-head`` accept only full lowercase hex
  object IDs (40 or 64 chars) — never branches, tags, abbreviated SHAs, or
  ref strings with option-injection potential.
- Source acquisition pins the checkout to the recorded revision
  (``checkout --detach`` + ``rev-parse HEAD`` assertion), treats a branch as
  a fetch hint only, performs one bounded fetch for missing objects, and
  fails closed with a named preflight error.
- Diff-scope records requested base/head, resolved revisions, merge base,
  analyzed files, context-only files, and limits as run provenance; an empty
  analyzable diff short-circuits to a no-change receipt with zero provider
  calls.

All Git operations run against ``git init`` fixtures in ``tmp_path`` or are
mocked — no network is touched.
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import sys
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

import lyrashield.interface.utils as interface_utils
from lyrashield.interface.utils import (
    SourcePreflightError,
    clone_repository,
    resolve_diff_scope_context,
    validate_git_object_id,
)


cli_main: Any = import_module("lyrashield.interface.main")

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_F = "f" * 40
SHA64 = "ab" * 32


# ---------------------------------------------------------------------------
# Git fixture helpers (all local — file paths and git init only)
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # nosec B603
        ["git", "-C", str(repo), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


def _init_repo(path: Path) -> Path:
    repo = path / "repo"
    repo.mkdir()
    subprocess.run(  # noqa: S603  # nosec B603
        ["git", "init", "-b", "main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def _commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message, "--allow-empty")
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _sources(repo: Path) -> list[dict[str, Any]]:
    return [{"source_path": str(repo), "workspace_subdir": "repo", "mount": False}]


@pytest.fixture
def diff_repo(tmp_path: Path) -> dict[str, Any]:
    """Two-commit repo: base on main, feature branch with add/modify/delete/
    rename/copy changes."""
    repo = _init_repo(tmp_path)
    (repo / "keep.py").write_text("print('v1')\n", encoding="utf-8")
    (repo / "deleted.py").write_text("gone\n", encoding="utf-8")
    (repo / "old_name.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "shared.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    base = _commit_all(repo, "base")

    _git(repo, "checkout", "-b", "feature")
    (repo / "keep.py").write_text("print('v2')\nprint('extra')\n", encoding="utf-8")
    (repo / "added.py").write_text("new file\n", encoding="utf-8")
    (repo / "deleted.py").unlink()
    _git(repo, "mv", "old_name.py", "renamed.py")
    (repo / "copied.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    head = _commit_all(repo, "feature work")
    return {"path": repo, "base": base, "head": head}


# ---------------------------------------------------------------------------
# Object-ID validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sha", [SHA_A, SHA64])
def test_validate_git_object_id_accepts_full_hex(sha: str) -> None:
    assert validate_git_object_id(sha) == sha


@pytest.mark.parametrize(
    "value",
    [
        "abc123",  # abbreviated SHA
        "main",  # branch name
        "origin/main",  # ref path
        "HEAD",
        "HEAD~1",
        "main@{u}",
        "refs/heads/main",
        "A" * 40,  # uppercase rejected — stored plans use lowercase
        "g" * 40,  # non-hex
        "a" * 39,
        "a" * 41,
        "a" * 63,
        "-x",  # option-shaped
        "--upload-pack=evil",
        f"{SHA_A};rm -rf /",
        "$(id)",
        f"{SHA_A} extra",
        "",
    ],
)
def test_validate_git_object_id_rejects_untrusted_refs(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="full 40- or 64-character"):
        validate_git_object_id(value)


# ---------------------------------------------------------------------------
# CLI flag wiring
# ---------------------------------------------------------------------------


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _parse(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> Any:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["lyrashield", *argv])
    return cli_main.parse_arguments()


_REPO = "https://github.com/org/repo.git"


def test_help_lists_revision_flags(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["lyrashield", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        cli_main.parse_arguments()
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "--repository-revision" in out
    assert "--diff-head" in out


def test_repository_revision_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse(monkeypatch, ["-t", _REPO, "--repository-revision", SHA_A, "-n"])
    assert args.repository_revision == SHA_A


def test_diff_head_requires_diff_base(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(monkeypatch, ["-t", _REPO, "--diff-head", SHA_B, "-n"])
    assert exc_info.value.code == 2
    assert "--diff-head requires --diff-base" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv_tail",
    [
        ["--scope-mode", "diff"],
        ["--scope-mode", "diff", "--diff-base", SHA_A],
        ["--scope-mode", "diff", "--diff-head", SHA_B],
    ],
)
def test_scope_mode_diff_requires_both_revisions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv_tail: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(monkeypatch, ["-t", _REPO, "-n", *argv_tail])
    assert exc_info.value.code == 2
    assert "--diff-base" in capsys.readouterr().err


def test_scope_mode_diff_with_both_revisions_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse(
        monkeypatch,
        [
            "-t",
            _REPO,
            "--scope-mode",
            "diff",
            "--diff-base",
            SHA_A,
            "--diff-head",
            SHA_B,
            "-n",
        ],
    )
    assert args.diff_base == SHA_A
    assert args.diff_head == SHA_B
    assert args.scope_mode == "diff"


def test_revision_and_head_must_agree(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(
            monkeypatch,
            [
                "-t",
                _REPO,
                "--scope-mode",
                "diff",
                "--diff-base",
                SHA_A,
                "--diff-head",
                SHA_B,
                "--repository-revision",
                SHA_F,
                "-n",
            ],
        )
    assert exc_info.value.code == 2
    assert "must name the same commit" in capsys.readouterr().err


def test_sha_branch_conflicts_with_revision(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(
            monkeypatch,
            [
                "-t",
                _REPO,
                "--repository-branch",
                SHA_B,
                "--repository-revision",
                SHA_A,
                "-n",
            ],
        )
    assert exc_info.value.code == 2
    assert "conflicts with --repository-revision" in capsys.readouterr().err


def test_repository_revision_requires_repository_target(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(
            monkeypatch,
            ["-t", str(tmp_path), "--repository-revision", SHA_A, "-n"],
        )
    assert exc_info.value.code == 2
    assert "requires at least one repository target" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--repository-revision", "--diff-head"])
def test_revision_flags_reject_resume(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    argv = ["--resume", "old-run", flag, SHA_A]
    if flag == "--diff-head":
        argv += ["--diff-base", SHA_B]
    with pytest.raises(SystemExit) as exc_info:
        _parse(monkeypatch, argv)
    assert exc_info.value.code == 2
    assert "--resume" in capsys.readouterr().err


def test_diff_base_must_be_object_id_when_head_set(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(
            monkeypatch,
            [
                "-t",
                _REPO,
                "--scope-mode",
                "diff",
                "--diff-base",
                "main",
                "--diff-head",
                SHA_B,
                "-n",
            ],
        )
    assert exc_info.value.code == 2
    assert "--diff-base" in capsys.readouterr().err


def test_scope_mode_full_needs_no_revisions(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse(monkeypatch, ["-t", _REPO, "--scope-mode", "full", "-n"])
    assert args.scope_mode == "full"


# ---------------------------------------------------------------------------
# Source acquisition (mocked git argv — no network)
# ---------------------------------------------------------------------------


def _clone_env(tmp_path: Path) -> Any:
    return (
        patch.object(interface_utils, "_git_executable", return_value="/usr/bin/git"),
        patch.object(interface_utils.tempfile, "gettempdir", return_value=str(tmp_path)),
    )


def _ok(argv: list[str], stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


def test_clone_revision_detaches_and_asserts_head(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_B}\n")
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with env1, env2, patch.object(interface_utils.subprocess, "run", side_effect=fake_run) as run:
        clone_repository("https://github.com/org/repo", "rev-run", revision=SHA_B)

    clone_argv = run.call_args_list[0].args[0]
    assert clone_argv[:3] == ["/usr/bin/git", "clone", "--no-checkout"]
    # A SHA must never reach --branch/--single-branch.
    assert "--branch" not in clone_argv
    assert "--single-branch" not in clone_argv
    # Bounded acquisition: the clone subprocess carries a timeout.
    assert run.call_args_list[0].kwargs.get("timeout", 0) > 0
    checkout_argv = run.call_args_list[1].args[0]
    assert checkout_argv[-3:] == ["checkout", "--detach", SHA_B]
    rev_parse_argv = run.call_args_list[2].args[0]
    assert rev_parse_argv[-2:] == ["rev-parse", "HEAD"]


def test_clone_revision_treats_branch_as_fetch_hint_only(tmp_path: Path) -> None:
    """A moving branch name never reaches the checkout path when a revision pins it."""

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_B}\n")
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with env1, env2, patch.object(interface_utils.subprocess, "run", side_effect=fake_run) as run:
        clone_repository(
            "https://github.com/org/repo",
            "hint-run",
            branch="main",
            revision=SHA_B,
        )

    clone_argv = run.call_args_list[0].args[0]
    assert "main" not in clone_argv
    assert "--branch" not in clone_argv
    assert "--single-branch" not in clone_argv


def test_real_moving_branch_still_checks_out_recorded_snapshot(tmp_path: Path) -> None:
    """A saved snapshot keeps commit A after its advertised branch moves to B."""
    remote = _init_repo(tmp_path)
    (remote / "app.py").write_text("version = 'A'\n", encoding="utf-8")
    recorded_revision = _commit_all(remote, "recorded plan")
    (remote / "app.py").write_text("version = 'B'\n", encoding="utf-8")
    _commit_all(remote, "moved branch")

    with patch.object(interface_utils.tempfile, "gettempdir", return_value=str(tmp_path)):
        acquired = Path(
            clone_repository(
                str(remote),
                "moving-branch",
                branch="main",
                revision=recorded_revision,
            )
        )

    assert _git(acquired, "rev-parse", "HEAD").stdout.strip() == recorded_revision
    assert (acquired / "app.py").read_text(encoding="utf-8") == "version = 'A'\n"


def test_clone_missing_revision_fetches_then_detaches(tmp_path: Path) -> None:
    """An unadvertised head (e.g. force-pushed) triggers one bounded fetch."""
    state = {"fetched": False}

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "fetch" in argv:
            state["fetched"] = True
            return _ok(argv)
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_B}\n")
        if "rev-parse" in argv:
            # rev-parse --verify <sha>^{commit} fails until the fetch lands.
            return subprocess.CompletedProcess(argv, 0 if state["fetched"] else 1, "", "")
        if "checkout" in argv:
            return subprocess.CompletedProcess(
                argv, 0 if state["fetched"] else 1, "", "unknown revision"
            )
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with env1, env2, patch.object(interface_utils.subprocess, "run", side_effect=fake_run) as run:
        clone_repository("https://github.com/org/repo", "fetch-run", revision=SHA_B)

    fetch_calls = [c.args[0] for c in run.call_args_list if "fetch" in c.args[0]]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][-3:] == ["fetch", "origin", SHA_B]
    checkout_calls = [c.args[0] for c in run.call_args_list if "checkout" in c.args[0]]
    assert len(checkout_calls) == 2


def test_clone_missing_revision_is_named_preflight_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_B}\n")
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "unknown object")
        if "checkout" in argv or "fetch" in argv:
            return subprocess.CompletedProcess(argv, 128, "", "remote: not found")
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with (
        env1,
        env2,
        patch.object(interface_utils.subprocess, "run", side_effect=fake_run),
        pytest.raises(SystemExit) as exc_info,
    ):
        clone_repository("https://github.com/org/repo", "gone-run", revision=SHA_B)

    assert exc_info.value.code == 1
    assert "missing_revision" in capsys.readouterr().out


def test_clone_checkout_mismatch_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """HEAD must equal the requested revision — a mismatched checkout exits."""

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_F}\n")  # wrong revision checked out
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with (
        env1,
        env2,
        patch.object(interface_utils.subprocess, "run", side_effect=fake_run),
        pytest.raises(SystemExit) as exc_info,
    ):
        clone_repository("https://github.com/org/repo", "mismatch-run", revision=SHA_B)

    assert exc_info.value.code == 1
    assert "checkout_mismatch" in capsys.readouterr().out


def test_clone_required_base_commit_fetched_when_missing(tmp_path: Path) -> None:
    """The recorded diff base is fetched if the clone does not already have it."""
    state = {"fetched": False}

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "fetch" in argv:
            state["fetched"] = True
            return _ok(argv)
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_B}\n")
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0 if state["fetched"] else 1, "", "")
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with env1, env2, patch.object(interface_utils.subprocess, "run", side_effect=fake_run) as run:
        clone_repository(
            "https://github.com/org/repo",
            "base-run",
            revision=SHA_B,
            required_commits=(SHA_A,),
        )

    fetch_calls = [c.args[0] for c in run.call_args_list if "fetch" in c.args[0]]
    assert fetch_calls and fetch_calls[0][-3:] == ["fetch", "origin", SHA_A]
    # Bounded: the fetch carries a timeout.
    fetch_call = next(c for c in run.call_args_list if "fetch" in c.args[0])
    assert fetch_call.kwargs.get("timeout", 0) > 0


def test_clone_missing_base_is_named_preflight_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A force-pushed base that cannot be fetched fails closed."""

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in argv and "HEAD" in argv:
            return _ok(argv, stdout=f"{SHA_B}\n")
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "")
        if "fetch" in argv:
            return subprocess.CompletedProcess(argv, 128, "", "not our ref")
        return _ok(argv)

    env1, env2 = _clone_env(tmp_path)
    with (
        env1,
        env2,
        patch.object(interface_utils.subprocess, "run", side_effect=fake_run),
        pytest.raises(SystemExit) as exc_info,
    ):
        clone_repository(
            "https://github.com/org/repo",
            "basegone-run",
            revision=SHA_B,
            required_commits=(SHA_A,),
        )

    assert exc_info.value.code == 1
    assert "missing_base" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Diff-scope against real local git fixtures
# ---------------------------------------------------------------------------


def test_diff_scope_records_revisions_and_classification(diff_repo: dict[str, Any]) -> None:
    result = resolve_diff_scope_context(
        _sources(diff_repo["path"]),
        "diff",
        diff_repo["base"],
        non_interactive=True,
        env={},
        diff_head=diff_repo["head"],
    )

    assert result.active
    meta = result.metadata
    assert meta["requested_base"] == diff_repo["base"]
    assert meta["requested_head"] == diff_repo["head"]
    assert meta["limits"]["max_files_per_section"] > 0
    assert "no_change" not in meta

    scope = meta["repos"][0]
    # The effective comparison is merge_base -> head, recorded honestly.
    assert scope["merge_base"] == diff_repo["base"]
    assert scope["base_revision"] == diff_repo["base"]
    assert scope["head_revision"] == diff_repo["head"]
    assert scope["worktree_dirty"] is False
    assert scope["snapshot_digest"] is None

    assert set(scope["analyzable_files"]) >= {
        "added.py",
        "keep.py",
        "renamed.py",
        "copied.py",
    }
    assert scope["deleted_files"] == ["deleted.py"]
    assert scope["renamed_files"][0]["old_path"] == "old_name.py"
    assert scope["renamed_files"][0]["new_path"] == "renamed.py"
    # Deleted paths and rename/copy sources are context-only provenance.
    assert "deleted.py" in scope["context_files"]
    assert "old_name.py" in scope["context_files"]
    assert "deleted.py" not in scope["analyzable_files"]


def test_diff_scope_detects_copied_files(diff_repo: dict[str, Any]) -> None:
    result = resolve_diff_scope_context(
        _sources(diff_repo["path"]),
        "diff",
        diff_repo["base"],
        non_interactive=True,
        env={},
        diff_head=diff_repo["head"],
    )
    scope = result.metadata["repos"][0]
    # Whether Git labels it A or C, a copied file is always analyzable.
    assert "copied.py" in scope["analyzable_files"]


def test_copied_status_entries_are_classified_and_recorded() -> None:
    # C-status entries (detected with --find-copies when the source is also
    # modified) keep their source path as related context.
    raw = b"C85\x00old_src.py\x00new_copy.py\x00D\x00gone.py\x00M\x00mod.py\x00"
    entries = interface_utils._parse_name_status_z(raw)
    classified = interface_utils._classify_diff_entries(entries)

    assert classified["copied_files"] == [
        {"old_path": "old_src.py", "new_path": "new_copy.py", "similarity": 85}
    ]
    assert "new_copy.py" in classified["analyzable_files"]
    assert classified["deleted_files"] == ["gone.py"]


def test_identical_revisions_produce_no_change_receipt(diff_repo: dict[str, Any]) -> None:
    head = diff_repo["head"]
    result = resolve_diff_scope_context(
        _sources(diff_repo["path"]),
        "diff",
        head,
        non_interactive=True,
        env={},
        diff_head=head,
    )

    meta = result.metadata
    assert meta["no_change"] is True
    assert meta["no_change_reason"] == "empty_diff"
    assert meta["total_analyzable_files"] == 0
    scope = meta["repos"][0]
    assert scope["merge_base"] == head  # merge-base(head, head) == head


def test_deleted_only_diff_gets_applicability_accounting(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "only.py").write_text("x\n", encoding="utf-8")
    base = _commit_all(repo, "base")
    (repo / "only.py").unlink()
    head = _commit_all(repo, "delete it")

    result = resolve_diff_scope_context(
        _sources(repo), "diff", base, non_interactive=True, env={}, diff_head=head
    )

    meta = result.metadata
    assert meta["no_change"] is True
    assert meta["no_change_reason"] == "no_analyzable_files"
    assert meta["total_deleted_files"] == 1
    scope = meta["repos"][0]
    assert scope["deleted_files"] == ["only.py"]
    assert scope["analyzable_files"] == []
    assert scope["context_files"] == ["only.py"]


def _different_sha(sha: str) -> str:
    return ("0" if sha[0] != "0" else "1") + sha[1:]


def test_head_mismatch_rejects_review_changes(diff_repo: dict[str, Any]) -> None:
    other = _different_sha(diff_repo["head"])  # valid shape, wrong revision
    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(diff_repo["path"]),
            "diff",
            diff_repo["base"],
            non_interactive=True,
            env={},
            diff_head=other,
        )
    assert exc_info.value.reason == "head_mismatch"


def test_missing_base_is_named_preflight_failure(diff_repo: dict[str, Any]) -> None:
    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(diff_repo["path"]),
            "diff",
            SHA_F,  # never existed in this repo
            non_interactive=True,
            env={},
            diff_head=diff_repo["head"],
        )
    assert exc_info.value.reason == "missing_base"


def test_shallow_repo_is_named_preflight_failure(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("x\n", encoding="utf-8")
    _commit_all(repo, "one")
    shallow = tmp_path / "shallow"
    subprocess.run(  # noqa: S603  # nosec B603
        ["git", "clone", "--depth", "1", f"file://{repo}", str(shallow)],  # noqa: S607
        check=True,
        capture_output=True,
    )

    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(shallow), "diff", SHA_A, non_interactive=True, env={}, diff_head=SHA_B
        )
    assert exc_info.value.reason == "insufficient_history"


def test_unrelated_base_history_is_named_preflight_failure(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("x\n", encoding="utf-8")
    head = _commit_all(repo, "main work")
    _git(repo, "checkout", "--orphan", "unrelated")
    _git(repo, "rm", "-rf", ".")
    (repo / "other.py").write_text("y\n", encoding="utf-8")
    orphan = _commit_all(repo, "orphan")
    _git(repo, "checkout", "main")

    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(repo), "diff", orphan, non_interactive=True, env={}, diff_head=head
        )
    assert exc_info.value.reason == "insufficient_history"


def test_dirty_worktree_gets_snapshot_digest(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    base = _commit_all(repo, "base")
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("new\n", encoding="utf-8")
    head = _commit_all(repo, "head")
    # Uncommitted content on top of the recorded head.
    (repo / "a.py").write_text("x = 3  # dirty\n", encoding="utf-8")
    (repo / "untracked.py").write_text("scratch\n", encoding="utf-8")

    result = resolve_diff_scope_context(_sources(repo), "diff", base, non_interactive=True, env={})

    scope = result.metadata["repos"][0]
    assert scope["head_revision"] == head
    assert scope["worktree_dirty"] is True
    assert scope["snapshot_digest"].startswith("sha256:")
    # Honest provenance: the instruction block tells the agent the analyzed
    # content is the working tree, not the recorded commit.
    assert "uncommitted changes" in result.instruction_block

    # Untracked bytes, not just their names, distinguish dirty preflight states.
    first_digest = scope["snapshot_digest"]
    (repo / "untracked.py").write_text("different scratch\n", encoding="utf-8")
    changed = resolve_diff_scope_context(_sources(repo), "diff", base, non_interactive=True, env={})
    assert changed.metadata["repos"][0]["snapshot_digest"] != first_digest

    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(repo), "diff", base, non_interactive=True, env={}, diff_head=head
        )
    assert exc_info.value.reason == "dirty_asserted_head"


def test_asserted_diff_rejects_unverified_worktree_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text("base\n", encoding="utf-8")
    base = _commit_all(repo, "base")
    (repo / "app.py").write_text("changed\n", encoding="utf-8")
    head = _commit_all(repo, "head")
    original = interface_utils._run_git_command_raw

    def failed_status(path: Path, args: list[str], **kwargs: Any) -> Any:
        if args[:2] == ["status", "--porcelain=v1"]:
            return subprocess.CompletedProcess(args, 1, b"", b"status unavailable")
        return original(path, args, **kwargs)

    monkeypatch.setattr(interface_utils, "_run_git_command_raw", failed_status)
    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(repo), "diff", base, non_interactive=True, env={}, diff_head=head
        )
    assert exc_info.value.reason == "dirty_asserted_head"


def test_full_scope_records_dirty_local_source_before_upload(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text("base\n", encoding="utf-8")
    head = _commit_all(repo, "base")
    (repo / "app.py").write_text("dirty\n", encoding="utf-8")

    result = resolve_diff_scope_context(_sources(repo), "full", None, non_interactive=True)

    assert result.active is False
    source = result.metadata["repos"][0]
    assert source["head_revision"] == head
    assert source["worktree_dirty"] is True
    assert source["snapshot_digest_stage"] == "preflight"


def test_unsafe_base_ref_cannot_inject_options(diff_repo: dict[str, Any]) -> None:
    """``--all`` must never reach ``git merge-base`` as an option."""
    with pytest.raises(SourcePreflightError, match="Unsafe or empty revision"):
        interface_utils._resolve_repo_diff_scope(_sources(diff_repo["path"])[0], "--all", {})


def test_unsafe_base_ref_under_diff_head_is_named_failure(
    diff_repo: dict[str, Any],
) -> None:
    """Under an asserted head, a non-object-ID base fails closed at the
    immutable-input check before any Git invocation consumes it."""
    with pytest.raises(SourcePreflightError) as exc_info:
        interface_utils._resolve_repo_diff_scope(
            _sources(diff_repo["path"])[0], "--all", {}, diff_head=diff_repo["head"]
        )
    assert exc_info.value.reason == "invalid_base"


def test_diff_scope_with_head_rejects_non_sha_base(diff_repo: dict[str, Any]) -> None:
    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(diff_repo["path"]),
            "diff",
            "main",  # moving ref — not an immutable revision
            non_interactive=True,
            env={},
            diff_head=diff_repo["head"],
        )
    assert exc_info.value.reason == "invalid_base"


def test_auto_mode_fails_closed_when_head_asserted(diff_repo: dict[str, Any]) -> None:
    """Auto mode may skip heuristic inputs, but never an asserted Review
    Changes head — that would silently analyze the wrong revision."""
    other = _different_sha(diff_repo["head"])
    env = {"CI": "1", "GITHUB_BASE_REF": "main"}
    with pytest.raises(SourcePreflightError) as exc_info:
        resolve_diff_scope_context(
            _sources(diff_repo["path"]),
            "auto",
            diff_repo["base"],
            non_interactive=True,
            env=env,
            diff_head=other,
        )
    assert exc_info.value.reason == "head_mismatch"


def test_auto_mode_without_head_still_skips_unsuitable_repo(tmp_path: Path) -> None:
    """Legacy degrade: auto mode with no asserted head keeps skipping a repo
    that cannot support diff-scope."""
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("x\n", encoding="utf-8")
    _commit_all(repo, "one")
    shallow = tmp_path / "shallow"
    subprocess.run(  # noqa: S603  # nosec B603
        ["git", "clone", "--depth", "1", f"file://{repo}", str(shallow)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    env = {"CI": "1", "GITHUB_BASE_REF": "main"}

    result = resolve_diff_scope_context(
        _sources(shallow), "auto", None, non_interactive=True, env=env
    )
    assert result.active is False
    assert result.metadata["skipped_diff_scope_sources"]


def test_weird_filenames_survive_null_delimited_parsing(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "seed.py").write_text("x\n", encoding="utf-8")
    base = _commit_all(repo, "base")
    weird = [
        "sp ace.py",
        "quote'file.py",
        'double"quote.py',
        "uni-üñíçødé.py",
        "--flags.py",
        "dollar$ign.py",
    ]
    for name in weird:
        (repo / name).write_text("x = 1\n", encoding="utf-8")
    head = _commit_all(repo, "weird names")

    result = resolve_diff_scope_context(
        _sources(repo), "diff", base, non_interactive=True, env={}, diff_head=head
    )

    scope = result.metadata["repos"][0]
    assert set(scope["added_files"]) == set(weird)
    assert set(scope["analyzable_files"]) == set(weird)


# ---------------------------------------------------------------------------
# main(): no-change receipt with zero provider calls
# ---------------------------------------------------------------------------


def _stub_main_env(monkeypatch: pytest.MonkeyPatch, run_cli: Any) -> dict[str, Mock]:
    mocks = {
        "validate_environment": Mock(),
        "check_docker_installed": Mock(),
        "pull_docker_image": Mock(),
        "warm_up_llm": Mock(),
        "run_cli": run_cli,
        "posthog": Mock(),
        "scarf": Mock(),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(cli_main, name, mock)
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(
            llm=SimpleNamespace(model="openai/gpt-5.6-terra"),
            runtime=SimpleNamespace(max_local_copy_mb=1024, backend="docker", image="img"),
        ),
    )
    return mocks


def test_empty_diff_exits_with_no_change_receipt_and_no_provider_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("x\n", encoding="utf-8")
    head = _commit_all(repo, "only commit")

    runs_root = tmp_path / "runsroot"
    runs_root.mkdir()
    monkeypatch.chdir(runs_root)

    run_cli = AsyncMock()
    mocks = _stub_main_env(monkeypatch, run_cli)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(repo),
            "--target-type",
            "local_code",
            "--scope-mode",
            "diff",
            "--diff-base",
            head,
            "--diff-head",
            head,
            "--run-name",
            "nochange1",
            "-n",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli_main.main()

    assert exc_info.value.code == 0
    # The no-change receipt never reaches the LLM path.
    run_cli.assert_not_called()
    mocks["warm_up_llm"].assert_not_called()
    mocks["posthog"].start.assert_not_called()

    record = json.loads(
        (runs_root / "strix_runs" / "nochange1" / "run.json").read_text(encoding="utf-8")
    )
    assert record["status"] == "completed"
    assert record["terminal_reason"] == "no_change"
    assert record["diff_head"] == head
    assert record["diff_base"] == head
    assert record["scope_mode"] == "diff"
    assert record["diff_scope"]["no_change"] is True
    assert record["llm_usage"]["requests"] == 0


def test_snapshot_cli_uses_saved_revision_after_branch_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker's saved SNAPSHOT argv reaches the real pinned checkout."""
    remote = _init_repo(tmp_path)
    (remote / "app.py").write_text("version = 'A'\n", encoding="utf-8")
    recorded_revision = _commit_all(remote, "recorded plan")
    (remote / "app.py").write_text("version = 'B'\n", encoding="utf-8")
    _commit_all(remote, "moved branch")

    observed: dict[str, str] = {}

    async def inspect_cli(args: argparse.Namespace) -> None:
        source = Path(args.local_sources[0]["source_path"])
        observed["head"] = _git(source, "rev-parse", "HEAD").stdout.strip()
        observed["input"] = (source / "app.py").read_text(encoding="utf-8")

    _stub_main_env(monkeypatch, inspect_cli)
    monkeypatch.setattr(cli_main, "_non_interactive_exit_code", lambda _s: 0)
    real_clone = cli_main.clone_repository

    def clone_local(_url: str, *args: Any, **kwargs: Any) -> str:
        return real_clone(str(remote), *args, **kwargs)

    monkeypatch.setattr(cli_main, "clone_repository", clone_local)
    monkeypatch.setattr(interface_utils.tempfile, "gettempdir", lambda: str(tmp_path))
    runs_root = tmp_path / "runsroot"
    runs_root.mkdir()
    monkeypatch.chdir(runs_root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            "https://github.com/org/repo.git",
            "--target-type",
            "repository",
            "--repository-branch",
            "main",
            "--repository-revision",
            recorded_revision,
            "--scope-mode",
            "full",
            "--run-name",
            "snapshot1",
            "-n",
        ],
    )

    cli_main.main()

    assert observed == {"head": recorded_revision, "input": "version = 'A'\n"}
    record = json.loads(
        (runs_root / "strix_runs" / "snapshot1" / "run.json").read_text(encoding="utf-8")
    )
    assert record["scope_mode"] == "full"
    assert record["repository_revision"] == recorded_revision


def test_repository_revision_and_diff_flags_reach_guarded_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diff_repo: dict[str, Any]
) -> None:
    """The worker's Review Changes argv lands on the existing clone path —
    revision pinned, base required — never a second unchecked path."""
    base = diff_repo["base"]
    head = diff_repo["head"]
    clone = Mock(return_value=str(diff_repo["path"]))
    mocks = _stub_main_env(monkeypatch, AsyncMock())
    monkeypatch.setattr(cli_main, "clone_repository", clone)
    monkeypatch.setattr(cli_main, "_non_interactive_exit_code", lambda _s: 0)
    monkeypatch.setattr(cli_main, "get_global_report_state", lambda: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            _REPO,
            "--repository-revision",
            head,
            "--scope-mode",
            "diff",
            "--diff-base",
            base,
            "--diff-head",
            head,
            "--run-name",
            "review1",
            "-n",
        ],
    )
    runs_root = tmp_path / "runsroot"
    runs_root.mkdir()
    monkeypatch.chdir(runs_root)

    cli_main.main()

    clone.assert_called_once()
    _, kwargs = clone.call_args
    assert kwargs["revision"] == head
    assert kwargs["required_commits"] == (base,)
    mocks["run_cli"].assert_called_once()

    # Run provenance: requested/resolved revisions and the effective merge
    # base are all recorded in run.json.
    record = json.loads(
        (runs_root / "strix_runs" / "review1" / "run.json").read_text(encoding="utf-8")
    )
    assert record["repository_revision"] == head
    assert record["diff_head"] == head
    assert record["diff_base"] == base
    repo_meta = record["diff_scope"]["repos"][0]
    assert repo_meta["merge_base"] == base
    assert repo_meta["head_revision"] == head
    assert repo_meta["requested_head"] == head
    assert repo_meta["requested_base"] == base
