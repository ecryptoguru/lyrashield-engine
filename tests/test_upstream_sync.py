from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-upstream.sh"


def git(cwd: Path, *args: str) -> str:
    git_executable = shutil.which("git")
    assert git_executable is not None, "git must be available for upstream sync tests"
    return subprocess.run(  # noqa: S603
        [git_executable, *args], cwd=cwd, check=True, text=True, capture_output=True
    ).stdout.strip()


def commit(repo: Path, message: str, contents: str) -> str:
    (repo / "marker.txt").write_text(contents, encoding="utf-8")
    git(repo, "add", "marker.txt")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def make_repositories(tmp_path: Path) -> tuple[Path, Path, str]:
    upstream = tmp_path / "upstream"
    fork = tmp_path / "fork"
    upstream.mkdir()
    git(upstream, "init", "-b", "main")
    git(upstream, "config", "user.email", "test@example.com")
    git(upstream, "config", "user.name", "Test")
    base = commit(upstream, "base", "base")
    git(tmp_path, "clone", str(upstream), str(fork))
    git(fork, "config", "user.email", "test@example.com")
    git(fork, "config", "user.name", "Test")
    git(fork, "remote", "rename", "origin", "upstream")
    (fork / ".lyrashield-upstream-base").write_text(f"{base}\n", encoding="utf-8")
    return upstream, fork, base


def run_check(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [str(SCRIPT)],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "GITHUB_OUTPUT": str(repo / "outputs.txt")},
    )


def read_outputs(repo: Path) -> str:
    return (repo / "outputs.txt").read_text(encoding="utf-8")


def test_check_upstream_reports_no_change(tmp_path: Path) -> None:
    _, fork, _ = make_repositories(tmp_path)
    result = run_check(fork)
    assert result.returncode == 0
    assert "needs_sync=false" in read_outputs(fork)


def test_check_upstream_reports_fast_forward_update(tmp_path: Path) -> None:
    upstream, fork, _ = make_repositories(tmp_path)
    commit(upstream, "advance", "next")
    result = run_check(fork)
    assert result.returncode == 0
    assert "needs_sync=true" in read_outputs(fork)


def test_check_upstream_rejects_rewritten_history(tmp_path: Path) -> None:
    upstream, fork, _ = make_repositories(tmp_path)
    git(upstream, "checkout", "--orphan", "rewritten")
    git(upstream, "rm", "-rf", ".")
    commit(upstream, "replacement", "replacement")
    git(upstream, "branch", "-f", "main", "HEAD")
    result = run_check(fork)
    assert result.returncode == 20
    assert "not an ancestor" in result.stderr
