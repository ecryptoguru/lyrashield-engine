from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync-upstream-release.sh"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SYNC_WORKFLOW = ROOT / ".github" / "workflows" / "upstream-sync.yml"


def git(cwd: Path, *args: str, check: bool = True) -> str:
    executable = shutil.which("git")
    assert executable is not None
    return subprocess.run(  # noqa: S603
        [executable, *args], cwd=cwd, check=check, text=True, capture_output=True
    ).stdout.strip()


def write_project(repo: Path, *, marker: str, version: str) -> None:
    (repo / "upstream.txt").write_text(f"{marker}\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        f'[project]\nname = "fixture"\nversion = "{version}"\n', encoding="utf-8"
    )


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def make_release_repositories(tmp_path: Path) -> tuple[Path, Path, str]:
    upstream = tmp_path / "upstream"
    fork = tmp_path / "fork"
    upstream.mkdir()
    git(upstream, "init", "-b", "main")
    git(upstream, "config", "user.email", "test@example.com")
    git(upstream, "config", "user.name", "Test")
    write_project(upstream, marker="v1.1.0", version="1.1.0")
    base_sha = commit_all(upstream, "release 1.1.0")
    git(upstream, "tag", "v1.1.0")

    git(tmp_path, "clone", str(upstream), str(fork))
    git(fork, "config", "user.email", "test@example.com")
    git(fork, "config", "user.name", "Test")
    git(fork, "remote", "rename", "origin", "upstream")
    (fork / ".lyrashield-upstream-base").write_text(f"{base_sha}\n", encoding="utf-8")
    (fork / ".lyrashield-upstream-release").write_text("v1.1.0\n", encoding="utf-8")
    (fork / "UPGRADES.md").write_text(
        f"## Current upstream release\n\n`v1.1.0`\n\n## Current upstream base\n\n`{base_sha}`\n",
        encoding="utf-8",
    )
    (fork / "fork-only.txt").write_text("preserve me\n", encoding="utf-8")
    commit_all(fork, "add fork state")
    return upstream, fork, base_sha


def publish_release(upstream: Path, tag: str, marker: str = "v1.1.1") -> str:
    write_project(upstream, marker=marker, version=tag.removeprefix("v"))
    sha = commit_all(upstream, f"release {tag}")
    git(upstream, "tag", tag)
    return sha


def run_sync(repo: Path, release: str) -> subprocess.CompletedProcess[str]:
    report = repo / "report"
    output = repo / "outputs.txt"
    return subprocess.run(  # noqa: S603
        [str(SCRIPT), release],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "GITHUB_OUTPUT": str(output),
            "SYNC_REPORT_DIR": str(report),
        },
    )


def read_outputs(repo: Path) -> str:
    return (repo / "outputs.txt").read_text(encoding="utf-8")


def test_same_release_is_a_noop(tmp_path: Path) -> None:
    _, fork, base_sha = make_release_repositories(tmp_path)
    result = run_sync(fork, "v1.1.0")
    assert result.returncode == 0, result.stderr
    assert "needs_sync=false" in read_outputs(fork)
    assert f"base_sha={base_sha}" in read_outputs(fork)
    assert git(fork, "diff", "--stat") == ""
    assert git(fork, "diff", "--cached", "--stat") == ""


def test_same_release_keeps_a_post_release_base(tmp_path: Path) -> None:
    upstream, fork, _ = make_release_repositories(tmp_path)
    write_project(upstream, marker="post release", version="1.1.0")
    post_release_sha = commit_all(upstream, "post-release fix")
    git(fork, "fetch", "upstream", "main")
    (fork / ".lyrashield-upstream-base").write_text(f"{post_release_sha}\n", encoding="utf-8")
    commit_all(fork, "record post-release base")

    result = run_sync(fork, "v1.1.0")
    assert result.returncode == 0, result.stderr
    assert "needs_sync=false" in read_outputs(fork)
    assert f"base_sha={post_release_sha}" in read_outputs(fork)


def test_newer_release_applies_tree_delta_and_preserves_fork_files(tmp_path: Path) -> None:
    upstream, fork, _ = make_release_repositories(tmp_path)
    release_sha = publish_release(upstream, "v1.1.1")
    result = run_sync(fork, "v1.1.1")
    assert result.returncode == 0, result.stderr
    assert "needs_sync=true" in read_outputs(fork)
    assert (fork / "upstream.txt").read_text(encoding="utf-8") == "v1.1.1\n"
    assert (fork / "fork-only.txt").read_text(encoding="utf-8") == "preserve me\n"
    assert (fork / ".lyrashield-upstream-base").read_text().strip() == release_sha
    assert (fork / ".lyrashield-upstream-release").read_text().strip() == "v1.1.1"
    assert 'version = "1.1.1.post1"' in (fork / "pyproject.toml").read_text()
    upgrades = (fork / "UPGRADES.md").read_text()
    assert "`v1.1.1`" in upgrades
    assert f"`{release_sha}`" in upgrades


def test_release_delta_does_not_require_main_ancestry(tmp_path: Path) -> None:
    upstream, fork, base_sha = make_release_repositories(tmp_path)
    release_sha = publish_release(upstream, "v1.1.1")
    git(upstream, "switch", "--orphan", "replacement-main")
    git(upstream, "rm", "-rf", "--ignore-unmatch", ".")
    write_project(upstream, marker="unreleased", version="9.0.0")
    commit_all(upstream, "rewrite main")
    git(upstream, "branch", "-M", "main")
    assert git(upstream, "merge-base", "--is-ancestor", base_sha, "main", check=False) == ""

    result = run_sync(fork, "v1.1.1")
    assert result.returncode == 0, result.stderr
    assert (fork / ".lyrashield-upstream-base").read_text().strip() == release_sha
    assert (fork / "upstream.txt").read_text() == "v1.1.1\n"


def test_conflicting_release_writes_report_and_exits_20(tmp_path: Path) -> None:
    upstream, fork, _ = make_release_repositories(tmp_path)
    (fork / "upstream.txt").write_text("fork edit\n", encoding="utf-8")
    commit_all(fork, "fork edit")
    publish_release(upstream, "v1.1.1", marker="upstream edit")

    result = run_sync(fork, "v1.1.1")
    assert result.returncode == 20
    assert "upstream.txt" in (fork / "report" / "conflicts.txt").read_text()
    assert "requires review" in result.stderr


def test_rejects_invalid_or_older_release(tmp_path: Path) -> None:
    _, fork, _ = make_release_repositories(tmp_path)
    invalid = run_sync(fork, "main")
    assert invalid.returncode == 2
    assert "stable release tag" in invalid.stderr

    older = run_sync(fork, "v1.0.9")
    assert older.returncode == 2
    assert "older than recorded" in older.stderr


def test_engine_ci_defines_complete_required_check() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    required_fragments = (
        "name: Engine CI",
        "pull_request:",
        "workflow_dispatch:",
        "verify:",
        "timeout-minutes:",
        "scripts/verify-thin-fork.sh",
        "uv build",
        "bash scripts/build.sh",
        "containers/Dockerfile",
        'test "$(id -u)" != "0"',
        "test ! -S /var/run/docker.sock",
        "scripts/verify-worker-contract.sh",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    )
    for fragment in required_fragments:
        assert fragment in workflow


def test_upstream_workflow_opens_reviewed_auto_merge_pr_or_conflict_issue() -> None:
    workflow = SYNC_WORKFLOW.read_text(encoding="utf-8")
    required_fragments = (
        'cron: "23 3 * * *"',
        "release_tag:",
        "issues: write",
        "repos/usestrix/strix/releases/latest",
        "scripts/sync-upstream-release.sh",
        "persist-credentials: false",
        "uv lock",
        "reviewers[]=ecryptoguru",
        "gh pr merge --auto --squash",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "Upstream sync blocked:",
        "upstream-sync",
    )
    for fragment in required_fragments:
        assert fragment in workflow


def test_upstream_workflow_does_not_rebase_or_deploy() -> None:
    workflow = SYNC_WORKFLOW.read_text(encoding="utf-8")
    assert "git rebase" not in workflow
    assert "scripts/verify-thin-fork.sh" not in workflow
    assert "bash scripts/build.sh" not in workflow
    assert "docker build" not in workflow
    assert "scripts/verify-worker-contract.sh" not in workflow
    for deployment_command in ("wrangler deploy", "docker push", "gh release create"):
        assert deployment_command not in workflow
