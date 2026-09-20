from __future__ import annotations

import argparse
import importlib
import subprocess  # nosec B404
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

import pytest


main_module = importlib.import_module("lyrashield.interface.main")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603  # nosec B603
        ["git", "-C", str(repo), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


def _git_clone(path: Path) -> str:
    """Create a fixture clone under the cache root and return its HEAD."""
    path.mkdir(parents=True)
    subprocess.run(  # noqa: S603  # nosec B603
        ["git", "init", "-b", "main", str(path)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    _git(path, "config", "commit.gpgsign", "false")
    (path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-m", "initial")
    return _git(path, "rev-parse", "HEAD")


def _commit_file(repo: Path, name: str, content: str, message: str) -> str:
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _resume_args() -> argparse.Namespace:
    return argparse.Namespace(resume="resume-run", instruction=None, scan_mode="deep")


def _stage_resumed_repository_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_record: dict[str, Any],
    *,
    clone: Path | None = None,
) -> Path:
    """Stage a resumable run whose repository target is a fixture clone.

    When *clone* is omitted a fresh single-commit clone is created under the
    fake cache root. Returns the clone path either way.
    """
    run_dir = tmp_path / "runs" / "resume-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text("{}", encoding="utf-8")
    if clone is None:
        clone = tmp_path / "strix_repos" / "resume-run" / "repo"
        _git_clone(clone)
    targets = [
        {
            "type": "repository",
            "details": {
                "target_repo": "https://example.com/org/repo.git",
                "cloned_repo_path": str(clone),
            },
        }
    ]
    monkeypatch.setattr(main_module, "run_dir_for", lambda _name: run_dir)
    monkeypatch.setattr(main_module, "runs_base_dir", lambda: tmp_path / "runs")
    monkeypatch.setattr(main_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(main_module, "read_run_record", lambda _run_dir: run_record)
    monkeypatch.setattr(
        main_module,
        "read_resume_record",
        lambda _run_dir: {"targets_info": targets},
    )
    return clone


def test_resume_mounts_product_docker_repository_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "runs" / "resume-run"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text("{}")
    clone = tmp_path / "strix_repos" / "resume-run" / "repo"
    clone.mkdir(parents=True)
    targets = [
        {
            "type": "repository",
            "details": {"cloned_repo_path": str(clone)},
        }
    ]
    local_sources = [{"source_path": str(clone), "workspace_subdir": "repo", "mount": False}]

    monkeypatch.setattr(main_module, "run_dir_for", lambda _name: run_dir)
    monkeypatch.setattr(main_module, "runs_base_dir", lambda: tmp_path / "runs")
    monkeypatch.setattr(main_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(main_module, "read_run_record", lambda _run_dir: {"scan_mode": "standard"})
    monkeypatch.setattr(
        main_module,
        "read_resume_record",
        lambda _run_dir: {"targets_info": targets, "local_sources": local_sources},
    )
    monkeypatch.setattr(main_module, "is_lyrashield_product", lambda: True)
    monkeypatch.setattr(
        main_module,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    args = argparse.Namespace(resume="resume-run", instruction=None, scan_mode="deep")

    main_module._load_resume_state(args, argparse.ArgumentParser())

    assert args.local_sources == [
        {"source_path": str(clone), "workspace_subdir": "repo", "mount": True}
    ]


def test_resume_accepts_clone_at_recorded_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cached clone still at the recorded immutable revision resumes."""
    clone = tmp_path / "strix_repos" / "resume-run" / "repo"
    recorded = _git_clone(clone)
    _stage_resumed_repository_run(
        tmp_path,
        monkeypatch,
        {"repository_revision": recorded, "scan_mode": "standard"},
        clone=clone,
    )
    args = _resume_args()

    main_module._load_resume_state(args, argparse.ArgumentParser())

    assert args.repository_revision == recorded


def test_resume_refuses_a_clone_whose_head_moved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A new commit on the cached clone between runs must refuse the resume."""
    clone = tmp_path / "strix_repos" / "resume-run" / "repo"
    recorded = _git_clone(clone)
    _stage_resumed_repository_run(
        tmp_path,
        monkeypatch,
        {"repository_revision": recorded, "scan_mode": "standard"},
        clone=clone,
    )
    # Simulate a cache alteration: a fresh commit moves HEAD off the revision.
    _git(clone, "checkout", "--detach", recorded)
    altered = _commit_file(clone, "app.py", "print('tampered')\n", "cache alteration")
    assert altered != recorded

    with pytest.raises(SystemExit) as exc_info:
        main_module._load_resume_state(_resume_args(), argparse.ArgumentParser())

    assert exc_info.value.code == 2
    assert "--resume resume-run" in capsys.readouterr().err
    # The refusal must leave the altered clone untouched: no checkout, no
    # reset, no fetch — HEAD still points at the tampered commit.
    assert _git(clone, "rev-parse", "HEAD") == altered


def test_resume_refuses_a_detached_clone_off_the_recorded_diff_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The recorded diff head pins the clone even without repository_revision."""
    clone = tmp_path / "strix_repos" / "resume-run" / "repo"
    recorded = _git_clone(clone)
    _commit_file(clone, "later.py", "x = 1\n", "later")
    _git(clone, "checkout", "--detach", recorded)
    _stage_resumed_repository_run(
        tmp_path,
        monkeypatch,
        {"diff_head": recorded, "scan_mode": "standard"},
        clone=clone,
    )
    # Tamper: move HEAD to the newer commit the run never recorded.
    _git(clone, "checkout", "--detach", "main")
    moved = _git(clone, "rev-parse", "HEAD")
    assert moved != recorded

    with pytest.raises(SystemExit) as exc_info:
        main_module._load_resume_state(_resume_args(), argparse.ArgumentParser())

    assert exc_info.value.code == 2
    assert "--resume resume-run" in capsys.readouterr().err
    assert _git(clone, "rev-parse", "HEAD") == moved


def test_resume_without_recorded_revision_skips_head_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Runs recorded before immutable revisions resume without a HEAD check."""
    clone = _stage_resumed_repository_run(tmp_path, monkeypatch, {"scan_mode": "standard"})
    args = _resume_args()

    main_module._load_resume_state(args, argparse.ArgumentParser())

    assert args.targets_info[0]["details"]["cloned_repo_path"] == str(clone)
