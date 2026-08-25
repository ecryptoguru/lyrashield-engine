from __future__ import annotations

import argparse
import importlib
from types import SimpleNamespace
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


main_module = importlib.import_module("lyrashield.interface.main")


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
