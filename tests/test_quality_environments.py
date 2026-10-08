"""Keep local, pre-commit and CI type checks on the maintained project gate."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import yaml
from packaging.version import Version


ROOT = Path(__file__).resolve().parents[1]


def test_precommit_and_make_run_the_same_type_check() -> None:
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hook = next(
        hook
        for repository in config["repos"]
        for hook in repository["hooks"]
        if hook["id"] == "mypy"
    )
    make = shutil.which("make")
    assert make is not None
    result = subprocess.run(  # noqa: S603 - invokes the fixed local Makefile target
        [make, "-n", "type-check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    commands = [
        line.strip() for line in result.stdout.splitlines() if line.strip().startswith("uv ")
    ]

    assert hook["language"] == "system"
    assert hook["pass_filenames"] is False
    assert commands == [hook["entry"]]
    assert hook["entry"] == "uv run mypy strix lyrashield_adapter lyrashield"


def test_strict_type_gate_includes_owned_tui_and_excludes_only_upstream_tui() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    mypy = config["tool"]["mypy"]
    excluded = {str(path).replace("\\", "/") for path in mypy["exclude"]}

    assert mypy["strict"] is True
    assert "strix/interface/tui" in excluded
    assert not any(path.startswith("lyrashield/") for path in excluded)
    assert "lyrashield" in (ROOT / "Makefile").read_text(encoding="utf-8")


def test_python_locks_meet_the_reviewed_security_floors() -> None:
    engine_lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    engine_versions = {
        package["name"]: Version(package["version"]) for package in engine_lock["package"]
    }
    sandbox_versions = dict(
        re.findall(
            r"(?m)^([a-zA-Z0-9_-]+)==([^\\\s]+)",
            (ROOT / "containers/python-requirements.txt").read_text(encoding="utf-8"),
        )
    )

    for name, minimum in {"pyjwt": "2.15.0", "urllib3": "2.8.0"}.items():
        assert engine_versions[name] >= Version(minimum)
        assert Version(sandbox_versions[name]) >= Version(minimum)
    assert engine_versions["virtualenv"] >= Version("21.13.0")
    assert Version(sandbox_versions["setuptools"]) >= Version("83.0.0")


def test_npm_lock_meets_the_reviewed_parser_and_address_floors() -> None:
    lock = json.loads((ROOT / "containers/npm-tools/package-lock.json").read_text(encoding="utf-8"))
    floors = {"brace-expansion": "5.0.11", "ip-address": "10.7.1"}
    actual = {name: lock["packages"][f"node_modules/{name}"]["version"] for name in floors}
    below_floor = {
        name: {"actual": actual[name], "minimum": minimum}
        for name, minimum in floors.items()
        if Version(actual[name]) < Version(minimum)
    }
    assert not below_floor, f"sandbox npm packages below reviewed security floors: {below_floor}"


def _locked_version(name: str) -> str:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return next(package["version"] for package in lock["package"] if package["name"] == name)


def test_precommit_hooks_use_the_locked_tool_versions() -> None:
    """A local hook must not run a different ruff or bandit than CI does.

    Ruff 0.11.13 and 0.15.20 disagree on formatter and lint output, so an
    unaligned rev lets a commit pass locally and fail the locked CI gate.
    """
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    revs = {
        repository["repo"]: str(repository["rev"])
        for repository in config["repos"]
        if "rev" in repository
    }

    assert revs["https://github.com/astral-sh/ruff-pre-commit"] == f"v{_locked_version('ruff')}"
    assert revs["https://github.com/PyCQA/bandit"] == _locked_version("bandit")


def test_bandit_severity_floor_is_enforced_by_the_invocation() -> None:
    """Bandit reads no severity floor from pyproject.toml; the flag must carry it.

    The config previously said ``severity = "medium"``, which bandit accepts and
    never applies. The enforced floor is LOW (bandit's default) and every
    invocation states it with ``-l``. A medium floor is rejected here because it
    would drop B311/B403/B405-B409 while their ruff equivalents (S403, S405-S409)
    are preview-only and inactive, so medium would weaken the gate.
    """
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    bandit_config = config["tool"]["bandit"]

    assert "severity" not in bandit_config
    assert "B101" in bandit_config["skips"]

    invocations = {
        "Makefile": "uv run bandit -r strix lyrashield_adapter lyrashield -q -c pyproject.toml -l",
        "scripts/verify-controlled-derivative.sh": (
            "uv run bandit -c pyproject.toml -r strix lyrashield_adapter lyrashield -q -l"
        ),
    }
    for relative, expected in invocations.items():
        assert expected in (ROOT / relative).read_text(encoding="utf-8")

    hook_config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    bandit_hook = next(
        hook
        for repository in hook_config["repos"]
        for hook in repository["hooks"]
        if hook["id"] == "bandit"
    )
    assert bandit_hook["args"] == ["-c", "pyproject.toml", "-l"]
