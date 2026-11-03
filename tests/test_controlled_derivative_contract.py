"""Pin the reviewed substrate bytes before any quality command may run."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE = "200a501f15a24a4152f92897a6b72af238ee69ef"
PATCH_OID = "51682200fe3b9ec8fa2e0f998c80c095e7add114"


def _git(repo: Path, *args: str, input: str | None = None) -> str:  # noqa: A002
    return subprocess.run(  # noqa: S603 - fixed git executable and test-controlled args
        [shutil.which("git") or "/usr/bin/git", "-C", str(repo), *args],
        input=input,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _add_ignored_runtime_file(repo: Path, mutation: str) -> None:
    if mutation == "ignored-skill":
        name = "strix/skills/dist/unreviewed.md"
        content = "---\nname: unreviewed\ndescription: Probe skill.\n---\nUNREVIEWED_SKILL\n"
        probe = (
            "import strix.skills as skills; "
            "assert any(item['name'] == 'unreviewed' for item in "
            "skills.get_available_skills()['dist']); "
            "assert 'UNREVIEWED_SKILL' in skills.load_skills(['dist/unreviewed'])['unreviewed']"
        )
    else:
        name = (
            "strix/plugins/dist/ignored_plugin.py"
            if mutation == "ignored-python"
            else "strix/__pycache__/unreviewed.py"
        )
        content = "UNREVIEWED_PLUGIN = True\n"
        probe = (
            "from strix.plugins.dist import ignored_plugin; "
            "assert ignored_plugin.UNREVIEWED_PLUGIN is True"
        )
    dest = repo / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    _git(repo, "check-ignore", name)
    if mutation != "cache-source":
        subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled probe
            [sys.executable, "-c", probe],
            cwd=repo,
            env={**os.environ, "PYTHONPATH": str(repo)},
            check=True,
            capture_output=True,
            text=True,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "patch",
        "path",
        "deletion",
        "untracked",
        "untracked-deletion",
        "ignored",
        "ignored-skill",
        "ignored-python",
        "excluded-deletion",
        "cache-source",
    ],
)
def test_only_exact_reviewed_substrate_reaches_quality_commands(
    tmp_path: Path, mutation: str | None
) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    # Origin clones need not contain the pinned upstream commit. Reconstruct an
    # offline baseline from the checked-in tree and the exact reviewed patch;
    # its blob IDs and patch digest stay identical regardless of commit IDs.
    assert (ROOT / ".lyrashield-upstream-base").read_text().strip() == BASE
    patch = json.loads((ROOT / "tests/fixtures/controlled-derivative.patch.json").read_text())[
        "patch"
    ]
    assert _git(repo, "hash-object", "--stdin", input=patch).strip() == PATCH_OID
    for name in _git(ROOT, "ls-files", "-z", "--", "strix").split("\0"):
        if name:
            dest = repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, dest)
    shutil.copy(ROOT / ".gitignore", repo / ".gitignore")
    _git(repo, "apply", "--reverse", "-", input=patch)
    _git(repo, "add", "strix")
    _git(
        repo,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "Offline upstream fixture",
    )
    baseline = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "remote", "add", "upstream", str(repo))
    _git(repo, "apply", "--index", "-", input=patch)
    (repo / ".lyrashield-upstream-base").write_text(baseline + "\n")
    shutil.copy(ROOT / "scripts/verify-controlled-derivative.sh", repo / "verify.sh")

    if mutation == "patch":
        with (repo / "strix/config/loader.py").open("a") as handle:
            handle.write("\n# unreviewed seam change\n")
    elif mutation in {"path", "untracked"}:
        (repo / "strix/unreviewed.py").write_text("# unreviewed added file\n")
    elif mutation in {"deletion", "untracked-deletion", "excluded-deletion"}:
        (repo / "strix/skills/tooling/hurl.md").write_text(
            _git(repo, "show", f"{baseline}:strix/skills/tooling/hurl.md")
        )
        if mutation == "excluded-deletion":
            (repo / ".git/info/exclude").write_text("strix/skills/tooling/hurl.md\n")
    elif mutation in {"ignored-skill", "ignored-python", "cache-source"}:
        _add_ignored_runtime_file(repo, mutation)
    elif mutation == "ignored":
        for name in (
            "strix/__pycache__/fixture.pyc",
            "strix/interface/viewer/frontend/node_modules/fixture/index.js",
            "strix/interface/viewer/frontend/dist/assets/index.js",
            "strix/interface/viewer/frontend/.vite/cache.json",
        ):
            dest = repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("ignored local build output\n")
    if mutation not in {"untracked", "untracked-deletion", "excluded-deletion"}:
        _git(repo, "add", "strix")

    # Only stub the expensive quality tools in this boundary regression. The
    # real suite/lint/types/security checks run independently in the full gate.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text('#!/bin/sh\nprintf "quality invoked\\n" >> quality-invocations\n')
    uv.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    result = subprocess.run(  # noqa: S603 - fixed test gate and executable
        [shutil.which("bash") or "/bin/bash", "verify.sh"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if mutation in {None, "ignored"}:
        assert result.returncode == 0, result.stderr
        assert (repo / "quality-invocations").read_text().count("quality invoked") == 6
    else:
        assert result.returncode != 0
        assert not (repo / "quality-invocations").exists()
        assert "error:" in result.stderr
