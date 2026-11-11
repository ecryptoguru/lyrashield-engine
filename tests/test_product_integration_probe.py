"""Safety and local integration checks for the disposable product diagnostic."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks import product_integration_probe


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = Path(os.environ.get("LYRASHIELD_AI_DIR", "/nonexistent"))
INSTALLED = (PRODUCT / ".github/scripts/run-user-scan-slot-runtime.mjs").is_file()


def test_failed_run_reports_only_its_unconfirmed_container_ids() -> None:
    first, second = "a" * 64, "b" * 64
    output = f"OWNED_CREATED:{first}\nOWNED_CREATED:{second}\nOWNED_REMOVED:{first}\n"
    detail = product_integration_probe.cleanup_description(output)
    assert second in detail
    assert first not in detail


@pytest.mark.skipif(sys.platform != "darwin", reason="local macOS write sandbox required")
def test_fixture_sandbox_denies_shared_writes_and_allows_private_scratch(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    protected = tmp_path / "protected"
    protected.mkdir()
    code = (
        "from pathlib import Path\n"
        f"allowed = Path({str(scratch / 'ok')!r})\n"
        f"blocked = Path({str(protected / 'blocked')!r})\n"
        "allowed.write_text('ok')\n"
        "try: blocked.write_text('forbidden')\n"
        "except PermissionError: pass\n"
        "else: raise SystemExit('shared write succeeded')\n"
    )
    proc = subprocess.run(  # noqa: S603 -- fixed sandbox and controlled fixture paths
        [
            "/usr/bin/sandbox-exec",
            "-p",
            product_integration_probe.write_sandbox_profile(scratch),
            sys.executable,
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (scratch / "ok").read_text() == "ok"
    assert not (protected / "blocked").exists()


@pytest.mark.skipif(not INSTALLED, reason="set LYRASHIELD_AI_DIR to a product checkout")
def test_remote_docker_context_is_rejected_before_container_creation(tmp_path: Path) -> None:
    executable = tmp_path / "docker"
    marker = tmp_path / "commands"
    executable.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> '{marker}'\n"
        "printf '\"tcp://example.invalid:2376\"\\n'\n"
    )
    executable.chmod(0o700)
    proc = subprocess.run(
        [sys.executable, "-m", "benchmarks.product_integration_probe"],
        cwd=ROOT,
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode != 0
    assert "local" in proc.stderr.lower()
    assert "create" not in marker.read_text()


def test_stale_product_revision_is_rejected_before_fixture_creation(tmp_path: Path) -> None:
    repo = tmp_path / "product"
    repo.mkdir()
    git_executable = shutil.which("git")
    assert git_executable
    git_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    def git(*args: str) -> None:
        subprocess.run(  # noqa: S603 -- fixed local git with controlled fixture inputs
            [git_executable, "-C", str(repo), *args], env=git_env, check=True, capture_output=True
        )

    git("init", "-q", "--template=")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.test")
    (repo / "input").write_text("main\n")
    git("add", "input")
    git("commit", "-qm", "main")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    (repo / "input").write_text("stale checkout\n")
    git("add", "input")
    git("commit", "-qm", "different")
    decoy = tmp_path / "decoy"
    shutil.copytree(repo, decoy)
    subprocess.run(  # noqa: S603 -- controlled local fixture repository
        [git_executable, "-C", str(decoy), "update-ref", "refs/remotes/origin/main", "HEAD"],
        env=git_env,
        check=True,
        capture_output=True,
    )

    executable = tmp_path / "docker"
    marker = tmp_path / "commands"
    executable.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(marker))}\n"
        "printf '\"unix:///tmp/fixture.sock\"\\n'\n"
    )
    executable.chmod(0o700)
    proc = subprocess.run(
        [sys.executable, "-m", "benchmarks.product_integration_probe"],
        cwd=ROOT,
        env={
            **os.environ,
            "LYRASHIELD_AI_DIR": str(repo),
            "GIT_DIR": str(decoy / ".git"),
            "GIT_WORK_TREE": str(decoy),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode != 0
    assert "source identity mismatch" in proc.stderr.lower()
    assert "create" not in marker.read_text()


@pytest.mark.skipif(
    not INSTALLED or os.environ.get("LYRASHIELD_PRODUCT_INTEGRATION_TEST") != "1",
    reason="explicit disposable product integration opt-in required",
)
def test_owned_postgres_redis_run_records_product_queue_evidence() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "benchmarks.product_integration_probe"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    receipt = json.loads(proc.stdout)
    assert receipt["profileStatus"] == "NOT_MEASURED"
    assert receipt["claimStatus"] == "NOT_REPORTABLE"
    assert receipt["adjudicationStatus"] == "NOT_INDEPENDENTLY_REVIEWED"
    assert receipt["heldOutStatus"] == "NOT_PROVIDED"
    assert receipt["modelRoute"] is None
    assert receipt["sources"]["engine"]["revision"]
    assert receipt["sources"]["product"]["revision"]
    assert receipt["result"]["passed"] == 14
    assert receipt["result"]["failed"] == 0
    assert receipt["result"]["skipped"] == 0
    assert len(receipt["images"]) == 2
    assert all(image["observedImageId"] == image["preflightImageId"] for image in receipt["images"])
    assert receipt["cleanup"] == "OWNED_SERVICES_REMOVED"
    assert receipt["writeIsolation"] == "PRIVATE_TEMP_ONLY"
