"""Safety and local integration checks for the disposable product diagnostic."""

from __future__ import annotations

import json
import os
import runpy
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from benchmarks import product_integration_probe


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = product_integration_probe.PRODUCT_REPO
INSTALLED = (PRODUCT / ".github/scripts/run-user-scan-slot-runtime.mjs").is_file()


def test_opt_in_uses_the_probe_default_product_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / ".github/scripts/run-user-scan-slot-runtime.mjs"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("fixture\n")
    monkeypatch.delenv("LYRASHIELD_AI_DIR", raising=False)
    monkeypatch.setenv("LYRASHIELD_PRODUCT_INTEGRATION_TEST", "1")
    monkeypatch.setattr(product_integration_probe, "PRODUCT_REPO", tmp_path)
    namespace = runpy.run_path(str(Path(__file__)))
    assert namespace["PRODUCT"] == tmp_path
    assert namespace["INSTALLED"] is True
    marks = namespace["test_owned_postgres_redis_run_records_product_queue_evidence"].pytestmark
    assert all(not mark.args[0] for mark in marks if mark.name == "skipif")


def test_dirty_engine_is_rejected_before_fixture_execution(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(product_integration_probe.shutil, "which", lambda _name: "/fake/docker")
    monkeypatch.setattr(
        product_integration_probe, "command", lambda *_args, **_kwargs: '"unix:///tmp/fixture.sock"'
    )
    monkeypatch.setattr(product_integration_probe, "current_product_main", lambda: "a" * 40)
    monkeypatch.setattr(
        product_integration_probe,
        "source_state",
        lambda repo: {"revision": "a" * 40, "dirty": repo == ROOT},
    )
    monkeypatch.setattr(
        product_integration_probe,
        "validate",
        lambda _path: pytest.fail("dirty engine reached fixture preflight"),
    )
    assert product_integration_probe.main() == 1
    assert "clean engine checkout" in capsys.readouterr().err


def cleanup_docker(tmp_path: Path, records: dict) -> tuple[Path, Path]:
    executable = tmp_path / "docker"
    marker = tmp_path / "commands.jsonl"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        f"records = {records!r}\n"
        f"with Path({str(marker)!r}).open('a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1] == 'inspect': print(json.dumps([records[sys.argv[2]]]))\n"
        "elif sys.argv[1] == 'rm': print(sys.argv[-1])\n"
        "else: raise SystemExit(1)\n"
    )
    executable.chmod(0o700)
    return executable, marker


def test_parent_cleanup_rejects_foreign_identity_and_image(tmp_path: Path) -> None:
    identity = "fixture-parent"
    owned, foreign, wrong_image = "a" * 64, "b" * 64, "c" * 64
    expected = "sha256:" + "d" * 64
    record = {
        "Id": owned,
        "Config": {
            "Image": "redis:7-alpine",
            "Labels": {product_integration_probe.OWNERSHIP_LABEL: identity},
        },
        "Image": expected,
    }
    records = {
        owned: record,
        foreign: {**record, "Id": foreign, "Config": {**record["Config"], "Labels": {}}},
        wrong_image: {**record, "Id": wrong_image, "Image": "sha256:" + "e" * 64},
    }
    docker, marker = cleanup_docker(tmp_path, records)
    output = product_integration_probe.cleanup_owned_containers(
        "".join(f"OWNED_CREATED:{container}\n" for container in records)
        + f"OWNED_REMOVED:{owned}\n",
        docker=str(docker),
        env={"PATH": os.environ.get("PATH", "")},
        cwd=tmp_path,
        identity=identity,
        image_ids={"redis:7-alpine": expected},
    )
    calls = [json.loads(line) for line in marker.read_text().splitlines()]
    assert [call for call in calls if call[0] == "rm"] == [["rm", "--force", "--volumes", owned]]
    detail = product_integration_probe.cleanup_description(output)
    assert foreign in detail and wrong_image in detail and owned not in detail


def test_forced_child_timeout_runs_verified_parent_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned = "a" * 64
    expected = "sha256:" + "d" * 64
    identity = "fixture-parent"
    docker, marker = cleanup_docker(
        tmp_path,
        {
            owned: {
                "Id": owned,
                "Image": expected,
                "Config": {
                    "Image": "redis:7-alpine",
                    "Labels": {product_integration_probe.OWNERSHIP_LABEL: identity},
                },
            }
        },
    )
    monkeypatch.setattr(product_integration_probe, "CHILD_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(product_integration_probe, "CHILD_INTERRUPT_SECONDS", 0.1)
    code = (
        "import signal,time\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        f"print('OWNED_CREATED:{owned}', flush=True)\n"
        "time.sleep(30)\n"
    )
    started = time.monotonic()
    with pytest.raises(
        RuntimeError, match="fixture timed out; all logged owned containers removed"
    ):
        product_integration_probe.run_child(
            [sys.executable, "-c", code],
            env={"PATH": os.environ.get("PATH", "")},
            cwd=tmp_path,
            cleanup=lambda output: product_integration_probe.cleanup_owned_containers(
                output,
                docker=str(docker),
                env={"PATH": os.environ.get("PATH", "")},
                cwd=tmp_path,
                identity=identity,
                image_ids={"redis:7-alpine": expected},
            ),
        )
    assert time.monotonic() - started < 5
    assert json.loads(marker.read_text().splitlines()[-1]) == ["rm", "--force", "--volumes", owned]


def test_parent_cleanup_has_a_global_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = tmp_path / "docker"
    docker.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    docker.chmod(0o700)
    monkeypatch.setattr(product_integration_probe, "CLEANUP_TIMEOUT_SECONDS", 0.1)
    output = "OWNED_CREATED:" + "a" * 64 + "\n"
    started = time.monotonic()
    assert (
        product_integration_probe.cleanup_owned_containers(
            output,
            docker=str(docker),
            env={},
            cwd=tmp_path,
            identity="fixture",
            image_ids={"redis:7-alpine": "sha256:" + "d" * 64},
        )
        == output
    )
    assert time.monotonic() - started < 2


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


def test_remote_docker_context_is_rejected_before_container_creation(tmp_path: Path) -> None:
    product = tmp_path / "product"
    product.mkdir()
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
        env={
            **os.environ,
            "LYRASHIELD_AI_DIR": str(product),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
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
