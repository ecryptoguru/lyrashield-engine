"""Exercise the Docker boundary with a synthetic product fixture, never Docker."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "2f4f2a04-c540-40b6-a06a-5739c44d0a63"
FIXTURE = "3f4f2a04-c540-40b6-a06a-5739c44d0a63"
OWNED = "a" * 64
FOREIGN = "b" * 64


def run_fixture(
    tmp_path: Path, args: list[str], *, followup: list[str] | None = None
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    node = shutil.which("node")
    assert node, "Node is required to exercise the fixture boundary"
    product = tmp_path / "product"
    scripts = product / ".github/scripts"
    scripts.mkdir(parents=True)
    temporary = tmp_path / "private"
    temporary.mkdir()
    (temporary / "postgres.env").write_text("POSTGRES_USER=slot_owner\n")
    expanded = [str(temporary / "postgres.env") if arg == "ENV_FILE" else arg for arg in args]
    (scripts / "run-user-scan-slot-runtime.mjs").write_text(
        "export async function runUserScanSlotRuntime({run}) {\n"
        f"await run('docker', {json.dumps(expanded)});\n"
        + (f"await run('docker', {json.dumps(followup)});\n" if followup else "")
        + "}\n"
    )
    marker = tmp_path / "commands.jsonl"
    docker = tmp_path / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        f"with Path({str(marker)!r}).open('a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1] == 'inspect':\n"
        f"    print(json.dumps([{{'Id': {OWNED!r}, "
        "'Config': {'Image': 'redis:7-alpine'}, 'Image': 'sha256:fixture'}]))\n"
        f"else: print({OWNED!r})\n"
    )
    docker.chmod(0o700)
    proc = subprocess.run(  # noqa: S603 -- controlled local fixture and fake Docker executable
        [
            node,
            str(ROOT / "benchmarks/run_product_integration.mjs"),
            "--product",
            str(product),
            "--docker",
            str(docker),
            "--docker-host",
            "unix:///tmp/fixture.sock",
            "--identity",
            IDENTITY,
            "--pnpm",
            node,
            "--corepack-home",
            str(temporary),
            "--temporary",
            str(temporary),
            "--report",
            str(temporary / "report.json"),
        ],
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    calls = (
        [json.loads(line) for line in marker.read_text().splitlines()] if marker.exists() else []
    )
    return proc, calls


@pytest.mark.parametrize(
    "extra",
    [
        ["--privileged"],
        ["--mount", "type=bind,src=/,dst=/host"],
        ["-v", "/:/host"],
        ["--network", "host"],
        ["--network=host"],
        ["--pull=always"],
        ["--pull", "always"],
        ["--publish", "0.0.0.0:6379:6379"],
        ["--label", "lyrashield.product-integration-probe=other"],
        ["--entrypoint", "/bin/sh"],
    ],
)
def test_create_rejects_every_option_outside_the_fixture_schema(
    tmp_path: Path, extra: list[str]
) -> None:
    _, calls = run_fixture(
        tmp_path,
        [
            "create",
            "--label",
            f"lyrashield.user-scan-slot-fixture={FIXTURE}",
            "--publish",
            "127.0.0.1::6379",
            *extra,
            "redis:7-alpine",
        ],
    )
    assert calls == []


@pytest.mark.parametrize(
    "image,port,environment",
    [
        ("postgres:16-alpine", "5432", ["--env-file", "ENV_FILE"]),
        ("redis:7-alpine", "6379", []),
    ],
)
def test_required_create_options_receive_non_overridable_parent_ownership(
    tmp_path: Path, image: str, port: str, environment: list[str]
) -> None:
    proc, calls = run_fixture(
        tmp_path,
        [
            "create",
            "--label",
            f"lyrashield.user-scan-slot-fixture={FIXTURE}",
            "--publish",
            f"127.0.0.1::{port}",
            *environment,
            image,
        ],
    )
    assert f"OWNED_CREATED:{OWNED}" in proc.stdout
    assert calls[0][:4] == [
        "create",
        "--pull=never",
        "--label",
        f"lyrashield.product-integration-probe={IDENTITY}",
    ]
    assert calls[0][-1] == image


@pytest.mark.parametrize("relative", [False, True])
def test_postgres_env_file_cannot_read_shared_or_relative_files(
    tmp_path: Path, *, relative: bool
) -> None:
    shared = tmp_path / "shared/postgres.env"
    shared.parent.mkdir()
    shared.write_text("not fixture input\n")
    path = os.path.relpath(tmp_path / "private/postgres.env", ROOT) if relative else str(shared)
    _, calls = run_fixture(
        tmp_path,
        [
            "create",
            "--label",
            f"lyrashield.user-scan-slot-fixture={FIXTURE}",
            "--publish",
            "127.0.0.1::5432",
            "--env-file",
            path,
            "postgres:16-alpine",
        ],
    )
    assert calls == []


@pytest.mark.parametrize(
    "operation",
    [
        ["start", OWNED, FOREIGN],
        ["start", OWNED, "--attach"],
        ["inspect", OWNED, FOREIGN],
        ["rm", "--force", "--volumes", FOREIGN, OWNED],
        ["rm", "--force", "--volumes", OWNED, FOREIGN],
        ["rm", "--force", "--volumes", "--link", OWNED],
        ["exec", "--privileged", OWNED, "redis-cli", "ping"],
    ],
)
def test_owned_id_does_not_authorize_extra_targets_or_operation_flags(
    tmp_path: Path, operation: list[str]
) -> None:
    create = [
        "create",
        "--label",
        f"lyrashield.user-scan-slot-fixture={FIXTURE}",
        "--publish",
        "127.0.0.1::6379",
        "redis:7-alpine",
    ]
    proc, calls = run_fixture(tmp_path, create, followup=operation)
    assert proc.returncode != 0
    assert len(calls) == 1
    assert calls[0][0] == "create"


@pytest.mark.parametrize(
    "operation",
    [
        ["start", OWNED],
        ["inspect", OWNED],
        ["exec", OWNED, "redis-cli", "ping"],
        ["exec", "-i", OWNED, "psql", "-U", "slot_owner"],
        ["rm", "--force", "--volumes", OWNED],
    ],
)
def test_required_single_target_operations_still_reach_only_the_owned_fixture(
    tmp_path: Path, operation: list[str]
) -> None:
    _, calls = run_fixture(
        tmp_path,
        [
            "create",
            "--label",
            f"lyrashield.user-scan-slot-fixture={FIXTURE}",
            "--publish",
            "127.0.0.1::6379",
            "redis:7-alpine",
        ],
        followup=operation,
    )
    assert calls[-1] == operation
    assert len(calls) == 2
