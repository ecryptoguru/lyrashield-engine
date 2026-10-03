"""The network provisioner must reject legacy shared internal bridges."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path


def test_existing_internal_bridge_with_icc_enabled_is_not_admitted(tmp_path: Path) -> None:
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        "  *'network inspect --format'*) printf '%s\\n' \"$SANDBOX_NETWORK_STATE\" ;;\n"
        "  *'network inspect'*) exit 0 ;;\n"
        '  *) echo "unexpected docker call: $*" >&2; exit 2 ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}",
        "SANDBOX_NETWORK_STATE": "bridge true true",
        "STRIX_DOCKER_SANDBOX_NETWORK": "lyrashield-sandbox",
    }

    result = subprocess.run(
        ["/bin/bash", "scripts/provision-sandbox-network.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert "inter-container communication disabled" in result.stderr


def test_new_network_is_created_with_egress_and_sibling_isolation(tmp_path: Path) -> None:
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        "  *'network inspect --format'*) printf '%s\\n' 'bridge true false' ;;\n"
        "  *'network inspect'*) exit 1 ;;\n"
        "  *'network create'*) printf '%s\\n' \"$*\" >> \"$DOCKER_CALLS\" ;;\n"
        '  *) echo "unexpected docker call: $*" >&2; exit 2 ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    calls = tmp_path / "calls"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}",
        "DOCKER_CALLS": str(calls),
        "STRIX_DOCKER_SANDBOX_NETWORK": "lyrashield-sandbox",
    }

    result = subprocess.run(
        ["/bin/bash", "scripts/provision-sandbox-network.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert (
        "network create --driver bridge --internal --opt "
        "com.docker.network.bridge.enable_icc=false lyrashield-sandbox" in calls.read_text()
    )
