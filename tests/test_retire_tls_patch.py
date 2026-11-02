"""Retire source amendments must reject unexpected bytes before writing."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_retire_amendment_refuses_tampered_source(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to run the sandbox source amendment")
    package = tmp_path / "retire"
    (package / "lib").mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"version": "6.1.0"}))
    source = package / "lib/http.js"
    source.write_bytes(b"// unreviewed source\n")
    before = source.read_bytes()
    result = subprocess.run(  # noqa: S603 - fixed amendment and isolated fixture
        [node, str(ROOT / "containers/patch_retire_tls.cjs"), str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert "Unreviewed Retire TLS source" in result.stderr
    assert source.read_bytes() == before


def test_retire_amendment_is_applied_after_npm_hash_lock_installation() -> None:
    dockerfile = (ROOT / "containers/Dockerfile").read_text()
    installed = dockerfile.index("RUN npm ci --omit=dev")
    amended = dockerfile.index("    node /tmp/patch_retire_tls.cjs")
    assert installed < amended < dockerfile.index("    npm cache clean", installed)
