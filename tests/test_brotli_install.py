"""The checksum-pinned decoder overlay fails before installing untrusted bytes."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


INSTALL = Path(__file__).parents[1] / "containers" / "install_brotli.sh"


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_brotli_checksum_failure_never_installs_package(tmp_path: Path, architecture: str) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    installed = tmp_path / "installed"
    programs = {
        "dpkg-query": "#!/bin/sh\nprintf '1.2.0-4+b1'\n",
        "dpkg": (
            '#!/bin/sh\ncase "$1" in\n'
            " --compare-versions) exit 1 ;;\n"
            f" --print-architecture) printf '{architecture}' ;;\n"
            f" --install) touch '{installed}' ;;\nesac\n"
        ),
        "curl": (
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n"
            ' if [ "$1" = \'-o\' ]; then shift; printf tampered > "$1"; exit 0; fi\n'
            " shift\ndone\n"
        ),
        "sha256sum": (
            f"#!{sys.executable}\nimport hashlib,sys\n"
            "expected,path=sys.stdin.read().strip().split(None,1)\n"
            "sys.exit(hashlib.sha256(open(path,'rb').read()).hexdigest()!=expected)\n"
        ),
    }
    for name, content in programs.items():
        path = binaries / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
    result = subprocess.run(  # noqa: S603 - tracked fixed installer and isolated fake package tools
        ["/bin/sh", str(INSTALL)],
        env=os.environ | {"PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert not installed.exists()
