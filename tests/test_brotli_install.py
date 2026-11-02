"""The checksum-pinned decoder overlay fails before installing untrusted bytes."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


INSTALL = Path(__file__).parents[1] / "containers" / "install_brotli.sh"


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
@pytest.mark.parametrize("failure_position", [1, 2])
def test_brotli_checksum_failure_never_installs_package(
    tmp_path: Path, architecture: str, failure_position: int
) -> None:
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
            f"#!{sys.executable}\nimport hashlib,sys,pathlib\n"
            f"counter=pathlib.Path({str(tmp_path / 'checks')!r})\n"
            "count=int(counter.read_text())+1 if counter.exists() else 1\n"
            "counter.write_text(str(count))\n"
            f"if count < {failure_position}: sys.stdin.read(); sys.exit(0)\n"
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


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_fixed_shared_library_does_not_skip_vulnerable_python_decoder(
    tmp_path: Path, architecture: str
) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    installed = tmp_path / "installed"
    programs = {
        "dpkg-query": (
            "#!/bin/sh\nfor arg do package=$arg; done\n"
            f'if [ "$package" = libbrotli1 ] || [ -f "{installed}" ]; then '
            "printf 1.2.0-4.1; else printf 1.2.0-4+b1; fi\n"
        ),
        "dpkg": (
            '#!/bin/sh\ncase "$1" in\n'
            ' --compare-versions) [ "$2" = 1.2.0-4.1 ] ;;\n'
            f" --print-architecture) printf '{architecture}' ;;\n"
            f" --install) touch '{installed}' ;;\nesac\n"
        ),
        "curl": (
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n"
            ' if [ "$1" = \'-o\' ]; then shift; printf fixture > "$1"; exit 0; fi\n'
            " shift\ndone\n"
        ),
        # This fixture isolates package selection; checksum rejection is above.
        "sha256sum": "#!/bin/sh\ncat >/dev/null\nexit 0\n",
    }
    for name, content in programs.items():
        path = binaries / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
    result = subprocess.run(  # noqa: S603 - tracked installer with isolated package tools
        ["/bin/sh", str(INSTALL)],
        env=os.environ | {"PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert installed.exists(), "the separately bundled Python decoder must be patched"


def test_brotli_overlay_runs_after_final_apt_install() -> None:
    dockerfile = (INSTALL.parent / "Dockerfile").read_text()
    assert dockerfile.rindex("apt-get install") < dockerfile.index(
        "RUN sh /opt/lyrashield/install_brotli.sh"
    )
