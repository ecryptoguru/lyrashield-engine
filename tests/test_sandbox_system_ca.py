"""The sandbox must distrust the compromised root in both OpenSSL trust paths."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_system_ca_repair_precedes_https_and_survives_bulk_install() -> None:
    dockerfile = (ROOT / "containers/Dockerfile").read_text()
    bootstrap = dockerfile.index("apt-get install -y --no-install-recommends ca-certificates")
    https = dockerfile.index("https://kali.download/kali")
    first = dockerfile.index("/opt/lyrashield/distrust_emsign_g3.sh", bootstrap)
    assert bootstrap < first < https
    assert dockerfile.count("    sh /opt/lyrashield/distrust_emsign_g3.sh") == 2


def test_system_ca_repair_refuses_unreviewed_certificate(tmp_path: Path) -> None:
    source = tmp_path / "usr/share/ca-certificates/mozilla"
    source.mkdir(parents=True)
    # A valid, unrelated certificate must never be disabled by filename alone.
    subprocess.run(  # noqa: S603 - fixed local OpenSSL fixture
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=fixture",
            "-days",
            "1",
            "-keyout",
            str(tmp_path / "key"),
            "-out",
            str(source / "emSign_ECC_Root_CA_-_G3.crt"),
        ],
        check=True,
        capture_output=True,
    )
    result = subprocess.run(  # noqa: S603 - tracked build helper and isolated fixture
        ["/bin/sh", str(ROOT / "containers/distrust_emsign_g3.sh"), str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Unreviewed" in result.stderr
