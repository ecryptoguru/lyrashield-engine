"""The sandbox must distrust the compromised root in both OpenSSL trust paths."""

from __future__ import annotations

import importlib.util
import os
import ssl
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_system_ca_repair_precedes_https_and_survives_bulk_install() -> None:
    dockerfile = (ROOT / "containers/Dockerfile").read_text()
    stages = dockerfile.split("\nFROM ")[1:]
    assert len(stages) == 2
    builder, runtime = stages
    helper = "/opt/lyrashield/distrust_emsign_g3.sh"
    call = f"    sh {helper}"
    for stage, expected_calls in ((builder, 1), (runtime, 2)):
        bootstrap = stage.index("apt-get install -y --no-install-recommends ca-certificates")
        distrust = stage.index(call)
        first_https = stage.index("https://")
        assert stage.index(f"containers/distrust_emsign_g3.sh {helper}") < bootstrap
        assert bootstrap < distrust < first_https
        assert stage.count(call) == expected_calls
    assert f"COPY --chown=root:root containers/distrust_emsign_g3.sh {helper}" in builder
    # Runtime bulk installation and custom CA registration can regenerate trust;
    # the second runtime call must follow both before subsequent HTTPS work.
    bulk_install = runtime.index("    wget curl git vim nano unzip tar")
    refresh = runtime.index("update-ca-certificates &&")
    assert bulk_install < refresh < runtime.rindex(call)
    assert dockerfile.count(call) == 3


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


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "revoked_in_bundle",
        "revoked_in_pem",
        "revoked_hash_only",
        "malformed",
        "malformed_pem",
        "malformed_der",
        "missing",
    ],
)
def test_all_certificates_in_active_files_and_bundle_are_checked(tmp_path: Path, case: str) -> None:
    store = tmp_path / "etc/ssl/certs"
    store.mkdir(parents=True)
    certificate = tmp_path / "unrelated.pem"
    subprocess.run(  # noqa: S603 - fixed local certificate fixture
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=unrelated",
            "-days",
            "1",
            "-keyout",
            str(tmp_path / "key"),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    good = certificate.read_bytes()
    revoked = (ROOT / "tests/fixtures/emsign-g3.crt").read_bytes()
    (store / "local.pem").write_bytes(good + (revoked if case == "revoked_in_pem" else b""))
    if case == "revoked_hash_only":
        (store / "01234567.0").write_bytes(good + revoked)
    if case == "malformed_der":
        (store / "local.pem").write_bytes(
            good + b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        )
    if case == "malformed_pem":
        (store / "local.pem").write_bytes(good + b"-----BEGIN CERTIFICATE-----\nmalformed\n")
    if case != "missing":
        (store / "ca-certificates.crt").write_bytes(
            good
            + (
                revoked
                if case == "revoked_in_bundle"
                else b"-----BEGIN CERTIFICATE-----\nmalformed\n"
                if case == "malformed"
                else b""
            )
        )
    binaries = tmp_path / "bin"
    binaries.mkdir()
    updater = binaries / "update-ca-certificates"
    updater.write_text("#!/bin/sh\nexit 0\n")
    updater.chmod(0o755)
    result = subprocess.run(  # noqa: S603 - actual helper with modeled updater output
        ["/bin/sh", str(ROOT / "containers/distrust_emsign_g3.sh"), str(tmp_path)],
        env={
            **os.environ,
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "SSL_CERT_FILE": str(store / "ca-certificates.crt"),
            "SSL_CERT_DIR": str(store),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert (result.returncode == 0) == (case == "valid"), result.stdout + result.stderr
    if case not in {"revoked_in_pem", "revoked_hash_only", "malformed_pem", "malformed_der"}:
        spec = importlib.util.spec_from_file_location(
            "bundle_check", ROOT / "containers/verify_ca_bundle.py"
        )
        assert spec and spec.loader
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        previous = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(store / "ca-certificates.crt")
        try:
            if case == "valid":
                checker.verify_effective_bundle()
            else:
                with pytest.raises((ValueError, FileNotFoundError)):
                    checker.verify_effective_bundle()
        finally:
            if previous is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous


def test_smoke_rejects_missing_effective_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_ca_bundle", ROOT / "containers/verify_ca_bundle.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.pem"))
    with pytest.raises(FileNotFoundError):
        module.verify_effective_bundle()


def test_smoke_rejects_unreadable_effective_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read regardless of permission bits")
    spec = importlib.util.spec_from_file_location(
        "unreadable_bundle", ROOT / "containers/verify_ca_bundle.py"
    )
    assert spec and spec.loader
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    bundle = tmp_path / "private.pem"
    bundle.write_text("not reached")
    bundle.chmod(0)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    try:
        with pytest.raises(PermissionError):
            checker.verify_effective_bundle()
    finally:
        bundle.chmod(0o600)


def test_smoke_rejects_noncanonical_revoked_der(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = (ROOT / "tests/fixtures/emsign-g3.crt").read_text()
    der = ssl.PEM_cert_to_DER_cert(source)
    bundle = tmp_path / "trailing-g3.pem"
    bundle.write_text(ssl.DER_cert_to_PEM_cert(der + b"\0"))
    spec = importlib.util.spec_from_file_location(
        "canonical_bundle", ROOT / "containers/verify_ca_bundle.py"
    )
    assert spec and spec.loader
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    with pytest.raises(ValueError):
        checker.verify_effective_bundle()
