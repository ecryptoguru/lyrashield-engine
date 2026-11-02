"""Exercise rebuilt Go tools with loopback crawling and synthetic secret fixtures."""

# ruff: noqa: INP001
from __future__ import annotations

import base64
import functools
import http.server
import json
import lzma
import subprocess
import tarfile
import tempfile
import threading
from pathlib import Path


def run(*args: str, expected: int = 0, include_stderr: bool = False) -> str:
    result = subprocess.run(  # noqa: S603 - fixed CLI names and local fixtures
        args, capture_output=True, text=True, timeout=90, check=False
    )
    if result.returncode != expected:
        raise AssertionError(
            f"{args[0]} exited {result.returncode}: {result.stderr} {result.stdout}"
        )
    return result.stdout + (result.stderr if include_stderr else "")


def main() -> None:
    for name, flag, version in (
        ("gitleaks", "version", "8.30.1"),
        ("trivy", "--version", "0.73.0"),
        ("trufflehog", "--version", "3.99.2"),
    ):
        assert version in run(name, flag, include_stderr=True)
    run("interactsh-client", "-version")
    assert "v2.0.2" in run("vulnx", "version", "--disable-update-check", include_stderr=True)
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        site = root / "site"
        site.mkdir()
        (site / "index.html").write_text('<a href="/fixture-page.html">fixture</a>')
        (site / "fixture-page.html").write_text("local crawler fixture")
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(site))
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_port}"
            try:
                assert url in run("httpx", "-u", url, "-silent", "-no-fallback-scheme", "-duc")
                assert "/fixture-page.html" in run(
                    "katana", "-u", url, "-silent", "-d", "1", "-duc"
                )
                assert "/fixture-page.html" in run(
                    "gospider", "-s", url, "-B", "-d", "1", "-t", "1"
                )
            finally:
                server.shutdown()
                thread.join()
        secrets = root / "secrets"
        secrets.mkdir()
        # Deliberately fake: deterministic format and entropy, never a usable key.
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        (secrets / "fixture.txt").write_text(f'github_token="{token}"\n')
        report = root / "gitleaks.json"
        run(
            "gitleaks",
            "dir",
            str(secrets),
            "--no-banner",
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            expected=1,
        )
        assert any(item["RuleID"] == "github-pat" for item in json.loads(report.read_text()))
        archives = root / "archives"
        archives.mkdir()
        with tarfile.open(archives / "fixture.tar.gz", "w:gz") as archive:
            archive.add(secrets / "fixture.txt", arcname="fixture.txt")
        # Independently encoded valid Zstandard bytes containing the same fake token.
        (archives / "fixture.txt.zst").write_bytes(
            base64.b64decode(
                "KLUv/SA4wQEAZ2l0aHViX3Rva2VuPSJnaHBfQTFiMkMzZDRFNWY2RzdoOEk5ajBLMWwyTTNuNE81cDZRN3I4Igo="
            )
        )
        (archives / "fixture.txt.xz").write_bytes(
            lzma.compress((secrets / "fixture.txt").read_bytes())
        )
        archive_report = root / "gitleaks-archive.json"
        run(
            "gitleaks",
            "dir",
            str(archives),
            "--no-banner",
            "--redact",
            "--max-archive-depth",
            "1",
            "--report-format",
            "json",
            "--report-path",
            str(archive_report),
            expected=1,
        )
        assert any(
            item["RuleID"] == "github-pat" and "fixture.tar.gz" in item["File"]
            for item in json.loads(archive_report.read_text())
        )
        for extension in (".zst", ".xz"):
            assert any(
                item["RuleID"] == "github-pat" and extension in item["File"]
                for item in json.loads(archive_report.read_text())
            )
        benign = root / "benign"
        benign.mkdir()
        (benign / "safe.txt").write_text("A benign local fixture.\n")
        run("gitleaks", "dir", str(benign), "--no-banner")
        output = run(
            "trufflehog",
            "--no-update",
            "--json",
            "filesystem",
            str(secrets),
            "--no-verification",
            "--include-detectors",
            "Github",
        )
        assert any(json.loads(line).get("DetectorName") == "Github" for line in output.splitlines())
        output = run(
            "trivy",
            "filesystem",
            "--scanners",
            "secret",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--format",
            "json",
            str(secrets),
        )
        assert any(result.get("Secrets") for result in json.loads(output).get("Results", []))
    print("Go tool local compatibility fixtures passed")  # noqa: T201


if __name__ == "__main__":
    main()
