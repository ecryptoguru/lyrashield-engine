"""Local URL/API diagnostics exercise the product scanner and scoped relay."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from benchmarks.url_api_local_probe import create_certificates


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = Path(os.environ.get("LYRASHIELD_AI_DIR", "/nonexistent"))
pytestmark = pytest.mark.skipif(
    not (PRODUCT / "apps/worker/node_modules/.bin/tsx").is_file(),
    reason="set LYRASHIELD_AI_DIR to an installed product checkout",
)


def test_real_scanners_and_tls_relay_are_scoped_and_non_reportable(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    proc = subprocess.run(  # noqa: S603 -- fixed local executable and fixture path
        [sys.executable, "-m", "benchmarks.url_api_local_probe", "--output", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    receipt = json.loads((output / "receipt.json").read_text())
    assert receipt["profileStatus"] == "NOT_MEASURED"
    assert receipt["diagnosticStatus"] == "NOT_MEASURED"
    assert receipt["claimStatus"] == "NOT_REPORTABLE"
    assert receipt["adjudicationStatus"] == "NOT_INDEPENDENTLY_REVIEWED"
    assert receipt["heldOutStatus"] == "NOT_PROVIDED"
    assert receipt["modelRoute"] is None and receipt["image"] is None
    assert receipt["sources"]["engine"]["revision"]
    assert receipt["sources"]["product"]["revision"]
    assert receipt["runnerSha256"] and receipt["fixtureSha256"]
    assert receipt["scopeGrantSha256"] and receipt["tls"]["caSha256"]
    assert (
        receipt["tls"]["caSha256"] == hashlib.sha256((output / "ca.pem").read_bytes()).hexdigest()
    )
    assert (
        receipt["tls"]["targetCertSha256"]
        == hashlib.sha256((output / "target.pem").read_bytes()).hexdigest()
    )
    artifact = output / "diagnostic.json"
    assert receipt["resultSha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    result = json.loads(artifact.read_text())
    assert receipt["targetIdentity"] == result["targetIdentity"]
    assert result["targetIdentity"]["host"] == "fixture.test"
    assert 0 < result["targetIdentity"]["port"] <= 65535
    assert result["targetIdentity"]["certificateSha256"] == receipt["tls"]["targetCertSha256"]
    assert (
        result["responseSha256"]
        == hashlib.sha256(
            (ROOT / "benchmarks/fixtures/url_api/v1/health.json").read_bytes()
        ).hexdigest()
    )
    assert result["web"]["profile"] == "WEB_APP_SAFE"
    assert result["web"]["documentCount"] == 1
    assert isinstance(result["web"]["findings"], list)
    assert any(item["id"].startswith("surface.csp-missing.") for item in result["web"]["findings"])
    assert result["api"]["profile"] == "API_STANDARD"
    assert result["api"]["operationCount"] == 2
    assert isinstance(result["api"]["findings"], list)
    assert result["api"]["operations"] == [
        {"method": "GET", "path": "/api/health"},
        {"method": "HEAD", "path": "/api/health"},
    ]
    assert result["checks"] == {
        "allowed": 200,
        "blockedPath": 403,
        "blockedMethod": 403,
        "blockedHost": 403,
        "blockedPort": 403,
        "opaqueConnect": 403,
        "invalidGrant": 403,
        "revokedGrant": 403,
        "untrustedCa": 502,
        "wrongHostname": 502,
        "externalRedirect": "ssrf_blocked",
    }
    assert all(request["path"] != "/admin" for request in result["targetRequests"])
    assert all(request["method"] != "POST" for request in result["targetRequests"])
    assert not any(
        "grant" in key.lower() for request in result["targetRequests"] for key in request
    )
    denied = {item.get("denyReason") for item in result["relayAudit"]}
    assert {
        "path_blocked",
        "method_not_allowed",
        "host_out_of_scope",
        "port_not_allowed",
        "connect_not_supported",
    } <= denied


def test_invalid_openapi_document_fails_the_diagnostic(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    shutil.copytree(ROOT / "benchmarks/fixtures/url_api/v1", fixture)
    (fixture / "openapi.json").write_text("not an OpenAPI document")
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    certs = create_certificates(cert_dir)
    short_tmp = "/tmp" if Path("/tmp").is_dir() else None  # noqa: S108 -- private mkdtemp below
    with tempfile.TemporaryDirectory(prefix="lyra-test-", dir=short_tmp) as temp_dir:
        proc = subprocess.run(  # noqa: S603 -- fixed local executable and test paths
            [
                str(PRODUCT / "apps/worker/node_modules/.bin/tsx"),
                str(ROOT / "benchmarks/run_url_api_local.ts"),
                "--fixture",
                str(fixture),
                "--ca",
                str(certs["ca.pem"]),
                "--wrong-ca",
                str(certs["wrong-ca.pem"]),
                "--cert",
                str(certs["target.pem"]),
                "--key",
                str(certs["target-key.pem"]),
            ],
            cwd=ROOT,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": temp_dir,
                "TMPDIR": temp_dir,
                "LYRASHIELD_AI_DIR": str(PRODUCT),
            },
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    assert proc.returncode != 0
    assert "incomplete" in proc.stderr.lower()
    assert "URLPROBE:" not in proc.stdout
