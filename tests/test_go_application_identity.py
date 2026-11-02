"""Application audit identity must stay separate from, and bound to, the local overlay."""

from __future__ import annotations

import copy
import hashlib
import json
import runpy
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
API = runpy.run_path(str(ROOT / "containers/verify_go_tool_provenance.py"))
MANIFEST = json.loads((ROOT / "containers/go-tools/applications.json").read_text())


@pytest.fixture
def installed(tmp_path):
    fs = tmp_path / "root"
    provenance = tmp_path / "provenance"
    for app in MANIFEST["applications"]:
        binary = fs / app["binary"].lstrip("/")
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(app["name"].encode())
        meta = provenance / app["name"]
        meta.mkdir(parents=True)
        (meta / "binary.sha256").write_text(
            hashlib.sha256(binary.read_bytes()).hexdigest() + "  " + app["name"] + "\n"
        )
        (meta / "buildinfo.txt").write_text(f"\tmod\t{app['module']}\t(devel)\n")
        (meta / "go.mod").write_text(f"module {app['module']}\n")
        (meta / "go.sum").write_text("locked dependency checksums\n")
        (meta / "source.txt").write_text(
            f"https://codeload.github.com/{app['repository']}/tar.gz/{app['commit']}\n"
            f"SHA256 {app['archive_sha256']}\n"
        )
    return fs, provenance


def test_all_eight_real_source_coordinates_are_present(installed):
    fs, provenance = installed
    sbom = API["make_sbom"](MANIFEST, provenance, fs)
    assert len(sbom["components"]) == 8
    assert {a["name"] for a in MANIFEST["applications"]} == {
        row.split("|")[0]
        for row in (ROOT / "containers/go-tools/sources.tsv").read_text().splitlines()
        if row and not row.startswith("#")
    }
    for app, component in zip(MANIFEST["applications"], sbom["components"], strict=True):
        assert component["version"] == app["version"] != "(devel)"
        assert component["purl"].endswith("@" + app["version"])
        properties = {p["name"]: p["value"] for p in component["properties"]}
        assert properties["lyrashield:overlay:kind"] == "local-security-rebuild"
        assert properties["lyrashield:source:commit"] == app["commit"]


@pytest.mark.parametrize("tamper", ["missing", "version", "hash", "overlay"])
def test_missing_or_modified_audit_coordinates_fail(installed, tamper):
    fs, provenance = installed
    expected = API["make_sbom"](MANIFEST, provenance, fs)
    actual = copy.deepcopy(expected)
    if tamper == "missing":
        actual["components"].pop()
    elif tamper == "version":
        actual["components"][0]["version"] = "v0.0.0"
    elif tamper == "hash":
        actual["components"][0]["hashes"][0]["content"] = "0" * 64
    else:
        actual["components"][0]["properties"].pop()
    with pytest.raises(ValueError, match="SBOM differs"):
        API["verify_sbom"](expected, actual)


def test_final_installed_byte_tampering_fails_before_scan(installed):
    fs, provenance = installed
    app = MANIFEST["applications"][0]
    (fs / app["binary"].lstrip("/")).write_bytes(b"npm hook replacement")
    with pytest.raises(ValueError, match="installed bytes differ"):
        API["make_sbom"](MANIFEST, provenance, fs)


def test_direct_builder_install_and_required_source_regressions():
    dockerfile = (ROOT / "containers/Dockerfile").read_text()
    for name in ("gitleaks", "trivy", "trufflehog"):
        assert f"--chown=root:root /out/bin/{name} /usr/local/bin/{name}" in dockerfile
        assert f"install -m 0755 /home/pentester/go/bin/{name}" not in dockerfile
    assert "/out/bin/ /home/pentester/go/bin/" not in dockerfile
    builder = (ROOT / "containers/go-tools/build.sh").read_text()
    assert 'GOEXPERIMENT="$experiment" go test -count=1 -p 1 -mod=readonly' in builder
    assert "./pkg/x/json ./pkg/iac/scanners/cloudformation/parser" in builder
    smoke = (ROOT / "scripts/smoke-sandbox.sh").read_text()
    assert "verify_go_tool_provenance.py" in smoke


def test_release_gate_requires_both_inventory_receipts_and_real_canary():
    workflow = (ROOT / ".github/workflows/publish-sandbox.yml").read_text()
    gate = (ROOT / "scripts/audit-sandbox-go-applications.sh").read_text()
    assert workflow.index("Audit byte-bound Go application coordinates") < workflow.index(
        "Promote the smoke-qualified digest"
    )
    for text in (
        "expected-applications.json",
        "expected-distro.cdx.json",
        "--receipts-only",
        "--emit-verified-sbom",
        "CVE-2024-5262",
        "--exit-code 1",
        "scan applications.cdx.json",
        "scan distro-applications.cdx.json",
    ):
        assert text in gate


def test_compression_fixtures_cannot_match_the_stored_token():
    fixtures = runpy.run_path(str(ROOT / "containers/go_compression_fixtures.py"))
    token = fixtures["TOKEN"].encode()
    payload = fixtures["payload"]()
    assert len(payload) > 20_000
    assert token in payload
    for name in ("ZSTD", "XZ"):
        assert token not in fixtures[name]
        assert len(fixtures[name]) < len(payload) // 20
    assert fixtures["lzma"].decompress(fixtures["XZ"]) == payload
