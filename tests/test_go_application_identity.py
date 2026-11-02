"""Application audit identity must stay separate from, and bound to, the local overlay."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import runpy
import subprocess
import sys
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


def test_sbom_build_runs_as_root_with_isolated_system_python():
    dockerfile = (ROOT / "containers/Dockerfile").read_text()
    effective_user = "root"
    generation_steps = []
    for line in dockerfile.splitlines():
        if line.startswith("FROM "):
            effective_user = "root"
        elif line.startswith("USER "):
            effective_user = line.split()[1]
        elif line.startswith("RUN ") and "--write-sbom" in line:
            generation_steps.append((effective_user, line))
    assert len(generation_steps) == 1
    user, command = generation_steps[0]
    assert user == "root"
    assert command.startswith("RUN /usr/bin/python3 -I -S ")
    assert "--chown=root:root containers/verify_go_tool_provenance.py" in dockerfile
    assert "--chown=root:root containers/go-tools/applications.json" in dockerfile


def test_receipt_gate_and_smoke_use_isolated_system_python():
    gate = (ROOT / "scripts/audit-sandbox-go-applications.sh").read_text()
    validator_runs = [
        line for line in gate.splitlines() if "--entrypoint" in line and "python" in line
    ]
    assert len(validator_runs) == 3
    assert all('--entrypoint /usr/bin/python3 "$image" -I -S' in line for line in validator_runs)
    assert "/app/.venv/bin/python" not in gate
    smoke = (ROOT / "scripts/smoke-sandbox.sh").read_text()
    assert "/usr/bin/python3 -I -S /opt/lyrashield/verify_go_tool_provenance.py" in smoke


def test_isolated_verifier_ignores_untrusted_python_startup_and_modules(installed, tmp_path):
    fs, provenance = installed
    hostile = tmp_path / "hostile-python"
    hostile.mkdir()
    marker = hostile / "startup-executed"
    (hostile / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').write('injected')\n")
    (hostile / "json.py").write_text("raise RuntimeError('untrusted json imported')\n")
    manifest = tmp_path / "applications.json"
    manifest.write_text(json.dumps(MANIFEST))
    sbom = tmp_path / "applications.cdx.json"
    command = [
        sys.executable,
        "-I",
        "-S",
        str(ROOT / "containers/verify_go_tool_provenance.py"),
        "--manifest",
        str(manifest),
        "--filesystem",
        str(fs),
        "--provenance",
        str(provenance),
    ]
    env = dict(os.environ, PYTHONPATH=str(hostile), PYTHONSTARTUP=str(hostile / "sitecustomize.py"))
    generated = subprocess.run(  # noqa: S603 - fixed local verifier with synthetic receipts
        [*command, "--write-sbom", str(sbom)],
        cwd=hostile,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    assert len(json.loads(sbom.read_text())["components"]) == 8
    assert not marker.exists()
    (fs / MANIFEST["applications"][0]["binary"].lstrip("/")).write_bytes(b"tampered")
    rejected = subprocess.run(  # noqa: S603 - fixed local verifier with synthetic tampering
        [*command, "--sbom", str(sbom)],
        cwd=hostile,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "installed bytes differ" in rejected.stderr
    assert not marker.exists()
