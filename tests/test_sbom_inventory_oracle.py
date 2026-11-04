"""Independent, explicitly scoped filesystem inventory compared with SPDX."""

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts/check_sbom_inventory.py"


def write_inputs(tmp_path, *, omit="", malformed=False):
    root = {
        "var/lib/dpkg/status": (
            "Package: libsample\nStatus: install ok installed\nArchitecture: amd64\n"
            "Version: 1.2-3\n\n"
        ),
        "app/.venv/lib/python3.12/site-packages/My_Pkg-2.dist-info/METADATA": (
            "Name: My_Pkg\nVersion: 2.0\n\n"
        ),
        "home/pentester/.npm-tools/node_modules/@scope/example/package.json": json.dumps(
            {"name": "@scope/example", "version": "3.0"}
        ),
    }
    if malformed:
        root["home/pentester/.npm-tools/node_modules/@scope/example/package.json"] = "{bad"
    with tarfile.open(tmp_path / "rootfs.tar", "w") as archive:
        for name, value in root.items():
            data = value.encode()
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    packages = [
        {
            "name": "libsample",
            "versionInfo": "1.2-3",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:deb/kali/libsample@1.2-3?arch=amd64",
                }
            ],
        },
        {
            "name": "my-pkg",
            "versionInfo": "2.0",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/my-pkg@2.0"}],
        },
        {
            "name": "@scope/example",
            "versionInfo": "3.0",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:npm/%40scope/example@3.0"}
            ],
        },
    ]
    (tmp_path / "sbom.json").write_text(
        json.dumps({"packages": [p for p in packages if p["name"] != omit]})
    )


def invoke(tmp_path):
    return subprocess.run(  # noqa: S603 - fixed local script, test-owned paths
        [
            sys.executable,
            str(SCRIPT),
            "--rootfs",
            str(tmp_path / "rootfs.tar"),
            "--sbom",
            str(tmp_path / "sbom.json"),
            "--output",
            str(tmp_path / "result.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_scoped_inventory_matches_dpkg_python_and_installed_npm(tmp_path):
    write_inputs(tmp_path)
    run = invoke(tmp_path)
    assert run.returncode == 0, run.stderr
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["status"] == "scoped_inventory_matched"
    assert result["inventoryCounts"] == {"deb": 1, "pypi": 1, "npm": 1}
    assert result["missing"] == []


@pytest.mark.parametrize("name", ["libsample", "my-pkg", "@scope/example"])
def test_missing_inventory_item_fails_closed(tmp_path, name):
    write_inputs(tmp_path, omit=name)
    run = invoke(tmp_path)
    assert run.returncode != 0
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["status"] == "incomplete"
    assert len(result["missing"]) == 1


def test_unparseable_installed_metadata_is_unresolved(tmp_path):
    write_inputs(tmp_path, malformed=True)
    run = invoke(tmp_path)
    assert run.returncode != 0
    assert json.loads((tmp_path / "result.json").read_text())["unresolved"]


@pytest.mark.parametrize("ecosystem", ["deb", "pypi", "npm"])
def test_wrong_purl_identity_cannot_satisfy_inventory(tmp_path, ecosystem):
    write_inputs(tmp_path)
    path = tmp_path / "sbom.json"
    doc = json.loads(path.read_text())
    package = next(
        p
        for p in doc["packages"]
        if p["externalRefs"][0]["referenceLocator"].startswith(f"pkg:{ecosystem}/")
    )
    package["externalRefs"][0]["referenceLocator"] = f"pkg:{ecosystem}/wrong@0.1?arch=amd64"
    path.write_text(json.dumps(doc))
    assert invoke(tmp_path).returncode != 0


@pytest.mark.parametrize(
    "target,expected",
    [
        ("../example/package.json", 0),
        ("../missing/package.json", 1),
        ("../../../../../../../../etc/passwd", 1),
    ],
)
def test_npm_metadata_symlink_requires_an_in_scope_resolvable_target(tmp_path, target, expected):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        link = tarfile.TarInfo("home/pentester/.npm-tools/node_modules/@scope/alias/package.json")
        link.type = tarfile.SYMTYPE
        link.linkname = target
        archive.addfile(link)
    assert (invoke(tmp_path).returncode == 0) == (expected == 0)
