"""Verify required repair coverage against root-owned qualification manifests.

The installed receipt is evidence to be checked, never a source of which files or
packages must be checked. Input/output identities come from the trusted manifest.
"""

# ruff: noqa: INP001
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from amend_sources import HERE, sha, wheel_files
from safe_io import read_regular


# Package names are fixed by the root-owned manifest; no shell is involved.
def version(package: str) -> str:
    return subprocess.check_output(  # noqa: S603
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package],
        text=True,
    )


def contract(manifest: dict) -> dict:
    originals = {p["path"]: p["before_sha256"] for p in manifest["patches"]}
    originals.update(
        {
            "usr/lib/python3/dist-packages/" + n: digest
            for n, digest in manifest["pip"]["files"].items()
        }
    )
    for name in ("seed", "setuptools_seed"):
        originals[manifest["pip"][name + "_path"]] = manifest["pip"][name + "_sha256"]
    return {
        "schema": 1,
        "amendment": manifest["amendment"],
        "qualification_sha256": manifest["qualification_sha256"],
        "manifest_sha256": sha((HERE / "amendments.json").read_bytes()),
        "original_versions": {p["package"]: p["version"] for p in manifest["patches"]},
        "urllib3": manifest["urllib3"],
        "upstream_commits": sorted({c for p in manifest["patches"] for c in p["upstream_commits"]}),
        "files": {
            n: {"before_sha256": originals.get(n), "after_sha256": digest}
            for n, digest in manifest["expected_outputs"].items()
        },
        "removed": manifest["expected_removed"],
    }


def verify(root: Path = Path("/"), *, arch: str | None = None, package_version=version) -> None:
    manifest = json.loads((HERE / "amendments.json").read_text())
    leaves = json.loads((HERE / "leaves.json").read_text())
    receipt = json.loads(
        read_regular(root, "usr/share/lyrashield/security/system-python-amendments.json")
    )
    expected = contract(manifest)
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("amendment receipt differs from trusted coverage/hash contract")
    if arch is None:
        arch = subprocess.check_output(["/usr/bin/dpkg", "--print-architecture"], text=True).strip()
    packages = leaves["packages"][arch]
    installed = json.loads(
        read_regular(root, "usr/share/lyrashield/security/system-python-leaves.json")
    )
    expected_leaves = {
        "architecture": arch,
        "packages": packages,
        "release_sha256": {n: r["release_sha256"] for n, r in leaves["releases"].items()},
    }
    if installed != expected_leaves:
        raise ValueError("leaf receipt differs from trusted package coverage")
    for name, digest in manifest["expected_outputs"].items():
        data = read_regular(root, name)
        if sha(data) != digest:
            raise ValueError("installed output differs from trusted hash: " + name)
        if name.endswith(".whl"):
            wheel_files(data)
    for name in manifest["expected_removed"]:
        if (root / name).exists() or (root / name).is_symlink():
            raise ValueError("obsolete source survived amendment: " + name)
    for package in packages:
        if package_version(package["Package"]) != package["Version"]:
            raise ValueError("installed package version differs: " + package["Package"])
