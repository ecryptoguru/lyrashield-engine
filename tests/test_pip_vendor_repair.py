"""Fail-closed source replacement and truthful inventory for the pip exception."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repair_pip_vendors", ROOT / "containers/repair_pip_vendors.py"
)
assert SPEC and SPEC.loader
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


def _dist(site: Path, name: str, version: str, files: dict[str, bytes]) -> None:
    dist = site / f"{name}-{version}.dist-info"
    files = {
        **files,
        f"{dist.name}/WHEEL": b"fixture wheel",
        f"{dist.name}/METADATA": f"Name: {name}\nVersion: {version}\n".encode(),
    }
    rows = []
    for relative, data in files.items():
        target = site / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rows.append([relative, HELPER.record_hash(data), str(len(data))])
    rows.append([f"{dist.name}/RECORD", "", ""])
    stream = io.StringIO()
    csv.writer(stream).writerows(rows)
    (dist / "RECORD").write_text(stream.getvalue())


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    manifest = b"msgpack==1.1.2\nurllib3==2.7.0\n"
    bom = json.dumps(
        {
            "components": [
                {
                    "name": name,
                    "version": old,
                    "purl": f"pkg:pypi/{name}@{old}",
                    "bom-ref": f"pkg:pypi/{name}@{old}",
                }
                for name, (old, _new) in HELPER.REPLACEMENTS.items()
            ],
            "dependencies": [{"ref": "pkg:pypi/msgpack@1.1.2"}],
        }
    ).encode()
    _dist(
        tmp_path,
        "pip",
        "26.2.2",
        {
            "pip/_vendor/vendor.txt": manifest,
            "pip/_vendor/bom.cdx.json": bom,
            "pip/_vendor/__init__.py": b"DEBUNDLED = False",
            "pip/_vendor/msgpack/old.py": b"old",
            "pip/_vendor/urllib3/old.py": b"old",
        },
    )
    monkeypatch.setattr(HELPER, "VENDOR_SHA256", hashlib.sha256(manifest).hexdigest())
    monkeypatch.setattr(HELPER, "BOM_SHA256", hashlib.sha256(bom).hexdigest())
    for name, (_old, new) in HELPER.REPLACEMENTS.items():
        _dist(
            tmp_path,
            name,
            new,
            {
                f"{name}/__init__.py": f"__version__ = '{new}'".encode(),
                f"{name}/_extension.so": b"never vendor ABI bytes",
                **(
                    {"urllib3/contrib/emscripten/emscripten_fetch_worker.js": b"// verified worker"}
                    if name == "urllib3"
                    else {}
                ),
                f"{name}-{new}.dist-info/licenses/LICENSE": b"upstream license",
            },
        )
    inventories = []
    for name, version in [("pip", "26.2.2"), ("msgpack", "1.2.3"), ("urllib3", "2.8.0")]:
        record = tmp_path / f"{name}-{version}.dist-info/RECORD"
        expected = {row[0]: row[1:] for row in csv.reader(record.open()) if row[1]}
        inventories.append(
            {"name": name, "version": version, "files": expected, "sha256": "fixture"}
        )
    monkeypatch.setattr(HELPER, "WHEEL_INVENTORIES", inventories)
    return tmp_path


def test_repair_copies_verified_python_and_updates_inventory_and_record(site: Path) -> None:
    HELPER.repair(site)
    record = site / "pip-26.2.2.dist-info/RECORD"
    HELPER.verified_record_files(site, {row[0]: row for row in csv.reader(record.open())})
    vendor = site / "pip/_vendor"
    assert "msgpack==1.2.3" in (vendor / "vendor.txt").read_text()
    assert not list(vendor.rglob("*.so"))
    assert not list(vendor.rglob("old.py"))
    bom = json.loads((vendor / "bom.cdx.json").read_text())
    assert bom["dependencies"][0]["ref"] == "pkg:pypi/msgpack@1.2.3"
    assert {c["version"] for c in bom["components"]} == {"1.2.3", "2.8.0"}
    assert (vendor / "msgpack/LICENSE.txt").read_text() == "upstream license"
    receipt = json.loads((vendor / "lyrashield-vendor-repair.json").read_text())
    assert {p["mode"] for p in receipt["replacements"]} == {"pure-python"}


@pytest.mark.parametrize(
    "relative",
    [
        "pip/_vendor/msgpack/old.py",
        "urllib3/__init__.py",
        "msgpack-1.2.3.dist-info/licenses/LICENSE",
    ],
)
def test_tampered_original_or_replacement_fails_before_any_write(site: Path, relative: str) -> None:
    target = site / relative
    target.write_bytes(b"tampered")
    before = {str(p.relative_to(site)): p.read_bytes() for p in site.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="RECORD mismatch"):
        HELPER.repair(site)
    after = {str(p.relative_to(site)): p.read_bytes() for p in site.rglob("*") if p.is_file()}
    assert after == before


def test_repair_rejects_unreviewed_manifest_even_with_valid_record(site: Path) -> None:
    _dist(site, "pip", "26.2.2", {"pip/_vendor/vendor.txt": b"msgpack==9.0\n"})
    with pytest.raises(ValueError, match=r"manifest|inventory|RECORD"):
        HELPER.repair(site)


def test_repair_is_not_silently_reapplied(site: Path) -> None:
    HELPER.repair(site)
    with pytest.raises(ValueError, match=r"manifest|inventory|RECORD"):
        HELPER.repair(site)


def test_app_lock_replaces_same_version_distro_seed_before_vendor_validation() -> None:
    dockerfile = (ROOT / "containers/Dockerfile").read_text()
    installation = next(
        line
        for line in dockerfile.splitlines()
        if "/app/.venv/bin/pip install" in line and "python-requirements.txt" in line
    )
    # A repaired Debian 26.2.2 seed is not the official wheel whose RECORD and
    # exact vendor manifests the application repair deliberately validates.
    assert "--force-reinstall" in installation
    assert "--require-hashes" in installation and "--no-deps" in installation


def _snapshot(site: Path) -> dict[str, bytes | str]:
    return {
        str(p.relative_to(site)): str(p.readlink()) if p.is_symlink() else p.read_bytes()
        for p in site.rglob("*")
        if p.is_file() or p.is_symlink()
    }


def _remove_record_row(site: Path, package: str, version: str, relative: str) -> None:
    record = site / f"{package}-{version}.dist-info/RECORD"
    rows = list(csv.reader(record.open()))
    stream = io.StringIO()
    csv.writer(stream).writerows(row for row in rows if row[0] != relative)
    record.write_text(stream.getvalue())


@pytest.mark.parametrize(
    "package,version,relative",
    [
        ("pip", "26.2.2", "pip/_vendor/__init__.py"),
        ("msgpack", "1.2.3", "msgpack-1.2.3.dist-info/licenses/LICENSE"),
    ],
)
def test_removed_record_row_cannot_authorize_tampered_payload(
    site: Path, package: str, version: str, relative: str
) -> None:
    _remove_record_row(site, package, version, relative)
    (site / relative).write_bytes(b"DEBUNDLED = False\n# tampered")
    before = _snapshot(site)
    with pytest.raises(ValueError):
        HELPER.repair(site)
    assert _snapshot(site) == before


def test_missing_second_destination_is_rejected_before_first_deletion(site: Path) -> None:

    shutil.rmtree(site / "pip/_vendor/msgpack")
    _remove_record_row(site, "pip", "26.2.2", "pip/_vendor/msgpack/old.py")
    before = _snapshot(site)
    with pytest.raises(ValueError):
        HELPER.repair(site)
    assert _snapshot(site) == before


def test_symlink_destination_is_rejected_before_mutation(site: Path, tmp_path: Path) -> None:

    other = tmp_path / "other"
    (site / "pip/_vendor/msgpack").rename(other)
    (site / "pip/_vendor/msgpack").symlink_to(other, target_is_directory=True)
    before = _snapshot(site)
    with pytest.raises(ValueError):
        HELPER.repair(site)
    assert _snapshot(site) == before


def test_repair_retains_verified_emscripten_worker_resource(site: Path) -> None:
    HELPER.repair(site)
    expected = site / "urllib3/contrib/emscripten/emscripten_fetch_worker.js"
    actual = site / "pip/_vendor/urllib3/contrib/emscripten/emscripten_fetch_worker.js"
    assert actual.read_bytes() == expected.read_bytes()


def test_rehashed_tampered_code_does_not_replace_trusted_wheel_identity(site: Path) -> None:
    path = site / "urllib3/__init__.py"
    path.write_bytes(b"raise RuntimeError('tampered')")
    record = site / "urllib3-2.8.0.dist-info/RECORD"
    rows = list(csv.reader(record.open()))
    for row in rows:
        if row[0] == "urllib3/__init__.py":
            row[1:] = [HELPER.record_hash(path.read_bytes()), str(path.stat().st_size)]
    stream = io.StringIO()
    csv.writer(stream).writerows(rows)
    record.write_text(stream.getvalue())
    before = _snapshot(site)
    with pytest.raises(ValueError, match="inventory/RECORD"):
        HELPER.repair(site)
    assert _snapshot(site) == before


@pytest.mark.parametrize("relative", ["pip/_vendor/msgpack", "pip-26.2.2.dist-info/RECORD"])
def test_unwritable_destination_rejected_before_any_mutation(site: Path, relative: str) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can write regardless of permission bits")
    target = site / relative
    mode = target.stat().st_mode
    target.chmod(0o500 if target.is_dir() else 0o400)
    try:
        before = _snapshot(site)
        with pytest.raises(ValueError, match="writable"):
            HELPER.repair(site)
        assert _snapshot(site) == before
    finally:
        target.chmod(mode)
