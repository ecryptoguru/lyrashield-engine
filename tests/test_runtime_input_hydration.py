"""Transport integrity, strict archive parsing, and safe cache publication."""

# Helpers are imported inside isolated fixture tests when needed.
# ruff: noqa: PLC0415
from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

import pytest


DIRECTORY = Path(__file__).resolve().parents[1] / "containers/system-python-security"
sys.path.insert(0, str(DIRECTORY))
import hydrate_runtime_inputs as hydration  # noqa: E402


def fixture():
    files = {"a-Packages.gz": b"signed fixture index", "package.deb": b"qualified fixture package"}
    data = hydration.encode(files)
    manifest = {
        "files": {
            name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
            for name, value in files.items()
        },
        "bundle": {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "raw_bytes": sum(map(len, files.values())),
    }
    return files, data, manifest


def repin(data, manifest):
    manifest = copy.deepcopy(manifest)
    manifest["bundle"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return manifest


def tar_fixture(files, *, mutation=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for index, (name, data) in enumerate(sorted(files.items())):
            member = hydration.header(name, len(data))
            if mutation:
                mutation(archive, member, index)
            archive.addfile(member, io.BytesIO(data) if member.isreg() else None)
    return gzip.compress(raw.getvalue(), mtime=0)


def test_deterministic_positive_hydration_and_idempotent_cache(tmp_path):
    files, data, manifest = fixture()
    assert data == hydration.encode(dict(reversed(list(files.items()))))
    assert hydration.decode(data, manifest) == files
    hydration.hydrate(data, manifest, tmp_path)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == files
    first_inodes = {p.name: p.stat().st_ino for p in tmp_path.iterdir()}
    hydration.hydrate(data, manifest, tmp_path)
    assert first_inodes == {p.name: p.stat().st_ino for p in tmp_path.iterdir()}


@pytest.mark.parametrize(
    "mutation",
    [
        "hash",
        "size",
        "omission",
        "extra",
        "duplicate",
        "symlink",
        "hardlink",
        "traversal",
        "absolute",
        "directory",
        "oversize",
        "padding",
        "gzip-tail",
        "gzip-bomb",
    ],
)
def test_untrusted_bundle_is_rejected_before_cache_mutation(tmp_path, mutation):  # noqa: PLR0915
    files, data, manifest = fixture()
    if mutation == "hash":
        data = bytes([data[0] ^ 1]) + data[1:]
    elif mutation == "size":
        data += b"extra"
    elif mutation == "omission":
        data = hydration.encode({next(iter(files)): next(iter(files.values()))})
        manifest = repin(data, manifest)
    elif mutation == "extra":
        data = hydration.encode({**files, "extra": b"unreviewed"})
        manifest = repin(data, manifest)
    elif mutation in (
        "duplicate",
        "symlink",
        "hardlink",
        "traversal",
        "absolute",
        "directory",
        "oversize",
    ):

        def alter(_archive, member, index):
            if index != 1:
                return
            if mutation == "duplicate":
                member.name = "a-Packages.gz"
            elif mutation == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "outside"
            elif mutation == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = "a-Packages.gz"
            elif mutation == "traversal":
                member.name = "../outside"
            elif mutation == "absolute":
                member.name = "/outside"
            elif mutation == "directory":
                member.type = tarfile.DIRTYPE
            else:
                pass

        if mutation == "oversize":
            files["package.deb"] += b"x"
        data = tar_fixture(files, mutation=alter)
        manifest = repin(data, manifest)
    elif mutation == "padding":
        raw = bytearray(gzip.decompress(data))
        raw[-1] = 1
        data = gzip.compress(raw, mtime=0)
        manifest = repin(data, manifest)
    elif mutation == "gzip-tail":
        data += gzip.compress(b"", mtime=0)
        manifest = repin(data, manifest)
    else:
        data = gzip.compress(b"x" * 1_000_000, mtime=0)
        manifest = repin(data, manifest)
    sentinel = tmp_path / ".gitignore"
    sentinel.write_bytes(b"fixture sentinel")
    with pytest.raises((ValueError, OSError)):
        hydration.hydrate(data, manifest, tmp_path)
    assert list(tmp_path.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"fixture sentinel"


def test_late_inner_hash_failure_writes_nothing(tmp_path):
    _, data, manifest = fixture()
    manifest["files"]["package.deb"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="member"):
        hydration.hydrate(data, manifest, tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("kind", ["altered", "symlink", "hardlink", "extra", "ancestor"])
def test_existing_cache_drift_or_links_are_not_overwritten(tmp_path, kind):
    files, data, manifest = fixture()
    cache = tmp_path / "cache"
    cache.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(files["package.deb"])
    path = cache / "package.deb"
    if kind == "altered":
        path.write_bytes(b"altered")
    elif kind == "symlink":
        path.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, path)
    elif kind == "extra":
        (cache / "unreviewed").write_bytes(b"extra")
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        cache = alias / "cache"
    with pytest.raises((ValueError, OSError)):
        hydration.hydrate(data, manifest, cache)
    assert outside.read_bytes() == files["package.deb"]
    assert not (cache / "a-Packages.gz").exists()


def test_fixed_gh_download_has_no_caller_selected_host_or_auth_forwarding(monkeypatch):
    _, data, manifest = fixture()

    def run(command, **kwargs):
        assert command[1:4] == ["release", "download", hydration.TAG]
        assert command[command.index("--repo") + 1] == "github.com/ecryptoguru/lyrashield-engine"
        assert command[command.index("--pattern") + 1] == hydration.ASSET
        assert kwargs["env"]["GH_HOST"] == "github.com"
        assert "GH_ENTERPRISE_TOKEN" not in kwargs["env"]
        assert "GH_REPO" not in kwargs["env"]
        assert kwargs["timeout"] == 120
        target = Path(command[command.index("--dir") + 1]) / hydration.ASSET
        target.write_bytes(data)

    monkeypatch.setenv("GH_HOST", "attacker.invalid")
    monkeypatch.setenv("GH_REPO", "attacker/other")
    monkeypatch.setenv("GH_ENTERPRISE_TOKEN", "inert-enterprise-token")
    monkeypatch.setattr(hydration.shutil, "which", lambda _: "/reviewed/gh")
    monkeypatch.setattr(hydration.subprocess, "run", run)
    assert hydration.download(manifest) == data


def test_transport_manifest_cannot_drift_from_qualified_inputs(monkeypatch):
    manifest = hydration.load_manifest()
    assert len(manifest["files"]) == 14
    assert manifest["raw_bytes"] == 69_409_899
    assert manifest["repository"] == "ecryptoguru/lyrashield-engine"
    assert manifest["release_tag"] == hydration.TAG
    original = hydration.MANIFEST
    altered = json.loads(original.read_text())
    name = next(iter(altered["files"]))
    altered["files"][name]["sha256"] = "0" * 64
    monkeypatch.setattr(hydration, "_read_manifest", lambda: altered)
    with pytest.raises(ValueError, match="qualification"):
        hydration.load_manifest()


@pytest.mark.parametrize(
    "field",
    [
        "repository",
        "release_tag",
        "asset",
        "leaves_sha256",
        "signed_releases",
        "coverage",
        "raw_bytes",
    ],
)
def test_fixed_transport_identity_cannot_be_retargeted(monkeypatch, field):
    changed = json.loads(hydration.MANIFEST.read_text())
    if field == "signed_releases":
        changed[field]["sid"] = "0" * 64
    elif field == "coverage":
        changed["files"].pop(next(iter(changed["files"])))
    elif field == "raw_bytes":
        changed[field] -= 1
    else:
        changed[field] = "unreviewed"
    monkeypatch.setattr(hydration, "_read_manifest", lambda: changed)
    with pytest.raises(ValueError, match="qualification"):
        hydration.load_manifest()


@pytest.mark.parametrize("kind", ["oversized", "symlink", "hardlink"])
def test_local_bundle_read_is_bounded_and_regular(tmp_path, kind):
    _, data, manifest = fixture()
    original = tmp_path / "original"
    original.write_bytes(data)
    selected = tmp_path / "selected"
    if kind == "symlink":
        selected.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, selected)
    else:
        selected.write_bytes(data + b"unbounded extra bytes")
    with pytest.raises((ValueError, OSError)):
        hydration.local_bundle(selected, manifest)


def test_partial_cache_publication_failure_rolls_back_and_retries(tmp_path, monkeypatch):
    import safe_io

    files, data, manifest = fixture()
    (tmp_path / ".gitignore").write_bytes(b"fixture sentinel")
    replace = safe_io.os.replace
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected cache publication failure")
        return replace(*args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(safe_io.os, "replace", fail_second)
        with pytest.raises(OSError, match="injected"):
            hydration.hydrate(data, manifest, tmp_path)
    assert {p.name for p in tmp_path.iterdir()} == {".gitignore"}
    hydration.hydrate(data, manifest, tmp_path)
    assert all((tmp_path / name).read_bytes() == value for name, value in files.items())


def test_creator_refuses_unreviewed_output_hash_and_does_not_rewrite_manifest(tmp_path):
    files, _, manifest = fixture()
    cache = tmp_path / "cache"
    cache.mkdir()
    for name, data in files.items():
        (cache / name).write_bytes(data)
    before = hydration.MANIFEST.read_bytes()
    manifest["bundle"]["sha256"] = "0" * 64
    output = tmp_path / hydration.ASSET
    with pytest.raises(ValueError, match="transport"):
        hydration.create(cache, output, manifest)
    assert not output.exists()
    assert hydration.MANIFEST.read_bytes() == before


def test_positive_creator_reproduces_only_the_fixed_asset(tmp_path):
    files, data, manifest = fixture()
    cache = tmp_path / "cache"
    cache.mkdir()
    for name, content in files.items():
        (cache / name).write_bytes(content)
    output = tmp_path / hydration.ASSET
    hydration.create(cache, output, manifest)
    assert output.read_bytes() == data
    with pytest.raises(ValueError, match="basename"):
        hydration.create(cache, tmp_path / "other.tar.gz", manifest)
