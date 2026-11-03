"""Fail-closed source and wheel contracts, independent of the host Python layout."""

# Each fixture imports the helper it exercises after the standalone path is selected.
# ruff: noqa: PLC0415
from __future__ import annotations

import csv
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest


DIRECTORY = Path(__file__).resolve().parents[1] / "containers/system-python-security"
sys.path.insert(0, str(DIRECTORY))
SPEC = importlib.util.spec_from_file_location("system_python_amend", DIRECTORY / "amend_sources.py")
assert SPEC and SPEC.loader
amend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(amend)


def wheel_fixture() -> bytes:
    files = {"example/__init__.py": b"value = 1\n", "example-1.dist-info/RECORD": b""}
    return amend.pack_wheel(files)


def test_patch_checks_entire_original_and_result():
    original = b"before\nuntouched\n"
    patched = b"after\nuntouched\n"
    contract = {
        "path": "fixture.py",
        "before_sha256": amend.sha(original),
        "after_sha256": amend.sha(patched),
        "replacements": [("before", "after")],
    }
    assert amend.patched(original, contract) == patched
    with pytest.raises(ValueError, match="precondition"):
        amend.patched(b"before\ntampered\n", contract)
    with pytest.raises(ValueError, match="postcondition"):
        amend.patched(original, {**contract, "after_sha256": "0" * 64})


def test_wheel_output_is_reproducible_and_every_record_is_honest():
    first = wheel_fixture()
    assert first == wheel_fixture()
    files = amend.wheel_files(first)
    assert files["example/__init__.py"] == b"value = 1\n"
    rows = list(csv.reader(io.StringIO(files["example-1.dist-info/RECORD"].decode())))
    assert rows == [
        ["example-1.dist-info/RECORD", "", ""],
        ["example/__init__.py", amend.record_hash(b"value = 1\n"), "10"],
    ]


def test_wheel_tampering_is_rejected():
    data = wheel_fixture()
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, "w") as target:
        for name in source.namelist():
            target.writestr(
                name, b"tampered" if name.endswith("__init__.py") else source.read(name)
            )
    with pytest.raises(ValueError, match="RECORD mismatch"):
        amend.wheel_files(output.getvalue())


def test_wheel_path_traversal_and_duplicate_are_rejected():
    for names in [
        ["../escape", "example-1.dist-info/RECORD"],
        ["example/__init__.py", "example/__init__.py"],
    ]:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as target:
            for name in names:
                if name in target.namelist():
                    with pytest.warns(UserWarning, match="Duplicate name"):
                        target.writestr(name, b"")
                else:
                    target.writestr(name, b"")
        with pytest.raises(ValueError, match="unsafe wheel"):
            amend.wheel_files(output.getvalue())


def test_signed_leaf_receipt_and_source_scope():
    leaves = json.loads((DIRECTORY / "leaves.json").read_text())
    for archive, release in leaves["releases"].items():
        assert (
            amend.sha((DIRECTORY / "provenance" / f"{archive}.InRelease").read_bytes())
            == release["release_sha256"]
        )
    for arch in ["arm64", "amd64"]:
        packages = leaves["packages"][arch]
        assert len(packages) == 8
        assert len({p["Package"] for p in packages}) == 8
        assert not any("brotli" in p["Package"] or "setuptools" in p["Package"] for p in packages)
        assert all(p["Architecture"] in (arch, "all") for p in packages)
    source = json.loads((DIRECTORY / "amendments.json").read_text())
    assert len(source["pip"]["files"]) > 400
    assert all(
        p["before_md5"] and p["before_sha256"] and p["after_sha256"] and p["upstream_commits"]
        for p in source["patches"]
    )
    assert not any(
        p["path"].startswith("usr/lib/python3/dist-packages/jaraco/") for p in source["patches"]
    )


def test_cached_artifact_tamper_rejected_before_network(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "system_python_install", DIRECTORY / "install_leaves.py"
    )
    assert spec and spec.loader
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    (tmp_path / "fixture.deb").write_bytes(b"tampered")

    def forbidden_network(*_args, **_kwargs):
        raise AssertionError("network request made for an existing bad cache entry")

    monkeypatch.setattr(installer.urllib.request, "urlopen", forbidden_network)
    with pytest.raises(ValueError, match="cached digest mismatch"):
        installer.obtain(
            "https://deb.debian.org/fixture", amend.sha(b"official"), tmp_path, "fixture.deb"
        )


@pytest.mark.parametrize(
    "plan",
    [
        "8 upgraded, 1 newly installed, 0 to remove\n",
        "8 upgraded, 0 newly installed, 1 to remove\n",
        "7 upgraded, 0 newly installed, 0 to remove\n",
        "8 upgraded, 0 newly installed, 0 to remove\nInst unexpected-package [1] (2)\n",
    ],
)
def test_unexpected_apt_plan_never_installs(plan, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "system_python_install", DIRECTORY / "install_leaves.py"
    )
    assert spec and spec.loader
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    manifest = json.loads((DIRECTORY / "leaves.json").read_text())
    commands = []
    monkeypatch.setattr(installer.subprocess, "run", lambda cmd, **_kwargs: commands.append(cmd))
    monkeypatch.setattr(installer.subprocess, "check_output", lambda *_args, **_kwargs: plan)
    with pytest.raises(ValueError, match=r"(exactly eight|unexpected APT)"):
        installer.install(manifest, "arm64", [Path("/fixture.deb")])
    assert all(cmd[0] == "/usr/bin/dpkg-query" for cmd in commands)


@pytest.mark.parametrize("topology", ["symlink", "hardlink", "parent"])
def test_cache_link_topology_is_rejected(tmp_path, topology):
    import os

    import install_leaves as installer

    cache = tmp_path / "cache"
    cache.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"official")
    if topology == "parent":
        alias = tmp_path / "alias"
        alias.symlink_to(cache, target_is_directory=True)
        cache = alias
        (tmp_path / "cache/fixture.deb").write_bytes(b"official")
    elif topology == "symlink":
        (cache / "fixture.deb").symlink_to(outside)
    else:
        os.link(outside, cache / "fixture.deb")
    with pytest.raises((ValueError, OSError)):
        installer.obtain(
            "https://deb.debian.org/fixture", amend.sha(b"official"), cache, "fixture.deb"
        )
    assert outside.read_bytes() == b"official"


@pytest.mark.parametrize("topology", ["symlink", "hardlink", "parent", "receipt"])
def test_publication_never_writes_through_links(tmp_path, topology):
    import os

    from safe_io import publish

    root = tmp_path / "root"
    source = root / "source"
    source.mkdir(parents=True)
    target = source / "module.py"
    target.write_bytes(b"original")
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    if topology == "symlink":
        target.unlink()
        target.symlink_to(outside)
    elif topology == "hardlink":
        target.unlink()
        os.link(outside, target)
    elif topology == "parent":
        source.rename(root / "real-source")
        source.symlink_to(root / "real-source", target_is_directory=True)
    else:
        (root / "receipt.json").symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        publish(root, {"source/module.py": b"changed", "receipt.json": b"receipt"})
    assert target.read_bytes() == b"original"
    assert outside.read_bytes() == b"original"


def test_late_invalid_output_is_preflighted_before_source_write(tmp_path):
    from safe_io import publish

    (tmp_path / "module.py").write_bytes(b"original")
    (tmp_path / "bad-parent").write_bytes(b"non-directory")
    with pytest.raises(OSError):
        publish(tmp_path, {"module.py": b"changed", "bad-parent/receipt.json": b"receipt"})
    assert (tmp_path / "module.py").read_bytes() == b"original"
    (tmp_path / "bad-parent").unlink()
    publish(tmp_path, {"module.py": b"changed", "bad-parent/receipt.json": b"receipt"})
    assert (tmp_path / "module.py").read_bytes() == b"changed"


@pytest.mark.parametrize("point", ["middle", "receipt", "removal"])
def test_mid_publication_failure_rolls_back_all_bytes_and_retry_succeeds(
    tmp_path, monkeypatch, point
):
    import safe_io

    for name in ("first.py", "second.py", "obsolete.pyc"):
        (tmp_path / name).write_bytes(name.encode())
    replace = safe_io.os.replace
    unlink = safe_io.os.unlink
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if (point == "middle" and calls == 2) or (point == "receipt" and calls == 3):
            raise OSError("injected publication failure")
        return replace(*args, **kwargs)

    def fail_removal(name, **kwargs):
        if name == "obsolete.pyc":
            raise OSError("injected removal failure")
        return unlink(name, **kwargs)

    writes = {
        "first.py": b"first amended",
        "second.py": b"second amended",
        "new/receipt.json": b"receipt",
    }
    with monkeypatch.context() as context:
        context.setattr(safe_io.os, "replace", fail_second)
        if point == "removal":
            context.setattr(safe_io.os, "unlink", fail_removal)
        with pytest.raises(OSError, match="injected"):
            safe_io.publish(tmp_path, writes, ["obsolete.pyc"])
    for name in ("first.py", "second.py", "obsolete.pyc"):
        assert (tmp_path / name).read_bytes() == name.encode()
    assert not (tmp_path / "new").exists()
    assert not list(tmp_path.rglob(".lyrashield-*"))
    safe_io.publish(tmp_path, writes, ["obsolete.pyc"])
    assert (tmp_path / "first.py").read_bytes() == b"first amended"
    assert not (tmp_path / "obsolete.pyc").exists()


@pytest.mark.parametrize("change", ["empty", "omitted", "joint", "leaf-empty", "leaf-omitted"])
def test_receipt_cannot_reduce_trusted_coverage(tmp_path, change):
    import verify_receipts

    manifest = json.loads((DIRECTORY / "amendments.json").read_text())
    leaves = json.loads((DIRECTORY / "leaves.json").read_text())
    receipt = verify_receipts.contract(manifest)
    leaf = {
        "architecture": "arm64",
        "packages": leaves["packages"]["arm64"],
        "release_sha256": {n: r["release_sha256"] for n, r in leaves["releases"].items()},
    }
    if change == "empty":
        receipt["files"] = {}
    elif change == "omitted":
        receipt["files"].pop(next(iter(receipt["files"])))
    elif change == "joint":
        name = next(iter(receipt["files"]))
        data = b"jointly falsified bytes"
        target = tmp_path / name
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        receipt["files"][name]["after_sha256"] = amend.sha(data)
    elif change == "leaf-empty":
        leaf["packages"] = []
    else:
        leaf["packages"] = leaf["packages"][:-1]
    directory = tmp_path / "usr/share/lyrashield/security"
    directory.mkdir(parents=True)
    (directory / "system-python-amendments.json").write_text(json.dumps(receipt))
    (directory / "system-python-leaves.json").write_text(json.dumps(leaf))
    with pytest.raises(ValueError, match=r"(trusted coverage|package coverage)"):
        verify_receipts.verify(tmp_path, arch="arm64")


def test_vendor_keeps_record_verified_resources_and_rejects_native_extensions():
    files = {
        "urllib3/__init__.py": b"",
        "urllib3/contrib/emscripten/__init__.py": b"import urllib3.connection\n",
        "urllib3/data/resource.json": b'{"fixture":true}',
        "urllib3/py.typed": b"",
        "urllib3-2.8.0.dist-info/licenses/LICENSE.txt": b"fixture license",
        "urllib3-2.8.0.dist-info/RECORD": b"",
    }
    wheel = amend.pack_wheel(files.copy())
    result = amend.urllib3_files(wheel, amend.sha(wheel))
    assert result["pip/_vendor/urllib3/data/resource.json"] == b'{"fixture":true}'
    assert result["pip/_vendor/urllib3/LICENSE.txt"] == b"fixture license"
    files["urllib3/extension.so"] = b"unintended ABI"
    wheel = amend.pack_wheel(files)
    with pytest.raises(ValueError, match="ABI extension"):
        amend.urllib3_files(wheel, amend.sha(wheel))


def test_retained_cache_avoids_rotated_online_index(tmp_path, monkeypatch):
    import install_leaves as installer

    cached = b"qualified index"
    (tmp_path / "sid-arm64-Packages.xz").write_bytes(cached)

    def rotated_online(*_args, **_kwargs):
        raise AssertionError("rotated online index must not replace retained authenticated input")

    monkeypatch.setattr(installer.urllib.request, "urlopen", rotated_online)
    path = installer.obtain(
        "https://deb.debian.org/rotated-index", amend.sha(cached), tmp_path, "sid-arm64-Packages.xz"
    )
    assert path.read_bytes() == cached
    assert (DIRECTORY / "cache/.gitignore").is_file()
    assert (
        "--cache /opt/lyrashield/system-python-security/cache"
        in (DIRECTORY / "README.md").read_text()
    )


def test_cache_ancestor_link_cannot_redirect_download_publication(tmp_path, monkeypatch):
    import install_leaves as installer

    tmp_path = tmp_path.resolve()
    external = tmp_path / "external"
    (external / "cache").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(external, target_is_directory=True)
    monkeypatch.setattr(
        installer.urllib.request, "urlopen", lambda *_args, **_kwargs: io.BytesIO(b"official")
    )
    with pytest.raises((ValueError, OSError)):
        installer.obtain(
            "https://deb.debian.org/fixture", amend.sha(b"official"), alias / "cache", "fixture.deb"
        )
    assert not (external / "cache/fixture.deb").exists()


def test_failed_publication_cleanup_cannot_follow_switched_parent(tmp_path, monkeypatch):
    import safe_io

    root = tmp_path / "root"
    root.mkdir()
    (root / "module.py").write_bytes(b"original")
    outside = tmp_path / "outside"
    (outside / "leaf").mkdir(parents=True)

    def switch_parent(*_args, **_kwargs):
        (root / "new").rename(root / "held-new")
        (root / "new").symlink_to(outside, target_is_directory=True)
        raise OSError("injected switched parent")

    monkeypatch.setattr(safe_io.os, "replace", switch_parent)
    with pytest.raises(OSError, match="switched parent"):
        safe_io.publish(root, {"module.py": b"changed", "new/leaf/receipt.json": b"receipt"})
    assert (root / "module.py").read_bytes() == b"original"
    assert (outside / "leaf").is_dir()
