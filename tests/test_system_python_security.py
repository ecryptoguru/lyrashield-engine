"""Fail-closed source and wheel contracts, independent of the host Python layout."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest


DIRECTORY = Path(__file__).resolve().parents[1] / "containers/system-python-security"
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
