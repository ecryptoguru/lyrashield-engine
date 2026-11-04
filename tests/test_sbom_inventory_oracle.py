"""Independent, explicitly scoped filesystem inventory compared with SPDX."""

import io
import json
import os
import runpy
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts/check_sbom_inventory.py"


def write_inputs(tmp_path, *, omit="", malformed=False, duplicate=""):
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
    deb = "var/lib/dpkg/status"
    python = "app/.venv/lib/python3.12/site-packages/My_Pkg-2.dist-info/METADATA"
    npm = "home/pentester/.npm-tools/node_modules/@scope/example/package.json"
    if duplicate.startswith("deb:"):
        field = duplicate.removeprefix("deb:")
        line = next(line for line in root[deb].splitlines() if line.startswith(f"{field}:"))
        root[deb] = root[deb].replace(line, line + "\n" + line, 1)
    elif duplicate.startswith("pypi:"):
        field = duplicate.removeprefix("pypi:")
        line = next(line for line in root[python].splitlines() if line.startswith(f"{field}:"))
        root[python] = root[python].replace(line, line + "\n" + line, 1)
    elif duplicate.startswith("npm:"):
        field = duplicate.removeprefix("npm:")
        original = json.loads(root[npm])[field]
        root[npm] = root[npm][:-1] + f', "{field}": {json.dumps(original)}' + "}"
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


@pytest.mark.parametrize(
    "path",
    [
        "usr/local/lib/node_modules/missing",
        "usr/share/nodejs/@scope",
        "home/pentester/.npm-tools/node_modules/@scope/example/node_modules/missing",
        "home/pentester/.npm-tools",
    ],
)
@pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_scoped_package_directory_links_are_unresolved(tmp_path, path, link_type):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        link = tarfile.TarInfo(path)
        link.type = link_type
        link.linkname = "../../../../opt/missing"
        archive.addfile(link)
    result = invoke(tmp_path)
    assert result.returncode != 0
    assert any(
        item["path"] == path
        for item in json.loads((tmp_path / "result.json").read_text())["unresolved"]
    )


@pytest.mark.parametrize(
    "duplicate",
    [
        "deb:Package",
        "deb:Version",
        "deb:Architecture",
        "deb:Status",
        "pypi:Name",
        "pypi:Version",
        "npm:name",
        "npm:version",
    ],
)
def test_duplicate_identity_fields_are_unresolved(tmp_path, duplicate):
    write_inputs(tmp_path, duplicate=duplicate)
    result = invoke(tmp_path)
    assert result.returncode != 0
    assert json.loads((tmp_path / "result.json").read_text())["unresolved"]


def test_metadata_link_resolution_has_a_bounded_depth():
    api = runpy.run_path(str(SCRIPT))
    links = {f"link-{index}": f"link-{index + 1}" for index in range(65)}
    links["link-65"] = "terminal"
    unresolved = api["unresolved_links"](links, {"terminal"})
    assert any(item["path"] == "link-0" for item in unresolved)
    assert all(item["path"] != "link-65" for item in unresolved)


def test_unresolved_diagnostics_are_bounded():
    api = runpy.run_path(str(SCRIPT))
    record = api["record_unresolved"]
    record.__globals__["MAX_METADATA_FILES"] = 2
    unresolved = []
    record(unresolved, "first", "example")
    record(unresolved, "second", "example")
    with pytest.raises(ValueError, match="too many unresolved"):
        record(unresolved, "third", "example")


def test_duplicate_spdx_package_identity_is_rejected(tmp_path):
    write_inputs(tmp_path)
    path = tmp_path / "sbom.json"
    raw = path.read_text()
    path.write_text(raw.replace('"name": "libsample"', '"name": "other", "name": "libsample"'))
    assert invoke(tmp_path).returncode != 0


def test_sbom_read_remains_bounded_if_file_changes_after_stat():
    api = runpy.run_path(str(SCRIPT))
    read = api["read_sbom"]
    read.__globals__["MAX_SBOM_BYTES"] = 4

    class GrowingFile:
        def is_file(self):
            return True

        def stat(self):
            return type("Stat", (), {"st_size": 3})()

        def open(self, _mode):
            return io.BytesIO(b"123456789")

    with pytest.raises(ValueError, match="invalid SBOM size"):
        read(GrowingFile())


@pytest.mark.parametrize(
    "path",
    [
        "app/.venv/lib/python3.12/site-packages/missing-1.0.dist-info",
        "app/.venv/lib/python3.12/site-packages",
        "app/.venv",
        "unrelated/symlink-that-may-hide-a-python-root",
    ],
)
@pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_python_directory_or_ancestor_links_cannot_be_silently_skipped(tmp_path, path, link_type):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        link = tarfile.TarInfo(path)
        link.type = link_type
        link.linkname = "../../../../opt/missing"
        archive.addfile(link)
    result = invoke(tmp_path)
    assert result.returncode != 0
    assert any(
        item["path"] == path
        for item in json.loads((tmp_path / "result.json").read_text())["unresolved"]
    )


def test_archive_entry_limit_counts_irrelevant_entries(tmp_path):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        item = tarfile.TarInfo("unrelated-file")
        item.size = 1
        archive.addfile(item, io.BytesIO(b"x"))
    collect = runpy.run_path(str(SCRIPT))["collect_rootfs"]
    collect.__globals__["MAX_ARCHIVE_ENTRIES"] = 3
    with (
        (tmp_path / "rootfs.tar").open("rb") as archive,
        pytest.raises(ValueError, match="archive entry limit"),
    ):
        collect(archive)


def test_cumulative_metadata_bytes_are_bounded(tmp_path):
    write_inputs(tmp_path)
    collect = runpy.run_path(str(SCRIPT))["collect_rootfs"]
    with tarfile.open(tmp_path / "rootfs.tar") as archive:
        sizes = [item.size for item in archive.getmembers()][:2]
    limit = sum(sizes) - 1
    assert max(sizes) < limit
    collect.__globals__["MAX_TOTAL_METADATA_BYTES"] = limit
    with (
        (tmp_path / "rootfs.tar").open("rb") as archive,
        pytest.raises(ValueError, match="metadata byte limit"),
    ):
        collect(archive)


@pytest.mark.parametrize("kind", ["deb", "pypi", "npm"])
def test_package_identity_length_is_bounded(kind):
    collect = runpy.run_path(str(SCRIPT))["collect_metadata"]
    collect.__globals__["MAX_IDENTITY_CHARS"] = 4
    payload = {
        "deb": (
            b"Package: too-long\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n"
        ),
        "pypi": b"Name: too-long\nVersion: 1\n\n",
        "npm": b'{"name":"too-long","version":"1"}',
    }
    with pytest.raises(ValueError, match="identity"):
        collect(kind, payload[kind])


def test_spdx_purl_length_is_bounded():
    inventory = runpy.run_path(str(SCRIPT))["spdx_inventory"]
    package = {
        "name": "libsample",
        "versionInfo": "1",
        "externalRefs": [
            {
                "referenceType": "purl",
                "referenceLocator": "pkg:deb/kali/libsample@1?arch=" + "a" * 5000,
            }
        ],
    }
    with pytest.raises(ValueError, match=r"purl.*length"):
        inventory({"packages": [package]})


def test_oversized_pax_header_fails_before_reading_payload():
    api = runpy.run_path(str(SCRIPT))
    collect = api["collect_rootfs"]
    header = tarfile.TarInfo("extended")
    header.type = tarfile.XHDTYPE
    header.size = 1024 * 1024 + 1
    archive = io.BytesIO(header.tobuf() + b"\0" * 1024)
    with pytest.raises(ValueError, match="extended tar header"):
        collect(archive)


@pytest.mark.parametrize("method", ["_proc_pax", "_proc_gnulong"])
def test_negative_extended_header_sizes_fail_before_read(method):
    tarinfo = runpy.run_path(str(SCRIPT))["BoundedTarInfo"]("extended")
    tarinfo.size = -1
    with pytest.raises(ValueError, match="extended tar header"):
        getattr(tarinfo, method)(None)


@pytest.mark.parametrize(
    "method,args",
    [
        ("_proc_sparse", (None,)),
        ("_proc_gnusparse_00", (None, None)),
        ("_proc_gnusparse_01", (None, None)),
        ("_proc_gnusparse_10", (None, None, None)),
    ],
)
def test_sparse_archive_encodings_fail_closed(method, args):
    tarinfo = runpy.run_path(str(SCRIPT))["BoundedTarInfo"]("sparse")
    with pytest.raises(ValueError, match="sparse tar"):
        getattr(tarinfo, method)(*args)


def test_overlong_archive_paths_are_rejected(tmp_path):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        link = tarfile.TarInfo("a" * 4097)
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        archive.addfile(link)
    result = invoke(tmp_path)
    assert result.returncode != 0
    assert "archive path exceeds length limit" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX SIGALRM")
def test_processing_timeout_interrupts_a_blocked_input_pipe(tmp_path):
    (tmp_path / "sbom.json").write_text('{"packages": []}')
    code = (
        "import runpy,sys; "
        "m=runpy.run_path(sys.argv.pop(1)); "
        "m['main'].__globals__['MAX_PROCESS_SECONDS']=0.2; "
        "sys.exit(m['main']())"
    )
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test-owned paths
        [
            sys.executable,
            "-c",
            code,
            str(SCRIPT),
            "--rootfs",
            "-",
            "--sbom",
            str(tmp_path / "sbom.json"),
            "--output",
            str(tmp_path / "result.json"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        process.wait(timeout=5)
        assert process.returncode != 0
        assert b"processing deadline" in process.stderr.read()
        assert not (tmp_path / "result.json").exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdin:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
