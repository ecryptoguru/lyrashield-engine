"""Independent, explicitly scoped filesystem inventory compared with SPDX."""

import gzip
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
        assert (tmp_path / "result.json").read_bytes() == b""
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


def test_output_path_cannot_reuse_or_overwrite_a_success_receipt(tmp_path):
    write_inputs(tmp_path)
    first = invoke(tmp_path)
    assert first.returncode == 0, first.stderr
    output = tmp_path / "result.json"
    original = output.read_bytes()
    assert output.stat().st_mode & 0o077 == 0
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        link = tarfile.TarInfo("x" * 4097)
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        archive.addfile(link)
    second = invoke(tmp_path)
    assert second.returncode != 0
    assert "FileExistsError" in second.stderr
    assert output.read_bytes() == original


def test_output_creation_does_not_follow_existing_symlinks(tmp_path):
    write_inputs(tmp_path)
    target = tmp_path / "owned-by-user.txt"
    target.write_text("preserve")
    (tmp_path / "result.json").symlink_to(target)
    result = invoke(tmp_path)
    assert result.returncode != 0
    assert target.read_text() == "preserve"


def test_many_long_archive_paths_exceed_aggregate_budget(tmp_path):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        for index in range(30):
            entry = tarfile.TarInfo(f"unused-{index}-" + "a" * 400)
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b"x"))
    collect = runpy.run_path(str(SCRIPT))["collect_rootfs"]
    collect.__globals__["MAX_TOTAL_PATH_CHARS"] = 4_000
    with (
        (tmp_path / "rootfs.tar").open("rb") as archive,
        pytest.raises(ValueError, match="archive path budget"),
    ):
        collect(archive)


def test_streaming_does_not_retain_prior_tar_entries(tmp_path, monkeypatch):
    write_inputs(tmp_path)
    with tarfile.open(tmp_path / "rootfs.tar", "a") as archive:
        for index in range(80):
            entry = tarfile.TarInfo(f"unused-{index}-" + "a" * 500)
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b"x"))
    original = tarfile.TarFile.next
    cached_sizes = []

    def observed_next(archive):
        entry = original(archive)
        cached_sizes.append(len(archive.members))
        return entry

    monkeypatch.setattr(tarfile.TarFile, "next", observed_next)
    collect = runpy.run_path(str(SCRIPT))["collect_rootfs"]
    with (tmp_path / "rootfs.tar").open("rb") as archive:
        inventory, unresolved = collect(archive)
    assert not unresolved
    assert len(inventory["deb"]) == 1
    assert len(cached_sizes) > 80
    assert max(cached_sizes) <= 1


def tar_without_end_blocks(path):
    with tarfile.open(path) as archive:
        last = archive.getmembers()[-1]
        end = last.offset_data + ((last.size + 511) // 512) * 512
    return path.read_bytes()[:end]


def hidden_package_frame():
    raw = b'{"name":"missing-package","version":"1.0"}'
    item = tarfile.TarInfo("usr/share/nodejs/missing-package/package.json")
    item.size = len(raw)
    return item.tobuf(format=tarfile.USTAR_FORMAT) + raw + b"\0" * (-len(raw) % 512)


@pytest.mark.parametrize(
    "kind",
    [
        "invalid_header_hides_package",
        "missing_end",
        "single_end_block",
        "truncated_header",
        "truncated_payload",
        "nonzero_after_end",
        "concatenated_archive",
        "gzip_archive",
        "pax_size_override",
    ],
)
def test_tar_framing_is_complete_and_rejects_hidden_entries(tmp_path, kind):
    write_inputs(tmp_path)
    path = tmp_path / "rootfs.tar"
    prefix = tar_without_end_blocks(path)
    zeros = b"\0" * 512
    if kind == "invalid_header_hides_package":
        content = prefix + b"X" * 512 + hidden_package_frame() + zeros * 2
    elif kind == "missing_end":
        content = prefix
    elif kind == "single_end_block":
        content = prefix + zeros
    elif kind == "truncated_header":
        content = prefix + b"x" * 37
    elif kind == "truncated_payload":
        frame = tarfile.TarInfo("unused")
        frame.size = 1024
        content = prefix + frame.tobuf(format=tarfile.USTAR_FORMAT) + b"x" * 512
    elif kind == "nonzero_after_end":
        content = prefix + zeros * 2 + b"x" * 512
    elif kind == "concatenated_archive":
        content = prefix + zeros * 2 + hidden_package_frame() + zeros * 2
    elif kind == "gzip_archive":
        content = gzip.compress(path.read_bytes())
    else:
        pax = b"9 size=1\n"
        extension = tarfile.TarInfo("extended")
        extension.type = tarfile.XHDTYPE
        extension.size = len(pax)
        content = (
            prefix
            + extension.tobuf(format=tarfile.USTAR_FORMAT)
            + pax
            + b"\0" * (-len(pax) % 512)
            + hidden_package_frame()
            + zeros * 2
        )
    path.write_bytes(content)
    result = invoke(tmp_path)
    assert result.returncode != 0
    assert (tmp_path / "result.json").read_bytes() == b""


def test_two_exact_end_blocks_are_accepted(tmp_path):
    write_inputs(tmp_path)
    path = tmp_path / "rootfs.tar"
    path.write_bytes(tar_without_end_blocks(path) + b"\0" * 1024)
    result = invoke(tmp_path)
    assert result.returncode == 0, result.stderr


def test_tar_frame_validation_handles_short_stream_reads(tmp_path):
    write_inputs(tmp_path)
    collect = runpy.run_path(str(SCRIPT))["collect_rootfs"]

    class ShortReader(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 7))

    inventory, unresolved = collect(ShortReader((tmp_path / "rootfs.tar").read_bytes()))
    assert not unresolved
    assert len(inventory["deb"]) == 1


def test_total_tar_bytes_are_bounded(tmp_path):
    write_inputs(tmp_path)
    collect = runpy.run_path(str(SCRIPT))["collect_rootfs"]
    collect.__globals__["MAX_ARCHIVE_BYTES"] = 1024
    with (
        (tmp_path / "rootfs.tar").open("rb") as archive,
        pytest.raises(ValueError, match="archive byte limit"),
    ):
        collect(archive)
