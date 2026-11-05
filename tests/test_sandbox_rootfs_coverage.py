"""One-pass rootfs inventory and exact pinned-binary capture contracts."""

import hashlib
import io
import json
import runpy
import tarfile
from pathlib import Path

import pytest


API = runpy.run_path(str(Path(__file__).parents[1] / "scripts" / "check_sbom_inventory.py"))


def add(tar, name, data=b"", **kwargs):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for key, value in kwargs.items():
        setattr(info, key, value)
    tar.addfile(info, io.BytesIO(data) if data else None)


def metadata_files():
    return {
        "var/lib/dpkg/status": (
            b"Package: example\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n"
        ),
        "app/.venv/lib/python3.14/site-packages/example-1.0.dist-info/METADATA": (
            b"Name: Example\nVersion: 1.0\n"
        ),
        "home/pentester/.npm-tools/node_modules/example/package.json": json.dumps(
            {"name": "example", "version": "1.0.0"}
        ).encode(),
    }


def archive_bytes(*, extra=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, data in metadata_files().items():
            add(tar, name, data)
        for item in extra:
            add(tar, **item)
    return output.getvalue()


def scan(raw, capture_paths=(), capture_dir=None):
    return API["scan_rootfs"](io.BytesIO(raw), capture_paths=capture_paths, capture_dir=capture_dir)


def test_inventory_and_exact_binary_capture_share_one_archive_pass(tmp_path):
    binary = b"\x7fELFfixture"
    result = scan(
        archive_bytes(extra=[{"name": "usr/local/bin/tool", "data": binary}]),
        capture_paths=("/usr/local/bin/tool",),
        capture_dir=tmp_path,
    )
    assert result["counts"] == {"deb": 1, "npm": 1, "pypi": 1}
    assert result["unresolved"] == []
    assert result["inventory"]["deb"] == {("example", "1.0", "amd64")}
    assert result["inventory"]["pypi"] == {("example", "1.0")}
    assert result["inventory"]["npm"] == {("example", "1.0.0")}
    assert len(result["captures"]) == 1
    capture = result["captures"][0]
    assert capture["path"] == "/usr/local/bin/tool"
    assert capture["size"] == len(binary)
    assert capture["sha256"] == hashlib.sha256(binary).hexdigest()
    assert Path(capture["localPath"]).read_bytes() == binary
    assert Path(capture["localPath"]).stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "mutation",
    ["missing", "symlink", "hardlink", "duplicate", "oversized"],
)
def test_pinned_binary_must_be_one_bounded_regular_member(tmp_path, mutation, monkeypatch):
    binary = b"\x7fELFfixture"
    extra = [{"name": "opt/tool", "data": binary}]
    if mutation == "symlink":
        extra.append(
            {
                "name": "usr/local/bin/tool",
                "type": tarfile.SYMTYPE,
                "linkname": "../../../opt/tool",
            }
        )
    elif mutation == "hardlink":
        extra.append(
            {
                "name": "usr/local/bin/tool",
                "type": tarfile.LNKTYPE,
                "linkname": "opt/tool",
            }
        )
    elif mutation == "duplicate":
        extra.extend(
            [
                {"name": "usr/local/bin/tool", "data": binary},
                {"name": "usr/local/bin/tool", "data": binary},
            ]
        )
    elif mutation == "oversized":
        monkeypatch.setitem(API["scan_rootfs"].__globals__, "MAX_GO_BINARY_BYTES", 4)
        extra.append({"name": "usr/local/bin/tool", "data": b"12345"})
    elif mutation == "missing":
        pass
    result = scan(
        archive_bytes(extra=extra),
        capture_paths=("/usr/local/bin/tool",),
        capture_dir=tmp_path,
    )
    assert result["unresolved"]
    assert "/usr/local/bin/tool" in {item["path"] for item in result["unresolved"]}


def test_link_outside_declared_inventory_scopes_is_counted_but_does_not_fail():
    raw = archive_bytes(
        extra=[
            {"name": "usr/local/bin/helper", "data": b"regular"},
            {
                "name": "usr/local/bin/alias",
                "type": tarfile.SYMTYPE,
                "linkname": "helper",
            },
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == []
    assert result["ignoredLinks"] == 1


def test_nonmetadata_npm_leaf_link_is_ignored_without_hiding_metadata():
    raw = archive_bytes(
        extra=[
            {
                "name": "home/pentester/.npm-tools/node_modules/@ast-grep/cli/sg-linux-x64",
                "data": b"x",
            },
            {
                "name": "home/pentester/.npm-tools/node_modules/@ast-grep/cli/sg",
                "type": tarfile.SYMTYPE,
                "linkname": "sg-linux-x64",
            },
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == []
    assert result["ignoredLinks"] == 1


def test_absolute_link_target_is_resolved_inside_the_same_guarded_root():
    target = "home/pentester/.npm-tools/node_modules/@ast-grep/cli/sg-linux-x64"
    link = "home/pentester/.npm-tools/node_modules/@ast-grep/cli/sg"
    result = scan(
        archive_bytes(
            extra=[
                {"name": target, "data": b"regular"},
                {"name": link, "type": tarfile.SYMTYPE, "linkname": "/" + target},
            ]
        )
    )
    assert result["unresolved"] == []
    assert result["ignoredLinks"] == 1


def test_directory_link_without_reachable_metadata_is_ignored():
    raw = archive_bytes(
        extra=[
            {"name": "home/pentester/.npm-tools/node_modules/real", "type": tarfile.DIRTYPE},
            {
                "name": "home/pentester/.npm-tools/node_modules/alias",
                "type": tarfile.SYMTYPE,
                "linkname": "real",
            },
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == []
    assert result["ignoredLinks"] == 1


def test_directory_link_that_aliases_unscanned_package_metadata_fails_closed():
    raw = archive_bytes(
        extra=[
            {"name": "opt/example", "type": tarfile.DIRTYPE},
            {
                "name": "opt/example/package.json",
                "data": b'{"name":"hidden","version":"1.0.0"}',
            },
            {
                "name": "home/pentester/.npm-tools/node_modules/alias",
                "type": tarfile.SYMTYPE,
                "linkname": "../../../../../opt/example",
            },
        ]
    )
    result = scan(raw)
    assert "home/pentester/.npm-tools/node_modules/alias" in {
        item["path"] for item in result["unresolved"]
    }


def test_directory_link_to_already_parsed_metadata_is_ignored():
    raw = archive_bytes(
        extra=[
            {"name": "home/pentester/.npm-tools/node_modules/real", "type": tarfile.DIRTYPE},
            {
                "name": "home/pentester/.npm-tools/node_modules/real/package.json",
                "data": b'{"name":"real","version":"1.0.0"}',
            },
            {
                "name": "home/pentester/.npm-tools/node_modules/alias",
                "type": tarfile.SYMTYPE,
                "linkname": "real",
            },
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == []
    assert result["ignoredLinks"] == 1


def test_external_asset_directory_link_without_metadata_or_nested_links_is_ignored():
    raw = archive_bytes(
        extra=[
            {"name": "usr/share/assets", "type": tarfile.DIRTYPE},
            {"name": "usr/share/assets/style.css", "data": b"body{}"},
            {
                "name": "usr/share/nodejs/assets",
                "type": tarfile.SYMTYPE,
                "linkname": "../assets",
            },
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == []
    assert result["ignoredLinks"] == 1


def test_external_directory_link_with_an_unguarded_nested_link_fails_closed():
    raw = archive_bytes(
        extra=[
            {"name": "usr/share/assets", "type": tarfile.DIRTYPE},
            {"name": "usr/share/assets/style.css", "data": b"body{}"},
            {
                "name": "usr/share/assets/alias.css",
                "type": tarfile.SYMTYPE,
                "linkname": "style.css",
            },
            {
                "name": "usr/share/nodejs/assets",
                "type": tarfile.SYMTYPE,
                "linkname": "../assets",
            },
        ]
    )
    result = scan(raw)
    assert "usr/share/nodejs/assets" in {item["path"] for item in result["unresolved"]}


@pytest.mark.parametrize(
    ("link_name", "link_target", "target_name", "data"),
    [
        (
            "home/pentester/.npm-tools/node_modules/alias/package.json",
            "../real/package.json",
            "home/pentester/.npm-tools/node_modules/real/package.json",
            b'{"name":"alias","version":"1.0.0"}',
        ),
        (
            "app/.venv/lib/python3.14/site-packages/alias-1.0.dist-info/METADATA",
            "../real-1.0.dist-info/METADATA",
            "app/.venv/lib/python3.14/site-packages/real-1.0.dist-info/METADATA",
            b"Name: alias\nVersion: 1.0\n",
        ),
    ],
)
def test_final_metadata_symlink_resolves_only_within_its_root(
    link_name, link_target, target_name, data
):
    raw = archive_bytes(
        extra=[
            {"name": target_name, "data": data},
            {
                "name": link_name,
                "type": tarfile.SYMTYPE,
                "linkname": link_target,
            },
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == []
    assert any(
        identity[0] == "alias"
        for identity in result["inventory"]["pypi"] | result["inventory"]["npm"]
    )


@pytest.mark.parametrize(
    "path",
    [
        "usr/local",
        "home/pentester/.npm-tools/node_modules",
        "app/.venv/lib/python3.14",
    ],
)
def test_link_at_inventory_root_or_ancestor_blocks(path):
    raw = archive_bytes(
        extra=[
            {"name": path, "type": tarfile.SYMTYPE, "linkname": "/outside"},
        ]
    )
    result = scan(raw)
    assert path in {item["path"] for item in result["unresolved"]}


def test_hardlink_inside_inventory_scope_blocks_even_outside_metadata_shape():
    raw = archive_bytes(
        extra=[
            {"name": "home/pentester/.npm-tools/node_modules/real/data", "data": b"x"},
            {
                "name": "home/pentester/.npm-tools/node_modules/alias/data",
                "type": tarfile.LNKTYPE,
                "linkname": "home/pentester/.npm-tools/node_modules/real/data",
            },
        ]
    )
    result = scan(raw)
    assert "home/pentester/.npm-tools/node_modules/alias/data" in {
        item["path"] for item in result["unresolved"]
    }


def test_metadata_symlink_to_the_other_npm_root_blocks():
    raw = archive_bytes(
        extra=[
            {
                "name": "usr/share/nodejs/example/package.json",
                "data": b'{"name":"example","version":"1.0.0"}',
            },
            {
                "name": "home/pentester/.npm-tools/node_modules/example/package.json",
                "type": tarfile.SYMTYPE,
                "linkname": "../../../../../usr/share/nodejs/example/package.json",
            },
        ]
    )
    result = scan(raw)
    assert "home/pentester/.npm-tools/node_modules/example/package.json" in {
        item["path"] for item in result["unresolved"]
    }


def test_duplicate_npm_json_keys_remain_an_explicit_failure():
    raw = archive_bytes(
        extra=[
            {
                "name": "home/pentester/.npm-tools/node_modules/broken/package.json",
                "data": b'{"name":"broken","version":"1.0.0","version":"2.0.0"}',
            }
        ]
    )
    result = scan(raw)
    assert result["unresolved"] == [
        {
            "path": "home/pentester/.npm-tools/node_modules/broken/package.json",
            "reason": "duplicate version JSON field",
        }
    ]
