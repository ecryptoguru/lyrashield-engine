"""Synthetic tests for restrictive virtual OCI layer application."""

import io
import os
import runpy
import tarfile
import zlib
from pathlib import Path

import pytest

from scripts import reconstruct_oci_layers as reconstruction
from scripts.reconstruct_oci_layers import VirtualRoot, reconstruct_verified


def tar(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as stream:
        for name, kind, value in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = value
            elif kind == "file":
                info.size = len(value)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            stream.addfile(info, io.BytesIO(value) if kind == "file" else None)
    return result.getvalue()


def apply(root, entries):
    root.apply(tar(entries))


def test_whiteouts_only_hide_lower_entries_even_when_after_additions():
    root = VirtualRoot()
    apply(root, [("a", "dir", None), ("a/old", "file", b"old"), ("a/keep", "file", b"old")])
    apply(
        root,
        [("a/new", "file", b"new"), ("a/.wh..wh..opq", "file", b""), ("a/keep", "file", b"new")],
    )
    assert set(root.entries) == {"", "a", "a/new", "a/keep"}
    assert root.entries["a/keep"].content == b"new"


def test_explicit_whiteout_and_directory_merge():
    root = VirtualRoot()
    apply(
        root,
        [
            ("a", "dir", None),
            ("a/delete", "dir", None),
            ("a/delete/item", "file", b"x"),
            ("a/keep", "file", b"y"),
        ],
    )
    apply(root, [("a", "dir", None), ("a/.wh.delete", "file", b""), ("a/delete", "file", b"new")])
    assert root.entries["a/delete"].content == b"new"
    assert "a/delete/item" not in root.entries
    assert root.entries["a/keep"].content == b"y"


def test_hardlink_preserves_old_inode_when_target_replaced():
    root = VirtualRoot()
    apply(root, [("a", "file", b"old"), ("b", "hardlink", "a")])
    apply(root, [("a", "file", b"new")])
    assert root.entries["a"].content == b"new"
    assert root.entries["b"].content == b"old"


def test_self_hardlink_replacement_fails_without_retaining_old_file_as_success():
    root = VirtualRoot()
    apply(root, [("a", "file", b"old")])
    with pytest.raises(ValueError, match="self hardlink"):
        apply(root, [("a", "hardlink", "a")])
    assert root.entries["a"].content == b"old"


@pytest.mark.parametrize("attribute,value", [("mode", 0o600), ("uid", 1), ("gid", 1), ("mtime", 1)])
def test_hardlink_with_different_inode_metadata_fails_atomically(attribute, value):
    root = VirtualRoot()
    apply(root, [("a", "file", b"old")])
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        entry = tarfile.TarInfo("b")
        entry.type = tarfile.LNKTYPE
        entry.linkname = "a"
        setattr(entry, attribute, value)
        archive.addfile(entry)
    with pytest.raises(ValueError, match="hardlink metadata"):
        root.apply(result.getvalue())
    assert set(root.entries) == {"", "a"}
    assert root.entries["a"].content == b"old"


@pytest.mark.parametrize(
    "entries",
    [
        [("../escape", "file", b"x")],
        [("/absolute", "file", b"x")],
        [("a", "file", b"x"), ("./a", "file", b"y")],
        [("a", "symlink", ".."), ("a/x", "file", b"x")],
        [("a", "hardlink", "missing")],
        [("a", "symlink", "/etc/passwd")],
        [("a", "fifo", None)],
        [(".wh.", "file", b"")],
        [(".wh..", "file", b"")],
        [(".wh...", "file", b"")],
        [(".wh.x", "file", b"nonempty")],
        [("missing/child", "file", b"x")],
    ],
)
def test_rejects_unsafe_or_unsupported_entries_atomically(entries):
    root = VirtualRoot()
    apply(root, [("retained", "file", b"old")])
    with pytest.raises(ValueError):
        apply(root, entries)
    assert set(root.entries) == {"", "retained"}
    assert root.entries["retained"].content == b"old"


def test_rejects_truncated_or_hidden_tar_without_changing_tree():
    root = VirtualRoot()
    apply(root, [("retained", "file", b"old")])
    raw = tar([("new", "file", b"new")])[:1024] + b"X" * 512 + tar([("hidden", "file", b"x")])
    with pytest.raises(ValueError):
        root.apply(raw)
    assert set(root.entries) == {"", "retained"}


def test_applies_only_bytes_bound_to_verified_manifest(tmp_path):
    fixture = runpy.run_path(str(Path(__file__).with_name("test_oci_layer_binding.py")))
    layout = fixture["Layout"](tmp_path / "blobs")
    digest = layout.manifest()
    directory = os.open(layout.path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        report, root = reconstruct_verified(directory, digest, "linux/amd64")
        assert report["manifestDigest"] == digest
        assert root.entries["file-0"].content == bytes([0]) * 23
        assert root.entries["file-1"].content == bytes([1]) * 23
        (layout.path / layout.layers[1]["digest"][7:]).write_bytes(b"tampered")
        with pytest.raises((OSError, ValueError, zlib.error)):
            reconstruct_verified(directory, digest, "linux/amd64")
    finally:
        os.close(directory)


def test_root_opaque_keeps_same_layer_files():
    root = VirtualRoot()
    apply(root, [("old", "file", b"old")])
    apply(root, [("new", "file", b"new"), (".wh..wh..opq", "file", b"")])
    assert set(root.entries) == {"", "new"}


def test_refuses_nonempty_directory_replacement():
    root = VirtualRoot()
    apply(root, [("a", "dir", None), ("a/item", "file", b"x")])
    with pytest.raises(ValueError, match="nonempty directory"):
        apply(root, [("a", "file", b"x")])
    assert root.entries["a/item"].content == b"x"


@pytest.mark.parametrize(
    "change",
    [
        [("a/new", "file", b"new")],
        [("a/old", "file", b"replacement")],
        [("a/.wh.old", "file", b"")],
        [("a/.wh..wh..opq", "file", b"")],
    ],
    ids=["add", "replace", "whiteout", "opaque"],
)
def test_parent_mtime_becomes_unknown_after_child_mutation(change):
    root = VirtualRoot()
    apply(root, [("a", "dir", None), ("a/old", "file", b"old")])
    apply(root, [("a", "dir", None)])
    assert root.entries["a"].mtime == 0
    apply(root, change)
    assert root.entries["a"].mtime is None


def test_directory_mtime_stays_unknown_when_header_and_mutation_share_layer():
    root = VirtualRoot()
    apply(root, [("a", "dir", None)])
    apply(root, [("a/new", "file", b"new"), ("a", "dir", None)])
    assert root.entries["a"].mtime is None


def test_directory_mtime_stays_known_when_other_directory_changes():
    root = VirtualRoot()
    apply(root, [("a", "dir", None), ("b", "dir", None)])
    apply(root, [("b/file", "file", b"x")])
    assert root.entries["a"].mtime == 0
    assert root.entries["b"].mtime is None


def test_deadline_fails_without_mutating_tree():
    root = VirtualRoot(deadline=0)
    with pytest.raises(TimeoutError, match="deadline"):
        apply(root, [("new", "file", b"new")])
    assert set(root.entries) == {""}


def test_rejects_pax_extension_headers():
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as stream:
        info = tarfile.TarInfo("a" * 200)
        info.size = 1
        stream.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="unsupported tar type or extension"):
        VirtualRoot().apply(result.getvalue())


def test_receiver_bounds_uncompressed_layer_bytes(monkeypatch):
    receiver = reconstruction.VerifiedLayerReceiver()
    monkeypatch.setattr(reconstruction, "MAX_LAYER_BYTES", 3)
    receiver.begin()
    with pytest.raises(ValueError, match="layer memory limit"):
        receiver.write(b"four")
    assert set(receiver.root.entries) == {""}


def test_tree_limits_fail_without_partial_application(monkeypatch):
    root = VirtualRoot()
    apply(root, [("one", "file", b"a")])
    monkeypatch.setattr(reconstruction, "MAX_TREE_BYTES", 1)
    with pytest.raises(ValueError, match="tree byte limit"):
        apply(root, [("two", "file", b"b")])
    assert set(root.entries) == {"", "one"}


def test_whiteout_work_is_bounded_before_mutation(monkeypatch):
    root = VirtualRoot()
    apply(root, [("one", "file", b"a")])
    monkeypatch.setattr(reconstruction, "MAX_SCAN_WORK", 1)
    with pytest.raises(ValueError, match="whiteout work limit"):
        apply(root, [(".wh.one", "file", b"")])
    assert root.entries["one"].content == b"a"
