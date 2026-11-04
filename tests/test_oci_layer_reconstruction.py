"""Synthetic tests for restrictive virtual OCI layer application."""

import io
import os
import runpy
import tarfile
import zlib
from pathlib import Path

import pytest

from scripts import reconstruct_oci_layers as reconstruction
from scripts.reconstruct_oci_layers import VirtualRoot, inert_symlink_target, reconstruct_verified


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


def test_absolute_symlink_is_inert_and_cannot_be_used_as_ancestor_or_hardlink():
    root = VirtualRoot()
    apply(root, [("link", "symlink", "/etc/passwd")])
    assert root.entries["link"].target == "/etc/passwd"
    with pytest.raises(ValueError):
        apply(root, [("link/child", "file", b"x")])
    with pytest.raises(ValueError):
        apply(root, [("alias", "hardlink", "link")])
    with pytest.raises(ValueError):
        apply(root, [("link/.wh.child", "file", b"")])
    assert set(root.entries) == {"", "link"}


@pytest.mark.parametrize(
    "target",
    [
        "/foo\\bar",
        "/foo\nbar",
        "/foo\u0085bar",
        "/foo\u202ebar",
    ],
)
def test_ambiguous_absolute_symlink_targets_still_reject(target):
    root = VirtualRoot()
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("link")
        entry.type = tarfile.SYMTYPE
        entry.linkname = target
        archive.addfile(entry)
    with pytest.raises(ValueError):
        root.apply(result.getvalue())
    assert set(root.entries) == {""}


def test_absolute_hardlink_target_still_rejects():
    root = VirtualRoot()
    with pytest.raises(ValueError):
        apply(root, [("link", "hardlink", "/etc/passwd")])
    assert set(root.entries) == {""}


def test_raw_hardlink_target_trailing_slash_does_not_alias_regular_file():
    root = VirtualRoot()
    apply(root, [("foo", "file", b"old")])
    with pytest.raises(ValueError):
        apply(root, [("alias", "hardlink", "foo/")])
    assert set(root.entries) == {"", "foo"}
    assert root.entries["foo"].content == b"old"


@pytest.mark.parametrize("name", ["new/", ".wh.foo/"])
def test_raw_nondirectory_member_trailing_slash_is_rejected_atomically(name):
    root = VirtualRoot()
    apply(root, [("foo", "file", b"old")])
    with pytest.raises(ValueError):
        apply(root, [(name, "file", b"")])
    assert set(root.entries) == {"", "foo"}
    assert root.entries["foo"].content == b"old"


def test_directory_member_with_trailing_slash_remains_valid():
    root = VirtualRoot()
    apply(root, [("directory/", "dir", None), ("directory/file", "file", b"x")])
    assert root.entries["directory"].kind == "dir"
    assert root.entries["directory/file"].content == b"x"


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


def test_applies_pax_path_override():
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as stream:
        info = tarfile.TarInfo("a" * 200)
        info.size = 1
        stream.addfile(info, io.BytesIO(b"x"))
    root = VirtualRoot()
    root.apply(result.getvalue())
    assert root.entries["a" * 200].content == b"x"


def pax_record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + 1 + len(body) != size:
        size = len(str(size)) + 1 + len(body)
    return str(size).encode() + b" " + body


def pax_tar(payload, *, kind=tarfile.XHDTYPE, member_type=tarfile.REGTYPE, add_member=True):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        extension = tarfile.TarInfo("PaxHeader")
        extension.type = kind
        extension.size = len(payload)
        stream.addfile(extension, io.BytesIO(payload))
        if add_member:
            entry = tarfile.TarInfo("placeholder")
            entry.type = member_type
            if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                entry.linkname = "original"
            else:
                entry.size = 1
            stream.addfile(entry, io.BytesIO(b"x") if entry.isfile() else None)
    return result.getvalue()


def test_applies_pax_linkpath_override():
    root = VirtualRoot()
    root.apply(pax_tar(pax_record(b"linkpath", b"safe-target"), member_type=tarfile.SYMTYPE))
    assert root.entries["placeholder"].target == "safe-target"


def test_pax_absolute_symlink_target_is_inert():
    root = VirtualRoot()
    root.apply(pax_tar(pax_record(b"linkpath", b"/etc/passwd"), member_type=tarfile.SYMTYPE))
    assert root.entries["placeholder"].target == "/etc/passwd"


def test_pax_absolute_hardlink_target_still_rejects():
    root = VirtualRoot()
    with pytest.raises(ValueError):
        root.apply(pax_tar(pax_record(b"linkpath", b"/etc/passwd"), member_type=tarfile.LNKTYPE))
    assert set(root.entries) == {""}


def test_pax_hardlink_target_trailing_slash_rejects():
    root = VirtualRoot()
    apply(root, [("foo", "file", b"old")])
    with pytest.raises(ValueError):
        root.apply(pax_tar(pax_record(b"linkpath", b"foo/"), member_type=tarfile.LNKTYPE))
    assert set(root.entries) == {"", "foo"}


def test_pax_absolute_symlink_target_with_parent_component_is_inert():
    root = VirtualRoot()
    root.apply(pax_tar(pax_record(b"linkpath", b"/../host"), member_type=tarfile.SYMTYPE))
    assert root.entries["placeholder"].target == "/../host"


@pytest.mark.parametrize("target", ["../outside", "../../outside", "/../outside", "/../../outside"])
def test_dotdot_symlink_is_inert_and_never_used_as_parent_or_hardlink(target):
    root = VirtualRoot()
    apply(root, [("link", "symlink", target)])
    assert root.entries["link"].target == target
    with pytest.raises(ValueError):
        apply(root, [("link/child", "file", b"x")])
    with pytest.raises(ValueError):
        apply(root, [("link/.wh.child", "file", b"")])
    with pytest.raises(ValueError):
        apply(root, [("alias", "hardlink", "link")])
    with pytest.raises(ValueError):
        apply(root, [("alias", "hardlink", "link/child")])
    assert set(root.entries) == {"", "link"}


def test_dotdot_symlink_cannot_replace_nonempty_directory():
    root = VirtualRoot()
    apply(root, [("dir", "dir", None), ("dir/child", "file", b"old")])
    with pytest.raises(ValueError):
        apply(root, [("dir", "symlink", "../../outside")])
    assert root.entries["dir"].kind == "dir"
    assert root.entries["dir/child"].content == b"old"


def test_pax_relative_dotdot_symlink_target_is_inert():
    root = VirtualRoot()
    root.apply(pax_tar(pax_record(b"linkpath", b"../../outside"), member_type=tarfile.SYMTYPE))
    assert root.entries["placeholder"].target == "../../outside"


def test_oversized_dotdot_symlink_target_is_rejected():
    root = VirtualRoot()
    target = b"../" + b"a" * 4096
    with pytest.raises(ValueError):
        root.apply(pax_tar(pax_record(b"linkpath", target), member_type=tarfile.SYMTYPE))
    assert set(root.entries) == {""}


@pytest.mark.parametrize("target", ["/foo\nbar", "/foo\u0085bar", "/foo\u202ebar"])
def test_pax_absolute_symlink_target_with_controls_still_rejects(target):
    root = VirtualRoot()
    with pytest.raises(ValueError):
        root.apply(pax_tar(pax_record(b"linkpath", target.encode()), member_type=tarfile.SYMTYPE))
    assert set(root.entries) == {""}


@pytest.mark.parametrize("target", ["foo\nbar", "foo\u0085bar", "foo\u202ebar"])
@pytest.mark.parametrize("header_format", ["raw", "pax"])
def test_relative_symlink_target_with_controls_is_rejected_in_raw_and_pax(target, header_format):
    if header_format == "pax":
        data = pax_tar(pax_record(b"linkpath", target.encode()), member_type=tarfile.SYMTYPE)
    else:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            entry = tarfile.TarInfo("link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = target
            archive.addfile(entry)
        data = output.getvalue()
    root = VirtualRoot()
    with pytest.raises(ValueError):
        root.apply(data)
    assert set(root.entries) == {""}


@pytest.mark.parametrize("header_format", ["raw", "pax"])
def test_relative_symlink_target_with_trailing_slash_is_retained_verbatim(header_format):
    if header_format == "pax":
        data = pax_tar(pax_record(b"linkpath", b"foo/"), member_type=tarfile.SYMTYPE)
    else:
        data = tar([("link", "symlink", "foo/")])
    root = VirtualRoot()
    root.apply(data)
    path = "placeholder" if header_format == "pax" else "link"
    assert root.entries[path].target == "foo/"


@pytest.mark.parametrize("target", ["/", "//host/path", "foo//bar", "foo/./bar", "../", ".", ".."])
@pytest.mark.parametrize("header_format", ["raw", "pax"])
def test_opaque_symlink_text_is_verbatim_and_cannot_be_followed(target, header_format):
    if header_format == "pax":
        data = pax_tar(pax_record(b"linkpath", target.encode()), member_type=tarfile.SYMTYPE)
        path = "placeholder"
    else:
        data = tar([("link", "symlink", target)])
        path = "link"
    root = VirtualRoot()
    root.apply(data)
    assert root.entries[path].target == target
    with pytest.raises(ValueError):
        apply(root, [(path + "/child", "file", b"x")])
    with pytest.raises(ValueError):
        apply(root, [(path + "/.wh.child", "file", b"")])
    with pytest.raises(ValueError):
        apply(root, [("alias", "hardlink", path)])
    assert set(root.entries) == {"", path}


def test_opaque_symlink_cannot_become_ancestor_within_one_layer():
    root = VirtualRoot()
    with pytest.raises(ValueError):
        apply(root, [("link", "symlink", "../"), ("link/child", "file", b"x")])
    assert set(root.entries) == {""}


@pytest.mark.parametrize("target", ["dir//file", "dir/./file", "dir/../file", "dir/file/"])
def test_ambiguous_hardlink_targets_remain_rejected(target):
    root = VirtualRoot()
    apply(root, [("dir", "dir", None), ("dir/file", "file", b"old")])
    with pytest.raises(ValueError):
        apply(root, [("alias", "hardlink", target)])
    assert root.entries["dir/file"].content == b"old"
    assert "alias" not in root.entries


@pytest.mark.parametrize("target", ["", "x\x00y", "x\\y", "x\n", "x\u0085", "x\u202e", "x\ud800"])
def test_opaque_symlink_targets_still_reject_empty_controls_and_backslash(target):
    with pytest.raises(ValueError):
        inert_symlink_target(target)


def test_pax_path_whiteout_is_applied_to_lower_layer():
    root = VirtualRoot()
    apply(root, [("old", "file", b"old")])
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as stream:
        info = tarfile.TarInfo("placeholder")
        info.pax_headers = {"path": ".wh.old"}
        stream.addfile(info)
    root.apply(result.getvalue())
    assert set(root.entries) == {""}


@pytest.mark.parametrize(
    "payload",
    [
        b"invalid",
        pax_record(b"path", b"a") + pax_record(b"path", b"b"),
        pax_record(b"path", b""),
        pax_record(b"path", b"../escape"),
        pax_record(b"path", b"invalid-\xff"),
        pax_record(b"path", b"bad\nname"),
        pax_record(b"path", "bad\u0085name".encode()),
        pax_record(b"path", "bad\u202ename".encode()),
        pax_record(b"path", b"non-directory/"),
        pax_record(b"path", b"a" * 16384),
        pax_record(b"linkpath", b"safe"),
        pax_record(b"mtime", b"0"),
        pax_record(b"size", b"1"),
        pax_record(b"GNU.sparse.map", b"0,1"),
        pax_record(b"SCHILY.xattr.security.capability", b"x"),
    ],
)
def test_rejects_unsupported_pax_without_partial_application(payload):
    root = VirtualRoot()
    apply(root, [("existing", "file", b"old")])
    with pytest.raises((ValueError, UnicodeError)):
        root.apply(pax_tar(payload))
    assert root.entries["existing"].content == b"old"
    assert set(root.entries) == {"", "existing"}


def test_rejects_global_and_dangling_pax():
    root = VirtualRoot()
    for data in (
        pax_tar(pax_record(b"path", b"a"), kind=tarfile.XGLTYPE),
        pax_tar(pax_record(b"path", b"a"), add_member=False),
    ):
        with pytest.raises((ValueError, tarfile.ReadError)):
            root.apply(data)
    assert set(root.entries) == {""}


def test_rejects_stacked_pax_headers():
    result = io.BytesIO()
    payload = pax_record(b"path", b"new")
    with tarfile.open(fileobj=result, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for _ in range(2):
            header = tarfile.TarInfo("pax")
            header.type = tarfile.XHDTYPE
            header.size = len(payload)
            stream.addfile(header, io.BytesIO(payload))
        stream.addfile(tarfile.TarInfo("placeholder"))
    with pytest.raises(ValueError, match="stacked"):
        VirtualRoot().apply(result.getvalue())


def test_pax_link_targets_count_toward_staged_and_retained_path_limit(monkeypatch):
    def links(entries):
        result = io.BytesIO()
        with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as stream:
            for name, target in entries:
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = "original"
                info.pax_headers = {"linkpath": target}
                stream.addfile(info)
        return result.getvalue()

    root = VirtualRoot()
    monkeypatch.setattr(reconstruction, "MAX_PATH_BYTES", 10)
    root.apply(links([("a", "1234")]))
    with pytest.raises(ValueError, match="path limit"):
        root.apply(links([("b", "56789")]))
    assert root.entries["a"].target == "1234"
    assert set(root.entries) == {"", "a"}
    with pytest.raises(ValueError, match="path limit"):
        VirtualRoot().apply(links([("a", "1234"), ("b", "56789")]))


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
