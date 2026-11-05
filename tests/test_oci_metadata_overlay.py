"""Synthetic offline tests for an unqualified metadata-only OCI overlay model."""

import gzip
import hashlib
import importlib
import importlib.util
import io
import json
import os
import tarfile
import tracemalloc
from dataclasses import replace

import pytest

from scripts.catalog_pax_capability_headers import inspect_layer_changeset
from scripts.verify_oci_layer_binding import OCI_CONFIG, OCI_GZIP, OCI_MANIFEST


CAP_KEY = b"SCHILY.xattr.security.capability"
CAP_VALUE = b"private-capability-value\x00\xff"


def api():
    name = "scripts.model_oci_metadata_overlay"
    assert importlib.util.find_spec(name), "expected unqualified metadata overlay model"
    return importlib.import_module(name)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pax_record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + len(body) + 1 != size:
        size = len(str(size)) + len(body) + 1
    return str(size).encode() + b" " + body


def layer(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, kind, data, cap in entries:
            if cap is not None:
                raw = pax_record(CAP_KEY, cap)
                pax = tarfile.TarInfo("pax")
                pax.type = tarfile.XHDTYPE
                pax.size = len(raw)
                archive.addfile(pax, io.BytesIO(raw))
            entry = tarfile.TarInfo(path)
            if kind == "dir":
                entry.type = tarfile.DIRTYPE
            elif kind == "hardlink":
                entry.type = tarfile.LNKTYPE
                entry.linkname = data
            elif kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = data
            elif kind == "file":
                entry.size = len(data)
            else:
                raise AssertionError("invalid fixture")
            archive.addfile(entry, io.BytesIO(data) if kind == "file" else None)
    return out.getvalue()


def changes(raw):
    return inspect_layer_changeset(io.BytesIO(raw), digest(raw))


def apply(model, raw, index):
    model.apply(changes(raw), index, len(raw))


def image(tmp_path, raw_layers, *, architecture="amd64", diff_ids=None):
    folder = tmp_path / "blobs"
    folder.mkdir(mode=0o700)

    def store(blob):
        value = digest(blob)
        (folder / value[7:]).write_bytes(blob)
        return value

    layers = []
    for raw in raw_layers:
        encoded = gzip.compress(raw, mtime=0)
        layers.append({"mediaType": OCI_GZIP, "digest": store(encoded), "size": len(encoded)})
    config = json.dumps(
        {
            "architecture": architecture,
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": diff_ids or [digest(x) for x in raw_layers]},
        },
        separators=(",", ":"),
    ).encode()
    cfg = {"mediaType": OCI_CONFIG, "digest": store(config), "size": len(config)}
    manifest = json.dumps(
        {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": cfg, "layers": layers},
        separators=(",", ":"),
    ).encode()
    manifest_digest = store(manifest)
    return folder, manifest_digest, layers


def run(tmp_path, raw_layers, platform="linux/amd64", **kwargs):
    folder, manifest_digest, _ = image(tmp_path, raw_layers)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return api().model_verified_image(fd, manifest_digest, platform, **kwargs)
    finally:
        os.close(fd)


def test_metadata_model_keeps_hardlinks_and_capability_unknown(tmp_path):
    raw = layer(
        [
            ("bin", "dir", None, None),
            ("bin/private", "file", b"content", CAP_VALUE),
            ("bin/alias", "hardlink", "bin/private", None),
        ]
    )
    result = run(tmp_path, [raw])
    original, alias = result.entries["bin/private"], result.entries["bin/alias"]
    assert original.inode is alias.inode
    assert original.inode.capability_state == "unknown"
    assert original.inode.capability_header == CAP_VALUE
    assert original.inode.source_layer == 0 and original.inode.size == 7
    assert result.runtime_equivalent is False and result.release_qualified is False
    assert "private" not in repr(result) and "private-capability" not in repr(result)
    with pytest.raises(TypeError):
        result.entries["new"] = original


def test_whiteout_removes_one_alias_without_destroying_surviving_inode(tmp_path):
    first = layer(
        [
            ("original", "file", b"value", CAP_VALUE),
            ("alias", "hardlink", "original", None),
        ]
    )
    second = layer([(".wh.original", "file", b"", None)])
    result = run(tmp_path, [first, second])
    assert "original" not in result.entries
    assert result.entries["alias"].inode.capability_state == "unknown"
    assert result.entries["alias"].inode.capability_header == CAP_VALUE


def test_removing_all_hardlink_names_discards_the_symbolic_inode(tmp_path):
    first = layer(
        [
            ("original", "file", b"value", CAP_VALUE),
            ("alias", "hardlink", "original", None),
        ]
    )
    second = layer([(".wh.original", "file", b"", None), (".wh.alias", "file", b"", None)])
    result = run(tmp_path, [first, second])
    assert set(result.entries) == {""}


def test_opaque_whiteout_removes_only_lower_children_and_not_same_layer_additions(tmp_path):
    first = layer([("d", "dir", None, None), ("d/old", "file", b"old", None)])
    second = layer([("d/new", "file", b"new", None), ("d/.wh..wh..opq", "file", b"", None)])
    result = run(tmp_path, [first, second])
    assert "d/old" not in result.entries and result.entries["d/new"].inode.source_layer == 1


def test_ambiguous_replacement_with_live_hardlink_fails_atomically():
    model = api().MetadataRoot()
    apply(model, layer([("a", "file", b"old", CAP_VALUE), ("alias", "hardlink", "a", None)]), 0)
    before = model.entries.copy()
    with pytest.raises(ValueError):
        apply(model, layer([("a", "file", b"new", None)]), 1)
    assert model.entries == before and model.entries["a"].inode is model.entries["alias"].inode


def test_symlink_ancestor_and_unresolved_hardlink_fail_atomically():
    model = api().MetadataRoot()
    apply(model, layer([("link", "symlink", "/target", None)]), 0)
    before = model.entries.copy()
    for entries in [
        [("link/child", "file", b"x", None)],
        [("bad", "hardlink", "missing", None)],
    ]:
        with pytest.raises(ValueError):
            apply(model, layer(entries), 1)
        assert model.entries == before


def test_hardlink_with_conflicting_metadata_fails_atomically():
    raw = layer([("a", "file", b"old", CAP_VALUE), ("alias", "hardlink", "a", None)])
    members = list(changes(raw))
    members[1] = replace(members[1], mode=members[1].mode ^ 1)
    model = api().MetadataRoot()
    with pytest.raises(ValueError, match="hardlink metadata"):
        model.apply(members, 0, len(raw))
    assert set(model.entries) == {""} and model.next_layer == 0


def test_wrong_layer_diffid_and_wrong_platform_return_no_overlay(tmp_path):
    raw = layer([("file", "file", b"content", None)])
    folder, manifest_digest, _ = image(tmp_path, [raw], diff_ids=["sha256:" + "0" * 64])
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError):
            api().model_verified_image(fd, manifest_digest, "linux/amd64")
        with pytest.raises(ValueError):
            api().model_verified_image(fd, manifest_digest, "linux/arm64")
    finally:
        os.close(fd)


def test_repeated_layer_is_applied_twice_without_deduplication(tmp_path):
    raw = layer([("file", "file", b"same", None)])
    result = run(tmp_path, [raw, raw])
    assert result.entries["file"].inode.source_layer == 1
    assert len(result.layers) == 2 and result.layers[0] == result.layers[1]
    assert result.entries["file"].inode.capability_state == "unknown"
    assert result.entries["file"].inode.capability_header is None


def test_invalid_capability_header_association_fails_atomically():
    raw = layer([("file", "file", b"bytes", CAP_VALUE)])
    member = changes(raw)[0]
    model = api().MetadataRoot()
    before = model.entries.copy()
    for tampered in [
        replace(member, capability_value=b"different"),
        replace(member, pax_payload=pax_record(CAP_KEY, b"different")),
        replace(member, pax_payload=pax_record(b"path", b"another") + member.pax_payload),
    ]:
        with pytest.raises(ValueError):
            model.apply([tampered], 0, len(raw))
        assert model.entries == before and model.next_layer == 0


@pytest.mark.parametrize("alteration", ["offset", "size", "duplicate", "order"])
def test_tampered_changeset_is_rejected_atomically(alteration):
    raw = layer([("a", "file", b"a", None), ("b", "file", b"b", None)])
    members = list(changes(raw))
    if alteration == "offset":
        members[0] = replace(members[0], data_offset=0)
    elif alteration == "size":
        members[0] = replace(members[0], size=len(raw))
    elif alteration == "duplicate":
        members[1] = replace(members[1], path="a")
    else:
        members.reverse()
    model = api().MetadataRoot()
    with pytest.raises(ValueError):
        model.apply(members, 0, len(raw))
    assert set(model.entries) == {""} and model.next_layer == 0


def test_wrong_layer_order_and_tampered_blob_never_return_a_model(tmp_path):
    first = layer([("a", "file", b"first", None)])
    second = layer([("b", "file", b"second", None)])
    order_dir, tamper_dir = tmp_path / "order", tmp_path / "tamper"
    order_dir.mkdir()
    tamper_dir.mkdir()
    folder, manifest_digest, _ = image(
        order_dir, [first, second], diff_ids=[digest(second), digest(first)]
    )
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError):
            api().model_verified_image(fd, manifest_digest, "linux/amd64")
    finally:
        os.close(fd)
    folder, manifest_digest, layers = image(tamper_dir, [first, second])
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        (folder / layers[1]["digest"][7:]).write_bytes(b"tampered")
        with pytest.raises(ValueError):
            api().model_verified_image(fd, manifest_digest, "linux/amd64")
    finally:
        os.close(fd)


def test_entry_and_work_budgets_preserve_previous_state(monkeypatch):
    model = api().MetadataRoot()
    apply(model, layer([("a", "file", b"a", None)]), 0)
    before = model.entries.copy()
    monkeypatch.setattr(api(), "MAX_OVERLAY_ENTRIES", 2)
    with pytest.raises(ValueError, match="entry limit"):
        apply(model, layer([("b", "file", b"b", None)]), 1)
    assert model.entries == before and model.next_layer == 1
    monkeypatch.setattr(api(), "MAX_OVERLAY_ENTRIES", 100_000)
    monkeypatch.setattr(api(), "MAX_SCAN_WORK", 0)
    with pytest.raises(ValueError, match="work limit"):
        apply(model, layer([(".wh.a", "file", b"", None)]), 1)
    assert model.entries == before and model.next_layer == 1


def test_no_capability_metadata_is_applied_to_the_host(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "setxattr", lambda *_args, **_kwargs: calls.append(True), raising=False)
    result = run(tmp_path, [layer([("file", "file", b"data", CAP_VALUE)])])
    assert result.entries["file"].inode.capability_state == "unknown" and not calls


def test_linux_literal_path_policy_requires_explicit_opt_in(tmp_path):
    raw = layer([("a\\b", "file", b"data", None)])
    strict, literal = tmp_path / "strict", tmp_path / "literal"
    strict.mkdir()
    literal.mkdir()
    with pytest.raises(ValueError, match="incomplete"):
        run(strict, [raw])
    result = run(literal, [raw], linux_literal_paths=True)
    assert "a\\b" in result.entries and "a/b" not in result.entries


def test_layer_larger_than_old_128m_limit_is_streamed_without_file_contents(tmp_path):
    size = 129 * 1024 * 1024
    compressed = io.BytesIO()
    raw_hash = hashlib.sha256()

    class HashingSink:
        def __init__(self, destination):
            self.destination = destination

        def write(self, data):
            raw_hash.update(data)
            return self.destination.write(data)

        def flush(self):
            self.destination.flush()

    class Zeros:
        def __init__(self, remaining):
            self.remaining = remaining

        def read(self, n):
            n = min(n, self.remaining)
            self.remaining -= n
            return bytes(n)

    with (
        gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as encoded,
        tarfile.open(fileobj=HashingSink(encoded), mode="w|", format=tarfile.USTAR_FORMAT) as tar,
    ):
        entry = tarfile.TarInfo("large")
        entry.size = size
        tar.addfile(entry, Zeros(size))
    blob = compressed.getvalue()
    assert len(blob) < 200_000
    folder = tmp_path / "blobs"
    folder.mkdir(mode=0o700)

    def store(data):
        value = digest(data)
        (folder / value[7:]).write_bytes(data)
        return value

    item = {"mediaType": OCI_GZIP, "digest": store(blob), "size": len(blob)}
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + raw_hash.hexdigest()]},
        },
        separators=(",", ":"),
    ).encode()
    cfg = {"mediaType": OCI_CONFIG, "digest": store(config), "size": len(config)}
    manifest = json.dumps(
        {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": cfg, "layers": [item]},
        separators=(",", ":"),
    ).encode()
    manifest_digest = store(manifest)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    tracemalloc.start()
    try:
        result = api().model_verified_image(fd, manifest_digest, "linux/amd64")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        os.close(fd)
    assert result.entries["large"].inode.size == size
    assert not hasattr(result.entries["large"].inode, "content")
    assert peak < 20 * 1024 * 1024
