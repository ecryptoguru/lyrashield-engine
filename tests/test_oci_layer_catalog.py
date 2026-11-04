"""Synthetic single-layer catalog tests; never extract archive members."""

import hashlib
import io
import sqlite3
import tarfile
import tempfile

import pytest

from scripts import index_verified_oci_changeset as catalog


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, kind, value in entries:
            entry = tarfile.TarInfo(name)
            if kind == "file":
                entry.size = len(value)
            elif kind == "dir":
                entry.type = tarfile.DIRTYPE
            elif kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = value
            elif kind == "hardlink":
                entry.type = tarfile.LNKTYPE
                entry.linkname = value
            tf.addfile(entry, io.BytesIO(value) if kind == "file" else None)
    return output.getvalue()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture
def root(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    return directory


def test_indexes_offsets_and_unapplied_whiteout_and_links(root):
    data = archive(
        [
            ("a", "dir", None),
            ("a/file", "file", b"hello"),
            ("a/alias", "hardlink", "a/file"),
            ("link", "symlink", "a/file"),
            ("a/.wh.old", "file", b""),
        ]
    )
    report = catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    path = root / report["privateChild"] / "catalog.sqlite3"
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        rows = {
            row[0]: row[1:]
            for row in conn.execute("SELECT path,kind,target,offset,size FROM entries")
        }
    assert rows["a/file"][0] == "file"
    offset, size = rows["a/file"][-2:]
    assert data[offset : offset + size] == b"hello"
    assert rows["a/alias"][:2] == ("hardlink", "a/file")
    assert rows["link"][:2] == ("symlink", "a/file")
    assert rows["a/.wh.old"][0] == "whiteout"
    assert report["scope"] == "verified-single-layer-catalog-only"
    assert report["finalImageVerified"] is False


def test_pax_path_and_offset_refer_to_same_verified_stream(root):
    path = "a" * 200
    data = archive([(path, "file", b"actual-content")])
    report = catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    index = root / report["privateChild"] / "catalog.sqlite3"
    with sqlite3.connect(f"file:{index}?mode=ro", uri=True) as conn:
        row = conn.execute("SELECT path, offset, size FROM entries").fetchone()
    assert row[0] == path
    assert data[row[1] : row[1] + row[2]] == b"actual-content"


def test_forward_only_stream_can_be_cataloged_but_seekable_api_stays_strict(root):
    data = archive([("file", "file", b"hello")])

    class ForwardOnly:
        def __init__(self, contents):
            self.source = io.BytesIO(contents)

        def read(self, size):
            return self.source.read(size)

        def seekable(self):
            return False

    with pytest.raises(ValueError, match="seekable"):
        catalog.catalog_layer(ForwardOnly(data), digest(data), root)
    report = catalog.catalog_forward_layer(ForwardOnly(data), digest(data), root)
    assert report["scope"] == "verified-single-layer-catalog-only"
    assert report["finalImageVerified"] is False
    assert report["provisional"] is True
    child = root / report["privateChild"]
    assert sorted(entry.name for entry in child.iterdir()) == ["provisional.sqlite3"]


def test_catalog_keeps_cross_layer_link_and_parent_resolution_open(root):
    data = archive([("missing/child", "hardlink", "other-layer-target")])
    report = catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert report["finalImageVerified"] is False
    assert report["releaseQualified"] is False


def test_catalog_keeps_absolute_symlink_as_inert_text(root):
    data = archive([("link", "symlink", "/etc/passwd")])
    report = catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    index = root / report["privateChild"] / "catalog.sqlite3"
    with sqlite3.connect(f"file:{index}?mode=ro", uri=True) as db:
        assert db.execute("SELECT kind,target FROM entries").fetchone() == (
            "symlink",
            "/etc/passwd",
        )
    assert report["finalImageVerified"] is False


@pytest.mark.parametrize("target", ["../outside", "../../outside", "/../outside", "./../outside"])
def test_catalog_keeps_dotdot_symlink_target_verbatim_as_inert_text(root, target):
    data = archive([("link", "symlink", target)])
    report = catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    index = root / report["privateChild"] / "catalog.sqlite3"
    with sqlite3.connect(f"file:{index}?mode=ro", uri=True) as db:
        assert db.execute("SELECT kind,target FROM entries").fetchone() == ("symlink", target)
    assert report["finalImageVerified"] is False


@pytest.mark.parametrize("target", ["foo\nbar", "foo\u0085bar", "foo\u202ebar"])
def test_catalog_rejects_raw_relative_symlink_controls(root, target):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        entry = tarfile.TarInfo("link")
        entry.type = tarfile.SYMTYPE
        entry.linkname = target
        tf.addfile(entry)
    data = output.getvalue()
    with pytest.raises(ValueError):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())


def test_catalog_rejects_relative_symlink_target_trailing_slash(root):
    data = archive([("link", "symlink", "foo/")])
    with pytest.raises(ValueError):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())


def test_catalog_rejects_hardlink_target_trailing_slash(root):
    data = archive([("foo", "file", b"old"), ("alias", "hardlink", "foo/")])
    with pytest.raises(ValueError):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())


@pytest.mark.parametrize("name", ["new/", ".wh.foo/"])
def test_catalog_rejects_nondirectory_member_trailing_slash(root, name):
    data = archive([(name, "file", b"")])
    with pytest.raises(ValueError):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())


def test_indexes_synthetic_layer_above_in_memory_limit(root):
    size = 129 * 1024 * 1024
    entry = tarfile.TarInfo("large")
    entry.size = size
    with tempfile.TemporaryFile(dir=root) as stream:
        stream.write(entry.tobuf(format=tarfile.USTAR_FORMAT))
        stream.seek(512 + size)
        stream.write(bytes(1024))
        stream.seek(0)
        hasher = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
        stream.seek(0)
        report = catalog.catalog_layer(stream, "sha256:" + hasher.hexdigest(), root)
        index = root / report["privateChild"] / "catalog.sqlite3"
        with sqlite3.connect(f"file:{index}?mode=ro", uri=True) as conn:
            assert conn.execute("SELECT offset, size FROM entries").fetchone() == (512, size)
        assert report["uncompressedBytes"] == size + 1536


@pytest.mark.parametrize(
    "mutation", ["digest", "truncated", "unsafe-path", "duplicate", "whiteout", "link"]
)
def test_invalid_input_cleans_stage_without_touching_other_files(root, mutation):
    data = archive([("safe", "file", b"x")])
    if mutation == "truncated":
        data = data[:1024]
    elif mutation == "unsafe-path":
        data = archive([("../escape", "file", b"x")])
    elif mutation == "duplicate":
        data = archive([("a", "file", b"x"), ("./a", "file", b"y")])
    elif mutation == "whiteout":
        data = archive([(".wh.old", "file", b"not empty")])
    elif mutation == "link":
        data = archive([("s", "symlink", "bad\\target")])
    expected = "sha256:" + "0" * 64 if mutation == "digest" else digest(data)
    sentinel = root / "unrelated"
    sentinel.write_text("keep")
    with pytest.raises((ValueError, tarfile.TarError)):
        catalog.catalog_layer(io.BytesIO(data), expected, root)
    assert list(root.iterdir()) == [sentinel]
    assert sentinel.read_text() == "keep"


def test_resource_limits_fail_without_catalog(root, monkeypatch):
    data = archive([("a", "file", b"x")])
    monkeypatch.setattr(catalog, "MAX_LAYER_BYTES", len(data) - 1)
    with pytest.raises(ValueError, match="limit"):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())
    monkeypatch.setattr(catalog, "MAX_LAYER_BYTES", len(data) + 1)
    monkeypatch.setattr(catalog, "free_space", lambda _fd: catalog.MIN_FREE_BYTES)
    with pytest.raises(ValueError, match="reserve"):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())


def test_database_and_entry_limits_fail_without_catalog(root, monkeypatch):
    data = archive([("a", "file", b"x"), ("b", "file", b"y")])
    monkeypatch.setattr(catalog, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="entry limit"):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())
    monkeypatch.setattr(catalog, "MAX_ENTRIES", 100)
    monkeypatch.setattr(catalog, "MAX_DB_BYTES", 4095)
    with pytest.raises(ValueError, match="catalog byte limit"):
        catalog.catalog_layer(io.BytesIO(data), digest(data), root)
    assert not list(root.iterdir())
