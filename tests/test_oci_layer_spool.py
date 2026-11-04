"""Synthetic, bounded spool checks; no real image or host path extraction."""

import hashlib
import io
import os
import stat
import tarfile
import zlib

import pytest

from scripts import spool_verified_oci_layer as spool
from scripts.verify_oci_layer_binding import OCI_GZIP, OCI_TAR


def layer():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, value in [
            ("a", "file", b"binary"),
            ("alias", "hardlink", "a"),
            ("link", "symlink", "a"),
            (".wh.old", "file", b""),
        ]:
            entry = tarfile.TarInfo(name)
            if kind == "hardlink":
                entry.type = tarfile.LNKTYPE
                entry.linkname = value
            elif kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = value
            else:
                entry.size = len(value)
            archive.addfile(entry, io.BytesIO(value) if kind == "file" else None)
    return stream.getvalue()


def descriptor(data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    return {"mediaType": OCI_TAR, "digest": digest, "size": len(data)}, digest


@pytest.fixture
def private_root(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    return root


def test_verified_tar_is_committed_only_as_private_layer_bytes(private_root):
    data = layer()
    item, diff = descriptor(data)
    report, result = spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    try:
        assert result.read() == data
        assert report["scope"] == "verified-layer-spool-only"
        assert report["diffId"] == diff
        assert report["uncompressedBytes"] == len(data)
        assert stat.S_IMODE(os.fstat(result.fileno()).st_mode) == 0o600
        assert len(list(private_root.iterdir())) == 1
    finally:
        result.close()


def test_verified_name_is_not_visible_during_stream_validation(private_root):
    data = layer()
    item, diff = descriptor(data)

    class InspectStream(io.BytesIO):
        def read(self, size=-1):
            for child in private_root.iterdir():
                assert not (child / "verified.tar").exists()
            return super().read(size)

    report, result = spool.spool_verified_layer(InspectStream(data), item, diff, private_root)
    try:
        assert result.read() == data
        assert (private_root / report["privateChild"] / "verified.tar").exists()
    finally:
        result.close()


@pytest.mark.parametrize("mutation", ["digest", "diff", "size", "truncated-tar", "trailing-data"])
def test_rejected_stream_leaves_no_committed_or_provisional_files(private_root, mutation):
    data = layer()
    if mutation == "truncated-tar":
        data = data[:1024]
    elif mutation == "trailing-data":
        data += b"hidden" + bytes(506)
    item, diff = descriptor(data)
    if mutation == "digest":
        item["digest"] = "sha256:" + "1" * 64
    elif mutation == "diff":
        diff = "sha256:" + "2" * 64
    elif mutation == "size":
        item["size"] += 1
    sentinel = private_root / "unrelated"
    sentinel.write_text("keep")
    with pytest.raises(ValueError):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    assert list(private_root.iterdir()) == [sentinel]
    assert sentinel.read_text() == "keep"


def test_disk_reserve_and_spool_cap_fail_without_committing(private_root, monkeypatch):
    data = layer()
    item, diff = descriptor(data)
    monkeypatch.setattr(spool, "free_space", lambda _fd: spool.MIN_FREE_BYTES)
    with pytest.raises(ValueError, match="reserve"):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    assert list(private_root.iterdir()) == []
    monkeypatch.setattr(spool, "free_space", lambda _fd: spool.MIN_FREE_BYTES + len(data) + 1)
    monkeypatch.setattr(spool, "MAX_SPOOL_BYTES", len(data) - 1)
    with pytest.raises(ValueError, match="limit"):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    assert list(private_root.iterdir()) == []


def test_header_count_limit_fails_without_committing(private_root, monkeypatch):
    data = layer()
    item, diff = descriptor(data)
    monkeypatch.setattr(spool, "MAX_HEADERS", 1)
    with pytest.raises(ValueError, match="header limit"):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    assert list(private_root.iterdir()) == []


def test_private_root_must_be_owned_non_symlink_and_private(tmp_path):
    root = tmp_path / "public"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    data = layer()
    item, diff = descriptor(data)
    with pytest.raises(ValueError):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, root)
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, link)


@pytest.mark.parametrize("failure", ["write", "publish"])
def test_io_failure_discards_only_this_attempt(private_root, monkeypatch, failure):
    data = layer()
    item, diff = descriptor(data)
    sentinel = private_root / "unrelated"
    sentinel.write_text("keep")
    if failure == "write":

        def fail_write(fd, data):
            os.write(fd, data[:512])
            raise OSError("fixture write failure")

        monkeypatch.setattr(spool, "write_all", fail_write)
    else:

        def fail_link(*_args, **_kwargs):
            raise OSError("fixture commit failure")

        monkeypatch.setattr(spool.os, "link", fail_link)
    with pytest.raises(OSError):
        spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    assert list(private_root.iterdir()) == [sentinel]
    assert sentinel.read_text() == "keep"


def test_opaque_bytes_are_not_extracted_or_interpreted_as_overlay(private_root, tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("../outside")
        entry.size = 7
        archive.addfile(entry, io.BytesIO(b"payload"))
    data = stream.getvalue()
    item, diff = descriptor(data)
    report, result = spool.spool_verified_layer(io.BytesIO(data), item, diff, private_root)
    try:
        assert result.read() == data
        assert report["scope"] == "verified-layer-spool-only"
        assert not (tmp_path / "outside").exists()
    finally:
        result.close()


def test_spools_layer_larger_than_virtual_reconstructor_limit(private_root):
    size = 129 * 1024 * 1024
    entry = tarfile.TarInfo("large")
    entry.size = size
    compressed = io.BytesIO()
    compressor = zlib.compressobj(wbits=31)
    digest = hashlib.sha256()

    def feed(data):
        digest.update(data)
        compressed.write(compressor.compress(data))

    feed(entry.tobuf(format=tarfile.USTAR_FORMAT))
    chunk = bytes(1024 * 1024)
    for _ in range(size // len(chunk)):
        feed(chunk)
    feed(bytes(1024))
    compressed.write(compressor.flush())
    raw = compressed.getvalue()
    item = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    report, result = spool.spool_verified_layer(
        io.BytesIO(raw), item, "sha256:" + digest.hexdigest(), private_root
    )
    try:
        assert report["uncompressedBytes"] == size + 1536
        assert os.fstat(result.fileno()).st_size == size + 1536
    finally:
        result.close()
        owned = private_root / report["privateChild"]
        (owned / "verified.tar").unlink()
        owned.rmdir()
