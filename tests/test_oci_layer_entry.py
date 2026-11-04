"""Offline synthetic selective capture; no image or executable is run."""

import hashlib
import io
import tarfile
import zlib

import pytest

from scripts import inspect_oci_layer_entry as capture
from scripts.verify_oci_layer_binding import OCI_GZIP, OCI_TAR


TARGET = "usr/bin/example"


def tar(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.USTAR_FORMAT) as archive:
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
            else:
                info.size = len(value)
            archive.addfile(info, io.BytesIO(value) if kind == "file" else None)
    return result.getvalue()


def item(data, media=OCI_TAR):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    return {"mediaType": media, "digest": digest, "size": len(data)}, digest


def test_returns_only_verified_selected_bytes():
    data = tar([("other", "file", b"ignore"), (TARGET, "file", b"binary")])
    descriptor, diff = item(data)
    report, selected = capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)
    try:
        assert selected.read() == b"binary"
        assert report["scope"] == "verified-single-layer-entry-only"
        assert report["entrySha256"] == hashlib.sha256(b"binary").hexdigest()
    finally:
        selected.close()


@pytest.mark.parametrize("wrong", ["digest", "diff", "size"])
def test_never_returns_content_before_all_layer_integrity_checks(wrong):
    data = tar([(TARGET, "file", b"binary")])
    descriptor, diff = item(data)
    if wrong == "digest":
        descriptor["digest"] = "sha256:" + "1" * 64
    elif wrong == "diff":
        diff = "sha256:" + "2" * 64
    else:
        descriptor["size"] += 1
    with pytest.raises(ValueError):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_failed_layer_closes_provisional_capture(monkeypatch):
    data = tar([(TARGET, "file", b"binary")])
    descriptor, diff = item(data)
    descriptor["digest"] = "sha256:" + "1" * 64
    created = []
    original = capture.tempfile.TemporaryFile

    def track(*args, **kwargs):
        result = original(*args, **kwargs)
        created.append(result)
        return result

    monkeypatch.setattr(capture.tempfile, "TemporaryFile", track)
    with pytest.raises(ValueError):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)
    assert len(created) == 1 and created[0].closed


def test_disk_reserve_checked_before_selected_bytes_written(monkeypatch):
    data = tar([(TARGET, "file", b"binary")])
    descriptor, diff = item(data)
    usage = type("Usage", (), {"free": capture.MIN_FREE_BYTES})()
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: usage)
    with pytest.raises(ValueError, match="storage reserve"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_links_anywhere_are_unresolved_not_ignored(kind):
    data = tar([(TARGET, "file", b"binary"), ("elsewhere", kind, "other")])
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="link"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


@pytest.mark.parametrize(
    "marker", [".wh.usr", "usr/.wh.bin", "usr/bin/.wh.example", "usr/.wh..wh..opq"]
)
@pytest.mark.parametrize("after", [False, True])
def test_target_or_ancestor_whiteout_is_unresolved_regardless_of_order(marker, after):
    entries = [(marker, "file", b""), (TARGET, "file", b"binary")]
    if after:
        entries.reverse()
    data = tar(entries)
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="whiteout"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_unrelated_whiteout_does_not_claim_a_final_filesystem():
    data = tar([("usr/bin/.wh.other", "file", b""), (TARGET, "file", b"binary")])
    descriptor, diff = item(data)
    report, selected = capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)
    try:
        assert report["scope"] == "verified-single-layer-entry-only"
        assert selected.read() == b"binary"
    finally:
        selected.close()


@pytest.mark.parametrize(
    "entries",
    [
        [("../escape", "file", b"x"), (TARGET, "file", b"binary")],
        [(TARGET, "file", b"binary"), ("./" + TARGET, "file", b"other")],
        [("usr", "file", b"not a directory"), (TARGET, "file", b"binary")],
        [("usr/bin/.wh.other", "file", b"not-empty"), (TARGET, "file", b"binary")],
        [("other", "file", b"no target")],
    ],
)
def test_ambiguous_or_malformed_entries_fail_closed(entries):
    data = tar(entries)
    descriptor, diff = item(data)
    with pytest.raises(ValueError):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


@pytest.mark.parametrize("path", [TARGET + "/", "usr/bin/.wh.other/"])
def test_non_directory_trailing_slash_is_not_normalized_into_an_entry(path):
    entries = [(path, "file", b"binary" if path.startswith(TARGET) else b"")]
    if path != TARGET + "/":
        entries.append((TARGET, "file", b"binary"))
    data = tar(entries)
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="trailing slash"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_requested_file_with_trailing_slash_is_not_normalized():
    data = tar([(TARGET, "file", b"binary")])
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="trailing slash"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET + "/")


def test_rejects_truncated_tar_even_if_selected_file_was_captured():
    data = tar([(TARGET, "file", b"binary")])[:1024]
    descriptor, diff = item(data)
    with pytest.raises(ValueError):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_rejects_hidden_nonzero_bytes_after_tar_terminator():
    data = tar([(TARGET, "file", b"binary")]) + b"hidden" + bytes(506)
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="nonzero"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_rejects_pax_headers_instead_of_guessing_names():
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo(TARGET)
        entry.pax_headers = {"comment": "unsupported"}
        entry.size = 6
        archive.addfile(entry, io.BytesIO(b"binary"))
    data = result.getvalue()
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="unsupported"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_declared_selected_file_larger_than_limit_is_rejected():
    entry = tarfile.TarInfo(TARGET)
    entry.size = capture.MAX_CAPTURE_BYTES + 1
    data = entry.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)
    descriptor, diff = item(data)
    with pytest.raises(ValueError, match="size"):
        capture.capture_verified_layer(io.BytesIO(data), descriptor, diff, TARGET)


def test_streams_a_layer_larger_than_the_in_memory_reconstructor_limit():
    filler_size = 129 * 1024 * 1024
    filler = tarfile.TarInfo("large-unselected-file")
    filler.size = filler_size
    chosen = tarfile.TarInfo(TARGET)
    chosen.size = 6
    chunks = [filler.tobuf(format=tarfile.USTAR_FORMAT)]
    digest = hashlib.sha256()
    compressor = zlib.compressobj(wbits=31)
    compressed = io.BytesIO()

    def feed(data):
        digest.update(data)
        compressed.write(compressor.compress(data))

    feed(chunks[0])
    chunk = b"\0" * (1024 * 1024)
    for _ in range(filler_size // len(chunk)):
        feed(chunk)
    feed(chosen.tobuf(format=tarfile.USTAR_FORMAT))
    feed(b"binary" + b"\0" * (512 - 6))
    feed(b"\0" * 1024)
    compressed.write(compressor.flush())
    data = compressed.getvalue()
    descriptor, _ = item(data, OCI_GZIP)
    report, selected = capture.capture_verified_layer(
        io.BytesIO(data), descriptor, "sha256:" + digest.hexdigest(), TARGET
    )
    try:
        assert selected.read() == b"binary"
        assert report["entrySize"] == 6
    finally:
        selected.close()
