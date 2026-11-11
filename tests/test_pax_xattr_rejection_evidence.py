"""Offline synthetic evidence for opaque binary PAX xattrs; no xattr is applied."""

import hashlib
import io
import tarfile

import pytest

from scripts.check_sbom_inventory import check_pax_framing
from scripts.index_verified_oci_changeset import catalog_layer
from scripts.reconstruct_oci_layers import VirtualRoot


KEY = b"SCHILY.xattr.security.capability"
# Deliberately synthetic, not asserted to be a valid Linux file capability.
VALUE = b"\x00\xff\n=\x80binary\x00"


def record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while len(str(length)) + 1 + len(body) != length:
        length = len(str(length)) + 1 + len(body)
    return str(length).encode() + b" " + body


def make_tar(payload):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        extension = tarfile.TarInfo("pax")
        extension.type = tarfile.XHDTYPE
        extension.size = len(payload)
        archive.addfile(extension, io.BytesIO(payload))
        entry = tarfile.TarInfo("file")
        entry.size = 1
        archive.addfile(entry, io.BytesIO(b"x"))
    return output.getvalue()


def test_python_tar_reader_can_round_trip_synthetic_binary_pax_value():
    data = make_tar(record(KEY, VALUE))
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as archive:
        entry = next(iter(archive))
        assert entry.pax_headers[KEY.decode()].encode("utf-8", "surrogateescape") == VALUE


def test_current_reconstructor_and_catalog_reject_capability_pax(tmp_path, monkeypatch):
    data = make_tar(record(KEY, VALUE))
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    calls = []
    monkeypatch.setattr(
        "os.setxattr", lambda *args, **kwargs: calls.append((args, kwargs)), raising=False
    )
    with pytest.raises(ValueError, match="unsupported or duplicate PAX key"):
        VirtualRoot().apply(data)
    with pytest.raises(ValueError, match="unsupported or duplicate PAX key"):
        catalog_layer(io.BytesIO(data), "sha256:" + hashlib.sha256(data).hexdigest(), root)
    assert calls == []
    assert not list(root.iterdir())


def test_naive_tarfile_duplicate_map_loses_prior_value_but_current_policy_rejects():
    payload = record(KEY, b"first") + record(KEY, b"second")
    data = make_tar(payload)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as archive:
        entry = next(iter(archive))
        assert entry.pax_headers[KEY.decode()] == "second"
    with pytest.raises(ValueError, match="duplicate"):
        check_pax_framing(payload)
    with pytest.raises(ValueError):
        VirtualRoot().apply(data)
