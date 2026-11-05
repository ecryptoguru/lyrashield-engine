"""Synthetic tests for an unwired, aggregate-only PAX layer stream."""

import gzip
import hashlib
import io
import tarfile

import pytest

from scripts import verify_pax_capability_stream as verify
from scripts.verify_oci_layer_binding import OCI_GZIP


def record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + 1 + len(body) != size:
        size = len(str(size)) + 1 + len(body)
    return str(size).encode() + b" " + body


def layer(payload, *, kind=tarfile.REGTYPE):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        pax = tarfile.TarInfo("pax")
        pax.type = tarfile.XHDTYPE
        pax.size = len(payload)
        archive.addfile(pax, io.BytesIO(payload))
        member = tarfile.TarInfo("private-member-name")
        member.type = kind
        if kind == tarfile.SYMTYPE:
            member.linkname = "private-target"
        archive.addfile(member)
    raw = output.getvalue()
    compressed = gzip.compress(raw)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    return compressed, descriptor, "sha256:" + hashlib.sha256(raw).hexdigest()


class Fetch:
    def __init__(self, data, status=0):
        self.stdout = io.BytesIO(data)
        self.status = status
        self.killed = False

    def poll(self):
        return self.status

    def wait(self, timeout=None):  # noqa: ARG002
        return self.status

    def kill(self):
        self.killed = True
        self.status = -9


@pytest.fixture
def private_root(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(verify, "free_space", lambda _fd: 10 * 1024**3)
    return root


@pytest.mark.parametrize(
    "kind, expected", [(tarfile.REGTYPE, "file"), (tarfile.SYMTYPE, "symlink")]
)
def test_only_aggregate_counts_follow_verified_complete_stream(private_root, kind, expected):
    secret = b"PRIVATE-CAPABILITY-\x00\xff"
    compressed, descriptor, diff = layer(
        record(b"SCHILY.xattr.security.capability", secret), kind=kind
    )
    result = verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert result["capabilityHeaders"] == 1
    assert result["fileHeaders"] == (expected == "file")
    assert result["symlinkHeaders"] == (expected == "symlink")
    assert result["finalImageVerified"] is False and result["releaseQualified"] is False
    assert "PRIVATE" not in str(result) and "private-member" not in str(result)
    assert not list(private_root.iterdir())


@pytest.mark.parametrize("failure", ["descriptor", "diffid", "fetch", "truncated"])
def test_no_counts_on_any_verification_failure(private_root, failure):
    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"private"))
    if failure == "descriptor":
        descriptor["digest"] = "sha256:" + "0" * 64
    if failure == "diffid":
        diff = "sha256:" + "0" * 64
    if failure == "truncated":
        compressed = compressed[:-5]
    with pytest.raises(ValueError, match="incomplete"):
        verify.inspect_fetched_layer(
            Fetch(compressed, 1 if failure == "fetch" else 0), descriptor, diff, private_root
        )


def test_unsupported_pax_stops_as_incomplete_without_exposing_content(private_root):
    compressed, descriptor, diff = layer(record(b"PRIVATE-KEY", b"PRIVATE-VALUE"))
    with pytest.raises(ValueError, match="incomplete") as caught:
        verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert "PRIVATE" not in str(caught.value)
    assert not list(private_root.iterdir())


def test_space_reserve_is_checked_and_no_counts_are_returned(private_root, monkeypatch):
    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    monkeypatch.setattr(verify, "free_space", lambda _fd: 0)
    with pytest.raises(ValueError, match="incomplete"):
        verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)


def test_invalid_root_stops_owned_live_fetch_without_returning_counts(tmp_path):
    class LiveFetch(Fetch):
        def __init__(self):
            super().__init__(b"", status=None)

    fetch = LiveFetch()
    with pytest.raises(ValueError, match="incomplete"):
        verify.inspect_fetched_layer(fetch, {}, "bad", tmp_path / "missing")
    assert fetch.killed and fetch.stdout.closed


def test_no_counts_if_cleanup_fails_after_complete_stream(private_root):
    class BadCleanup(Fetch):
        def poll(self):
            raise RuntimeError("PRIVATE-CLEANUP-CONTENT")

    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    with pytest.raises(ValueError, match="cleanup incomplete") as caught:
        verify.inspect_fetched_layer(BadCleanup(compressed), descriptor, diff, private_root)
    assert "PRIVATE" not in str(caught.value)
