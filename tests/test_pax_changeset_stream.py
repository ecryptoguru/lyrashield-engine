"""Synthetic single-layer streamed changeset security checks."""

import gzip
import hashlib
import inspect as inspect_module
import io
import subprocess
import sys
import tarfile
import traceback

import pytest

from scripts import verify_pax_capability_stream as verify
from scripts.verify_oci_layer_binding import OCI_GZIP


PRIVATE_PATH = "private-customer-name"
PRIVATE_VALUE = b"private-opaque-capability"


@pytest.fixture
def private_root(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(verify, "free_space", lambda _fd: 10 * 1024**3)
    return root


def record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + len(body) + 1 != size:
        size = len(str(size)) + len(body) + 1
    return str(size).encode() + b" " + body


def synthetic_layer():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        pax = record(b"path", PRIVATE_PATH.encode()) + record(
            b"SCHILY.xattr.security.capability", PRIVATE_VALUE
        )
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = len(pax)
        archive.addfile(header, io.BytesIO(pax))
        member = tarfile.TarInfo("placeholder")
        member.size = 3
        archive.addfile(member, io.BytesIO(b"abc"))
        archive.addfile(tarfile.TarInfo("later-member"))
    uncompressed = raw.getvalue()
    compressed = gzip.compress(uncompressed)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    return compressed, descriptor, "sha256:" + hashlib.sha256(uncompressed).hexdigest()


def descriptor_for_raw(raw):
    compressed = gzip.compress(raw)
    return (
        compressed,
        {
            "mediaType": OCI_GZIP,
            "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
            "size": len(compressed),
        },
        "sha256:" + hashlib.sha256(raw).hexdigest(),
    )


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


def inspect(fetch, descriptor, diff_id, root, **kwargs):
    fn = getattr(verify, "inspect_fetched_changeset", None)
    assert fn is not None, "expected verified in-memory changeset stream"
    return fn(fetch, descriptor, diff_id, root, **kwargs)


def test_verified_changeset_is_only_returned_after_fetch_and_cleanup(private_root):
    compressed, descriptor, diff = synthetic_layer()
    fetch = Fetch(compressed)
    result = inspect(fetch, descriptor, diff, private_root)
    assert result.descriptor_digest == descriptor["digest"] and result.diff_id == diff
    assert [member.path for member in result.members] == [PRIVATE_PATH, "later-member"]
    assert result.members[0].capability_value == PRIVATE_VALUE
    assert fetch.stdout.closed and not list(private_root.iterdir())
    assert PRIVATE_PATH not in repr(result) and PRIVATE_VALUE.decode() not in repr(result)
    assert result.final_image_verified is False and result.release_qualified is False


@pytest.mark.parametrize("failure", ["digest", "size", "diffid", "truncated", "producer"])
def test_failed_verification_or_producer_never_returns_sensitive_records(private_root, failure):
    compressed, descriptor, diff = synthetic_layer()
    if failure == "digest":
        descriptor["digest"] = "sha256:" + "0" * 64
    elif failure == "size":
        descriptor["size"] += 1
    elif failure == "diffid":
        diff = "sha256:" + "0" * 64
    elif failure == "truncated":
        compressed = compressed[:-3]
    fetch = Fetch(compressed, status=1 if failure == "producer" else 0)
    with pytest.raises(ValueError) as caught:
        inspect(fetch, descriptor, diff, private_root)
    formatted = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    assert PRIVATE_PATH not in formatted and PRIVATE_VALUE.decode() not in formatted
    assert fetch.stdout.closed and not list(private_root.iterdir())


def test_failed_cleanup_suppresses_even_a_fully_verified_changeset(private_root):
    class BadCleanup(Fetch):
        def poll(self):
            raise RuntimeError(PRIVATE_PATH)

    compressed, descriptor, diff = synthetic_layer()
    fetch = BadCleanup(compressed)
    with pytest.raises(ValueError, match="cleanup") as caught:
        inspect(fetch, descriptor, diff, private_root)
    assert PRIVATE_PATH not in str(caught.value)
    assert fetch.killed and fetch.stdout.closed


def test_record_count_and_record_byte_budgets_fail_closed(private_root, monkeypatch):
    compressed, descriptor, diff = synthetic_layer()
    monkeypatch.setattr(verify, "MAX_CHANGESET_RECORDS", 1, raising=False)
    with pytest.raises(ValueError):
        inspect(Fetch(compressed), descriptor, diff, private_root)
    monkeypatch.setattr(verify, "MAX_CHANGESET_RECORDS", 100_000, raising=False)
    monkeypatch.setattr(verify, "MAX_CHANGESET_RECORD_BYTES", 1, raising=False)
    with pytest.raises(ValueError):
        inspect(Fetch(compressed), descriptor, diff, private_root)


def test_caller_uncompressed_budget_is_enforced_during_verified_stream(private_root):
    assert (
        "max_uncompressed_bytes"
        in inspect_module.signature(verify.inspect_fetched_changeset).parameters
    )
    compressed, descriptor, diff = synthetic_layer()
    fetch = Fetch(compressed)
    with pytest.raises(ValueError, match="incomplete"):
        inspect(fetch, descriptor, diff, private_root, max_uncompressed_bytes=512)
    assert fetch.stdout.closed


@pytest.mark.parametrize("budget", [True, 0, -1, 1.0, verify.MAX_LAYER_BYTES + 1])
def test_caller_uncompressed_budget_requires_a_bounded_positive_integer(private_root, budget):
    compressed, descriptor, diff = synthetic_layer()
    fetch = Fetch(compressed)
    with pytest.raises(ValueError, match="incomplete"):
        inspect(fetch, descriptor, diff, private_root, max_uncompressed_bytes=budget)
    assert fetch.stdout.closed


@pytest.mark.parametrize("deadline", [0, True, float("nan"), float("inf"), "later"])
def test_caller_deadline_must_be_finite_and_not_expired(private_root, deadline):
    assert (
        "absolute_deadline" in inspect_module.signature(verify.inspect_fetched_changeset).parameters
    )
    compressed, descriptor, diff = synthetic_layer()
    fetch = Fetch(compressed)
    with pytest.raises(ValueError, match="incomplete"):
        inspect(fetch, descriptor, diff, private_root, absolute_deadline=deadline)
    assert fetch.stdout.closed


def test_matching_bytes_do_not_make_malformed_tar_framing_valid(private_root):
    compressed, _descriptor, _diff = synthetic_layer()
    raw = gzip.decompress(compressed)[:-512] + b"x" * 512
    compressed, descriptor, diff = descriptor_for_raw(raw)
    with pytest.raises(ValueError, match="incomplete"):
        inspect(Fetch(compressed), descriptor, diff, private_root)


def test_linux_literal_policy_is_explicit_and_does_not_expose_path(private_root):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(tarfile.TarInfo("private\\member"))
    compressed, descriptor, diff = descriptor_for_raw(output.getvalue())
    with pytest.raises(ValueError, match="incomplete"):
        inspect(Fetch(compressed), descriptor, diff, private_root)
    result = inspect(Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True)
    assert result.path_policy == "linux-literal" and result.members[0].path == "private\\member"
    assert "private" not in repr(result)
    with pytest.raises(ValueError, match="incomplete"):
        inspect(Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=1)


def test_untrusted_root_fails_closed_and_closes_fetch(private_root):
    compressed, descriptor, diff = synthetic_layer()
    private_root.chmod(0o755)
    fetch = Fetch(compressed)
    with pytest.raises(ValueError, match="incomplete"):
        inspect(fetch, descriptor, diff, private_root)
    assert fetch.stdout.closed


def test_real_local_fetch_is_waited_and_closed(private_root):
    compressed, descriptor, diff = synthetic_layer()
    fetch = subprocess.Popen(  # noqa: S603 - fixed interpreter and generated synthetic fixture
        [
            sys.executable,
            "-c",
            f"import sys;sys.stdout.buffer.write(bytes.fromhex('{compressed.hex()}'))",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        result = inspect(fetch, descriptor, diff, private_root)
        assert len(result.members) == 2 and fetch.poll() == 0 and fetch.stdout.closed
    finally:
        if fetch.poll() is None:
            fetch.kill()
        fetch.wait(timeout=10)
        if fetch.stdout:
            fetch.stdout.close()
