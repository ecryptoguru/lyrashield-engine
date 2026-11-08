"""No-network tests for authenticated, rejected-catalog diagnostics."""

import gzip
import hashlib
import io
import subprocess
import sys
import tarfile
import zlib

import pytest

from scripts import verify_oci_rejection_drain as drain
from scripts.index_verified_oci_changeset import CatalogUnsafePathError, catalog_path
from scripts.index_verified_oci_stream import worker_failure_category
from scripts.reconstruct_oci_layers import parse_local_pax
from scripts.verify_oci_layer_binding import OCI_GZIP


def valid_tar():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        entry = tarfile.TarInfo("file")
        body = bytes(2 * 1024 * 1024)
        entry.size = len(body)
        archive.addfile(entry, io.BytesIO(body))
    return output.getvalue()


def inputs():
    data = valid_tar()
    compressed = gzip.compress(data)
    return (
        compressed,
        {
            "mediaType": OCI_GZIP,
            "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
            "size": len(compressed),
        },
        "sha256:" + hashlib.sha256(data).hexdigest(),
    )


class TrackingStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.seen = 0

    def read(self, size=-1):
        value = super().read(size)
        self.seen += len(value)
        return value


class Fetch:
    def __init__(self, data, status=0):
        self.stdout = TrackingStream(data)
        self.status = status

    def poll(self):
        return self.status

    def wait(self, timeout=None):  # noqa: ARG002 - matches subprocess protocol
        return self.status

    def kill(self):
        self.status = -9


@pytest.fixture
def root(tmp_path):
    result = tmp_path / "private"
    result.mkdir(mode=0o700)
    return result


def fail_worker(*_args):
    raise ValueError("unsafe path")


def test_drain_reports_fixed_category_only_after_full_verification(root, monkeypatch):
    compressed, descriptor, diff = inputs()
    monkeypatch.setattr(drain, "catalog_forward_layer", fail_worker)
    fetch = Fetch(compressed)
    result = drain.diagnose_fetched_layer(fetch, descriptor, diff, root)
    assert result["category"] == "unsafe-path"
    assert result["scope"] == "authenticated-single-layer-rejection-diagnostic-only"
    assert result["catalogAccepted"] is False and result["releaseQualified"] is False
    assert result["compressedBytes"] == len(compressed)
    assert fetch.stdout.seen == len(compressed)
    assert list(root.iterdir()) == []


def test_unknown_worker_message_is_never_exposed(root, monkeypatch):
    compressed, descriptor, diff = inputs()

    def fail_after_eof(stream, *_args):
        while stream.read(65536):
            pass
        raise ValueError("secret-customer-content")

    monkeypatch.setattr(drain, "catalog_forward_layer", fail_after_eof)
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert result["category"] == "catalog-value-error"
    assert "secret-customer-content" not in str(result)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize(
    "name,kind,target,category",
    [
        ("/private-name", "file", "", "member-file-absolute"),
        ("bad\\private-name", "file", "", "member-file-backslash"),
        ("link", "symlink", "bad\\private-target", "symlink-target-backslash"),
        ("link", "hardlink", "/private-target", "hardlink-target-absolute"),
    ],
)
def test_verified_rejection_subcategory_has_no_archive_content(root, name, kind, target, category):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        entry = tarfile.TarInfo(name)
        if kind == "symlink":
            entry.type = tarfile.SYMTYPE
            entry.linkname = target
        elif kind == "hardlink":
            entry.type = tarfile.LNKTYPE
            entry.linkname = target
        archive.addfile(entry)
    data = output.getvalue()
    compressed = gzip.compress(data)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(data).hexdigest()
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert result["category"] == category
    assert "private-name" not in str(result) and "private-target" not in str(result)
    assert list(root.iterdir()) == []


def test_multiple_unsafe_characters_are_classified_without_content():
    with pytest.raises(CatalogUnsafePathError) as caught:
        catalog_path("/private\\value\x00", "symlink-target")
    assert caught.value.category == "symlink-target-multiple"
    assert "private" not in str(caught.value)


def test_mutated_path_error_category_cannot_leak_content():
    error = CatalogUnsafePathError("member-file", "absolute")
    error.category = "secret-customer-content"
    assert worker_failure_category(error) == "unsafe-path"


def test_unrecognized_or_nonplain_exception_message_remains_generic():
    class UntrustedText(str):
        def __hash__(self):
            raise AssertionError("untrusted message must not be inspected")

    assert worker_failure_category(ValueError("secret-customer-content")) == "catalog-value-error"
    assert (
        worker_failure_category(ValueError(UntrustedText("unsafe path"))) == "catalog-value-error"
    )


@pytest.mark.parametrize(
    "target,category",
    [
        ("private\nvalue", "invalid-symlink-character"),
    ],
)
def test_verified_rejection_reports_only_fixed_validation_reason(root, target, category):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("link")
        entry.type = tarfile.SYMTYPE
        entry.linkname = target
        archive.addfile(entry)
    data = output.getvalue()
    compressed = gzip.compress(data)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(data).hexdigest()
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert result["category"] == category
    assert "private" not in str(result)
    assert result["catalogAccepted"] is False and result["releaseQualified"] is False
    assert not list(root.iterdir())


@pytest.mark.parametrize(
    "name,kind,target,category",
    [
        ("private/../member", "file", "", "member-file-dotdot"),
        ("private/./member", "file", "", "member-file-dot"),
        ("private//member", "file", "", "member-file-empty-component"),
        ("private//../member", "file", "", "member-file-multiple-components"),
        ("link", "hardlink", "private/../target", "hardlink-target-dotdot"),
    ],
)
def test_verified_component_reason_has_fixed_role_without_values(
    root, name, kind, target, category
):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo(name)
        if kind == "symlink":
            entry.type = tarfile.SYMTYPE
            entry.linkname = target
        elif kind == "hardlink":
            entry.type = tarfile.LNKTYPE
            entry.linkname = target
        archive.addfile(entry)
    data = output.getvalue()
    compressed = gzip.compress(data)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(data).hexdigest()
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert result["category"] == category
    assert "private" not in str(result)
    assert result["catalogAccepted"] is False and result["releaseQualified"] is False
    assert not list(root.iterdir())


@pytest.mark.parametrize("failure", ["compressed-digest", "diff", "truncated", "fetch-exit"])
def test_drain_never_returns_category_when_verification_or_fetch_fails(root, monkeypatch, failure):
    compressed, descriptor, diff = inputs()
    status = 0
    monkeypatch.setattr(drain, "catalog_forward_layer", fail_worker)
    if failure == "compressed-digest":
        descriptor["digest"] = "sha256:" + "0" * 64
    elif failure == "diff":
        diff = "sha256:" + "0" * 64
    elif failure == "truncated":
        compressed = compressed[:-3]
    elif failure == "fetch-exit":
        status = 1
    sentinel = root / "unrelated"
    sentinel.write_text("keep")
    with pytest.raises((ValueError, OSError, zlib.error)) as caught:
        drain.diagnose_fetched_layer(Fetch(compressed, status), descriptor, diff, root)
    assert "unsafe-path" not in str(caught.value)
    assert list(root.iterdir()) == [sentinel]


def test_no_rejection_is_not_a_diagnostic_success(root):
    compressed, descriptor, diff = inputs()
    with pytest.raises(ValueError, match="did not reject"):
        drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert list(root.iterdir()) == []


def test_real_producer_failure_after_complete_stream_returns_no_category(root, monkeypatch):
    compressed, descriptor, diff = inputs()
    monkeypatch.setattr(drain, "catalog_forward_layer", fail_worker)
    source = root / "test-owned-source.gz"
    source.write_bytes(compressed)
    code = "import os,sys;os.write(1,open(sys.argv[1],'rb').read());sys.exit(1)"
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and owned fixture
        [sys.executable, "-c", code, str(source)], stdout=subprocess.PIPE
    )
    with pytest.raises(ValueError, match="fetch process failed") as caught:
        drain.diagnose_fetched_layer(process, descriptor, diff, root)
    assert "unsafe-path" not in str(caught.value)
    assert list(root.iterdir()) == [source]


def test_drain_enforces_uncompressed_limit(root, monkeypatch):
    compressed, descriptor, diff = inputs()
    monkeypatch.setattr(drain, "catalog_forward_layer", fail_worker)
    monkeypatch.setattr(drain, "MAX_DRAIN_BYTES", 1024)
    with pytest.raises(ValueError, match="limit"):
        drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert list(root.iterdir()) == []


def test_invalid_root_stops_real_fetch_process(tmp_path):
    _, descriptor, diff = inputs()
    process = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(30)"], stdout=subprocess.PIPE
    )
    with pytest.raises(OSError):
        drain.diagnose_fetched_layer(process, descriptor, diff, tmp_path / "missing")
    assert process.poll() is not None
    assert process.stdout.closed


def pax_record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while len(str(length)) + 1 + len(body) != length:
        length = len(str(length)) + 1 + len(body)
    return str(length).encode() + b" " + body


def synthetic_pax_layer(payload):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        extension = tarfile.TarInfo("synthetic-pax")
        extension.type = tarfile.XHDTYPE
        extension.size = len(payload)
        archive.addfile(extension, io.BytesIO(payload))
        archive.addfile(tarfile.TarInfo("synthetic-file"))
    return output.getvalue()


@pytest.mark.parametrize(
    "payload,category",
    [
        (pax_record(b"path", b"one") + pax_record(b"path", b"two"), "pax-duplicate-supported-key"),
        (
            pax_record(b"SCHILY.xattr.security.capability", b"secret-value"),
            "pax-unsupported-capability-key",
        ),
        (pax_record(b"private-key", b"secret-value"), "pax-unsupported-other-key"),
    ],
)
def test_authenticated_pax_rejection_reason_is_fixed_and_private(root, payload, category):
    data = synthetic_pax_layer(payload)
    compressed = gzip.compress(data)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(data).hexdigest()
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert result["category"] == category
    assert "secret-value" not in str(result) and "private-key" not in str(result)
    assert result["catalogAccepted"] is False and result["releaseQualified"] is False
    assert not list(root.iterdir())


def test_unverified_catalog_report_retains_generic_pax_reason():
    with pytest.raises(ValueError) as caught:
        parse_local_pax(pax_record(b"SCHILY.xattr.security.capability", b"secret"))
    assert worker_failure_category(caught.value) == "unsupported-pax-key"


def test_mutated_authenticated_pax_reason_remains_generic():
    with pytest.raises(ValueError) as caught:
        parse_local_pax(pax_record(b"SCHILY.xattr.security.capability", b"secret"))
    caught.value.reason = "secret-value"
    assert drain.authenticated_worker_failure_category(caught.value) == "unsupported-pax-key"
    del caught.value.reason
    assert drain.authenticated_worker_failure_category(caught.value) == "unsupported-pax-key"


@pytest.mark.parametrize("failure", ["descriptor", "diffid", "fetch"])
def test_specific_pax_reason_never_returned_on_failed_authentication(root, failure):
    data = synthetic_pax_layer(pax_record(b"SCHILY.xattr.security.capability", b"secret"))
    compressed = gzip.compress(data)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(data).hexdigest()
    if failure == "descriptor":
        descriptor["digest"] = "sha256:" + "0" * 64
    if failure == "diffid":
        diff = "sha256:" + "0" * 64
    fetch = Fetch(compressed, status=1 if failure == "fetch" else 0)
    with pytest.raises(ValueError) as caught:
        drain.diagnose_fetched_layer(fetch, descriptor, diff, root)
    assert "pax-unsupported-capability-key" not in str(caught.value)
    assert not list(root.iterdir())
