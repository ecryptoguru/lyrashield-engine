"""Synthetic producer and consumer failures for the private streaming catalog."""

import base64
import gzip
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
import tarfile
import time
import zlib

import pytest

from scripts import index_verified_oci_stream as stream_catalog
from scripts.index_verified_oci_stream import catalog_fetched_layer
from scripts.verify_oci_layer_binding import OCI_GZIP


def tar(name="file"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        entry = tarfile.TarInfo(name)
        entry.size = 5
        archive.addfile(entry, io.BytesIO(b"hello"))
    return output.getvalue()


def inputs(data):
    compressed = gzip.compress(data)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(data).hexdigest()
    return compressed, descriptor, diff


class Fetch:
    def __init__(self, data, status=0):
        self.stdout = io.BytesIO(data)
        self.status = status

    def wait(self, timeout=None):  # noqa: ARG002 - matches subprocess protocol
        return self.status

    def poll(self):
        return self.status

    def kill(self):
        self.status = -9


@pytest.fixture
def root(tmp_path):
    result = tmp_path / "private"
    result.mkdir(mode=0o700)
    return result


def test_success_requires_verified_stream_and_zero_fetch_exit(root):
    data = tar()
    compressed, descriptor, diff = inputs(data)
    result = catalog_fetched_layer(Fetch(compressed), descriptor, diff, root)
    path = root / result["privateStage"] / result["privateChild"] / "catalog.sqlite3"
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        name, offset, size = db.execute("SELECT path,offset,size FROM entries").fetchone()
    assert name == "file" and data[offset : offset + size] == b"hello"
    assert result["sourceRetained"] is False
    assert result["finalImageVerified"] is False
    assert result["releaseQualified"] is False


@pytest.mark.parametrize("failure", ["digest", "diff", "truncated", "fetch-exit", "bad-entry"])
def test_any_producer_or_catalog_failure_removes_only_own_stage(root, failure):
    data = tar("../escape" if failure == "bad-entry" else "file")
    compressed, descriptor, diff = inputs(data)
    status = 0
    if failure == "digest":
        descriptor["digest"] = "sha256:" + "0" * 64
    elif failure == "diff":
        diff = "sha256:" + "0" * 64
    elif failure == "truncated":
        compressed = compressed[:-3]
    elif failure == "fetch-exit":
        status = 1
    sentinel = root / "unrelated"
    sentinel.write_text("keep")
    with pytest.raises((ValueError, OSError, EOFError, tarfile.TarError)):
        catalog_fetched_layer(Fetch(compressed, status), descriptor, diff, root)
    assert list(root.iterdir()) == [sentinel]
    assert sentinel.read_text() == "keep"


def test_real_producer_exit_failure_after_complete_bytes_is_rejected(root):
    data = tar()
    compressed, descriptor, diff = inputs(data)
    payload = root / "test-owned-source.gz"
    payload.write_bytes(compressed)
    code = "import os,sys;os.write(1,open(sys.argv[1],'rb').read());sys.exit(1)"
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test-owned fixture
        [sys.executable, "-c", code, str(payload)], stdout=subprocess.PIPE
    )
    with pytest.raises(ValueError, match="fetch process failed"):
        catalog_fetched_layer(process, descriptor, diff, root)
    assert list(root.iterdir()) == [payload]


def test_pipe_failure_reports_safe_worker_category_without_private_exception(root, monkeypatch):
    data = tar() + bytes(2 * 1024 * 1024)
    compressed, descriptor, diff = inputs(data)

    def fail_early(*_args):
        raise ValueError("unsupported tar type or extension")

    monkeypatch.setattr(stream_catalog, "catalog_forward_layer", fail_early)
    with pytest.raises(stream_catalog.CatalogWorkerError) as caught:
        catalog_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert caught.value.category == "unsupported-tar-type"
    assert not list(root.iterdir())


def test_worker_failure_redacts_unrecognized_message(root, monkeypatch):
    data = tar() + bytes(2 * 1024 * 1024)
    compressed, descriptor, diff = inputs(data)

    def fail_early(*_args):
        raise ValueError("secret-customer-content")

    monkeypatch.setattr(stream_catalog, "catalog_forward_layer", fail_early)
    with pytest.raises(stream_catalog.CatalogWorkerError) as caught:
        catalog_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert caught.value.category == "catalog-value-error"
    assert "secret-customer-content" not in str(caught.value)
    assert not list(root.iterdir())


def test_worker_failure_after_complete_stream_is_sanitized(root, monkeypatch):
    compressed, descriptor, diff = inputs(tar())

    def fail_at_eof(stream, *_args):
        while stream.read(65536):
            pass
        raise ValueError("secret-customer-content")

    monkeypatch.setattr(stream_catalog, "catalog_forward_layer", fail_at_eof)
    with pytest.raises(stream_catalog.CatalogWorkerError) as caught:
        catalog_fetched_layer(Fetch(compressed), descriptor, diff, root)
    assert caught.value.category == "catalog-value-error"
    assert "secret-customer-content" not in str(caught.value)
    assert not list(root.iterdir())


def test_complete_bytes_are_only_provisional_until_fetch_exit(root):
    data = tar()
    compressed, descriptor, diff = inputs(data)

    class InspectFetch(Fetch):
        def wait(self, timeout=None):  # noqa: ARG002 - subprocess protocol
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                provisional = list(root.glob("stream-*/catalog-*/provisional.sqlite3"))
                if provisional:
                    break
                time.sleep(0.01)
            assert provisional
            assert not list(root.glob("stream-*/catalog-*/catalog.sqlite3"))
            return 1

    with pytest.raises(ValueError, match="fetch process failed"):
        catalog_fetched_layer(InspectFetch(compressed), descriptor, diff, root)
    assert not list(root.iterdir())


@pytest.mark.parametrize("kind", ["missing", "symlink"])
def test_invalid_root_stops_real_fetch_child_and_closes_pipe(tmp_path, kind):
    data = tar()
    _, descriptor, diff = inputs(data)
    invalid = tmp_path / "missing"
    if kind == "symlink":
        existing = tmp_path / "existing"
        existing.mkdir(mode=0o700)
        invalid.symlink_to(existing, target_is_directory=True)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(30)"], stdout=subprocess.PIPE
    )
    with pytest.raises(OSError):
        catalog_fetched_layer(process, descriptor, diff, invalid)
    assert process.poll() is not None
    assert process.stdout.closed


@pytest.mark.parametrize("phase", ["before-link", "after-link"])
def test_killed_publication_leaves_no_success_receipt(root, phase):
    compressed, descriptor, diff = inputs(tar())
    code = r"""
import base64, io, json, os, sys, time
from pathlib import Path
from scripts.index_verified_oci_stream import catalog_fetched_layer
root=Path(sys.argv[1]); phase=sys.argv[2]; raw=base64.b64decode(sys.argv[3])
descriptor=json.loads(sys.argv[4]); diff=sys.argv[5]; original=os.link
def barrier(*args, **kwargs):
    if phase == 'after-link': original(*args, **kwargs)
    (root/'ready').write_text('ready')
    time.sleep(30)
    if phase == 'before-link': original(*args, **kwargs)
os.link=barrier
class Fetch:
    stdout=io.BytesIO(raw)
    def poll(self): return 0
    def wait(self,timeout=None): return 0
    def kill(self): pass
catalog_fetched_layer(Fetch(),descriptor,diff,root)
(root/'success-receipt').write_text('success')
"""
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test-owned inputs
        [
            sys.executable,
            "-c",
            code,
            str(root),
            phase,
            base64.b64encode(compressed).decode(),
            json.dumps(descriptor),
            diff,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while (
            not (root / "ready").exists() and process.poll() is None and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert (root / "ready").exists()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    assert not (root / "success-receipt").exists()
    assert list(root.glob("stream-*/catalog-*/provisional.sqlite3"))
    assert bool(list(root.glob("stream-*/catalog-*/catalog.sqlite3"))) == (phase == "after-link")


def test_streams_synthetic_layer_above_in_memory_limit_without_retaining_tar(root):
    size = 129 * 1024 * 1024
    header = tarfile.TarInfo("large")
    header.size = size
    compressor = zlib.compressobj(wbits=31)
    sha = hashlib.sha256()
    compressed = io.BytesIO()

    def add(data):
        sha.update(data)
        compressed.write(compressor.compress(data))

    add(header.tobuf(format=tarfile.USTAR_FORMAT))
    chunk = bytes(1024 * 1024)
    for _ in range(size // len(chunk)):
        add(chunk)
    add(bytes(1024))
    compressed.write(compressor.flush())
    raw = compressed.getvalue()
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    result = catalog_fetched_layer(Fetch(raw), descriptor, "sha256:" + sha.hexdigest(), root)
    assert result["uncompressedBytes"] == size + 1536
    stage = root / result["privateStage"] / result["privateChild"]
    assert [entry.name for entry in stage.iterdir()] == ["catalog.sqlite3"]
