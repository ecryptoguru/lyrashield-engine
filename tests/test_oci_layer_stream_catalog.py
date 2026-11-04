"""Synthetic producer and consumer failures for the private streaming catalog."""

import gzip
import hashlib
import io
import sqlite3
import subprocess
import sys
import tarfile

import pytest

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
