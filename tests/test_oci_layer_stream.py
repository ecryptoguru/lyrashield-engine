"""Test streaming layer integrity without retaining the compressed blob."""

import gzip
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import verify_oci_layer_binding as binding


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_oci_layer_stream.py"
GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
TAR = "application/vnd.oci.image.layer.v1.tar"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def invoke(data, *, expected=None, diff=None, size=None, media=GZIP):
    raw = b"known uncompressed layer bytes"
    return subprocess.run(  # noqa: S603 - fixed local interpreter and script
        [
            sys.executable,
            str(SCRIPT),
            "--digest",
            expected or sha(data),
            "--size",
            str(len(data) if size is None else size),
            "--diff-id",
            diff or sha(raw),
            "--media-type",
            media,
        ],
        input=data,
        capture_output=True,
        check=False,
    )


def test_streams_gzip_and_reports_exact_integrity():
    raw = b"known uncompressed layer bytes"
    data = gzip.compress(raw, mtime=0)
    result = invoke(data)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["scope"] == "single_layer_integrity_only"
    assert report["diffId"] == sha(raw)
    assert report["uncompressedSize"] == len(raw)


def test_streams_plain_bytes():
    raw = b"known uncompressed layer bytes"
    result = invoke(raw, media=TAR)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["uncompressedSize"] == len(raw)


@pytest.mark.parametrize(
    "kind",
    ["truncated", "extra", "wrong_digest", "wrong_diff", "wrong_size", "unsupported", "bad_gzip"],
)
def test_rejects_corruption_and_unsupported_streams(kind):
    raw = b"known uncompressed layer bytes"
    data = gzip.compress(raw, mtime=0)
    kwargs = {}
    if kind == "truncated":
        data = data[:-1]
    elif kind == "extra":
        data += b"junk"
    elif kind == "wrong_digest":
        kwargs["expected"] = sha(b"other")
    elif kind == "wrong_diff":
        kwargs["diff"] = sha(b"other")
    elif kind == "wrong_size":
        kwargs["size"] = len(data) + 1
    elif kind == "unsupported":
        kwargs["media"] = "application/vnd.oci.image.layer.v1.tar+zstd"
    else:
        data = b"not a gzip stream"
    result = invoke(data, **kwargs)
    assert result.returncode != 0
    assert result.stdout == b""


def test_rejects_decompression_expansion_limit(monkeypatch):
    raw = b"a" * 10_000
    data = gzip.compress(raw, mtime=0)
    item = {"mediaType": GZIP, "size": len(data), "digest": sha(data)}
    monkeypatch.setattr(binding, "MAX_LAYER", 1000)
    with pytest.raises(ValueError, match="uncompressed layer byte limit"):
        binding.verify_layer_stream(io.BytesIO(data), item, sha(raw), 0)


@pytest.mark.parametrize("size", ["0", "-1", "+1", "01", "17179869185", "9" * 200])
def test_rejects_invalid_or_excessive_descriptor_size(size):
    raw = b"known uncompressed layer bytes"
    data = gzip.compress(raw, mtime=0)
    result = invoke(data, size=size)
    assert result.returncode != 0
    assert result.stdout == b""


def test_rejects_concatenated_gzip_with_matching_hashes():
    raw = b"known uncompressed layer bytes"
    data = gzip.compress(raw, mtime=0) + gzip.compress(raw, mtime=0)
    result = invoke(data, diff=sha(raw + raw))
    assert result.returncode != 0
    assert result.stdout == b""


def test_short_reads_are_verified_correctly():
    raw = b"known uncompressed layer bytes"
    data = gzip.compress(raw, mtime=0)

    class ShortReader(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 3))

    item = {"mediaType": GZIP, "size": len(data), "digest": sha(data)}
    result, total = binding.verify_layer_stream(ShortReader(data), item, sha(raw), 0)
    assert result["diffId"] == sha(raw)
    assert total == len(raw)


def test_rejects_reader_returning_more_than_requested(monkeypatch):
    class UnboundedReader:
        def read(self, _size):
            return b"x" * 11

    monkeypatch.setattr(binding, "CHUNK", 10)
    item = {"mediaType": TAR, "size": 11, "digest": sha(b"x" * 11)}
    with pytest.raises(ValueError, match="bounded binary stream"):
        binding.verify_layer_stream(UnboundedReader(), item, sha(b"x" * 11), 0)


def test_deadline_interrupts_blocked_pipe():
    code = (
        "import sys; sys.path.insert(0, sys.argv.pop(1)); "
        "import verify_oci_layer_stream as s; s.MAX_SECONDS=1; s.main()"
    )
    command = [
        sys.executable,
        "-c",
        code,
        str(SCRIPT.parent),
        "--digest",
        sha(b"x"),
        "--size",
        "1",
        "--diff-id",
        sha(b"x"),
        "--media-type",
        TAR,
    ]
    process = subprocess.Popen(  # noqa: S603 - fixed local interpreter and script
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        process.wait(timeout=5)
        stdout, stderr = process.communicate()
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert process.returncode != 0
    assert stdout == b""
    assert b"processing deadline exceeded" in stderr
