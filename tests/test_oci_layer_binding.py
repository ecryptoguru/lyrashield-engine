"""Offline manifest-to-layer binding; no filesystem reconstruction or release trust."""

import gzip
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_oci_layer_binding.py"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_TAR = "application/vnd.oci.image.layer.v1.tar"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def archive(name, content):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return stream.getvalue()


class Layout:
    def __init__(self, directory, docker=False, uncompressed=False):
        self.path = directory
        self.path.mkdir()
        self.manifest_type = DOCKER_MANIFEST if docker else OCI_MANIFEST
        self.config_type = DOCKER_CONFIG if docker else OCI_CONFIG
        self.layer_type = DOCKER_GZIP if docker else OCI_TAR if uncompressed else OCI_GZIP
        self.layers = []
        self.diff_ids = []
        for index in range(2):
            raw = archive(f"file-{index}", bytes([index]) * 23)
            data = raw if uncompressed else gzip.compress(raw, mtime=0)
            self.layers.append(self.descriptor(data, self.layer_type))
            self.diff_ids.append(sha(raw))
        self.config = {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": self.diff_ids},
        }

    def blob(self, data):
        digest = sha(data)
        (self.path / digest[7:]).write_bytes(data)
        return digest

    def descriptor(self, data, media):
        return {"mediaType": media, "digest": self.blob(data), "size": len(data)}

    def manifest(self, *, config_data=None, layers=None, media=None):
        config_data = config_data if config_data is not None else json.dumps(self.config).encode()
        doc = {
            "schemaVersion": 2,
            "mediaType": media or self.manifest_type,
            "config": self.descriptor(config_data, self.config_type),
            "layers": self.layers if layers is None else layers,
        }
        return self.blob(json.dumps(doc).encode())

    def run(self, manifest, platform="linux/amd64"):
        return subprocess.run(  # noqa: S603 - fixed local interpreter and script
            [
                sys.executable,
                str(SCRIPT),
                "--blob-dir",
                str(self.path),
                "--manifest-digest",
                manifest,
                "--platform",
                platform,
            ],
            text=True,
            capture_output=True,
            check=False,
        )


@pytest.mark.parametrize("docker,uncompressed", [(False, False), (False, True), (True, False)])
def test_binds_exact_manifest_config_and_ordered_layer_bytes(tmp_path, docker, uncompressed):
    layout = Layout(tmp_path / "blobs", docker, uncompressed)
    digest = layout.manifest()
    result = layout.run(digest)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["manifestDigest"] == digest
    assert report["platform"] == "linux/amd64"
    assert [entry["diffId"] for entry in report["layers"]] == layout.diff_ids
    assert report["scope"] == "offline_layer_binding_only"


@pytest.mark.parametrize(
    "mutation",
    [
        "layer_bytes",
        "layer_size",
        "wrong_diff",
        "swapped_layers",
        "wrong_arch",
        "unsupported_layer",
        "wrong_config_type",
        "duplicate_config",
        "bool_size",
        "gzip_trailing",
        "truncated_gzip",
        "wrong_manifest",
        "symlink_layer",
    ],
)
def test_rejects_unbound_unsupported_or_ambiguous_inputs(tmp_path, mutation):  # noqa: PLR0912
    layout = Layout(tmp_path / "blobs")
    layers = [entry.copy() for entry in layout.layers]
    config_data = None
    if mutation == "layer_bytes":
        (layout.path / layers[0]["digest"][7:]).write_bytes(b"tampered")
    elif mutation == "layer_size":
        layers[0]["size"] += 1
    elif mutation == "wrong_diff":
        layout.config["rootfs"]["diff_ids"][0] = sha(b"different")
    elif mutation == "swapped_layers":
        layers.reverse()
    elif mutation == "wrong_arch":
        layout.config["architecture"] = "arm64"
    elif mutation == "unsupported_layer":
        layers[0]["mediaType"] = "application/vnd.oci.image.layer.v1.tar+zstd"
    elif mutation == "wrong_config_type":
        layout.config_type = DOCKER_CONFIG
    elif mutation == "duplicate_config":
        config_data = (
            b'{"os":"linux","os":"windows","architecture":"amd64",'
            b'"rootfs":{"type":"layers","diff_ids":[]}}'
        )
    elif mutation == "bool_size":
        layers[0]["size"] = True
    elif mutation in {"gzip_trailing", "truncated_gzip"}:
        data = (layout.path / layers[0]["digest"][7:]).read_bytes()
        data = data + b"junk" if mutation == "gzip_trailing" else data[:-4]
        layers[0] = layout.descriptor(data, OCI_GZIP)
    elif mutation == "symlink_layer":
        target = layout.path / layers[0]["digest"][7:]
        moved = layout.path / "actual"
        target.rename(moved)
        target.symlink_to(moved)
    digest = layout.manifest(config_data=config_data, layers=layers)
    if mutation == "wrong_manifest":
        (layout.path / digest[7:]).write_bytes(b"{}")
    result = layout.run(digest)
    assert result.returncode != 0
    assert result.stdout == ""
    expected_error = {
        "layer_size": "layer size mismatch",
        "wrong_diff": "layer diff ID mismatch",
        "swapped_layers": "layer diff ID mismatch",
        "wrong_arch": "image platform mismatch",
        "unsupported_layer": "unsupported descriptor media type",
        "wrong_config_type": "unsupported descriptor media type",
        "duplicate_config": "duplicate JSON key",
        "bool_size": "invalid descriptor size",
        "gzip_trailing": "gzip trailing data unsupported",
        "truncated_gzip": "incomplete gzip stream",
        "wrong_manifest": "metadata digest mismatch",
    }
    if mutation in expected_error:
        assert expected_error[mutation] in result.stderr


def test_missing_blob_is_failure(tmp_path):
    layout = Layout(tmp_path / "blobs")
    digest = layout.manifest()
    (layout.path / layout.layers[0]["digest"][7:]).unlink()
    result = layout.run(digest)
    assert result.returncode != 0
    assert result.stdout == ""


def test_rejects_gzip_concatenation_even_when_bound(tmp_path):
    layout = Layout(tmp_path / "blobs")
    raw = archive("x", b"one")
    combined = gzip.compress(raw, mtime=0) + gzip.compress(raw, mtime=0)
    layout.layers[0] = layout.descriptor(combined, OCI_GZIP)
    layout.diff_ids[0] = sha(raw + raw)
    result = layout.run(layout.manifest())
    assert result.returncode != 0
    assert result.stdout == ""


def test_streams_large_gzip_output_in_bounded_chunks(tmp_path):
    layout = Layout(tmp_path / "blobs")
    raw = archive("large", b"a" * (4 * 1024 * 1024))
    layout.layers[0] = layout.descriptor(gzip.compress(raw, mtime=0), OCI_GZIP)
    layout.diff_ids[0] = sha(raw)
    result = layout.run(layout.manifest())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["layers"][0]["diffId"] == sha(raw)


def test_accepts_arm64_v8_when_requested(tmp_path):
    layout = Layout(tmp_path / "blobs")
    layout.config["architecture"] = "arm64"
    layout.config["variant"] = "v8"
    result = layout.run(layout.manifest(), platform="linux/arm64")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["platform"] == "linux/arm64"


def test_rejects_expansion_beyond_layer_budget(tmp_path):
    layout = Layout(tmp_path / "blobs")
    raw = archive("large", b"a" * 200_000)
    data = gzip.compress(raw, mtime=0)
    descriptor = layout.descriptor(data, OCI_GZIP)
    module = runpy.run_path(str(SCRIPT))
    verify_layer = module["verify_layer"]
    verify_layer.__globals__["MAX_LAYER"] = 32_000
    directory = os.open(layout.path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="uncompressed layer byte limit"):
            verify_layer(directory, descriptor, sha(raw), 0)
    finally:
        os.close(directory)


def test_rejects_symlink_blob_directory(tmp_path):
    layout = Layout(tmp_path / "blobs")
    digest = layout.manifest()
    alias = tmp_path / "alias"
    alias.symlink_to(layout.path, target_is_directory=True)
    layout.path = alias
    result = layout.run(digest)
    assert result.returncode != 0
    assert result.stdout == ""


def test_rejects_tampered_config_blob(tmp_path):
    layout = Layout(tmp_path / "blobs")
    digest = layout.manifest()
    manifest = json.loads((layout.path / digest[7:]).read_bytes())
    config_path = layout.path / manifest["config"]["digest"][7:]
    config_path.write_bytes(config_path.read_bytes().replace(b"amd64", b"arm64"))
    result = layout.run(digest)
    assert result.returncode != 0
    assert result.stdout == ""


def test_rejects_aggregate_uncompressed_limit(tmp_path):
    layout = Layout(tmp_path / "blobs")
    module = runpy.run_path(str(SCRIPT))
    verify_layer = module["verify_layer"]
    verify_layer.__globals__["MAX_TOTAL"] = 10_000
    directory = os.open(layout.path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="uncompressed layer byte limit"):
            verify_layer(directory, layout.layers[0], layout.diff_ids[0], 1)
    finally:
        os.close(directory)
