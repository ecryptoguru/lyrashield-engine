"""Synthetic ordered-stream checks; no network, registry or release access."""

import gzip
import importlib
import importlib.util
import io
import json
import subprocess
import sys
import time
import traceback

import pytest

from scripts import verify_pax_capability_stream as verify
from scripts.verify_oci_layer_binding import OCI_CONFIG, OCI_GZIP, OCI_MANIFEST
from tests.test_oci_metadata_overlay import CAP_VALUE, digest, layer


@pytest.fixture
def private_root(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(verify, "free_space", lambda _fd: 10 * 1024**3)
    monkeypatch.setattr(api(), "free_space", lambda _fd: 10 * 1024**3)
    return root


def api():
    name = "scripts.stream_oci_metadata_overlay"
    assert importlib.util.find_spec(name), "expected ordered streamed metadata model"
    return importlib.import_module(name)


def fixture(raw_layers, *, architecture="amd64", diff_ids=None):
    data = [gzip.compress(raw, mtime=0) for raw in raw_layers]
    descriptors = [
        {"mediaType": OCI_GZIP, "digest": digest(blob), "size": len(blob)} for blob in data
    ]
    config = json.dumps(
        {
            "architecture": architecture,
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": diff_ids or [digest(raw) for raw in raw_layers],
            },
        },
        separators=(",", ":"),
    ).encode()
    return make_manifest(config, descriptors), config, data


def make_manifest(config, layers):
    obj = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": digest(config), "size": len(config)},
        "layers": layers,
    }
    return json.dumps(obj, separators=(",", ":")).encode()


class Fetch:
    def __init__(self, data, status=0, bad_cleanup=False):
        self.stdout = io.BytesIO(data)
        self.status = status
        self.bad_cleanup = bad_cleanup
        self.killed = False

    def poll(self):
        if self.bad_cleanup:
            raise RuntimeError("PRIVATE-CLEANUP")
        return self.status

    def wait(self, timeout=None):  # noqa: ARG002
        return self.status

    def kill(self):
        self.killed = True
        self.status = -9


class Factory:
    def __init__(self, blobs, *, reverse=False, bad_status=None, bad_cleanup=None):
        self.blobs = blobs
        self.reverse = reverse
        self.bad_status = bad_status
        self.bad_cleanup = bad_cleanup
        self.calls = []
        self.fetches = []

    def __call__(self, ordinal, descriptor):
        self.calls.append((ordinal, descriptor["digest"]))
        blob = self.blobs[-ordinal - 1] if self.reverse else self.blobs[ordinal]
        fetch = Fetch(
            blob,
            status=1 if ordinal == self.bad_status else 0,
            bad_cleanup=ordinal == self.bad_cleanup,
        )
        self.fetches.append(fetch)
        return fetch


def run(manifest, config, factory, root, platform="linux/amd64", **kwargs):
    return api().model_fetched_image(
        manifest, digest(manifest), config, platform, factory, root, **kwargs
    )


def test_ordered_streams_stage_only_after_binding_and_hide_sensitive_records(private_root):
    first = layer(
        [
            ("private-dir", "dir", None, None),
            ("private-dir/file", "file", b"contents", CAP_VALUE),
            ("private-dir/alias", "hardlink", "private-dir/file", None),
        ]
    )
    second = layer([("private-dir/.wh.file", "file", b"", None)])
    manifest, config, blobs = fixture([first, second])
    factory = Factory(blobs)
    result = run(manifest, config, factory, private_root)
    assert [ordinal for ordinal, _ in factory.calls] == [0, 1]
    assert "private-dir/file" not in result.entries
    assert result.entries["private-dir/alias"].inode.capability_state == "unknown"
    assert result.entries["private-dir/alias"].inode.capability_header == CAP_VALUE
    assert result.source_authenticated is False
    assert result.runtime_equivalent is False and result.release_qualified is False
    assert "private" not in repr(result) and all(fetch.stdout.closed for fetch in factory.fetches)
    assert not list(private_root.iterdir())


def test_repeated_identical_layers_keep_their_ordinals(private_root):
    raw = layer([("file", "file", b"same", None)])
    manifest, config, blobs = fixture([raw, raw])
    factory = Factory(blobs)
    result = run(manifest, config, factory, private_root)
    assert [ordinal for ordinal, _ in factory.calls] == [0, 1]
    assert result.layers[0] == result.layers[1]
    assert result.entries["file"].inode.source_layer == 1


def test_arm64_platform_is_bound_but_not_claimed_as_authenticated(private_root):
    raw = layer([("a\\b", "file", b"data", None)])
    manifest, config, blobs = fixture([raw], architecture="arm64")
    result = run(
        manifest,
        config,
        Factory(blobs),
        private_root,
        platform="linux/arm64",
        linux_literal_paths=True,
    )
    assert result.platform == "linux/arm64" and "a\\b" in result.entries
    assert result.source_authenticated is False and result.release_qualified is False


def test_fetch_factory_cannot_mutate_bound_descriptor(private_root):
    raw = layer([("file", "file", b"same", None)])
    manifest, config, blobs = fixture([raw])

    def fetch(ordinal, descriptor):
        assert ordinal == 0
        with pytest.raises(TypeError):
            descriptor["digest"] = "sha256:" + "0" * 64
        return Fetch(blobs[0])

    assert run(manifest, config, fetch, private_root).entries["file"].inode.source_layer == 0


def test_wrong_layer_order_fails_without_returning_a_partial_model(private_root):
    first = layer([("a", "file", b"one", None)])
    second = layer([("b", "file", b"two", None)])
    manifest, config, blobs = fixture([first, second])
    factory = Factory(blobs, reverse=True)
    with pytest.raises(ValueError, match="incomplete"):
        run(manifest, config, factory, private_root)
    assert [ordinal for ordinal, _ in factory.calls] == [0]
    assert factory.fetches[0].stdout.closed


def test_metadata_or_wrong_platform_failure_happens_before_any_fetch(private_root):
    manifest, config, blobs = fixture([layer([("file", "file", b"x", None)])])
    for candidate, expected, cfg, platform in [
        (manifest, "sha256:" + "0" * 64, config, "linux/amd64"),
        (manifest, digest(manifest), config + b" ", "linux/amd64"),
        (manifest, digest(manifest), config, "linux/arm64"),
        (manifest, digest(manifest), config, "windows/amd64"),
    ]:
        factory = Factory(blobs)
        with pytest.raises(ValueError):
            api().model_fetched_image(candidate, expected, cfg, platform, factory, private_root)
        assert factory.calls == []


def test_manifest_compressed_budget_is_checked_before_fetch(private_root, monkeypatch):
    manifest, config, blobs = fixture([layer([("file", "file", b"x", None)])])
    monkeypatch.setattr(api(), "MAX_IMAGE_COMPRESSED_BYTES", len(blobs[0]) - 1, raising=False)
    factory = Factory(blobs)
    with pytest.raises(ValueError):
        run(manifest, config, factory, private_root)
    assert factory.calls == []


def test_duplicate_manifest_key_and_external_layer_are_rejected_before_fetch(private_root):
    raw = layer([("file", "file", b"x", None)])
    manifest, config, blobs = fixture([raw])
    duplicate = manifest.replace(b'"schemaVersion":2', b'"schemaVersion":2,"schemaVersion":2')
    altered = json.loads(manifest)
    altered["layers"][0]["urls"] = ["https://example.invalid/never-fetch"]
    external = json.dumps(altered, separators=(",", ":")).encode()
    for candidate in (duplicate, external):
        factory = Factory(blobs)
        with pytest.raises(ValueError):
            run(candidate, config, factory, private_root)
        assert factory.calls == []


def test_cumulative_uncompressed_budget_stops_before_return(private_root, monkeypatch):
    first = layer([("a", "file", b"a", None)])
    second = layer([("b", "file", b"b", None)])
    manifest, config, blobs = fixture([first, second])
    monkeypatch.setattr(api(), "MAX_IMAGE_UNCOMPRESSED_BYTES", len(first) + 1, raising=False)
    factory = Factory(blobs)
    with pytest.raises(ValueError, match="incomplete"):
        run(manifest, config, factory, private_root)
    assert [ordinal for ordinal, _ in factory.calls] == [0, 1]
    assert all(fetch.stdout.closed for fetch in factory.fetches)


def test_global_deadline_is_enforced_inside_each_layer_stream(private_root, monkeypatch):
    now = time.monotonic()

    class Clock:
        def __init__(self):
            self.calls = 0

        def monotonic(self):
            self.calls += 1
            return now if self.calls == 1 else now + api().MAX_SECONDS + 1

    monkeypatch.setattr(verify, "time", Clock())
    manifest, config, blobs = fixture([layer([("file", "file", b"x", None)])])
    factory = Factory(blobs)
    with pytest.raises(ValueError, match="incomplete"):
        run(manifest, config, factory, private_root)
    assert [ordinal for ordinal, _ in factory.calls] == [0]
    assert factory.fetches[0].stdout.closed


@pytest.mark.parametrize("failure", ["producer", "cleanup"])
def test_late_process_failure_suppresses_every_result(private_root, failure):
    raw = layer([("private-name", "file", b"secret", CAP_VALUE)])
    manifest, config, blobs = fixture([raw, raw])
    factory = Factory(
        blobs,
        bad_status=1 if failure == "producer" else None,
        bad_cleanup=1 if failure == "cleanup" else None,
    )
    with pytest.raises(ValueError) as caught:
        run(manifest, config, factory, private_root)
    formatted = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    assert "private-name" not in formatted and "PRIVATE-CLEANUP" not in formatted
    assert [ordinal for ordinal, _ in factory.calls] == [0, 1]
    assert all(fetch.stdout.closed for fetch in factory.fetches)
    if failure == "cleanup":
        assert factory.fetches[1].killed


def test_late_malformed_framing_suppresses_first_layer_and_stops_fetches(private_root):
    first = layer([("a", "file", b"first", None)])
    bad = layer([("private-name", "file", b"second", None)])[:-512] + b"x" * 512
    last = layer([("last", "file", b"third", None)])
    manifest, config, blobs = fixture([first, bad, last])
    factory = Factory(blobs)
    with pytest.raises(ValueError, match="incomplete"):
        run(manifest, config, factory, private_root)
    assert [ordinal for ordinal, _ in factory.calls] == [0, 1]
    assert all(fetch.stdout.closed for fetch in factory.fetches)


def test_local_subprocess_fetches_are_closed_and_waited(private_root):
    raw = layer([("file", "file", b"safe-fixture", None)])
    manifest, config, blobs = fixture([raw, raw])
    processes = []

    def fetch(ordinal, descriptor):
        assert descriptor["digest"] == digest(blobs[ordinal])
        proc = subprocess.Popen(  # noqa: S603 - fixed interpreter and synthetic bytes
            [
                sys.executable,
                "-c",
                f"import sys;sys.stdout.buffer.write(bytes.fromhex('{blobs[ordinal].hex()}'))",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        processes.append(proc)
        return proc

    try:
        result = run(manifest, config, fetch, private_root)
        assert len(result.layers) == 2
        assert all(proc.poll() == 0 and proc.stdout.closed for proc in processes)
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
            if proc.stdout:
                proc.stdout.close()
