#!/usr/bin/env python3
"""Offline byte binding only: does not authenticate images or apply OCI layers."""

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import sys
import zlib


OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
OCI_TAR = "application/vnd.oci.image.layer.v1.tar"
OCI_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MEDIA = {
    OCI_MANIFEST: (OCI_CONFIG, {OCI_TAR, OCI_GZIP}),
    DOCKER_MANIFEST: (DOCKER_CONFIG, {DOCKER_GZIP}),
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CHUNK = 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_CONFIG = 16 * 1024 * 1024
MAX_LAYER = 16 * 1024 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024 * 1024
MAX_LAYERS = 128
MAX_SECONDS = 900


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(data):
    def reject_constant(_value):
        raise ValueError("invalid JSON number")

    value = json.loads(
        data.decode("utf-8"), object_pairs_hook=unique_pairs, parse_constant=reject_constant
    )
    require(isinstance(value, dict), "expected JSON object")
    return value


def blob_file(directory, digest):
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid SHA-256 digest")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(digest[7:], flags, dir_fd=directory)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "blob must be a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def metadata_blob(directory, digest, limit, expected_size=None):
    with blob_file(directory, digest) as stream:
        data = stream.read(limit + 1)
    require(0 < len(data) <= limit, "metadata size limit exceeded")
    if expected_size is not None:
        require(len(data) == expected_size, "metadata size mismatch")
    require("sha256:" + hashlib.sha256(data).hexdigest() == digest, "metadata digest mismatch")
    return read_json(data)


def descriptor(value, allowed_types, maximum):
    require(isinstance(value, dict), "invalid descriptor")
    require(value.get("mediaType") in allowed_types, "unsupported descriptor media type")
    digest, size = value.get("digest"), value.get("size")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid descriptor digest")
    require(type(size) is int and 0 < size <= maximum, "invalid descriptor size")
    require("urls" not in value and "data" not in value, "external or inline blobs unsupported")
    return digest, size


def verify_layer(directory, item, expected_diff, total):
    digest, size = descriptor(item, {OCI_TAR, OCI_GZIP, DOCKER_GZIP}, MAX_LAYER)
    compressed_hash, diff_hash = hashlib.sha256(), hashlib.sha256()
    decompressor = None if item["mediaType"] == OCI_TAR else zlib.decompressobj(31)
    seen, uncompressed = 0, 0
    with blob_file(directory, digest) as stream:
        while True:
            data = stream.read(CHUNK)
            if not data:
                break
            seen += len(data)
            require(seen <= size, "layer size mismatch")
            compressed_hash.update(data)
            if decompressor is None:
                diff_hash.update(data)
                uncompressed += len(data)
            else:
                require(not decompressor.eof, "gzip trailing data unsupported")
                pending = data
                while pending:
                    decoded = decompressor.decompress(pending, CHUNK)
                    pending = decompressor.unconsumed_tail
                    diff_hash.update(decoded)
                    uncompressed += len(decoded)
                    require(
                        uncompressed <= MAX_LAYER and total + uncompressed <= MAX_TOTAL,
                        "uncompressed layer byte limit exceeded",
                    )
                    require(not decompressor.unused_data, "gzip trailing data unsupported")
            require(
                uncompressed <= MAX_LAYER and total + uncompressed <= MAX_TOTAL,
                "uncompressed layer byte limit exceeded",
            )
    require(seen == size, "layer size mismatch")
    require("sha256:" + compressed_hash.hexdigest() == digest, "layer digest mismatch")
    require(decompressor is None or decompressor.eof, "incomplete gzip stream")
    diff_id = "sha256:" + diff_hash.hexdigest()
    require(diff_id == expected_diff, "layer diff ID mismatch")
    return {"digest": digest, "size": size, "diffId": diff_id}, total + uncompressed


def verify(directory, manifest_digest, platform):
    manifest = metadata_blob(directory, manifest_digest, MAX_MANIFEST)
    require(
        type(manifest.get("schemaVersion")) is int and manifest["schemaVersion"] == 2,
        "unsupported manifest schema",
    )
    media = manifest.get("mediaType")
    require(
        media in MEDIA and "artifactType" not in manifest and "subject" not in manifest,
        "unsupported image manifest",
    )
    config_type, layer_types = MEDIA[media]
    config_digest, config_size = descriptor(manifest.get("config"), {config_type}, MAX_CONFIG)
    config = metadata_blob(directory, config_digest, MAX_CONFIG, config_size)
    require(
        config.get("os") == "linux" and config.get("architecture") == platform.split("/")[1],
        "image platform mismatch",
    )
    variant = config.get("variant")
    require(
        variant is None or (platform == "linux/arm64" and variant == "v8"),
        "unsupported architecture variant",
    )
    rootfs = config.get("rootfs")
    require(isinstance(rootfs, dict) and rootfs.get("type") == "layers", "unsupported rootfs")
    diff_ids, layers = rootfs.get("diff_ids"), manifest.get("layers")
    require(isinstance(layers, list) and 0 < len(layers) <= MAX_LAYERS, "invalid layer count")
    require(isinstance(diff_ids, list) and len(diff_ids) == len(layers), "diff ID count mismatch")
    compressed_total = 0
    for item, diff_id in zip(layers, diff_ids):  # noqa: B905 - lengths validated above; Python 3.9
        _, size = descriptor(item, layer_types, MAX_LAYER)
        require(isinstance(diff_id, str) and DIGEST.fullmatch(diff_id), "invalid diff ID")
        compressed_total += size
        require(compressed_total <= MAX_TOTAL, "compressed layer byte limit exceeded")
    results, total = [], 0
    for item, diff_id in zip(layers, diff_ids):  # noqa: B905 - lengths validated above; Python 3.9
        result, total = verify_layer(directory, item, diff_id, total)
        results.append(result)
    return {
        "scope": "offline_layer_binding_only",
        "manifestDigest": manifest_digest,
        "configDigest": config_digest,
        "platform": platform,
        "layers": results,
    }


def timeout(_signum, _frame):
    raise TimeoutError("processing deadline exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob-dir", required=True, help="directory of files named by SHA-256 hex")
    parser.add_argument(
        "--manifest-digest", required=True, help="independently qualified manifest SHA-256"
    )
    parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(MAX_SECONDS)
    directory = os.open(args.blob_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        report = verify(directory, args.manifest_digest, args.platform)
    finally:
        os.close(directory)
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True))  # noqa: T201 - output is the offline report


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, zlib.error, TimeoutError) as exc:
        print(f"layer binding failed: {exc}", file=sys.stderr)  # noqa: T201 - CLI error
        sys.exit(1)
