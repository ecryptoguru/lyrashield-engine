"""Unwired ordered streaming metadata model; never a release qualification.

The caller MUST independently authenticate the native manifest digest and
platform against the signed index and expected provenance before calling.
This helper checks byte bindings only; it does not verify any signature,
attestation, registry identity or OCI runtime behavior. Raw metadata, names,
link targets and capability headers may be sensitive. Never serialize, log,
follow or materialize them, including exception context and traceback locals.

Each fetch factory must return an owned, externally supervised process or
clean up on failure before returning. The caller must impose independent
RSS/CPU/FD/wall-time and process-group limits, protect swap/core dumps, and
safely drain or discard stderr. Only one process is owned at a time. No layer
content or sensitive records are written or extracted by this helper.
"""

# ruff: noqa: INP001, TRY301  # Keep all sensitive-data failures inside one sanitized boundary.
import hashlib
import os
import stat
import time
from dataclasses import dataclass, field
from types import MappingProxyType

from scripts.model_oci_metadata_overlay import MetadataRoot
from scripts.probe_pax_capability import MAX_LAYER_BYTES
from scripts.spool_verified_oci_layer import free_space, require_no_acl
from scripts.verify_oci_layer_binding import (
    DIGEST,
    MAX_CONFIG,
    MAX_LAYERS,
    MAX_MANIFEST,
    MAX_SECONDS,
    MAX_TOTAL,
    MEDIA,
    descriptor,
    read_json,
)
from scripts.verify_pax_capability_stream import (
    MAX_COMPRESSED_BYTES,
    MIN_FREE_BYTES,
    inspect_fetched_changeset,
)


MAX_IMAGE_COMPRESSED_BYTES = MAX_TOTAL
MAX_IMAGE_UNCOMPRESSED_BYTES = MAX_TOTAL


@dataclass(frozen=True)
class StreamedOverlayResult:
    manifest_digest: str
    config_digest: str
    platform: str
    layers: tuple
    entries: MappingProxyType = field(repr=False)
    source_authenticated: bool = False
    runtime_equivalent: bool = False
    release_qualified: bool = False


def _metadata(raw, expected_digest, limit, expected_size=None):
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= limit
        or not isinstance(expected_digest, str)
        or not DIGEST.fullmatch(expected_digest)
        or (expected_size is not None and len(raw) != expected_size)
        or "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest
    ):
        raise ValueError("metadata binding failed")
    return read_json(raw)


def _plan(manifest_raw, expected_digest, config_raw, platform):
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("unsupported platform")
    manifest = _metadata(manifest_raw, expected_digest, MAX_MANIFEST)
    if (
        type(manifest.get("schemaVersion")) is not int
        or manifest["schemaVersion"] != 2
        or manifest.get("mediaType") not in MEDIA
        or "artifactType" in manifest
        or "subject" in manifest
    ):
        raise ValueError("unsupported image manifest")
    config_type, layer_types = MEDIA[manifest["mediaType"]]
    config_digest, config_size = descriptor(manifest.get("config"), {config_type}, MAX_CONFIG)
    config = _metadata(config_raw, config_digest, MAX_CONFIG, config_size)
    variant = config.get("variant")
    if (
        config.get("os") != "linux"
        or config.get("architecture") != platform.split("/")[1]
        or not (variant is None or (platform == "linux/arm64" and variant == "v8"))
    ):
        raise ValueError("image platform mismatch")
    rootfs, layers = config.get("rootfs"), manifest.get("layers")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        raise ValueError("unsupported rootfs")
    diff_ids = rootfs.get("diff_ids")
    if (
        not isinstance(layers, list)
        or not 0 < len(layers) <= MAX_LAYERS
        or not isinstance(diff_ids, list)
        or len(diff_ids) != len(layers)
    ):
        raise ValueError("invalid layer plan")
    if type(MAX_IMAGE_COMPRESSED_BYTES) is not int or MAX_IMAGE_COMPRESSED_BYTES <= 0:
        raise ValueError("invalid compressed image budget")
    if type(MAX_IMAGE_UNCOMPRESSED_BYTES) is not int or MAX_IMAGE_UNCOMPRESSED_BYTES <= 0:
        raise ValueError("invalid uncompressed image budget")
    ordered, compressed_total = [], 0
    for item, diff_id in zip(layers, diff_ids):  # noqa: B905 - counts were verified; Python 3.9
        digest, size = descriptor(item, layer_types, MAX_COMPRESSED_BYTES)
        if not isinstance(diff_id, str) or not DIGEST.fullmatch(diff_id):
            raise ValueError("invalid diff ID")
        compressed_total += size
        if compressed_total > MAX_IMAGE_COMPRESSED_BYTES:
            raise ValueError("compressed image budget exceeded")
        ordered.append(({"mediaType": item["mediaType"], "digest": digest, "size": size}, diff_id))
    return config_digest, tuple(ordered)


def _check_private_root(private_root):
    root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        state = os.fstat(root)
        if (
            not stat.S_ISDIR(state.st_mode)
            or state.st_uid != os.geteuid()
            or stat.S_IMODE(state.st_mode) != 0o700
        ):
            raise ValueError("private root invalid")
        require_no_acl(root)
        if free_space(root) < MIN_FREE_BYTES + 1024 * 1024:
            raise ValueError("temporary storage reserve insufficient")
    finally:
        os.close(root)


def model_fetched_image(
    manifest_raw,
    expected_manifest_digest,
    config_raw,
    platform,
    fetch_layer,
    private_root,
    *,
    linux_literal_paths=False,
):
    """Return a private single-image metadata model only after every layer verifies.

    `expected_manifest_digest` and `platform` must already be bound to an
    independently authenticated source. `fetch_layer(ordinal, descriptor)`
    receives an immutable minimal descriptor; it must return an owned fetch or
    clean it up itself if creation fails. This is not authenticity, a runtime
    overlay, actual capability state, SBOM completeness or release evidence.
    """
    try:
        if type(linux_literal_paths) is not bool or not callable(fetch_layer):
            raise ValueError("invalid input")
        config_digest, plan = _plan(manifest_raw, expected_manifest_digest, config_raw, platform)
        _check_private_root(private_root)
        deadline = time.monotonic() + MAX_SECONDS
        root = MetadataRoot(linux_literal_paths=linux_literal_paths, deadline=deadline)
        total, layers = 0, []
        for ordinal, (item, diff_id) in enumerate(plan):
            root.check_deadline()
            remaining = MAX_IMAGE_UNCOMPRESSED_BYTES - total
            if remaining <= 0:
                raise ValueError("uncompressed image budget exceeded")
            budget = min(remaining, MAX_LAYER_BYTES)
            fetch = fetch_layer(ordinal, MappingProxyType(item))
            result = inspect_fetched_changeset(
                fetch,
                item,
                diff_id,
                private_root,
                linux_literal_paths=linux_literal_paths,
                max_uncompressed_bytes=budget,
                absolute_deadline=deadline,
            )
            if (
                result.descriptor_digest != item["digest"]
                or result.compressed_bytes != item["size"]
                or result.diff_id != diff_id
                or type(result.uncompressed_bytes) is not int
                or not 0 < result.uncompressed_bytes <= budget
                or result.path_policy != ("linux-literal" if linux_literal_paths else "strict")
                or result.final_image_verified is not False
                or result.release_qualified is not False
            ):
                raise ValueError("layer result mismatch")
            total += result.uncompressed_bytes
            root.apply(result.members, ordinal, result.uncompressed_bytes)
            layers.append((item["digest"], diff_id, item["size"]))
        return StreamedOverlayResult(
            expected_manifest_digest,
            config_digest,
            platform,
            tuple(layers),
            MappingProxyType(root.entries.copy()),
        )
    except Exception:  # noqa: BLE001 - parser and subprocess failures can contain sensitive data
        raise ValueError("streamed metadata overlay incomplete") from None
