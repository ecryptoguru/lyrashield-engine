#!/usr/bin/env python3
"""Verify a two-platform image index is composed of the qualified child manifests."""

import argparse
import json
import re
import sys
from pathlib import Path


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SUPPORTED = {"amd64", "arm64"}
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def platform_manifests(index):
    if (
        not isinstance(index, dict)
        or index.get("schemaVersion") != 2
        or index.get("mediaType") not in INDEX_TYPES
    ):
        raise ValueError("expected an OCI or Docker image index")
    entries = index.get("manifests")
    if not isinstance(entries, list) or not entries:
        raise ValueError("missing manifest descriptors")
    platforms = {}
    attestations = set()
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("digest"), str)
            or not DIGEST.fullmatch(entry["digest"])
            or entry.get("mediaType") not in MANIFEST_TYPES
            or not isinstance(entry.get("size"), int)
            or isinstance(entry["size"], bool)
            or entry["size"] <= 0
        ):
            raise ValueError("invalid manifest descriptor digest")
        platform = entry.get("platform")
        if not isinstance(platform, dict):
            raise ValueError("missing descriptor platform")  # noqa: TRY004 - invalid index data
        os_name, arch = platform.get("os"), platform.get("architecture")
        if os_name == "unknown" and arch == "unknown":
            # BuildKit attaches provenance/SBOM manifests as unknown platforms.
            annotations = entry.get("annotations")
            if (
                not isinstance(annotations, dict)
                or annotations.get("vnd.docker.reference.type") != "attestation-manifest"
            ):
                raise ValueError("unrecognized non-runnable descriptor")
            target = annotations.get("vnd.docker.reference.digest")
            if not isinstance(target, str) or not DIGEST.fullmatch(target):
                raise ValueError("invalid attestation target")
            descriptor = (entry["digest"], target, entry["mediaType"], entry["size"])
            if descriptor in attestations:
                raise ValueError("duplicate attestation descriptor")
            attestations.add(descriptor)
            continue
        if (
            os_name != "linux"
            or arch not in SUPPORTED
            or arch in platforms
            or set(platform) - {"os", "architecture", "variant"}
        ):
            raise ValueError("unexpected or duplicate runnable platform")
        variant = platform.get("variant")
        if variant is not None and not (arch == "arm64" and variant == "v8"):
            raise ValueError("unsupported platform variant")
        # OCI consumers also use descriptor metadata (such as size, media type,
        # and platform variant). Buildx drops descriptor annotations and
        # normalizes arm64/v8 to arm64 when assembling an index; the remaining
        # validated fields must still match the smoke-tested descriptor.
        platforms[arch] = (entry["digest"], entry["mediaType"], entry["size"])
    runnable_digests = {entry[0] for entry in platforms.values()}
    if any(target not in runnable_digests for _, target, _, _ in attestations):
        raise ValueError("attestation targets an unqualified manifest")
    return platforms, attestations


def verify(amd, arm, combined):
    expected = {}
    expected_attestations = set()
    for arch, data in (("amd64", amd), ("arm64", arm)):
        actual, attestations = platform_manifests(data)
        if set(actual) != {arch}:
            raise ValueError("native candidate has the wrong runnable platform")
        expected[arch] = actual[arch]
        if expected_attestations & attestations:
            raise ValueError("duplicate native attestation descriptor")
        expected_attestations.update(attestations)
    combined_platforms, combined_attestations = platform_manifests(combined)
    if combined_platforms != expected or combined_attestations != expected_attestations:
        raise ValueError("combined index differs from qualified native images")
    return {arch: entry[0] for arch, entry in expected.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("amd64", type=Path)
    parser.add_argument("arm64", type=Path)
    parser.add_argument("combined", type=Path)
    args = parser.parse_args()
    expected = verify(
        *(
            json.loads(path.read_text(encoding="utf8"))
            for path in (args.amd64, args.arm64, args.combined)
        )
    )
    sys.stdout.write(json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
