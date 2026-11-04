#!/usr/bin/env python3
"""Bind complete native SPDX documents to a qualified index and OCI artifact."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
NUMBER = re.compile(r"[1-9][0-9]*\Z")
PLATFORMS = ("amd64", "arm64")
ARTIFACT_TYPE = "application/vnd.lyrashield.sandbox-sbom.v1"
LAYER_TYPE = "application/spdx+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
IMAGE_MANIFESTS = {OCI_MANIFEST, DOCKER_MANIFEST}
CONFIG_TYPES = {
    OCI_MANIFEST: "application/vnd.oci.image.config.v1+json",
    DOCKER_MANIFEST: "application/vnd.docker.container.image.v1+json",
}
IMAGE_INDEXES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
EMPTY_CONFIG = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
MAX_SBOM_BYTES = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_bounded(path, maximum):
    require(path.is_file() and 0 < path.stat().st_size <= maximum, f"invalid file size: {path}")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(0 < len(data) <= maximum, f"invalid file size: {path}")
    return data


def json_object(raw):
    def unique_pairs(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, f"duplicate JSON key: {key}")
            out[key] = value
        return out

    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    require(isinstance(obj, dict), "expected JSON object")
    return obj


def config_for_manifest(path, expected):
    raw = read_bounded(path, 65537)
    if sha256(raw) != expected and raw.endswith(b"\n"):
        raw = raw[:-1]
    require(sha256(raw) == expected, "native manifest bytes differ from qualified digest")
    image = json_object(raw)
    config = image.get("config")
    require(
        image.get("schemaVersion") == 2 and image.get("mediaType") in IMAGE_MANIFESTS,
        "invalid native manifest",
    )
    require(
        isinstance(config, dict)
        and isinstance(config.get("digest"), str)
        and DIGEST.fullmatch(config["digest"])
        and config.get("mediaType") == CONFIG_TYPES[image["mediaType"]]
        and type(config.get("size")) is int
        and 0 < config["size"] <= 16 * 1024 * 1024,
        "invalid image config descriptor",
    )
    return config["digest"]


def describe_document(path, image, arch, native_digest, config_digest):
    raw = read_bounded(path, MAX_SBOM_BYTES)
    document = json_object(raw)
    relationships, packages = document.get("relationships"), document.get("packages")
    require(
        document.get("spdxVersion") == "SPDX-2.3" and document.get("SPDXID") == "SPDXRef-DOCUMENT",
        "unsupported SPDX document",
    )
    creation = document.get("creationInfo")
    require(
        isinstance(creation, dict)
        and isinstance(creation.get("creators"), list)
        and "Tool: syft-1.42.3" in creation["creators"],
        "unexpected SBOM generator",
    )
    require(
        isinstance(relationships, list) and isinstance(packages, list),
        "missing SPDX relationships or packages",
    )
    roots = [
        r.get("relatedSpdxElement")
        for r in relationships
        if isinstance(r, dict)
        and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and r.get("relationshipType") == "DESCRIBES"
    ]
    require(len(roots) == 1 and isinstance(roots[0], str), "missing or ambiguous SPDX image root")
    root = [p for p in packages if isinstance(p, dict) and p.get("SPDXID") == roots[0]]
    require(
        len(root) == 1
        and root[0].get("name") == image
        and root[0].get("versionInfo") == native_digest,
        "SPDX image identity mismatch",
    )
    require(
        any(
            isinstance(p, dict) and isinstance(p.get("SPDXID"), str) and p["SPDXID"] != roots[0]
            for p in packages
        ),
        "SPDX has no non-root packages",
    )
    checksums, refs = root[0].get("checksums"), root[0].get("externalRefs")
    require(
        isinstance(checksums, list)
        and sum(
            1
            for c in checksums
            if isinstance(c, dict)
            and c.get("algorithm") == "SHA256"
            and c.get("checksumValue") == native_digest[7:]
        )
        == 1,
        "SPDX root checksum mismatch",
    )
    require(isinstance(refs, list), "SPDX root has no package URL")
    purls = [
        r.get("referenceLocator")
        for r in refs
        if isinstance(r, dict) and r.get("referenceType") == "purl"
    ]
    require(len(purls) == 1 and isinstance(purls[0], str), "missing or ambiguous SPDX package URL")
    parsed = urlsplit(purls[0])
    require(
        parsed.scheme == "pkg"
        and unquote(parsed.path) == f"oci/{image}@{native_digest}"
        and parse_qs(parsed.query, keep_blank_values=True) == {"arch": [arch]}
        and not parsed.fragment,
        "SPDX package URL has wrong source or platform",
    )
    return {
        "manifestDigest": native_digest,
        "configDigest": config_digest,
        "documentDigest": sha256(raw),
        "size": len(raw),
        "filename": path.name,
    }


def build_predicate(
    qualification, index_metadata, artifact_raw, artifact_digest, image, manifest_paths, sbom_dir
):
    require(
        qualification.get("schema") == "lyrashield.sandbox.qualification.v1",
        "invalid qualification schema",
    )
    for name in ("engineRevision", "workflowRevision"):
        require(
            isinstance(qualification.get(name), str) and REVISION.fullmatch(qualification[name]),
            f"invalid {name}",
        )
    for name in ("runId", "runAttempt"):
        require(
            isinstance(qualification.get(name), str) and NUMBER.fullmatch(qualification[name]),
            f"invalid {name}",
        )
    index_digest = qualification.get("indexDigest")
    require(
        isinstance(index_digest, str) and DIGEST.fullmatch(index_digest),
        "invalid qualified index digest",
    )
    index_descriptor = index_metadata.get("containerimage.descriptor")
    require(
        isinstance(index_descriptor, dict)
        and index_descriptor.get("digest") == index_digest
        and index_descriptor.get("mediaType") in IMAGE_INDEXES
        and type(index_descriptor.get("size")) is int
        and 0 < index_descriptor["size"] <= 65536,
        "invalid qualified index descriptor",
    )
    manifests = qualification.get("platformManifests")
    require(
        isinstance(manifests, dict)
        and set(manifests) == set(PLATFORMS)
        and all(isinstance(v, str) and DIGEST.fullmatch(v) for v in manifests.values())
        and manifests["amd64"] != manifests["arm64"],
        "invalid qualified platform manifests",
    )
    require(
        isinstance(artifact_digest, str)
        and DIGEST.fullmatch(artifact_digest)
        and sha256(artifact_raw) == artifact_digest,
        "artifact digest mismatch",
    )
    artifact = json_object(artifact_raw)
    config, subject, layers = (
        artifact.get("config"),
        artifact.get("subject"),
        artifact.get("layers"),
    )
    require(
        artifact.get("schemaVersion") == 2
        and artifact.get("mediaType") == OCI_MANIFEST
        and artifact.get("artifactType") == ARTIFACT_TYPE,
        "invalid SBOM artifact type",
    )
    require(
        isinstance(config, dict)
        and config.get("mediaType") == "application/vnd.oci.empty.v1+json"
        and config.get("digest") == EMPTY_CONFIG
        and config.get("size") == 2
        and config.get("data", "e30=") == "e30=",
        "invalid SBOM artifact config",
    )
    require(
        isinstance(subject, dict)
        and all(
            subject.get(key) == index_descriptor[key] for key in ("digest", "mediaType", "size")
        )
        and type(subject.get("size")) is int,
        "SBOM artifact subject mismatch",
    )
    require(
        isinstance(layers, list) and len(layers) == 2, "SBOM artifact must have exactly two layers"
    )
    platforms = {}
    for arch in PLATFORMS:
        filename = f"sandbox-{arch}.spdx.json"
        config_digest = config_for_manifest(manifest_paths[arch], manifests[arch])
        item = describe_document(sbom_dir / filename, image, arch, manifests[arch], config_digest)
        matching = [
            layer
            for layer in layers
            if isinstance(layer, dict)
            and isinstance(layer.get("annotations"), dict)
            and layer["annotations"].get("org.opencontainers.image.title") == filename
        ]
        require(
            len(matching) == 1
            and matching[0].get("mediaType") == LAYER_TYPE
            and matching[0].get("digest") == item["documentDigest"]
            and type(matching[0].get("size")) is int
            and matching[0]["size"] == item["size"],
            f"SBOM artifact layer mismatch: {arch}",
        )
        platforms[arch] = item
    return {
        "schema": "lyrashield.sandbox.sbom.v1",
        "indexDigest": index_digest,
        "engineRevision": qualification["engineRevision"],
        "workflowRevision": qualification["workflowRevision"],
        "runId": qualification["runId"],
        "runAttempt": qualification["runAttempt"],
        "artifact": {"digest": artifact_digest, "mediaType": ARTIFACT_TYPE},
        "platforms": platforms,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "qualification",
        "index-metadata",
        "amd64-manifest",
        "arm64-manifest",
        "artifact-manifest",
        "sbom-dir",
        "output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    result = build_predicate(
        json_object(read_bounded(args.qualification, 65536)),
        json_object(read_bounded(args.index_metadata, 65536)),
        read_bounded(args.artifact_manifest, 65536),
        args.artifact_digest,
        args.image,
        {"amd64": args.amd64_manifest, "arm64": args.arm64_manifest},
        args.sbom_dir,
    )
    args.output.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
