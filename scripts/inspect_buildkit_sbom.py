#!/usr/bin/env python3
"""Inspect an index-bound BuildKit SPDX statement; no signature or coverage verification."""

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import sys
from urllib.parse import parse_qsl, urlsplit


INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INTOTO = "application/vnd.in-toto+json"
SPDX = "https://spdx.dev/Document"
BUILDKIT_ATTESTATION = "application/vnd.docker.attestation.manifest.v1+json"
EMPTY_CONFIG = {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2,
    "data": "e30=",
}
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
IMAGE = re.compile(r"ghcr\.io/[a-z0-9]+(?:[._/-][a-z0-9]+)*\Z")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
MAX_MANIFEST = 64 * 1024
MAX_STATEMENT = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_number(_value):
    raise ValueError("invalid number")


def deadline(_signum, _frame):
    raise TimeoutError("deadline exceeded")


def read_bound(path, expected_digest, limit, expected_size=None):
    require(isinstance(expected_digest, str) and SHA.fullmatch(expected_digest), "invalid digest")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "input must be a regular file")
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "input size limit exceeded")
    if expected_size is not None:
        require(len(raw) == expected_size, "descriptor size mismatch")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == expected_digest, "digest mismatch")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique_pairs,
        parse_constant=reject_number,
    )
    require(isinstance(value, dict), "expected JSON object")
    return value


def descriptor(value, media, limit):
    require(isinstance(value, dict) and value.get("mediaType") == media, "invalid media type")
    require(
        isinstance(value.get("digest"), str) and SHA.fullmatch(value["digest"]), "invalid digest"
    )
    size = value.get("size")
    require(type(size) is int and 0 < size <= limit, "invalid descriptor size")
    require("urls" not in value and "data" not in value, "unsupported descriptor source")
    return value["digest"], size


def inspect(index_path, index_digest, attestation_path, statement_path, image, arch):
    require(isinstance(image, str) and IMAGE.fullmatch(image), "invalid image name")
    require(arch in {"amd64", "arm64"}, "invalid architecture")
    index = read_bound(index_path, index_digest, MAX_MANIFEST)
    require(
        type(index.get("schemaVersion")) is int
        and index["schemaVersion"] == 2
        and index.get("mediaType") == INDEX,
        "invalid OCI index",
    )
    entries = index.get("manifests")
    require(isinstance(entries, list) and 0 < len(entries) <= 128, "invalid index entries")
    native = [
        item
        for item in entries
        if isinstance(item, dict)
        and isinstance(item.get("platform"), dict)
        and item["platform"].get("os") == "linux"
        and item["platform"].get("architecture") == arch
    ]
    require(len(native) == 1, "missing or ambiguous native manifest")
    native_digest, native_size = descriptor(native[0], MANIFEST, MAX_MANIFEST)
    attestations = [
        item
        for item in entries
        if isinstance(item, dict)
        and isinstance(item.get("annotations"), dict)
        and item["annotations"].get("vnd.docker.reference.type") == "attestation-manifest"
        and item["annotations"].get("vnd.docker.reference.digest") == native_digest
    ]
    require(len(attestations) == 1, "missing or ambiguous BuildKit attestation manifest")
    att_digest, att_size = descriptor(attestations[0], MANIFEST, MAX_MANIFEST)
    att = read_bound(attestation_path, att_digest, MAX_MANIFEST, att_size)
    require(
        type(att.get("schemaVersion")) is int
        and att["schemaVersion"] == 2
        and att.get("mediaType") == MANIFEST
        and att.get("artifactType") == BUILDKIT_ATTESTATION
        and att.get("config") == EMPTY_CONFIG,
        "invalid attestation manifest",
    )
    att_subject = descriptor(att.get("subject"), MANIFEST, MAX_MANIFEST)
    require(att_subject == (native_digest, native_size), "attestation subject mismatch")
    layers = att.get("layers")
    require(isinstance(layers, list) and 0 < len(layers) <= 128, "invalid attestation layers")
    matches = [
        x
        for x in layers
        if isinstance(x, dict)
        and isinstance(x.get("annotations"), dict)
        and x["annotations"].get("in-toto.io/predicate-type") == SPDX
    ]
    require(len(matches) == 1, "missing or ambiguous SPDX statement")
    statement_digest, statement_size = descriptor(matches[0], INTOTO, MAX_STATEMENT)
    statement = read_bound(statement_path, statement_digest, MAX_STATEMENT, statement_size)
    require(
        statement.get("_type")
        in {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}
        and statement.get("predicateType") == SPDX,
        "invalid statement type",
    )
    subjects = statement.get("subject")
    require(
        isinstance(subjects, list) and len(subjects) == 1 and isinstance(subjects[0], dict),
        "invalid statement subject",
    )
    subject = subjects[0]
    require(subject.get("digest") == {"sha256": native_digest[7:]}, "subject digest mismatch")
    name = subject.get("name")
    require(isinstance(name, str), "invalid subject name")
    url = urlsplit(name)
    prefix = f"docker/{image}@"
    require(
        url.scheme == "pkg"
        and not url.netloc
        and not url.fragment
        and url.path.startswith(prefix)
        and TAG.fullmatch(url.path[len(prefix) :])
        and parse_qsl(url.query, strict_parsing=True) == [("platform", f"linux/{arch}")],
        "subject name or platform mismatch",
    )
    doc = statement.get("predicate")
    require(
        isinstance(doc, dict)
        and doc.get("spdxVersion") == "SPDX-2.3"
        and doc.get("SPDXID") == "SPDXRef-DOCUMENT",
        "invalid SPDX document",
    )
    packages = doc.get("packages")
    require(isinstance(packages, list) and len(packages) > 0, "missing SPDX packages")
    return {
        "scope": "index_bound_buildkit_sbom_inspection_only",
        "indexDigest": index_digest,
        "nativeManifestDigest": native_digest,
        "attestationManifestDigest": att_digest,
        "statementDigest": statement_digest,
        "platform": f"linux/{arch}",
        "packageCount": len(packages),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("index", "index-digest", "attestation-manifest", "statement", "image"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    report = inspect(
        args.index,
        args.index_digest,
        args.attestation_manifest,
        args.statement,
        args.image,
        args.arch,
    )
    signal.alarm(0)
    print(json.dumps(report, sort_keys=True))  # noqa: T201 - machine-readable inspection


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print(f"inspection failed: {exc}", file=sys.stderr)  # noqa: T201 - CLI diagnostic
        sys.exit(1)
