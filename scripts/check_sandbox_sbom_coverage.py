#!/usr/bin/env python3
"""Qualify bounded package coverage for exact native sandbox images."""

# ruff: noqa: E501

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

from scripts.check_go_sbom_coverage import (
    MODULE,
    VERSION,
    digest_file,
    inspect_binary,
    parse_json,
)
from scripts.check_sbom_inventory import (
    LINK_POLICY,
    MAX_ARCHIVE_ENTRIES,
    MAX_GO_BINARY_BYTES,
    MAX_METADATA_BYTES,
    MAX_SBOM_BYTES,
    MAX_TOTAL_GO_BINARY_BYTES,
    MAX_TOTAL_METADATA_BYTES,
    create_output,
    scan_rootfs,
    spdx_inventory,
)
from scripts.prepare_sandbox_sbom import (
    config_descriptor_for_manifest,
    describe_document_bytes,
    json_object,
    normalized_manifest,
)
from scripts.sandbox_sbom_go import GoEvidenceIndex


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
NUMBER = re.compile(r"[1-9][0-9]*\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}\Z")
MAX_MANIFEST_BYTES = 65537
MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_INSPECT_BYTES = 16 * 1024 * 1024
MAX_APPS_BYTES = 2 * 1024 * 1024
MAX_LAYERS = 128
MAX_PROCESS_SECONDS = 1800
MAX_ROOTFS_EXPORT_BYTES = 8 * 1024 * 1024 * 1024
MAX_ROOTFS_EXPORT_SECONDS = 900
REQUIRED_APPS = {
    "httpx",
    "katana",
    "gospider",
    "interactsh-client",
    "vulnx",
    "gitleaks",
    "trivy",
    "trufflehog",
    "ffuf",
    "naabu",
    "nuclei",
    "subfinder",
}
POLICY = {"id": "sandbox-bounded-package-coverage", "version": 1}
LIMITS = {
    "rootfsExportBytes": MAX_ROOTFS_EXPORT_BYTES,
    "rootfsExportSeconds": MAX_ROOTFS_EXPORT_SECONDS,
    "archiveEntries": MAX_ARCHIVE_ENTRIES,
    "metadataBytes": MAX_TOTAL_METADATA_BYTES,
    "individualMetadataBytes": MAX_METADATA_BYTES,
    "sbomBytes": MAX_SBOM_BYTES,
    "goBinaries": 12,
    "totalGoBinaryBytes": MAX_TOTAL_GO_BINARY_BYTES,
    "individualGoBinaryBytes": MAX_GO_BINARY_BYTES,
    "processingSeconds": MAX_PROCESS_SECONDS,
}
SCOPE = [
    "debian:var/lib/dpkg/status",
    "python:dist-info-metadata-under-declared-roots",
    "npm:package-json-under-declared-roots",
    "go:twelve-pinned-application-files",
]
LIMITATIONS = [
    "Bounded scopes only; this is not proof of image-wide package completeness",
    "Debian coverage is limited to installed identities in var/lib/dpkg/status",
    "Python coverage is limited to dist-info METADATA under declared roots",
    "npm coverage is limited to installed package metadata under declared roots",
    "Go coverage is limited to the 12 pinned application files and their linked build metadata",
    "Docker export is trusted to produce the merged root filesystem for the verified unstarted container",
    "Local-build Go main modules are UNKNOWN in SPDX; source versions come from pinned repository manifests",
    "The gate does not prove completeness of Syft cataloger discovery or enumerate every file, source tree, binary, or ecosystem",
]
ALLOWED_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def normalize_hash(value, *, prefixed=True):
    require(isinstance(value, str), "invalid SHA-256 value")
    if prefixed:
        require(DIGEST.fullmatch(value) is not None, "invalid SHA-256 digest")
        return value[7:]
    require(SHA256.fullmatch(value) is not None, "invalid SHA-256 checksum")
    return value


def read_regular(path, maximum, *, allow_empty=False):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode), f"input is not a regular file: {path}")
        require(
            metadata.st_size <= maximum and (allow_empty or metadata.st_size > 0),
            f"invalid input size: {path}",
        )
        chunks, size = [], 0
        while chunk := os.read(fd, min(1024 * 1024, maximum + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            require(size <= maximum, f"input exceeds byte limit: {path}")
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    require(size == len(raw) and (allow_empty or raw), f"invalid input size: {path}")
    return raw


def read_object(path, maximum, message="expected JSON object"):
    value = parse_json(read_regular(path, maximum))
    require(isinstance(value, dict), message)
    return value


def read_array(path, maximum, message="expected JSON array"):
    value = parse_json(read_regular(path, maximum))
    require(isinstance(value, list), message)
    return value


def validate_shared_identity(qualification, predicate):
    require(
        qualification.get("schema") == "lyrashield.sandbox.qualification.v1",
        "invalid qualification schema",
    )
    require(
        predicate.get("schema") == "lyrashield.sandbox.sbom.v1", "invalid SBOM predicate schema"
    )
    for name in ("engineRevision", "workflowRevision"):
        require(
            isinstance(qualification.get(name), str)
            and REVISION.fullmatch(qualification[name]) is not None,
            f"invalid {name}",
        )
    for name in ("runId", "runAttempt"):
        require(
            isinstance(qualification.get(name), str)
            and NUMBER.fullmatch(qualification[name]) is not None,
            f"invalid {name}",
        )
    require(
        isinstance(qualification.get("indexDigest"), str)
        and DIGEST.fullmatch(qualification["indexDigest"]) is not None,
        "invalid qualified index digest",
    )
    for name in ("engineRevision", "workflowRevision", "runId", "runAttempt", "indexDigest"):
        require(predicate.get(name) == qualification.get(name), f"SBOM predicate {name} mismatch")
    manifests = qualification.get("platformManifests")
    require(
        isinstance(manifests, dict)
        and set(manifests) == {"amd64", "arm64"}
        and all(isinstance(value, str) and DIGEST.fullmatch(value) for value in manifests.values())
        and manifests["amd64"] != manifests["arm64"],
        "invalid qualified platform manifests",
    )
    platforms = predicate.get("platforms")
    require(
        isinstance(platforms, dict) and set(platforms) == {"amd64", "arm64"},
        "invalid SBOM predicate platforms",
    )
    for arch in ("amd64", "arm64"):
        item = platforms[arch]
        require(isinstance(item, dict), f"invalid SBOM predicate platform: {arch}")
        require(
            item.get("manifestDigest") == manifests[arch],
            f"SBOM predicate manifest mismatch: {arch}",
        )
        require(
            isinstance(item.get("configDigest"), str)
            and DIGEST.fullmatch(item["configDigest"]) is not None
            and isinstance(item.get("documentDigest"), str)
            and DIGEST.fullmatch(item["documentDigest"]) is not None
            and type(item.get("size")) is int
            and 0 < item["size"] <= MAX_SBOM_BYTES
            and item.get("filename") == f"sandbox-{arch}.spdx.json",
            f"invalid SBOM predicate platform evidence: {arch}",
        )
    return qualification, predicate


def validate_manifest_and_config(manifest_path, manifest_digest, config_path):
    image = normalized_manifest(read_regular(manifest_path, MAX_MANIFEST_BYTES), manifest_digest)
    descriptor = config_descriptor_for_manifest(image)
    layers = image.get("layers")
    require(
        isinstance(layers, list) and 0 < len(layers) <= MAX_LAYERS,
        "invalid native manifest layers",
    )
    for layer in layers:
        require(
            isinstance(layer, dict)
            and layer.get("mediaType") in ALLOWED_LAYER_TYPES
            and isinstance(layer.get("digest"), str)
            and DIGEST.fullmatch(layer["digest"]) is not None
            and type(layer.get("size")) is int
            and layer["size"] > 0
            and "urls" not in layer
            and "data" not in layer,
            "unsupported or external image layer",
        )
    raw = read_regular(config_path, MAX_CONFIG_BYTES)
    require(descriptor["size"] == len(raw), "image config size differs from manifest descriptor")
    require(
        sha256(raw) == descriptor["digest"], "image config digest differs from manifest descriptor"
    )
    config = json_object(raw)
    rootfs = config.get("rootfs")
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
    require(
        config.get("os") == "linux"
        and config.get("architecture") in {"amd64", "arm64"}
        and isinstance(rootfs, dict)
        and rootfs.get("type") == "layers"
        and isinstance(diff_ids, list)
        and len(diff_ids) == len(layers)
        and 0 < len(diff_ids) <= MAX_LAYERS
        and all(isinstance(item, str) and DIGEST.fullmatch(item) for item in diff_ids),
        "invalid image config platform or root filesystem",
    )
    return descriptor["digest"], config["architecture"], diff_ids


def validate_docker_identity(paths, architecture, config_digest, diff_ids, container_id):
    image_records = read_array(paths["image"], MAX_INSPECT_BYTES)
    require(
        len(image_records) == 1 and isinstance(image_records[0], dict), "ambiguous image inspect"
    )
    image = image_records[0]
    rootfs = image.get("RootFS")
    require(
        image.get("Id") == config_digest
        and image.get("Os") == "linux"
        and image.get("Architecture") == architecture
        and isinstance(rootfs, dict)
        and rootfs.get("Type") == "layers"
        and rootfs.get("Layers") == diff_ids,
        "local image identity differs from the verified manifest",
    )
    container_records = read_array(paths["container"], MAX_INSPECT_BYTES)
    require(
        len(container_records) == 1 and isinstance(container_records[0], dict),
        "ambiguous container inspect",
    )
    container = container_records[0]
    state = container.get("State")
    host = container.get("HostConfig")
    require(
        isinstance(container.get("Id"), str)
        and CONTAINER_ID.fullmatch(container["Id"]) is not None
        and container["Id"] == container_id
        and container.get("Image") == config_digest
        and isinstance(state, dict)
        and state.get("Status") == "created"
        and state.get("Running") is False
        and state.get("Pid") == 0
        and container.get("Mounts") == []
        and isinstance(host, dict)
        and host.get("Binds") in (None, []),
        "container was not created without running or mounts",
    )


def validate_application_entry(name, module, version, binary_path, seen):
    require(
        isinstance(name, str) and name and "://" not in name,
        "invalid Go application name",
    )
    require(
        isinstance(module, str)
        and MODULE.fullmatch(module) is not None
        and all(part not in {"", ".", ".."} for part in module.split("/")),
        f"invalid Go module: {name}",
    )
    require(
        isinstance(version, str) and VERSION.fullmatch(version) is not None,
        f"invalid pinned Go version: {name}",
    )
    require(
        isinstance(binary_path, str)
        and binary_path.startswith("/")
        and len(binary_path) <= 4096
        and str(PurePosixPath(binary_path)) == binary_path
        and ".." not in PurePosixPath(binary_path).parts,
        f"invalid Go binary path: {name}",
    )
    for value, field in ((name, "name"), (module, "module"), (binary_path, "path")):
        require(value not in seen[field], f"duplicate Go application {field}")
        seen[field].add(value)
    return {"name": name, "module": module, "version": version, "binary": binary_path}


def load_applications(path, distro_path):
    applications = read_object(path, MAX_APPS_BYTES, "invalid application manifest")
    require(applications.get("schema_version") == 1, "unsupported application manifest")
    entries = applications.get("applications")
    require(isinstance(entries, list) and len(entries) == 8, "expected eight pinned applications")
    supplement = read_object(distro_path, MAX_APPS_BYTES, "invalid distro application manifest")
    components = supplement.get("components")
    require(
        supplement.get("bomFormat") == "CycloneDX"
        and isinstance(components, list)
        and len(components) == 4,
        "expected four pinned distro applications",
    )
    seen = {"name": set(), "module": set(), "path": set()}
    result = []
    for item in entries:
        require(isinstance(item, dict), "invalid pinned application")
        result.append(
            validate_application_entry(
                item.get("name"), item.get("module"), item.get("version"), item.get("binary"), seen
            )
        )
    for component in components:
        require(isinstance(component, dict), "invalid distro application")
        properties = component.get("properties")
        paths = [
            item.get("value")
            for item in properties or []
            if isinstance(item, dict) and item.get("name") == "lyrashield:binary:path"
        ]
        require(len(paths) == 1, "distro application must declare one binary path")
        module, version, purl = (
            component.get("name"),
            component.get("version"),
            component.get("purl"),
        )
        require(
            purl == f"pkg:golang/{module}@{version}",
            "distro application module URL mismatch",
        )
        result.append(
            validate_application_entry(
                posixpath.basename(paths[0]), module, version, paths[0], seen
            )
        )
    require({item["name"] for item in result} == REQUIRED_APPS, "pinned application set mismatch")
    return sorted(result, key=lambda item: item["name"])


def validate_go_tool(path, expected_digest):
    require(Path(path).is_absolute(), "Go tool path must be absolute")
    expected = normalize_hash(expected_digest, prefixed=False)
    actual = digest_file(path)
    require(actual == expected, "Go metadata tool digest mismatch")
    result = subprocess.run(  # noqa: S603 - caller supplies a checksum-pinned host Go tool
        [str(path), "version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "GOTOOLCHAIN": "local",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOENV": "off",
            "GOWORK": "off",
            "LC_ALL": "C",
        },
        timeout=30,
        check=True,
        text=True,
    )
    require(
        result.stdout == "go version go1.27.3 linux/amd64\n",
        "unexpected Go metadata tool version or host",
    )
    require(digest_file(path) == expected, "Go metadata tool changed during version check")
    return actual


class DigestingReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, size):
        data = self.source.read(size)
        if not isinstance(data, bytes):
            raise TypeError("rootfs input must be binary")
        self.digest.update(data)
        self.size += len(data)
        if self.size > MAX_ROOTFS_EXPORT_BYTES:
            raise ValueError("rootfs archive exceeds byte limit")
        return data

    def value(self):
        return "sha256:" + self.digest.hexdigest()


def clear_captures(path):
    if path is None:
        return
    directory = Path(path)
    if not directory.is_dir():
        return
    for entry in directory.iterdir():
        if re.fullmatch(r"go-[0-9]{2}\.bin", entry.name):
            entry.unlink(missing_ok=True)


def scan_bound_rootfs(path, expected_digest, capture_paths, capture_dir):
    expected = normalize_hash(expected_digest)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= MAX_ROOTFS_EXPORT_BYTES,
            "invalid rootfs export",
        )
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                reader = DigestingReader(source)
                result = scan_rootfs(reader, capture_paths, capture_dir)
            require(reader.size == metadata.st_size, "rootfs export changed while reading")
            require(
                reader.value() == expected_digest,
                "rootfs export digest differs from workflow input",
            )
        except BaseException:
            clear_captures(capture_dir)
            raise
    finally:
        os.close(descriptor)
    return result, "sha256:" + expected, reader.size


def validate_capture_directory(path):
    metadata = os.lstat(path)
    require(
        stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o077 == 0,
        "capture directory must be owner-only",
    )
    require(not any(Path(path).iterdir()), "capture directory must be empty")


def validate_inventory(inventory, document):
    available = spdx_inventory(document)
    missing = []
    for kind, identities in inventory.items():
        require(identities, f"no {kind} identities found in bounded inventory")
        missing.extend(
            {"ecosystem": kind, "identity": list(identity)}
            for identity in sorted(identities - available[kind])
        )
    require(not missing, f"SPDX is missing bounded filesystem identities: {missing[:3]}")


def validate_spdx(path, predicate_item, image, architecture, manifest_digest, config_digest):
    raw = read_regular(path, MAX_SBOM_BYTES)
    require(
        sha256(raw) == predicate_item["documentDigest"], "SPDX bytes differ from signed predicate"
    )
    require(len(raw) == predicate_item["size"], "SPDX size differs from signed predicate")
    described = describe_document_bytes(
        raw, path.name, image, architecture, manifest_digest, config_digest
    )
    require(
        described == predicate_item,
        "SPDX root, platform, config, or manifest binding differs from signed predicate",
    )
    return raw, json_object(raw)


def build_go_receipts(
    applications,
    captures,
    document,
    architecture,
    go_tool,
    go_tool_digest,
    *,
    scratch=None,
    max_tool_address_space=None,
):
    captured = {item["path"]: item for item in captures}
    require(
        set(captured) == {item["binary"] for item in applications}, "Go binary capture set mismatch"
    )
    index = GoEvidenceIndex(document)
    receipts = []
    for application in applications:
        capture = captured[application["binary"]]
        build_info, binary_hash, tool_hash = inspect_binary(
            capture["localPath"],
            go_tool,
            architecture,
            scratch=scratch,
            max_address_space=max_tool_address_space,
        )
        require(binary_hash == capture["sha256"], "captured Go binary changed before inspection")
        require(tool_hash == go_tool_digest, "Go metadata tool changed during binary inspection")
        evidence = index.verify(
            build_info,
            architecture=architecture,
            expected_module=application["module"],
            binary_path=application["binary"],
            binary_sha256=binary_hash,
        )
        receipts.append(
            {
                "name": application["name"],
                "binaryPath": application["binary"],
                "binarySha256": binary_hash,
                "spdxFileId": evidence["spdx_file_id"],
                "mainModule": application["module"],
                "pinnedVersion": application["version"],
                "mainSpdxPackageId": evidence["main_spdx_package_id"],
                "dependencyCount": evidence["dependency_count"],
            }
        )
    return receipts, go_tool_digest


def qualify_platform(args):
    require(IMAGE.fullmatch(args.image) is not None and "@" not in args.image, "invalid image name")
    require(CONTAINER_ID.fullmatch(args.container_id) is not None, "invalid container ID")
    validate_capture_directory(args.capture_dir)
    qualification = read_object(args.qualification, 65536)
    predicate = read_object(args.sbom_predicate, 65536)
    validate_shared_identity(qualification, predicate)
    manifest_digest = qualification["platformManifests"][args.architecture]
    predicate_item = predicate["platforms"][args.architecture]
    config_digest, config_arch, diff_ids = validate_manifest_and_config(
        args.manifest, manifest_digest, args.config
    )
    require(config_arch == args.architecture, "image config architecture mismatch")
    require(
        config_digest == predicate_item["configDigest"], "config digest differs from SBOM predicate"
    )
    validate_docker_identity(
        {"image": args.image_inspect, "container": args.container_inspect},
        args.architecture,
        config_digest,
        diff_ids,
        args.container_id,
    )
    _spdx_raw, document = validate_spdx(
        args.spdx,
        predicate_item,
        args.image,
        args.architecture,
        manifest_digest,
        config_digest,
    )
    applications = load_applications(args.applications, args.distro_applications)
    go_tool_digest = validate_go_tool(args.go_tool, args.expected_go_tool_digest)
    scan, rootfs_digest, rootfs_size = scan_bound_rootfs(
        args.rootfs,
        args.expected_rootfs_digest,
        [item["binary"] for item in applications],
        args.capture_dir,
    )

    try:
        require(not scan["unresolved"], f"rootfs evidence is unresolved: {scan['unresolved'][:3]}")
        validate_inventory(scan["inventory"], document)
        go_applications, go_tool_digest = build_go_receipts(
            applications,
            scan["captures"],
            document,
            args.architecture,
            args.go_tool,
            go_tool_digest,
        )
        require(
            isinstance(args.docker_server, str) and args.docker_server.strip(),
            "Docker exporter identity is missing",
        )
        receipt = {
            "schema": "lyrashield.sandbox.sbom-coverage.platform.v1",
            "status": "bounded_scope_matched",
            "policy": POLICY,
            "image": args.image,
            "engineRevision": qualification["engineRevision"],
            "workflowRevision": qualification["workflowRevision"],
            "runId": qualification["runId"],
            "runAttempt": qualification["runAttempt"],
            "indexDigest": qualification["indexDigest"],
            "architecture": args.architecture,
            "manifestDigest": manifest_digest,
            "configDigest": config_digest,
            "containerId": args.container_id,
            "rootfs": {"sha256": rootfs_digest, "size": rootfs_size},
            "spdx": predicate_item,
            "inventoryCounts": {
                "deb": len(scan["inventory"]["deb"]),
                "pypi": len(scan["inventory"]["pypi"]),
                "npm": len(scan["inventory"]["npm"]),
                "goApplications": len(go_applications),
            },
            "goApplications": go_applications,
            "goToolSha256": go_tool_digest,
            "exporter": {"dockerServer": args.docker_server},
            "ignoredLinks": {"count": scan["ignoredLinks"], "policy": LINK_POLICY},
            "scope": SCOPE,
            "limits": LIMITS,
            "limitations": LIMITATIONS,
        }
    finally:
        for capture in scan["captures"]:
            Path(capture["localPath"]).unlink(missing_ok=True)
    return receipt


def validate_receipt(
    receipt,
    architecture,
    qualification,
    predicate,
    image,
    applications,
    expected_go_tool_digest,
    docker_server,
):
    require(
        isinstance(receipt, dict)
        and set(receipt)
        == {
            "schema",
            "status",
            "policy",
            "image",
            "engineRevision",
            "workflowRevision",
            "runId",
            "runAttempt",
            "indexDigest",
            "architecture",
            "manifestDigest",
            "configDigest",
            "containerId",
            "rootfs",
            "spdx",
            "inventoryCounts",
            "goApplications",
            "goToolSha256",
            "exporter",
            "ignoredLinks",
            "scope",
            "limits",
            "limitations",
        },
        f"invalid platform receipt fields: {architecture}",
    )
    require(
        receipt.get("schema") == "lyrashield.sandbox.sbom-coverage.platform.v1"
        and receipt.get("status") == "bounded_scope_matched"
        and receipt.get("policy") == POLICY
        and receipt.get("image") == image
        and receipt.get("architecture") == architecture,
        f"invalid platform receipt: {architecture}",
    )
    for name in ("engineRevision", "workflowRevision", "runId", "runAttempt", "indexDigest"):
        require(receipt.get(name) == qualification.get(name), f"receipt {name} mismatch")
    manifest = qualification["platformManifests"][architecture]
    platform = predicate["platforms"][architecture]
    rootfs = receipt.get("rootfs")
    require(
        receipt.get("manifestDigest") == manifest
        and receipt.get("configDigest") == platform["configDigest"]
        and isinstance(receipt.get("containerId"), str)
        and CONTAINER_ID.fullmatch(receipt["containerId"]) is not None
        and receipt.get("spdx") == platform
        and isinstance(rootfs, dict)
        and set(rootfs) == {"sha256", "size"}
        and isinstance(rootfs.get("sha256"), str)
        and DIGEST.fullmatch(rootfs["sha256"]) is not None
        and type(rootfs.get("size")) is int
        and 0 < rootfs["size"] <= MAX_ROOTFS_EXPORT_BYTES,
        f"receipt evidence mismatch: {architecture}",
    )
    counts = receipt.get("inventoryCounts")
    apps = receipt.get("goApplications")
    require(
        isinstance(counts, dict)
        and set(counts) == {"deb", "pypi", "npm", "goApplications"}
        and all(type(counts.get(key)) is int and counts[key] >= 1 for key in ("deb", "pypi", "npm"))
        and counts.get("goApplications") == 12
        and isinstance(apps, list)
        and [item.get("name") for item in apps if isinstance(item, dict)] == sorted(REQUIRED_APPS),
        f"receipt Go application coverage mismatch: {architecture}",
    )
    expected_apps = {item["name"]: item for item in applications}
    for app in apps:
        require(
            isinstance(app, dict)
            and set(app)
            == {
                "name",
                "binaryPath",
                "binarySha256",
                "spdxFileId",
                "mainModule",
                "pinnedVersion",
                "mainSpdxPackageId",
                "dependencyCount",
            }
            and app["name"] in expected_apps
            and app["binaryPath"] == expected_apps[app["name"]]["binary"]
            and app["mainModule"] == expected_apps[app["name"]]["module"]
            and app["pinnedVersion"] == expected_apps[app["name"]]["version"]
            and isinstance(app["binarySha256"], str)
            and SHA256.fullmatch(app["binarySha256"]) is not None
            and isinstance(app["spdxFileId"], str)
            and app["spdxFileId"].startswith("SPDXRef-")
            and isinstance(app["mainSpdxPackageId"], str)
            and app["mainSpdxPackageId"].startswith("SPDXRef-")
            and type(app["dependencyCount"]) is int
            and app["dependencyCount"] >= 0,
            f"invalid receipt Go application: {architecture}",
        )
    require(
        isinstance(receipt.get("goToolSha256"), str)
        and SHA256.fullmatch(receipt["goToolSha256"]) is not None
        and receipt["goToolSha256"] == expected_go_tool_digest,
        f"invalid Go tool receipt: {architecture}",
    )
    exporter = receipt.get("exporter")
    require(
        isinstance(exporter, dict)
        and set(exporter) == {"dockerServer"}
        and isinstance(exporter.get("dockerServer"), str)
        and re.fullmatch(r"[A-Za-z0-9._+/:-]{1,256}", exporter["dockerServer"]) is not None
        and exporter["dockerServer"] == docker_server,
        f"invalid Docker exporter receipt: {architecture}",
    )
    ignored = receipt.get("ignoredLinks")
    require(
        isinstance(ignored, dict)
        and set(ignored) == {"count", "policy"}
        and type(ignored.get("count")) is int
        and 0 <= ignored["count"] <= MAX_ARCHIVE_ENTRIES
        and ignored.get("policy") == LINK_POLICY,
        f"invalid ignored-link receipt: {architecture}",
    )
    require(
        receipt.get("scope") == SCOPE
        and receipt.get("limits") == LIMITS
        and receipt.get("limitations") == LIMITATIONS,
        f"receipt policy scope differs: {architecture}",
    )


def build_aggregate(
    qualification,
    predicate,
    image,
    applications,
    expected_go_tool_digest,
    docker_server,
    amd64_raw,
    arm64_raw,
):
    receipts = {"amd64": parse_json(amd64_raw), "arm64": parse_json(arm64_raw)}
    require(all(isinstance(item, dict) for item in receipts.values()), "invalid platform receipt")
    for arch in ("amd64", "arm64"):
        validate_receipt(
            receipts[arch],
            arch,
            qualification,
            predicate,
            image,
            applications,
            expected_go_tool_digest,
            docker_server,
        )
    return {
        "schema": "lyrashield.sandbox.sbom-coverage.v1",
        "policy": POLICY,
        "indexDigest": qualification["indexDigest"],
        "engineRevision": qualification["engineRevision"],
        "workflowRevision": qualification["workflowRevision"],
        "runId": qualification["runId"],
        "runAttempt": qualification["runAttempt"],
        "platforms": {
            arch: {
                "receiptDigest": sha256(raw),
                "manifestDigest": qualification["platformManifests"][arch],
                "configDigest": predicate["platforms"][arch]["configDigest"],
                "containerId": receipts[arch]["containerId"],
                "rootfsDigest": receipts[arch]["rootfs"]["sha256"],
                "rootfsSize": receipts[arch]["rootfs"]["size"],
                "spdxDocumentDigest": predicate["platforms"][arch]["documentDigest"],
                "goToolSha256": receipts[arch]["goToolSha256"],
                "exporter": receipts[arch]["exporter"],
                "ignoredLinks": receipts[arch]["ignoredLinks"],
                "goApplications": receipts[arch]["goApplications"],
                "limits": receipts[arch]["limits"],
            }
            for arch, raw in (("amd64", amd64_raw), ("arm64", arm64_raw))
        },
        "requiredGoApplications": sorted(REQUIRED_APPS),
        "scope": SCOPE,
        "limitations": LIMITATIONS,
    }


def write_deterministic(path, result):
    with create_output(path) as output:
        output.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


def deadline_exceeded(_signum, _frame):
    raise TimeoutError("SBOM coverage processing deadline exceeded")


def run_platform(args):
    result = qualify_platform(args)
    write_deterministic(args.output, result)


def run_aggregate(args):
    require(IMAGE.fullmatch(args.image) is not None and "@" not in args.image, "invalid image name")
    qualification = read_object(args.qualification, 65536)
    predicate = read_object(args.sbom_predicate, 65536)
    validate_shared_identity(qualification, predicate)
    applications = load_applications(args.applications, args.distro_applications)
    expected_go_tool_digest = normalize_hash(args.expected_go_tool_digest, prefixed=False)
    require(
        isinstance(args.docker_server, str)
        and re.fullmatch(r"[A-Za-z0-9._+/:-]{1,256}", args.docker_server) is not None,
        "invalid Docker exporter identity",
    )
    result = build_aggregate(
        qualification,
        predicate,
        args.image,
        applications,
        expected_go_tool_digest,
        args.docker_server,
        read_regular(args.amd64_receipt, MAX_INSPECT_BYTES),
        read_regular(args.arm64_receipt, MAX_INSPECT_BYTES),
    )
    write_deterministic(args.output, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    platform = subparsers.add_parser("platform")
    platform.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    platform.add_argument("--image", required=True)
    for name in (
        "qualification",
        "sbom-predicate",
        "manifest",
        "config",
        "image-inspect",
        "container-inspect",
        "rootfs",
        "spdx",
        "go-tool",
        "applications",
        "distro-applications",
        "capture-dir",
        "output",
    ):
        platform.add_argument("--" + name, required=True, type=Path)
    platform.add_argument("--expected-rootfs-digest", required=True)
    platform.add_argument("--expected-go-tool-digest", required=True)
    platform.add_argument("--container-id", required=True)
    platform.add_argument("--docker-server", required=True)
    aggregate = subparsers.add_parser("aggregate")
    for name in (
        "qualification",
        "sbom-predicate",
        "image",
        "applications",
        "distro-applications",
        "amd64-receipt",
        "arm64-receipt",
        "output",
    ):
        aggregate.add_argument("--" + name, required=True, type=str if name == "image" else Path)
    aggregate.add_argument("--expected-go-tool-digest", required=True)
    aggregate.add_argument("--docker-server", required=True)
    args = parser.parse_args()
    if not hasattr(signal, "setitimer") or not hasattr(signal, "SIGALRM"):
        raise RuntimeError("processing deadline requires POSIX interval timers")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("cannot replace an existing processing timer")
    previous = signal.signal(signal.SIGALRM, deadline_exceeded)
    try:
        signal.setitimer(signal.ITIMER_REAL, MAX_PROCESS_SECONDS)
        if args.command == "platform":
            run_platform(args)
        else:
            run_aggregate(args)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print(f"SBOM coverage incomplete: {error}", file=sys.stderr)  # noqa: T201
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
