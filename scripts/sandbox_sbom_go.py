"""Verify one Go binary against its file-attributed SPDX evidence slice."""

# ruff: noqa: INP001, PLR0912, TRY004

from __future__ import annotations

import posixpath
import re

from scripts.check_go_sbom_coverage import (
    MAX_DEPENDENCIES,
    MAX_PACKAGES,
    MODULE,
    SPDX_ID,
    identity,
    spdx_package_go_identity,
    validate_go_target,
)


EVIDENT_BY = "evident-by: indicates the package's existence is evident by the given file"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GO_VERSION = re.compile(r"go[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")
MAX_FILES = 200_000
MAX_RELATIONSHIPS = 500_000


def _unique_id(value, field):
    if not isinstance(value, str) or SPDX_ID.fullmatch(value) is None:
        raise ValueError(f"invalid SPDX {field}")
    return value


def _normal_file_name(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("invalid SPDX file name")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise ValueError("unsafe SPDX file name")
    normalized = posixpath.normpath(value)
    if normalized != value or normalized in {".", ".."} or normalized.startswith("../"):
        raise ValueError("non-normalized SPDX file name")
    return value


def _go_identity(package):
    name, version = package.get("name"), package.get("versionInfo")
    try:
        identity = spdx_package_go_identity(package, diagnostic=version == "UNKNOWN")
    except (TypeError, ValueError) as error:
        raise ValueError("invalid Go package identity") from error
    expected = (name, None if version == "UNKNOWN" else version)
    if (
        identity != expected
        or not isinstance(name, str)
        or MODULE.fullmatch(name) is None
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError("package URL is not the expected Go identity")
    return expected


def _validate_stdlib(package, go_version):
    try:
        identity = spdx_package_go_identity(package, diagnostic=True)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid Go standard library evidence") from error
    if (
        identity != ("stdlib", None)
        or not isinstance(go_version, str)
        or GO_VERSION.fullmatch(go_version) is None
        or package.get("versionInfo") != go_version
    ):
        raise ValueError("Go standard library evidence does not match build information")


def _main_and_dependencies(build_info, architecture, expected_module):
    validate_go_target(build_info, architecture)
    dependencies = build_info.get("Deps")
    if not isinstance(dependencies, list) or not 0 < len(dependencies) <= MAX_DEPENDENCIES:
        raise ValueError("Go dependency metadata is missing")
    main = build_info.get("Main")
    direct_main = None
    if isinstance(main, dict) and main.get("Path") is not None:
        if main.get("Path") != expected_module:
            raise ValueError("Go main module does not match the pinned application")
    elif main in ({}, None):
        if build_info.get("Path") != "command-line-arguments":
            raise ValueError("Go build path does not explain the missing main module")
        candidates = [
            (index, dependency)
            for index, dependency in enumerate(dependencies)
            if dependency.get("Path") == expected_module and dependency.get("Version") == "(devel)"
        ]
        if len(candidates) != 1 or candidates[0][1].get("Replace") is not None:
            raise ValueError("direct Go build lacks one exact self module")
        direct_main = candidates[0][0]
    else:
        raise ValueError("invalid Go main module metadata")
    embedded = set()
    declared_names = set()
    for index, dependency in enumerate(dependencies):
        if index == direct_main:
            continue
        if dependency.get("Version") == "(devel)" or dependency.get("Path") == expected_module:
            raise ValueError("ambiguous local Go main module dependency")
        original = identity(dependency)
        if original[0] in declared_names:
            raise ValueError("duplicate Go dependency")
        declared_names.add(original[0])
        replacement = dependency.get("Replace")
        effective = identity(replacement) if replacement is not None else original
        if replacement is not None and replacement.get("Replace") is not None:
            raise ValueError("nested Go replacement")
        if effective in embedded:
            raise ValueError("duplicate effective Go dependency")
        embedded.add(effective)
    return embedded


class GoEvidenceIndex:
    """Validated package-to-file evidence relationships from one SPDX document."""

    def __init__(self, document):
        packages = document.get("packages")
        files = document.get("files")
        relationships = document.get("relationships")
        if (
            not isinstance(packages, list)
            or len(packages) > MAX_PACKAGES
            or not isinstance(files, list)
            or len(files) > MAX_FILES
            or not isinstance(relationships, list)
            or len(relationships) > MAX_RELATIONSHIPS
        ):
            raise ValueError("invalid SPDX package and file inventory")
        self.packages = {}
        seen = set()
        for package in packages:
            if not isinstance(package, dict):
                raise ValueError("invalid SPDX package")
            package_id = _unique_id(package.get("SPDXID"), "package ID")
            if package_id in seen:
                raise ValueError("duplicate SPDX element ID")
            seen.add(package_id)
            self.packages[package_id] = package
        self.files_by_name = {}
        self.files = {}
        for file_entry in files:
            if not isinstance(file_entry, dict):
                raise ValueError("invalid SPDX file")
            file_id = _unique_id(file_entry.get("SPDXID"), "file ID")
            name = file_entry.get("fileName")
            if file_id in seen:
                raise ValueError("duplicate SPDX element ID")
            seen.add(file_id)
            self.files[file_id] = file_entry
            if isinstance(name, str):
                self.files_by_name.setdefault(name, []).append(file_entry)
        self.evident_packages = {}
        seen_relationships = set()
        for relationship in relationships:
            if not isinstance(relationship, dict) or relationship.get("comment") != EVIDENT_BY:
                continue
            package_id = relationship.get("spdxElementId")
            file_id = relationship.get("relatedSpdxElement")
            key = (package_id, file_id)
            if (
                relationship.get("relationshipType") != "OTHER"
                or package_id not in self.packages
                or file_id not in self.files
            ):
                raise ValueError("invalid evident-by relationship direction")
            if key in seen_relationships:
                raise ValueError("duplicate evident-by relationship")
            seen_relationships.add(key)
            self.evident_packages.setdefault(file_id, []).append(package_id)

    def verify(self, build_info, *, architecture, expected_module, binary_path, binary_sha256):
        if not isinstance(build_info, dict):
            raise TypeError("invalid Go build information")
        embedded = _main_and_dependencies(build_info, architecture, expected_module)
        if not isinstance(binary_path, str) or not binary_path.startswith("/"):
            raise ValueError("invalid binary path")
        normalized_binary = binary_path[1:]
        files = [
            item
            for item in self.files_by_name.get(normalized_binary, [])
            if _normal_file_name(item.get("fileName")) == normalized_binary
        ]
        if len(files) != 1:
            raise ValueError("missing or ambiguous SPDX binary file")
        file_entry = files[0]
        sha256 = [
            item.get("checksumValue")
            for item in file_entry.get("checksums", [])
            if isinstance(item, dict) and item.get("algorithm") == "SHA256"
        ]
        if (
            len(sha256) != 1
            or not isinstance(sha256[0], str)
            or not SHA256.fullmatch(sha256[0])
            or sha256[0] != binary_sha256
        ):
            raise ValueError("SPDX binary checksum does not match the captured file")
        linked = self.evident_packages.get(file_entry["SPDXID"], [])
        if not linked:
            raise ValueError("Go binary has no evident-by package evidence")
        identities = {}
        mains = []
        stdlib = []
        for package_id in linked:
            package = self.packages[package_id]
            if package.get("name") == "stdlib":
                _validate_stdlib(package, build_info.get("GoVersion"))
                stdlib.append(package_id)
                continue
            name, version = _go_identity(package)
            if version is None:
                if name != expected_module:
                    raise ValueError("unexpected unversioned package linked to binary")
                mains.append(package_id)
            else:
                identities.setdefault((name, version), []).append(package_id)
        if len(mains) != 1:
            raise ValueError("Go binary must link exactly one main package")
        if len(stdlib) != 1:
            raise ValueError("Go binary must link exactly one standard library package")
        if any(len(package_ids) != 1 for package_ids in identities.values()):
            raise ValueError("duplicate dependency identity linked to Go binary")
        if set(identities) != embedded:
            raise ValueError("linked Go dependency identities differ from build information")
        return {
            "dependency_count": len(embedded),
            "linked_package_count": len(linked),
            "main_spdx_package_id": mains[0],
            "spdx_file_id": file_entry["SPDXID"],
        }


def verify_application(
    document, build_info, *, architecture, expected_module, binary_path, binary_sha256
):
    """Verify one captured Go binary against its exact SPDX file relationship slice."""
    if not isinstance(document, dict):
        raise TypeError("unsupported SPDX document")
    return GoEvidenceIndex(document).verify(
        build_info,
        architecture=architecture,
        expected_module=expected_module,
        binary_path=binary_path,
        binary_sha256=binary_sha256,
    )
