"""Compare versioned Go build dependencies with SPDX; not an image qualification."""

# ruff: noqa: INP001
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import resource
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote


MAX_BINARY = 512 * 1024 * 1024
MAX_SBOM = 128 * 1024 * 1024
MAX_TOOL_OUTPUT = 16 * 1024 * 1024
MAX_DEPENDENCIES = 20_000
MAX_PACKAGES = 200_000
ARCHITECTURES = {"amd64": 62, "arm64": 183}
MODULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~+/-]{0,1023}\Z")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?\Z")
SPDX_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]{1,1024}\Z")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def json_constant(_value):
    raise ValueError("nonstandard JSON constant")


def json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def json_int(value):
    if len(value) > 64:
        raise ValueError("JSON integer exceeds bound")
    return int(value)


def parse_json(data):
    return json.loads(
        data,
        object_pairs_hook=unique_pairs,
        parse_constant=json_constant,
        parse_float=json_float,
        parse_int=json_int,
    )


def identity(value):
    if not isinstance(value, dict):
        raise TypeError("invalid module metadata")
    name, version = value.get("Path"), value.get("Version")
    if (
        not isinstance(name, str)
        or not MODULE.fullmatch(name)
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or not isinstance(version, str)
        or len(version) > 1024
        or not VERSION.fullmatch(version)
    ):
        raise ValueError("unresolved module identity")
    return name, version


def spdx_package_go_identity(package):
    name, version = package.get("name"), package.get("versionInfo")
    references = package.get("externalRefs", [])
    if not isinstance(references, list):
        raise TypeError("invalid SPDX references")
    purls = []
    for reference in references:
        if not isinstance(reference, dict) or any(
            not isinstance(reference.get(field), str)
            or not reference[field]
            or len(reference[field]) > 4096
            for field in ("referenceCategory", "referenceType", "referenceLocator")
        ):
            raise ValueError("malformed SPDX reference")
        if reference["referenceType"] == "purl":
            purls.append(reference)
    if len(purls) > 1:
        raise ValueError("conflicting SPDX purls")
    if not purls or not purls[0]["referenceLocator"].startswith("pkg:golang/"):
        return None
    identity({"Path": name, "Version": version})
    expected = f"pkg:golang/{quote(name, safe='/')}@{quote(version, safe='.-_~')}"
    if purls[0]["referenceLocator"] != expected:
        raise ValueError("Go purl identity mismatch")
    if purls[0]["referenceCategory"] != "PACKAGE-MANAGER":
        return None
    return name, version


def spdx_go_inventory(document):
    if not isinstance(document, dict):
        raise TypeError("unsupported SPDX document")
    if document.get("_type") == "https://in-toto.io/Statement/v1":
        if document.get("predicateType") != "https://spdx.dev/Document":
            raise ValueError("unsupported SPDX statement")
        document = document.get("predicate")
    if (
        not isinstance(document, dict)
        or document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise ValueError("unsupported SPDX document")
    packages = document.get("packages")
    if not isinstance(packages, list) or len(packages) > MAX_PACKAGES:
        raise ValueError("invalid SPDX package inventory")
    inventory = {}
    seen_ids = set()
    for package in packages:
        if not isinstance(package, dict):
            raise TypeError("invalid SPDX package")
        package_id = package.get("SPDXID")
        if not isinstance(package_id, str) or not SPDX_ID.fullmatch(package_id):
            raise ValueError("invalid SPDX package ID")
        if package_id in seen_ids or package_id == "SPDXRef-DOCUMENT":
            raise ValueError("duplicate SPDX package ID")
        seen_ids.add(package_id)
        go_identity = spdx_package_go_identity(package)
        if go_identity is not None:
            inventory.setdefault(go_identity, set()).add(package_id)
    return inventory


def validate_go_target(build_info, architecture):
    if not isinstance(build_info, dict):
        raise TypeError("invalid Go build information")
    if architecture not in ARCHITECTURES:
        raise ValueError("invalid architecture")
    settings = build_info.get("Settings")
    if not isinstance(settings, list):
        raise TypeError("Go target settings missing")
    target = {}
    for setting in settings:
        if not isinstance(setting, dict):
            raise TypeError("invalid Go setting")
        key = setting.get("Key")
        if key in {"GOOS", "GOARCH"}:
            if key in target:
                raise ValueError("duplicate Go target setting")
            target[key] = setting.get("Value")
    if target != {"GOOS": "linux", "GOARCH": architecture}:
        raise ValueError("Go target does not match requested architecture")


def compare_go_dependencies(build_info, document, architecture):
    validate_go_target(build_info, architecture)
    dependencies = build_info.get("Deps")
    if not isinstance(dependencies, list) or not 0 < len(dependencies) <= MAX_DEPENDENCIES:
        raise ValueError("versioned Go dependencies missing")
    embedded = set()
    declared_names = set()
    for dependency in dependencies:
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
    inventory = spdx_go_inventory(document)
    if embedded - inventory.keys():
        raise ValueError("SPDX is missing an embedded Go dependency")
    if any(len(inventory[item]) != 1 for item in embedded):
        raise ValueError("SPDX contains ambiguous Go dependency entries")
    return {"dependency_count": len(embedded), "matched_count": len(embedded)}


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise ValueError("input size or type is invalid")
        chunks, size = [], 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise ValueError("input size exceeds bound")
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if not data or len(data) > limit:
        raise ValueError("input size exceeds bound")
    return data


def limit_tool_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TOOL_OUTPUT, MAX_TOOL_OUTPUT))


def digest_file(path):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_BINARY:
            raise ValueError("invalid trusted Go tool")
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > MAX_BINARY:
                raise ValueError("trusted Go tool exceeds bound")
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def inspect_binary(binary, go_tool, architecture):
    if architecture not in ARCHITECTURES or not Path(go_tool).is_absolute():
        raise ValueError("invalid tool or architecture")
    tool_hash = digest_file(go_tool)
    fd = os.open(binary, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 20 <= metadata.st_size <= MAX_BINARY:
            raise ValueError("invalid binary size or type")
        with tempfile.TemporaryFile() as snapshot, tempfile.TemporaryFile() as output:
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(fd, 1024 * 1024):
                size += len(chunk)
                if size > MAX_BINARY:
                    raise ValueError("binary exceeds bound")
                digest.update(chunk)
                snapshot.write(chunk)
            if size != metadata.st_size:
                raise ValueError("binary changed while reading")
            snapshot.flush()
            snapshot.seek(0)
            header = snapshot.read(20)
            if (
                header[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(header[16:18], "little") not in {2, 3}
                or int.from_bytes(header[18:20], "little") != ARCHITECTURES[architecture]
            ):
                raise ValueError("ELF architecture mismatch")
            snapshot.seek(0)
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "GOTOOLCHAIN": "local",
                "GOPROXY": "off",
                "GOSUMDB": "off",
                "GOENV": "off",
                "GOWORK": "off",
                "LC_ALL": "C",
            }
            # The operator supplies a trusted Go tool. The copied target is only read.
            subprocess.run(  # noqa: S603
                [str(go_tool), "version", "-m", "-json", f"/dev/fd/{snapshot.fileno()}"],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env=env,
                timeout=30,
                check=True,
                pass_fds=(snapshot.fileno(),),
                preexec_fn=limit_tool_output,
            )
            output.seek(0)
            result = output.read(MAX_TOOL_OUTPUT + 1)
            if not result or len(result) > MAX_TOOL_OUTPUT:
                raise ValueError("Go build information exceeds bound")
            if digest_file(go_tool) != tool_hash:
                raise ValueError("Go tool changed while inspecting")
            return parse_json(result), digest.hexdigest(), tool_hash
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--spdx", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--go", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = read_bounded(args.spdx, MAX_SBOM)
        document = parse_json(raw)
        info, binary_hash, tool_hash = inspect_binary(args.binary, args.go, args.architecture)
        result = compare_go_dependencies(info, document, args.architecture)
        result.update(
            {
                "scope": "versioned-go-dependencies-only",
                "architecture": args.architecture,
                "binary_sha256": binary_hash,
                "go_tool_sha256": tool_hash,
                "spdx_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        print(json.dumps(result, sort_keys=True))  # noqa: T201 - machine-readable local result
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print(f"Go dependency coverage incomplete: {error}", file=sys.stderr)  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
