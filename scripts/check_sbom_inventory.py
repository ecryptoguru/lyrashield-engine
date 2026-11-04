#!/usr/bin/env python3
"""Compare a limited merged-filesystem package inventory against an SPDX SBOM.

This does not establish full SBOM completeness or authenticate either input.
The caller must bind the rootfs and document to the same image manifest.
"""

import argparse
import json
import posixpath
import re
import sys
import tarfile
from collections import defaultdict
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, unquote, urlsplit


MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_METADATA_FILES = 200_000
MAX_SBOM_BYTES = 256 * 1024 * 1024


def normalize_python(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def metadata_kind(name):
    if name == "var/lib/dpkg/status":
        return "deb"
    if re.search(r"(?:^|/)(?:site-packages|dist-packages)/[^/]+\.dist-info/METADATA$", name):
        return "pypi"
    prefixes = (
        "home/pentester/.npm-tools/node_modules/",
        "usr/share/nodejs/",
        "usr/local/lib/node_modules/",
    )
    for prefix in prefixes:
        if name.startswith(prefix):
            remaining = name[len(prefix) :]
            if "/node_modules/" in remaining:
                remaining = remaining.rsplit("/node_modules/", 1)[1]
            parts = remaining.split("/")
            if (
                len(parts) == 2 and not parts[0].startswith("@") and parts[-1] == "package.json"
            ) or (len(parts) == 3 and parts[0].startswith("@") and parts[-1] == "package.json"):
                return "npm"
    return None


def add_spdx_reference(result, name, version, ref):
    if not isinstance(ref, dict) or ref.get("referenceType") != "purl":
        return
    purl = ref.get("referenceLocator")
    if not isinstance(purl, str):
        return
    parsed = urlsplit(purl)
    if parsed.scheme != "pkg" or parsed.fragment:
        return
    typed_path, sep, purl_version = unquote(parsed.path).rpartition("@")
    if not sep or purl_version != version:
        return
    if purl.startswith("pkg:deb/"):
        arch = parse_qs(parsed.query).get("arch", [])
        if len(arch) == 1 and typed_path.rsplit("/", 1)[-1] == name:
            result["deb"].add((name, version, arch[0]))
    elif purl.startswith("pkg:pypi/"):
        if normalize_python(typed_path.removeprefix("pypi/")) == normalize_python(name):
            result["pypi"].add((normalize_python(name), version))
    elif purl.startswith("pkg:npm/") and typed_path.removeprefix("npm/") == name:
        result["npm"].add((name, version))


def spdx_inventory(document):
    result = {"deb": set(), "pypi": set(), "npm": set()}
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise TypeError("SPDX packages missing")
    for package in packages:
        if not isinstance(package, dict):
            raise TypeError("invalid SPDX package")
        name, version = package.get("name"), package.get("versionInfo")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        refs = package.get("externalRefs", [])
        if not isinstance(refs, list):
            raise TypeError("invalid SPDX external references")
        for ref in refs:
            add_spdx_reference(result, name, version, ref)
    return result


def collect_metadata(kind, data):
    identities = set()
    if kind == "deb":
        for stanza in re.split(rb"\n\s*\n", data):
            if not stanza.strip():
                continue
            msg = BytesParser().parsebytes(stanza)
            status = msg.get("Status", "").split()
            if len(status) != 3:
                raise ValueError("invalid Debian status")
            if status[2] != "installed":
                continue
            package, version, arch = msg.get("Package"), msg.get("Version"), msg.get("Architecture")
            if not all(isinstance(v, str) and v.strip() for v in (package, version, arch)):
                raise ValueError("missing Debian package identity")
            identities.add((package, version, arch))
    elif kind == "pypi":
        msg = BytesParser().parsebytes(data)
        package, version = msg.get("Name"), msg.get("Version")
        if not all(isinstance(v, str) and v.strip() for v in (package, version)):
            raise ValueError("missing Python package identity")
        identities.add((normalize_python(package), version))
    else:
        item = json.loads(data)
        package, version = item.get("name"), item.get("version")
        if not all(isinstance(v, str) and v.strip() for v in (package, version)):
            raise ValueError("missing npm package identity")
        identities.add((package, version))
    return identities


def safe_link_target(name, linkname, kind):
    target = posixpath.normpath(posixpath.join(posixpath.dirname(name), linkname))
    if (
        linkname.startswith("/")
        or target == ".."
        or target.startswith("../")
        or metadata_kind(target) != kind
    ):
        return None
    return target


def unresolved_links(links, parsed_paths):
    result = []
    for name, initial_target in links.items():
        target = initial_target
        chain = {name}
        while target in links and target not in chain:
            chain.add(target)
            target = links[target]
        if target not in parsed_paths:
            result.append({"path": name, "reason": "unresolved or cyclic metadata link"})
    return result


def collect_rootfs(stream):
    inventory = {"deb": set(), "pypi": set(), "npm": set()}
    unresolved, seen, counts = [], set(), defaultdict(int)
    parsed_paths, links = set(), {}
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for entry in archive:
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts:
                unresolved.append({"path": entry.name, "reason": "unsafe archive path"})
                continue
            name = str(path)
            kind = metadata_kind(name)
            if kind is None:
                continue
            counts[kind] += 1
            if sum(counts.values()) > MAX_METADATA_FILES:
                raise ValueError("too many package metadata files")
            if name in seen:
                unresolved.append(
                    {"path": name, "reason": "duplicate, non-file or oversized metadata"}
                )
                continue
            seen.add(name)
            if entry.issym() and kind == "npm":
                target = safe_link_target(name, entry.linkname, kind)
                if target is None:
                    unresolved.append(
                        {"path": name, "reason": "unsafe or out-of-scope metadata link"}
                    )
                else:
                    links[name] = target
                continue
            if not entry.isfile() or entry.size < 0 or entry.size > MAX_METADATA_BYTES:
                unresolved.append(
                    {"path": name, "reason": "duplicate, non-file or oversized metadata"}
                )
                continue
            file = archive.extractfile(entry)
            data = file.read(MAX_METADATA_BYTES + 1) if file else b""
            if len(data) != entry.size:
                unresolved.append({"path": name, "reason": "unreadable metadata"})
                continue
            try:
                inventory[kind].update(collect_metadata(kind, data))
                parsed_paths.add(name)
            except (ValueError, UnicodeError, AttributeError, TypeError) as exc:
                unresolved.append({"path": name, "reason": type(exc).__name__})
    unresolved.extend(unresolved_links(links, parsed_paths))
    if counts["deb"] != 1:
        unresolved.append(
            {"path": "var/lib/dpkg/status", "reason": "expected one Debian status file"}
        )
    unresolved.extend(
        {"path": kind, "reason": "no package identities found in scoped inventory"}
        for kind, entries in inventory.items()
        if not entries
    )
    return inventory, unresolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rootfs", required=True, help="Docker-exported merged filesystem tar, or - for stdin"
    )
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.sbom.is_file() or not 0 < args.sbom.stat().st_size <= MAX_SBOM_BYTES:
        raise ValueError("invalid SBOM size")
    document = json.loads(args.sbom.read_bytes())
    if not isinstance(document, dict):
        raise TypeError("expected SPDX object")
    available = spdx_inventory(document)
    if args.rootfs == "-":
        inventory, unresolved = collect_rootfs(sys.stdin.buffer)
    else:
        with Path(args.rootfs).open("rb") as stream:
            inventory, unresolved = collect_rootfs(stream)
    missing = [
        {"ecosystem": kind, "identity": list(identity)}
        for kind, entries in inventory.items()
        for identity in sorted(entries - available[kind])
    ]
    result = {
        "schema": "lyrashield.sbom.scoped-inventory.v1",
        "status": "incomplete" if missing or unresolved else "scoped_inventory_matched",
        "inventoryCounts": {kind: len(entries) for kind, entries in inventory.items()},
        "missing": missing,
        "unresolved": unresolved,
        "limitations": [
            "Inputs are caller-supplied and not authenticated or bound to the same image",
            "Checks only installed Debian, Python dist-info and selected npm metadata; "
            "not full SBOM completeness",
        ],
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 1 if missing or unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
