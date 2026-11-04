#!/usr/bin/env python3
"""Compare a limited merged-filesystem package inventory against an SPDX SBOM.

This does not establish full SBOM completeness or authenticate either input.
The caller must bind the rootfs and document to the same image manifest.
"""

import argparse
import json
import os
import posixpath
import re
import signal
import sys
import tarfile
from collections import defaultdict
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, unquote, urlsplit


MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_TOTAL_METADATA_BYTES = 256 * 1024 * 1024
MAX_METADATA_FILES = 200_000
MAX_SBOM_BYTES = 256 * 1024 * 1024
MAX_LINK_DEPTH = 64
MAX_ARCHIVE_ENTRIES = 1_000_000
MAX_ARCHIVE_HEADER_BYTES = 64 * 1024
MAX_ARCHIVE_PATH_CHARS = 4096
MAX_TOTAL_PATH_CHARS = 64 * 1024 * 1024
MAX_IDENTITY_CHARS = 1024
MAX_PURL_CHARS = 4096
MAX_PROCESS_SECONDS = 900
NPM_ROOTS = (
    "home/pentester/.npm-tools/node_modules",
    "usr/share/nodejs",
    "usr/local/lib/node_modules",
)


def normalize_python(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def metadata_kind(name):
    if name == "var/lib/dpkg/status":
        return "deb"
    if re.search(r"(?:^|/)(?:site-packages|dist-packages)/[^/]+\.dist-info/METADATA$", name):
        return "pypi"
    for root in NPM_ROOTS:
        prefix = root + "/"
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


class BoundedTarInfo(tarfile.TarInfo):
    """Bound extension parsing before tarfile reads its payload into memory."""

    def _proc_pax(self, archive):
        if not 0 <= self.size <= MAX_ARCHIVE_HEADER_BYTES:
            raise ValueError("extended tar header exceeds byte limit")
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        if not 0 <= self.size <= MAX_ARCHIVE_HEADER_BYTES:
            raise ValueError("extended tar header exceeds byte limit")
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, _archive):
        raise ValueError("sparse tar entries are unsupported")

    def _proc_gnusparse_00(self, *_args):
        raise ValueError("sparse tar entries are unsupported")

    def _proc_gnusparse_01(self, *_args):
        raise ValueError("sparse tar entries are unsupported")

    def _proc_gnusparse_10(self, *_args):
        raise ValueError("sparse tar entries are unsupported")


def valid_identity(*values):
    return all(
        isinstance(value, str) and value.strip() and len(value) <= MAX_IDENTITY_CHARS
        for value in values
    )


def record_unresolved(unresolved, path, reason):
    if len(unresolved) >= MAX_METADATA_FILES:
        raise ValueError("too many unresolved metadata records")
    unresolved.append({"path": path, "reason": reason})


def reject_duplicate_headers(message, fields):
    for field in fields:
        if len(message.get_all(field, [])) > 1:
            raise ValueError(f"duplicate {field} metadata")


def unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate {key} JSON field")
        result[key] = value
    return result


def add_spdx_reference(result, name, version, ref):
    if not isinstance(ref, dict) or ref.get("referenceType") != "purl":
        return
    purl = ref.get("referenceLocator")
    if not isinstance(purl, str):
        return
    if len(purl) > MAX_PURL_CHARS:
        raise ValueError("SPDX purl exceeds length limit")
    parsed = urlsplit(purl)
    if parsed.scheme != "pkg" or parsed.fragment:
        return
    typed_path, sep, purl_version = unquote(parsed.path).rpartition("@")
    if not sep or purl_version != version:
        return
    if purl.startswith("pkg:deb/"):
        arch = parse_qs(parsed.query).get("arch", [])
        if len(arch) == 1 and valid_identity(arch[0]) and typed_path.rsplit("/", 1)[-1] == name:
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
        if len(name) > MAX_IDENTITY_CHARS or len(version) > MAX_IDENTITY_CHARS:
            raise ValueError("SPDX package identity exceeds length limit")
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
            reject_duplicate_headers(msg, ("Package", "Status", "Version", "Architecture"))
            status = msg.get("Status", "").split()
            if len(status) != 3:
                raise ValueError("invalid Debian status")
            if status[2] != "installed":
                continue
            package, version, arch = msg.get("Package"), msg.get("Version"), msg.get("Architecture")
            if not valid_identity(package, version, arch):
                raise ValueError("missing Debian package identity")
            identities.add((package, version, arch))
    elif kind == "pypi":
        msg = BytesParser().parsebytes(data)
        reject_duplicate_headers(msg, ("Name", "Version"))
        package, version = msg.get("Name"), msg.get("Version")
        if not valid_identity(package, version):
            raise ValueError("missing Python package identity")
        identities.add((normalize_python(package), version))
    else:
        item = json.loads(data, object_pairs_hook=unique_json_pairs)
        package, version = item.get("name"), item.get("version")
        if not valid_identity(package, version):
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
        while target in links and target not in chain and len(chain) < MAX_LINK_DEPTH:
            chain.add(target)
            target = links[target]
        if target not in parsed_paths:
            result.append({"path": name, "reason": "unresolved or cyclic metadata link"})
    return result


def record_npm_metadata_link(name, linkname, links, unresolved):
    target = safe_link_target(name, linkname, "npm")
    if target is None:
        record_unresolved(unresolved, name, "unsafe or out-of-scope metadata link")
    else:
        links[name] = target


def finish_inventory(inventory, counts, links, parsed_paths, unresolved):
    for item in unresolved_links(links, parsed_paths):
        record_unresolved(unresolved, item["path"], item["reason"])
    if counts["deb"] != 1:
        record_unresolved(unresolved, "var/lib/dpkg/status", "expected one Debian status file")
    for kind, entries in inventory.items():
        if not entries:
            record_unresolved(unresolved, kind, "no package identities found in scoped inventory")


def validate_archive_entry(index, entry, total_path_chars):
    if index > MAX_ARCHIVE_ENTRIES:
        raise ValueError("archive entry limit exceeded")
    if len(entry.name) > MAX_ARCHIVE_PATH_CHARS or len(entry.linkname) > MAX_ARCHIVE_PATH_CHARS:
        raise ValueError("archive path exceeds length limit")
    total_path_chars += len(entry.name) + len(entry.linkname)
    if total_path_chars > MAX_TOTAL_PATH_CHARS:
        raise ValueError("archive path budget exceeded")
    return total_path_chars


def account_metadata_bytes(total, size):
    total += max(0, size)
    if total > MAX_TOTAL_METADATA_BYTES:
        raise ValueError("metadata byte limit exceeded")
    return total


def iter_uncached_archive(archive):
    # Hardlinks are rejected below; regular-file reads use the TarInfo directly.
    # Explicit next() plus clearing avoids unbounded TarInfo caching in Python <=3.12.
    while True:
        entry = archive.next()
        archive.members.clear()
        if entry is None:
            return
        yield entry


def collect_rootfs(stream):
    inventory = {"deb": set(), "pypi": set(), "npm": set()}
    unresolved, seen, counts = [], set(), defaultdict(int)
    parsed_paths, links = set(), {}
    total_metadata_bytes = 0
    total_path_chars = 0
    with tarfile.open(fileobj=stream, mode="r|*", tarinfo=BoundedTarInfo) as archive:
        for index, entry in enumerate(iter_uncached_archive(archive), 1):
            total_path_chars = validate_archive_entry(index, entry, total_path_chars)
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts:
                record_unresolved(unresolved, entry.name, "unsafe archive path")
                continue
            name = str(path)
            kind = metadata_kind(name)
            if (entry.issym() or entry.islnk()) and not (kind == "npm" and entry.issym()):
                record_unresolved(unresolved, name, "unresolved archive link")
                continue
            if kind is None:
                continue
            counts[kind] += 1
            if sum(counts.values()) > MAX_METADATA_FILES:
                raise ValueError("too many package metadata files")
            total_metadata_bytes = account_metadata_bytes(total_metadata_bytes, entry.size)
            if name in seen:
                record_unresolved(unresolved, name, "duplicate, non-file or oversized metadata")
                continue
            seen.add(name)
            if entry.issym() and kind == "npm":
                record_npm_metadata_link(name, entry.linkname, links, unresolved)
                continue
            if not entry.isfile() or entry.size < 0 or entry.size > MAX_METADATA_BYTES:
                record_unresolved(unresolved, name, "duplicate, non-file or oversized metadata")
                continue
            file = archive.extractfile(entry)
            data = file.read(MAX_METADATA_BYTES + 1) if file else b""
            if len(data) != entry.size:
                record_unresolved(unresolved, name, "unreadable metadata")
                continue
            try:
                inventory[kind].update(collect_metadata(kind, data))
                parsed_paths.add(name)
            except (ValueError, UnicodeError, AttributeError, TypeError) as exc:
                record_unresolved(unresolved, name, type(exc).__name__)
    finish_inventory(inventory, counts, links, parsed_paths, unresolved)
    return inventory, unresolved


def read_sbom(path):
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_SBOM_BYTES:
        raise ValueError("invalid SBOM size")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SBOM_BYTES + 1)
    if not 0 < len(raw) <= MAX_SBOM_BYTES:
        raise ValueError("invalid SBOM size")
    return raw


def process(args, output):
    document = json.loads(read_sbom(args.sbom), object_pairs_hook=unique_json_pairs)
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
    output.write(json.dumps(result, indent=2) + "\n")
    return 1 if missing or unresolved else 0


def deadline_exceeded(_signum, _frame):
    raise TimeoutError("SBOM inventory processing deadline exceeded")


def create_output(path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        return os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rootfs", required=True, help="Docker-exported merged filesystem tar, or - for stdin"
    )
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not hasattr(signal, "setitimer") or not hasattr(signal, "SIGALRM"):
        raise RuntimeError("processing deadline requires POSIX interval timers")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("cannot replace an existing processing timer")
    previous = signal.signal(signal.SIGALRM, deadline_exceeded)
    try:
        signal.setitimer(signal.ITIMER_REAL, MAX_PROCESS_SECONDS)
        with create_output(args.output) as output:
            return process(args, output)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
