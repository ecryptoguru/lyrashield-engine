#!/usr/bin/env python3
"""Compare a limited merged-filesystem package inventory against an SPDX SBOM.

This does not establish full SBOM completeness or authenticate either input.
The caller must bind the rootfs and document to the same image manifest.
"""

# ruff: noqa: PLR0912, PLR0915

import argparse
import hashlib
import json
import os
import posixpath
import re
import signal
import sys
import tarfile
from bisect import bisect_left
from collections import defaultdict
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, unquote, urlsplit


MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_TOTAL_METADATA_BYTES = 256 * 1024 * 1024
MAX_METADATA_FILES = 200_000
MAX_SBOM_BYTES = 256 * 1024 * 1024
MAX_LINK_DEPTH = 64
MAX_GUARDED_LINKS = 100_000
LINK_POLICY = {"id": "sandbox-bounded-package-link-policy", "version": 2}
IGNORED_LINK_POLICY = "metadata-safe-aliases-v2"
MAX_ARCHIVE_ENTRIES = 1_000_000
MAX_ARCHIVE_HEADER_BYTES = 64 * 1024
MAX_ARCHIVE_PATH_CHARS = 4096
MAX_TOTAL_PATH_CHARS = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
MAX_IDENTITY_CHARS = 1024
MAX_PURL_CHARS = 4096
MAX_PROCESS_SECONDS = 900
MAX_GO_BINARY_BYTES = 512 * 1024 * 1024
MAX_TOTAL_GO_BINARY_BYTES = 2 * 1024 * 1024 * 1024
NPM_ROOTS = (
    "home/pentester/.npm-tools/node_modules",
    "usr/share/nodejs",
    "usr/local/lib/node_modules",
)
PYTHON_ROOT = re.compile(
    r"(?:(?:usr/lib|usr/local/lib)/python[^/]+/dist-packages|"
    r"app/\.venv/lib/python[^/]+/site-packages)(?=/|\Z)"
)
PYTHON_ANCESTOR = re.compile(
    r"(?:(?:app|app/\.venv|app/\.venv/lib|app/\.venv/lib/python[^/]+)|"
    r"(?:usr|usr/lib|usr/lib/python[^/]+|usr/local|usr/local/lib|"
    r"usr/local/lib/python[^/]+))\Z"
)


def normalize_python(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def metadata_kind(name):
    if name == "var/lib/dpkg/status":
        return "deb"
    if re.fullmatch(
        r"(?:(?:usr/lib|usr/local/lib)/python[^/]+/dist-packages|"
        r"app/\.venv/lib/python[^/]+/site-packages)/[^/]+\.dist-info/METADATA",
        name,
    ):
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


def python_root(name):
    match = PYTHON_ROOT.match(name)
    return match.group(0) if match else None


def scope_inside(name):
    if name == "var/lib/dpkg/status":
        return "deb", name
    for root in NPM_ROOTS:
        if name == root or name.startswith(root + "/"):
            return "npm", root
    root = python_root(name)
    if root is not None:
        return "pypi", root
    return None


def guarded_scope(name, capture_names=()):
    inside = scope_inside(name)
    if inside is not None:
        return inside
    fixed_roots = (*NPM_ROOTS, "var/lib/dpkg/status")
    for root in fixed_roots:
        if root.startswith(name + "/"):
            return ("deb" if root == "var/lib/dpkg/status" else "npm", root)
    if PYTHON_ANCESTOR.fullmatch(name):
        return "pypi", name
    for root in capture_names:
        if root == name or root.startswith(name + "/"):
            return "go", root
    return None


def normalized_link_target(name, linkname):
    if not isinstance(linkname, str) or not linkname:
        return None
    target = posixpath.normpath(
        linkname[1:]
        if linkname.startswith("/")
        else posixpath.join(posixpath.dirname(name), linkname)
    )
    if target in {".", ".."} or target.startswith(("../", "/")):
        return None
    return target


def metadata_probe(name):
    return name.rsplit("/", 1)[-1] in {"package.json", "METADATA"}


def paths_below(sorted_paths, target):
    prefix = target + "/"
    start = bisect_left(sorted_paths, prefix)
    for path in sorted_paths[start:]:
        if not path.startswith(prefix):
            return
        yield path


def resolve_link(name, all_symlinks):
    chain = {name}
    current = all_symlinks[name]
    while current in all_symlinks and current not in chain and len(chain) < MAX_LINK_DEPTH:
        chain.add(current)
        current = all_symlinks[current]
    return current, chain


def directory_alias_is_metadata_safe(
    name,
    target,
    *,
    entry_types,
    parsed_paths,
    metadata_paths,
    symlink_paths,
    capture_names,
):
    if entry_types.get(target) != "directory":
        return False
    for nested_link in paths_below(symlink_paths, target):
        if guarded_scope(nested_link, capture_names) is None:
            return False
    for physical_path in paths_below(metadata_paths, target):
        alias = name + physical_path[len(target) :]
        alias_kind = metadata_kind(alias)
        if alias_kind is None:
            continue
        if (
            metadata_kind(physical_path) != alias_kind
            or entry_types.get(physical_path) != "regular"
            or physical_path not in parsed_paths
        ):
            return False
    return True


def resolve_guarded_links(
    links,
    entry_types,
    parsed_paths,
    unresolved,
    *,
    all_symlinks,
    metadata_paths,
    capture_names,
):
    ignored = 0
    if len(links) > MAX_GUARDED_LINKS:
        raise ValueError("guarded link limit exceeded")
    sorted_symlinks = sorted(all_symlinks)
    sorted_metadata = sorted(metadata_paths)
    for name, (_target, scope) in links.items():
        current, chain = resolve_link(name, all_symlinks)
        kind = metadata_kind(name)
        valid_target = entry_types.get(current) in {"regular", "directory"} and current not in chain
        if not valid_target:
            record_unresolved(unresolved, name, "missing or cyclic archive link")
            continue
        if kind is not None:
            if (
                scope_inside(current) != scope
                or entry_types.get(current) != "regular"
                or metadata_kind(current) != kind
                or current not in parsed_paths
            ):
                record_unresolved(unresolved, name, "unresolved metadata link")
            continue
        if entry_types.get(current) == "directory" and not directory_alias_is_metadata_safe(
            name,
            current,
            entry_types=entry_types,
            parsed_paths=parsed_paths,
            metadata_paths=sorted_metadata,
            symlink_paths=sorted_symlinks,
            capture_names=capture_names,
        ):
            record_unresolved(unresolved, name, "directory link can expose unscanned metadata")
            continue
        ignored += 1
    return ignored


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


def check_pax_framing(payload):
    position, keys = 0, set()
    while position < len(payload):
        separator = payload.find(b" ", position)
        if separator < 0 or not payload[position:separator].isdigit():
            raise ValueError("malformed PAX record")
        record_size = int(payload[position:separator])
        end = position + record_size
        if end > len(payload) or end <= separator + 2:
            raise ValueError("malformed PAX record length")
        record = payload[separator + 1 : end]
        if not record.endswith(b"\n") or b"=" not in record:
            raise ValueError("malformed PAX record")
        key, value = record[:-1].split(b"=", 1)
        if not re.fullmatch(rb"[A-Za-z0-9_.-]+", key) or key in keys:
            raise ValueError("invalid or duplicate PAX key")
        if key == b"size" or key.startswith(b"GNU.sparse.") or key == b"SCHILY.realsize":
            raise ValueError("PAX size and sparse overrides are unsupported")
        if key == b"SCHILY.filetype" and value == b"sparse":
            raise ValueError("PAX sparse overrides are unsupported")
        keys.add(key)
        position = end


class StrictTarReader:
    """Validate uncompressed tar frames as bytes are read, including the trailer."""

    def __init__(self, source):
        self.source = source
        self.partial = bytearray()
        self.payload_remaining = 0
        self.pax_payload = None
        self.zero_blocks = 0
        self.total_bytes = 0

    def consume_block(self, block):
        if self.zero_blocks:
            if any(block):
                raise ValueError("nonzero data after tar end marker")
            self.zero_blocks += 1
            return
        if self.payload_remaining:
            size = min(self.payload_remaining, 512)
            if self.pax_payload is not None:
                self.pax_payload.extend(block[:size])
            if size < 512 and any(block[size:]):
                raise ValueError("nonzero tar payload padding")
            self.payload_remaining -= size
            if not self.payload_remaining and self.pax_payload is not None:
                check_pax_framing(bytes(self.pax_payload))
                self.pax_payload = None
            return
        if not any(block):
            self.zero_blocks = 1
            return
        self.begin_header(block)

    def begin_header(self, block):
        try:
            header = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
        except tarfile.HeaderError as exc:
            raise ValueError("invalid tar header") from exc
        if header.size < 0:
            raise ValueError("negative tar payload size")
        extension_types = {
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        }
        regular_types = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE}
        zero_size_types = {
            tarfile.DIRTYPE,
            tarfile.LNKTYPE,
            tarfile.SYMTYPE,
            tarfile.CHRTYPE,
            tarfile.BLKTYPE,
            tarfile.FIFOTYPE,
        }
        if header.type not in extension_types | regular_types | zero_size_types:
            raise ValueError("unsupported tar entry type")
        if header.type in zero_size_types and header.size:
            raise ValueError("non-file tar entry has payload")
        if header.type in extension_types and header.size > MAX_ARCHIVE_HEADER_BYTES:
            raise ValueError("extended tar header exceeds byte limit")
        self.payload_remaining = header.size
        if header.type in {tarfile.XHDTYPE, tarfile.XGLTYPE}:
            self.pax_payload = bytearray()
            if not self.payload_remaining:
                check_pax_framing(bytes(self.pax_payload))
                self.pax_payload = None

    def feed(self, data):
        self.total_bytes += len(data)
        if self.total_bytes > MAX_ARCHIVE_BYTES:
            raise ValueError("archive byte limit exceeded")
        view = memoryview(data)
        position = 0
        if self.partial:
            take = min(512 - len(self.partial), len(view))
            self.partial.extend(view[:take])
            position += take
            if len(self.partial) == 512:
                self.consume_block(self.partial)
                self.partial.clear()
        while len(view) - position >= 512:
            self.consume_block(view[position : position + 512])
            position += 512
        if position < len(view):
            self.partial.extend(view[position:])

    def read(self, size):
        if size is None or size < 0:
            raise ValueError("unbounded tar read is unsupported")
        data = self.source.read(min(size, 64 * 1024))
        if not isinstance(data, bytes):
            raise TypeError("tar input must be a binary stream")
        self.feed(data)
        return data

    def finish(self):
        while self.read(64 * 1024):
            pass
        if self.partial or self.payload_remaining or self.zero_blocks < 2:
            raise ValueError("incomplete tar framing or end marker")


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


def normalize_capture_paths(paths):
    result = []
    seen = set()
    for value in paths:
        if not isinstance(value, str) or not value.startswith("/"):
            raise ValueError("capture path must be an absolute archive path")
        name = value[1:]
        path = PurePosixPath(name)
        if path.is_absolute() or not name or ".." in path.parts or str(path) != name:
            raise ValueError("unsafe capture path")
        if name in seen:
            raise ValueError("duplicate capture path")
        seen.add(name)
        result.append((value, name))
    return result


def create_capture_file(capture_dir, index):
    target = Path(capture_dir) / f"go-{index:02d}.bin"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    return target, os.fdopen(fd, "w+b")


def capture_archive_file(archive, entry, local_path, output):
    digest = hashlib.sha256()
    size = 0
    source = archive.extractfile(entry)
    if source is None:
        raise ValueError("capture entry has no payload")
    while chunk := source.read(min(1024 * 1024, MAX_GO_BINARY_BYTES + 1 - size)):
        size += len(chunk)
        if size > MAX_GO_BINARY_BYTES:
            raise ValueError("Go binary exceeds individual byte limit")
        digest.update(chunk)
        output.write(chunk)
    if size != entry.size:
        raise ValueError("Go binary size differs from archive header")
    output.flush()
    return {
        "path": "/" + entry.name,
        "sha256": digest.hexdigest(),
        "size": size,
        "localPath": str(local_path),
    }


def iter_uncached_archive(archive):
    # Hardlinks are rejected below; regular-file reads use the TarInfo directly.
    # Explicit next() plus clearing avoids unbounded TarInfo caching in Python <=3.12.
    while True:
        entry = archive.next()
        archive.members.clear()
        if entry is None:
            return
        yield entry


def scan_rootfs(stream, capture_paths=(), capture_dir=None):
    inventory = {"deb": set(), "pypi": set(), "npm": set()}
    unresolved, seen, counts = [], set(), defaultdict(int)
    parsed_paths, links, entry_types = set(), {}, {}
    all_symlinks, metadata_paths = {}, set()
    ignored_links = 0
    captures, seen_captures = [], set()
    normalized_captures = normalize_capture_paths(capture_paths)
    required_captures = {name: display for display, name in normalized_captures}
    capture_indexes = {name: index for index, (_, name) in enumerate(normalized_captures)}
    if required_captures and capture_dir is None:
        raise ValueError("capture directory is required for Go binary capture")
    total_go_bytes = 0
    total_metadata_bytes = 0
    total_path_chars = 0
    framed = StrictTarReader(stream)
    with tarfile.open(fileobj=framed, mode="r|", tarinfo=BoundedTarInfo) as archive:
        for index, entry in enumerate(iter_uncached_archive(archive), 1):
            total_path_chars = validate_archive_entry(index, entry, total_path_chars)
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts:
                record_unresolved(unresolved, entry.name, "unsafe archive path")
                continue
            name = str(path)
            entry_type = (
                "regular"
                if entry.isfile()
                else "directory"
                if entry.isdir()
                else "symlink"
                if entry.issym()
                else "hardlink"
                if entry.islnk()
                else "other"
            )
            if name in entry_types:
                entry_types[name] = "duplicate"
            else:
                entry_types[name] = entry_type
            if metadata_probe(name):
                metadata_paths.add(name)
                if len(metadata_paths) > MAX_METADATA_FILES:
                    raise ValueError("too many package metadata candidates")
            if entry.issym():
                target = normalized_link_target(name, entry.linkname)
                if target is not None:
                    all_symlinks[name] = target
                    if len(all_symlinks) > MAX_GUARDED_LINKS:
                        raise ValueError("archive symlink limit exceeded")
            if name in required_captures:
                if name in seen_captures:
                    record_unresolved(unresolved, "/" + name, "duplicate Go binary entry")
                    continue
                seen_captures.add(name)
                if not entry.isfile() or entry.size < 0 or entry.size > MAX_GO_BINARY_BYTES:
                    record_unresolved(
                        unresolved, "/" + name, "Go binary is not one bounded regular file"
                    )
                    continue
                total_go_bytes += entry.size
                if total_go_bytes > MAX_TOTAL_GO_BINARY_BYTES:
                    raise ValueError("Go binary capture byte limit exceeded")
                local_path, output = create_capture_file(capture_dir, capture_indexes[name])
                with output:
                    try:
                        capture = capture_archive_file(archive, entry, local_path, output)
                    except (OSError, ValueError, TypeError) as error:
                        local_path.unlink(missing_ok=True)
                        record_unresolved(unresolved, "/" + name, type(error).__name__)
                        continue
                captures.append(capture)
            kind = metadata_kind(name)
            if kind is None:
                if entry.issym() or entry.islnk():
                    scope = guarded_scope(name, required_captures)
                    if scope is None:
                        ignored_links += 1
                    elif entry.islnk() or scope_inside(name) is None or name == scope[1]:
                        record_unresolved(unresolved, name, "link at a guarded inventory boundary")
                    else:
                        target = normalized_link_target(name, entry.linkname)
                        if target is None:
                            record_unresolved(
                                unresolved, name, "unsafe or out-of-scope archive link"
                            )
                        else:
                            links[name] = (target, scope)
                continue
            counts[kind] += 1
            if sum(counts.values()) > MAX_METADATA_FILES:
                raise ValueError("too many package metadata files")
            total_metadata_bytes = account_metadata_bytes(total_metadata_bytes, entry.size)
            if name in seen:
                record_unresolved(unresolved, name, "duplicate, non-file or oversized metadata")
                continue
            seen.add(name)
            if entry.issym():
                scope = guarded_scope(name, required_captures)
                if scope is None or name == scope[1] or scope_inside(name) is None:
                    record_unresolved(unresolved, name, "link at a guarded inventory boundary")
                else:
                    target = normalized_link_target(name, entry.linkname)
                    if target is None:
                        record_unresolved(unresolved, name, "unsafe or out-of-scope metadata link")
                    else:
                        links[name] = (target, scope)
                continue
            if entry.islnk():
                record_unresolved(unresolved, name, "hardlink in guarded metadata scope")
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
                detail = re.sub(r"[\x00-\x1f]+", "?", str(exc))[:256] if exc.args else ""
                record_unresolved(unresolved, name, detail or type(exc).__name__)
    framed.finish()
    finish_inventory(inventory, counts, {}, parsed_paths, unresolved)
    ignored_links += resolve_guarded_links(
        links,
        entry_types,
        parsed_paths,
        unresolved,
        all_symlinks=all_symlinks,
        metadata_paths=metadata_paths,
        capture_names=required_captures,
    )
    for name, display_path in required_captures.items():
        if name not in seen_captures:
            record_unresolved(unresolved, display_path, "required Go binary is missing")
    return {
        "inventory": inventory,
        "unresolved": unresolved,
        "counts": {kind: counts[kind] for kind in inventory},
        "captures": captures,
        "ignoredLinks": ignored_links,
    }


def collect_rootfs(stream):
    result = scan_rootfs(stream)
    return result["inventory"], result["unresolved"]


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
