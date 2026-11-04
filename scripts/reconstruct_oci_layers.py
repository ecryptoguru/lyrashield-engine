#!/usr/bin/env python3
"""Restrictive in-memory OCI changeset prototype; never extracts to the host."""

import io
import tarfile
import time
import unicodedata
from dataclasses import dataclass, replace
from typing import Optional

from scripts.check_sbom_inventory import BoundedTarInfo, StrictTarReader, iter_uncached_archive
from scripts.verify_oci_layer_binding import verify


MAX_LAYER_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_PATH_BYTES = 16 * 1024 * 1024
MAX_PATH_LENGTH = 4096
MAX_SCAN_WORK = 10_000_000
MAX_PROCESS_SECONDS = 900
MAX_PAX_BYTES = 16 * 1024


@dataclass(frozen=True)
class Node:
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: Optional[int]  # noqa: UP045 - Python 3.9 support
    content: bytes = b""
    target: str = ""


def normalized_path(name, allow_root=False):
    if not isinstance(name, str) or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ValueError("unsafe path")
    name.encode("utf-8")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if name in {"", "."} and allow_root:
        return ""
    if not name or len(name.encode("utf-8")) > MAX_PATH_LENGTH:
        raise ValueError("invalid path length")
    if any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("ambiguous or traversing path")
    return name


def inert_symlink_target(name):
    """Validate a target as data; never resolve it against the host or image."""
    if isinstance(name, str) and any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in name
    ):
        raise ValueError("invalid symlink target character")
    if isinstance(name, str) and name.startswith("/"):
        if len(name.encode("utf-8")) > MAX_PATH_LENGTH:
            raise ValueError("invalid path length")
        remainder = name[1:]
        if normalized_path(remainder) != remainder:
            raise ValueError("ambiguous symlink target")
        return name
    normalized_path(name)
    return name


def require_parent(tree, path):
    parent = path.rpartition("/")[0]
    if parent not in tree or tree[parent].kind != "dir":
        raise ValueError("missing or non-directory parent")
    return parent


def metadata(entry):
    if (
        type(entry.mode) is not int
        or not 0 <= entry.mode <= 0o7777
        or type(entry.uid) is not int
        or not 0 <= entry.uid <= 0xFFFFFFFF
        or type(entry.gid) is not int
        or not 0 <= entry.gid <= 0xFFFFFFFF
        or type(entry.mtime) is not int
        or entry.mtime < 0
    ):
        raise ValueError("unsupported metadata")
    return entry.mode, entry.uid, entry.gid, entry.mtime


def parse_local_pax(payload):
    """Accept only canonical, nonempty UTF-8 path and linkpath overrides."""
    offset, fields = 0, {}
    while offset < len(payload):
        separator = payload.find(b" ", offset)
        if separator < 0:
            raise ValueError("malformed PAX record")
        digits = payload[offset:separator]
        if not digits.isdigit() or len(digits) > 5:
            raise ValueError("invalid PAX record length")
        size = int(digits)
        end = offset + size
        if str(size).encode() != digits or end > len(payload) or end <= separator + 2:
            raise ValueError("invalid PAX record length")
        record = payload[separator + 1 : end]
        if not record.endswith(b"\n") or b"=" not in record:
            raise ValueError("malformed PAX record")
        key, value = record[:-1].split(b"=", 1)
        if key not in {b"path", b"linkpath"} or key in fields:
            raise ValueError("unsupported or duplicate PAX key")
        if not value or any(byte < 32 or byte == 127 for byte in value):
            raise ValueError("invalid PAX path value")
        decoded = value.decode("utf-8", "strict")
        if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in decoded):
            raise ValueError("invalid PAX path character")
        fields[key] = decoded
        offset = end
    if not fields:
        raise ValueError("empty PAX header")
    return fields


class RestrictiveTarReader(StrictTarReader):
    def __init__(self, source):
        super().__init__(source)
        self.awaiting_pax_member = False
        self.local_pax = None

    def consume_block(self, block):
        if self.pax_payload is not None and self.payload_remaining <= 512:
            payload = bytes(self.pax_payload) + bytes(block[: self.payload_remaining])
            self.local_pax = parse_local_pax(payload)
        super().consume_block(block)

    def begin_header(self, block):
        try:
            header = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
        except tarfile.HeaderError as exc:
            raise ValueError("invalid tar header") from exc
        if header.type not in {
            tarfile.REGTYPE,
            tarfile.AREGTYPE,
            tarfile.DIRTYPE,
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.XHDTYPE,
        }:
            raise ValueError("unsupported tar type or extension")
        if header.type == tarfile.XHDTYPE:
            if self.awaiting_pax_member or not 0 < header.size <= MAX_PAX_BYTES:
                raise ValueError("stacked or invalid PAX header")
            self.awaiting_pax_member = True
            self.local_pax = None
        elif self.awaiting_pax_member:
            if self.local_pax is None:
                raise ValueError("incomplete PAX header")
            path = self.local_pax.get(b"path")
            link = self.local_pax.get(b"linkpath")
            if path is not None:
                if path.endswith("/") and not header.isdir():
                    raise ValueError("non-directory PAX path ends in slash")
                normalized_path(path, allow_root=header.isdir())
            if link is not None:
                if not (header.issym() or header.islnk()) or link.endswith("/"):
                    raise ValueError("invalid PAX linkpath")
                if header.issym():
                    inert_symlink_target(link)
                else:
                    normalized_path(link)
            self.awaiting_pax_member = False
            self.local_pax = None
        super().begin_header(block)

    def finish(self):
        super().finish()
        if self.awaiting_pax_member:
            raise ValueError("PAX header without following member")


class VirtualRoot:
    def __init__(self, deadline=None):
        self.entries = {"": Node("dir", 0o755, 0, 0, None)}
        self.deadline = deadline if deadline is not None else time.monotonic() + MAX_PROCESS_SECONDS

    def check_deadline(self):
        if time.monotonic() > self.deadline:
            raise TimeoutError("reconstruction deadline exceeded")

    def parse(self, raw):  # noqa: PLR0912 - explicit supported archive types
        self.check_deadline()
        if not isinstance(raw, bytes) or len(raw) > MAX_LAYER_BYTES:
            raise ValueError("layer memory limit exceeded")
        framed = RestrictiveTarReader(io.BytesIO(raw))
        staged, seen, path_bytes, total_file_bytes = [], set(), 0, 0
        with tarfile.open(fileobj=framed, mode="r|", tarinfo=BoundedTarInfo) as archive:
            for entry in iter_uncached_archive(archive):
                self.check_deadline()
                if len(seen) >= MAX_ENTRIES:
                    raise ValueError("layer entry limit exceeded")
                path = normalized_path(entry.name, allow_root=entry.isdir())
                if path in seen:
                    raise ValueError("duplicate layer path")
                seen.add(path)
                path_bytes += len(path.encode("utf-8"))
                if path_bytes > MAX_PATH_BYTES:
                    raise ValueError("layer path limit exceeded")
                attrs = metadata(entry)
                if entry.isfile():
                    if not 0 <= entry.size <= MAX_FILE_BYTES:
                        raise ValueError("file size limit exceeded")
                    total_file_bytes += entry.size
                    if total_file_bytes > MAX_TREE_BYTES:
                        raise ValueError("layer file bytes limit exceeded")
                    content = archive.extractfile(entry).read(entry.size + 1)
                    if len(content) != entry.size:
                        raise ValueError("truncated file")
                    node = Node("file", *attrs, content=content)
                elif entry.isdir():
                    node = Node("dir", *attrs)
                elif entry.issym():
                    inert_symlink_target(entry.linkname)
                    path_bytes += len(entry.linkname.encode("utf-8"))
                    node = Node("symlink", *attrs, target=entry.linkname)
                elif entry.islnk():
                    target = normalized_path(entry.linkname)
                    path_bytes += len(entry.linkname.encode("utf-8"))
                    node = Node("hardlink", *attrs, target=target)
                else:
                    raise ValueError("unsupported tar entry")
                if path_bytes > MAX_PATH_BYTES:
                    raise ValueError("layer path limit exceeded")
                staged.append((path, node))
        framed.finish()
        return staged

    def split_changes(self, staged):
        whiteouts, additions = [], []
        for path, node in staged:
            self.check_deadline()
            base = path.rpartition("/")[2]
            if base.startswith(".wh."):
                if node.kind != "file" or node.content or base == ".wh.":
                    raise ValueError("invalid whiteout")
                if base != ".wh..wh..opq" and (
                    base[4:] in {".", ".."} or base[4:].startswith(".wh.")
                ):
                    raise ValueError("invalid whiteout target")
                whiteouts.append((path, base))
            else:
                additions.append((path, node))
        return whiteouts, additions

    def apply_whiteouts(self, tree, whiteouts):
        if len(whiteouts) * len(tree) > MAX_SCAN_WORK:
            raise ValueError("whiteout work limit exceeded")
        touched = set()
        for path, base in whiteouts:
            self.check_deadline()
            parent = require_parent(tree, path)
            if base == ".wh..wh..opq":
                prefix = parent + "/" if parent else ""
                doomed = [name for name in tree if name != parent and name.startswith(prefix)]
            else:
                victim = (parent + "/" if parent else "") + base[4:]
                doomed = [name for name in tree if name == victim or name.startswith(victim + "/")]
            touched.add(parent)
            for name in doomed:
                del tree[name]
        return len(whiteouts) * len(self.entries), touched

    def apply_additions(self, tree, additions, work, touched):
        for path, entry_node in additions:
            self.check_deadline()
            node = entry_node
            if not path:
                if node.kind != "dir":
                    raise ValueError("invalid root entry")
                tree[path] = node
                continue
            parent = require_parent(tree, path)
            prior = tree.get(path)
            if prior is None or prior.kind != "dir" or node.kind != "dir":
                touched.add(parent)
            if prior and prior.kind == "dir" and node.kind != "dir":
                work += len(tree)
                if work > MAX_SCAN_WORK:
                    raise ValueError("directory replacement work limit exceeded")
                if any(name.startswith(path + "/") for name in tree):
                    raise ValueError("nonempty directory replacement unsupported")
            if node.kind == "hardlink":
                if node.target == path:
                    raise ValueError("self hardlink is unsupported")
                target = tree.get(node.target)
                if target is None or target.kind != "file":
                    raise ValueError("unresolved or non-file hardlink")
                if (node.mode, node.uid, node.gid, node.mtime) != (
                    target.mode,
                    target.uid,
                    target.gid,
                    target.mtime,
                ):
                    raise ValueError("hardlink metadata differs from target")
                node = target
            tree[path] = node
            if len(tree) > MAX_ENTRIES:
                raise ValueError("tree entry limit exceeded")

    def apply(self, raw):
        whiteouts, additions = self.split_changes(self.parse(raw))
        tree = self.entries.copy()
        work, touched = self.apply_whiteouts(tree, whiteouts)
        self.apply_additions(tree, additions, work, touched)
        for path in touched:
            node = tree.get(path)
            if node is not None and node.kind == "dir":
                tree[path] = replace(node, mtime=None)
        if sum(len(node.content) for node in tree.values() if node.kind == "file") > MAX_TREE_BYTES:
            raise ValueError("tree byte limit exceeded")
        if (
            sum(
                len(path.encode("utf-8"))
                + (len(node.target.encode("utf-8")) if node.kind == "symlink" else 0)
                for path, node in tree.items()
            )
            > MAX_PATH_BYTES
        ):
            raise ValueError("tree path limit exceeded")
        self.entries = tree


class VerifiedLayerReceiver:
    def __init__(self):
        self.root = VirtualRoot()
        self.buffer = bytearray()

    def begin(self):
        self.buffer.clear()

    def write(self, data):
        self.root.check_deadline()
        if len(self.buffer) + len(data) > MAX_LAYER_BYTES:
            raise ValueError("layer memory limit exceeded")
        self.buffer.extend(data)

    def finish(self):
        self.root.apply(bytes(self.buffer))
        self.buffer.clear()


def reconstruct_verified(directory, manifest_digest, platform):
    """Return a virtual tree only after every input layer's exact bytes have verified."""
    receiver = VerifiedLayerReceiver()
    report = verify(directory, manifest_digest, platform, receiver=receiver)
    return report, receiver.root
