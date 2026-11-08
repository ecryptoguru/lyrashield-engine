"""Unwired, bounded catalog of opaque capability PAX header observations.

This is a one-layer archive-record observation, not OCI extraction or an inode,
overlay, capability-validity, package-completeness or release qualification.
"""

# ruff: noqa: INP001
import hashlib
import tarfile
import time
from dataclasses import dataclass, field
from typing import Optional

from scripts.check_sbom_inventory import StrictTarReader
from scripts.probe_pax_capability import MAX_LAYER_BYTES, MAX_SECONDS
from scripts.reconstruct_oci_layers import (
    inert_symlink_target,
    metadata,
    normalized_path,
    parse_local_pax,
    validate_member_trailing_slash,
)
from scripts.verify_oci_layer_binding import DIGEST


CAP = b"SCHILY.xattr.security.capability"
MAX_PAX_BYTES = 16 * 1024
MAX_VALUE_BYTES = 4 * 1024
MAX_TOTAL_PAX_BYTES = 4 * 1024 * 1024
MAX_OBSERVATIONS = 1024
MAX_ENTRIES = 100_000
MAX_PATH_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class HeaderObservation:
    path: str = field(repr=False)
    kind: str
    target: str = field(repr=False)
    pax_header_offset: int
    member_header_offset: int
    pax_payload: bytes = field(repr=False)
    value: bytes = field(repr=False)


@dataclass(frozen=True)
class LayerMember:
    """One inert archive member; no entry has been applied to a filesystem."""

    path: str = field(repr=False)
    kind: str
    target: str = field(repr=False)
    member_header_offset: int
    data_offset: Optional[int]  # noqa: UP045 - Python 3.9 support
    size: int
    mode: int
    uid: int
    gid: int
    mtime: int
    pax_header_offset: Optional[int]  # noqa: UP045 - Python 3.9 support
    pax_payload: Optional[bytes] = field(repr=False)  # noqa: UP045 - Python 3.9 support
    capability_value: Optional[bytes] = field(repr=False)  # noqa: UP045 - Python 3.9 support


def parse_records(payload):
    """Parse bounded exact PAX bytes without decoding capability metadata."""
    if not 0 < len(payload) <= MAX_PAX_BYTES:
        raise ValueError("PAX byte limit exceeded")
    offset, seen, overrides, value = 0, set(), {}, None
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
        body = payload[separator + 1 : end]
        if not body.endswith(b"\n") or b"=" not in body:
            raise ValueError("malformed PAX record")
        key, raw = body[:-1].split(b"=", 1)
        if key in seen or key not in {b"path", b"linkpath", CAP}:
            raise ValueError("unsupported or duplicate PAX key")
        seen.add(key)
        if key == CAP:
            if not 0 < len(raw) <= MAX_VALUE_BYTES:
                raise ValueError("capability value limit exceeded")
            value = raw
        else:
            try:
                overrides.update(parse_local_pax(payload[offset:end]))
            except UnicodeError:
                raise ValueError("invalid PAX path encoding") from None
        offset = end
    return overrides, value


class HeaderReader(StrictTarReader):
    def __init__(self, *, linux_literal_paths=False):
        super().__init__(None)
        if type(linux_literal_paths) is not bool:
            raise ValueError("invalid path policy")
        self.linux_literal_paths = linux_literal_paths
        self.offset = 0
        self.awaiting_member = False
        self.pending = None
        self.pax_offset = None
        self.observations = []
        self.total_pax_bytes = 0
        self.paths = set()
        self.path_bytes = 0

    def consume_block(self, block):
        if self.pax_payload is not None and self.payload_remaining <= 512:
            payload = bytes(self.pax_payload) + bytes(block[: self.payload_remaining])
            overrides, value = parse_records(payload)
            self.pending = overrides, value, payload
        super().consume_block(block)
        self.offset += 512

    def begin_header(self, block):  # noqa: PLR0912 - closed tar member type dispatch
        try:
            entry = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
        except tarfile.HeaderError:
            raise ValueError("invalid tar header") from None
        if entry.type == tarfile.XHDTYPE:
            if self.awaiting_member or not 0 < entry.size <= MAX_PAX_BYTES:
                raise ValueError("stacked or invalid PAX header")
            self.awaiting_member = True
            self.pending = None
            self.pax_offset = self.offset
        else:
            if entry.type not in {
                tarfile.REGTYPE,
                tarfile.AREGTYPE,
                tarfile.DIRTYPE,
                tarfile.SYMTYPE,
                tarfile.LNKTYPE,
            }:
                raise ValueError("unsupported tar entry type")
            if self.awaiting_member and self.pending is None:
                raise ValueError("incomplete PAX association")
            overrides, value, payload = self.pending if self.awaiting_member else ({}, None, None)
            effective = overrides.get(b"path", entry.name)
            validate_member_trailing_slash(effective, is_directory=entry.isdir())
            try:
                path = normalized_path(
                    effective,
                    allow_root=entry.isdir(),
                    linux_literal_paths=self.linux_literal_paths,
                )
                target = overrides.get(b"linkpath", entry.linkname)
                if b"linkpath" in overrides and not (entry.issym() or entry.islnk()):
                    raise ValueError("invalid PAX linkpath")
                if entry.issym():
                    target = inert_symlink_target(target)
                elif entry.islnk():
                    if target.endswith("/"):
                        raise ValueError("invalid hardlink target")
                    target = normalized_path(target, linux_literal_paths=self.linux_literal_paths)
                else:
                    target = ""
            except UnicodeError:
                raise ValueError("invalid member encoding") from None
            if path in self.paths or len(self.paths) >= MAX_ENTRIES:
                raise ValueError("duplicate path or entry limit exceeded")
            self.paths.add(path)
            self.path_bytes += len(path.encode("utf-8")) + len(target.encode("utf-8"))
            if self.path_bytes > MAX_PATH_BYTES:
                raise ValueError("path byte limit exceeded")
            if value is not None:
                if not (entry.isfile() or entry.issym()) or path.rpartition("/")[2].startswith(
                    ".wh."
                ):
                    raise ValueError("unsupported capability member type")
                self.total_pax_bytes += len(payload)
                if (
                    len(self.observations) >= MAX_OBSERVATIONS
                    or self.total_pax_bytes > MAX_TOTAL_PAX_BYTES
                ):
                    raise ValueError("capability aggregate limit exceeded")
                self.observations.append(
                    HeaderObservation(
                        path,
                        "file" if entry.isfile() else "symlink",
                        target,
                        self.pax_offset,
                        self.offset,
                        payload,
                        value,
                    )
                )
            self.awaiting_member = False
            self.pending = None
            self.pax_offset = None
        super().begin_header(block)

    def complete(self):
        if self.partial or self.payload_remaining or self.zero_blocks < 2 or self.awaiting_member:
            raise ValueError("incomplete tar framing or PAX association")


class ChangesetReader(HeaderReader):
    """Collect supported member headers as inert, provisional metadata."""

    def __init__(self, *, linux_literal_paths=False):
        super().__init__(linux_literal_paths=linux_literal_paths)
        self.members = []

    def begin_header(self, block):
        try:
            entry = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
        except tarfile.HeaderError:
            raise ValueError("invalid tar header") from None
        if entry.type == tarfile.XHDTYPE:
            super().begin_header(block)
            return

        offsets = self.pax_offset, self.offset
        pending = self.pending if self.awaiting_member else None
        overrides, value, payload = pending if pending is not None else ({}, None, None)
        super().begin_header(block)
        path = normalized_path(
            overrides.get(b"path", entry.name),
            allow_root=entry.isdir(),
            linux_literal_paths=self.linux_literal_paths,
        )
        target = overrides.get(b"linkpath", entry.linkname)
        if entry.issym():
            kind, target = "symlink", inert_symlink_target(target)
        elif entry.islnk():
            kind = "hardlink"
            target = normalized_path(target, linux_literal_paths=self.linux_literal_paths)
        elif entry.isdir():
            kind, target = "dir", ""
        else:
            kind, target = "file", ""
        parent, _, base = path.rpartition("/")
        if base.startswith(".wh."):
            if kind != "file" or entry.size or base == ".wh.":
                raise ValueError("invalid whiteout")
            if base == ".wh..wh..opq":
                kind, target = "opaque", parent
            else:
                name = base[4:]
                if name in {".", ".."} or name.startswith(".wh."):
                    raise ValueError("invalid whiteout target")
                kind, target = "whiteout", f"{parent}/{name}" if parent else name
        mode, uid, gid, mtime = metadata(entry)
        self.members.append(
            LayerMember(
                path,
                kind,
                target,
                offsets[1],
                offsets[1] + 512 if kind == "file" else None,
                entry.size,
                mode,
                uid,
                gid,
                mtime,
                offsets[0],
                payload if value is not None else None,
                value,
            )
        )


def _read_verified(stream, expected_diff, reader):
    if not isinstance(expected_diff, str) or not DIGEST.fullmatch(expected_diff):
        raise ValueError("invalid expected diff ID")
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + MAX_SECONDS
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("catalog deadline exceeded")
        data = stream.read(64 * 1024)
        if not isinstance(data, bytes) or len(data) > 64 * 1024:
            raise ValueError("invalid bounded input")
        if not data:
            break
        total += len(data)
        if total > MAX_LAYER_BYTES:
            raise ValueError("layer byte limit exceeded")
        digest.update(data)
        reader.feed(data)
    reader.complete()
    if "sha256:" + digest.hexdigest() != expected_diff:
        raise ValueError("layer diff ID mismatch")


def inspect_layer(stream, expected_diff, *, linux_literal_paths=False):
    """Return raw observations only after complete framing and a matching DiffID.

    The caller must separately authenticate the expected DiffID, compressed
    descriptor and producer exit and enforce a wall timeout for blocked reads.
    Paths, targets, values and raw payloads may be sensitive; do not log them.
    """
    reader = HeaderReader(linux_literal_paths=linux_literal_paths)
    _read_verified(stream, expected_diff, reader)
    return tuple(reader.observations)


def inspect_layer_changeset(stream, expected_diff, *, linux_literal_paths=False):
    """Return inert layer members only after framing and a matching DiffID.

    This is not a final image, capability interpretation or release proof.
    The caller must authenticate the expected DiffID and compressed descriptor,
    check the producer exit, and supervise blocking I/O. Paths, targets and raw
    capability records are sensitive. Do not log or materialize them.
    """
    reader = ChangesetReader(linux_literal_paths=linux_literal_paths)
    _read_verified(stream, expected_diff, reader)
    return tuple(reader.members)
