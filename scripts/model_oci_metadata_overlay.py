"""Unwired offline metadata model; not a Linux overlay or release qualification.

Only `model_verified_image` binds local blob bytes to the supplied manifest and
config. The caller must independently authenticate the manifest and platform.
Raw names, link targets and capability headers are sensitive inert data; do not
log, serialize, follow or materialize them. Runtime xattr and hardlink semantics
are not established. External RSS, CPU, descriptor and wall-time limits remain
mandatory, including for blocked I/O and any long individual library call.
"""

# ruff: noqa: INP001
import time
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Optional

from scripts.catalog_pax_capability_headers import ChangesetReader, LayerMember, parse_records
from scripts.probe_pax_capability import MAX_LAYER_BYTES
from scripts.reconstruct_oci_layers import (
    inert_symlink_target,
    normalized_path,
    require_parent,
)
from scripts.verify_oci_layer_binding import MAX_SECONDS, verify
from scripts.verify_pax_capability_stream import MAX_CHANGESET_RECORD_BYTES, MAX_CHANGESET_RECORDS


MAX_OVERLAY_ENTRIES = 100_000
MAX_OVERLAY_BYTES = 64 * 1024**2
MAX_SCAN_WORK = 10_000_000


@dataclass(frozen=True)
class SymbolicInode:
    """A model-only file identity, not evidence of an actual Linux inode."""

    source_layer: int
    data_offset: int
    size: int
    mode: int
    uid: int
    gid: int
    mtime: int
    capability_header: Optional[bytes] = field(repr=False)  # noqa: UP045 - Python 3.9
    capability_state: str = "unknown"


@dataclass(frozen=True)
class MetadataEntry:
    kind: str
    mode: Optional[int]  # noqa: UP045 - Python 3.9
    uid: Optional[int]  # noqa: UP045 - Python 3.9
    gid: Optional[int]  # noqa: UP045 - Python 3.9
    mtime: Optional[int]  # noqa: UP045 - Python 3.9
    target: str = field(default="", repr=False)
    inode: Optional[SymbolicInode] = field(default=None, repr=False)  # noqa: UP045 - Python 3.9
    capability_header: Optional[bytes] = field(default=None, repr=False)  # noqa: UP045
    capability_state: str = "unknown"


@dataclass(frozen=True)
class MetadataOverlayResult:
    manifest_digest: str
    config_digest: str
    platform: str
    layers: tuple
    entries: MappingProxyType = field(repr=False)
    runtime_equivalent: bool = False
    release_qualified: bool = False


class MetadataRoot:
    """Transactional virtual state for already-verified supported members only.

    Calling this object directly does not authenticate or verify its inputs.
    """

    def __init__(self, *, linux_literal_paths=False, deadline=None):
        if type(linux_literal_paths) is not bool:
            raise ValueError("invalid path policy")
        self.linux_literal_paths = linux_literal_paths
        self.deadline = time.monotonic() + MAX_SECONDS if deadline is None else deadline
        self.entries = {"": MetadataEntry("dir", None, None, None, None)}
        self.next_layer = 0

    def check_deadline(self):
        if time.monotonic() > self.deadline:
            raise TimeoutError("metadata overlay deadline exceeded")

    def check_extent(self, member, previous_end, layer_size):
        if (
            type(member.member_header_offset) is not int
            or member.member_header_offset < previous_end
            or member.member_header_offset % 512
            or member.member_header_offset + 512 > layer_size
        ):
            raise ValueError("invalid member offset")
        if type(member.size) is not int or member.size < 0:
            raise ValueError("invalid member size")
        if member.kind == "file":
            if (
                type(member.data_offset) is not int
                or member.data_offset != member.member_header_offset + 512
                or member.data_offset + ((member.size + 511) // 512) * 512 > layer_size
                or member.target != ""
            ):
                raise ValueError("invalid file extent")
        elif member.data_offset is not None or member.size:
            raise ValueError("invalid non-file extent")
        if member.pax_header_offset is not None:
            if (
                type(member.pax_header_offset) is not int
                or member.pax_header_offset < previous_end
                or member.pax_header_offset % 512
                or member.pax_header_offset + 1024 > member.member_header_offset
            ):
                raise ValueError("invalid PAX offset")
            if member.pax_payload is not None:
                if type(member.pax_payload) is not bytes:
                    raise ValueError("invalid capability association")
                payload_blocks = (len(member.pax_payload) + 511) // 512
                if (
                    member.pax_header_offset + (payload_blocks + 1) * 512
                    != member.member_header_offset
                ):
                    raise ValueError("invalid PAX extent")
        if member.kind == "file":
            return member.data_offset + ((member.size + 511) // 512) * 512
        return member.member_header_offset + 512

    def check_target(self, member, path):
        if member.kind == "hardlink":
            if (
                normalized_path(member.target, linux_literal_paths=self.linux_literal_paths)
                != member.target
            ):
                raise ValueError("invalid hardlink target")
        elif member.kind == "symlink":
            if inert_symlink_target(member.target) != member.target:
                raise ValueError("invalid symlink target")
        elif member.kind in {"file", "dir"} and member.target != "":
            raise ValueError("unexpected member target")
        if member.kind in {"whiteout", "opaque"}:
            parent, _, base = path.rpartition("/")
            if member.kind == "opaque":
                expected = parent if base == ".wh..wh..opq" else None
            else:
                name = base[4:] if base.startswith(".wh.") else ""
                expected = (f"{parent}/{name}" if parent else name) if name else None
                if name in {".", ".."} or name.startswith(".wh."):
                    expected = None
            if expected is None or member.target != expected:
                raise ValueError("invalid whiteout marker")
        elif path.rpartition("/")[2].startswith(".wh."):
            raise ValueError("unclassified whiteout marker")

    def check_capability(self, member, path):
        for value in (member.mode, member.uid, member.gid, member.mtime):
            if type(value) is not int or value < 0:
                raise ValueError("invalid member metadata")
        if member.mode > 0o7777 or member.uid > 0xFFFFFFFF or member.gid > 0xFFFFFFFF:
            raise ValueError("invalid member metadata")
        cap = member.capability_value
        if cap is not None and (type(cap) is not bytes or not 0 < len(cap) <= 4096):
            raise ValueError("invalid capability header")
        if cap is not None and member.kind not in {"file", "symlink"}:
            raise ValueError("unsupported capability member")
        if (member.pax_payload is None) != (cap is None):
            raise ValueError("incomplete capability association")
        if member.pax_payload is not None:
            if type(member.pax_payload) is not bytes:
                raise ValueError("invalid capability association")
            overrides, parsed_capability = parse_records(member.pax_payload)
            if parsed_capability != cap:
                raise ValueError("invalid capability association")
            if (
                b"path" in overrides
                and normalized_path(
                    overrides[b"path"], linux_literal_paths=self.linux_literal_paths
                )
                != path
            ):
                raise ValueError("invalid capability path association")
            if b"linkpath" in overrides and (
                member.kind != "symlink" or overrides[b"linkpath"] != member.target
            ):
                raise ValueError("invalid capability link association")
        if cap is not None and member.pax_header_offset is None:
            raise ValueError("missing capability PAX header")

    def checked_members(self, members, layer_index, layer_size):
        if type(layer_index) is not int or layer_index != self.next_layer:
            raise ValueError("unexpected layer position")
        if type(layer_size) is not int or not 0 < layer_size <= MAX_LAYER_BYTES:
            raise ValueError("invalid layer size")
        if not isinstance(members, (tuple, list)) or len(members) > MAX_CHANGESET_RECORDS:
            raise ValueError("invalid changeset")
        seen, previous_end, retained = set(), 0, 0
        for member in members:
            self.check_deadline()
            if type(member) is not LayerMember:
                raise ValueError("invalid changeset member")
            if member.kind not in {"file", "dir", "symlink", "hardlink", "whiteout", "opaque"}:
                raise ValueError("unsupported changeset member")
            path = normalized_path(
                member.path,
                allow_root=member.kind == "dir",
                linux_literal_paths=self.linux_literal_paths,
            )
            if path != member.path or path in seen:
                raise ValueError("duplicate or noncanonical member")
            seen.add(path)
            previous_end = self.check_extent(member, previous_end, layer_size)
            self.check_target(member, path)
            self.check_capability(member, path)
            retained += len(path.encode()) + len(member.target.encode())
            retained += len(member.pax_payload or b"") + len(member.capability_value or b"")
            if retained > MAX_CHANGESET_RECORD_BYTES:
                raise ValueError("changeset retained-data limit exceeded")
        return members

    def apply_whiteouts(self, tree, whiteouts):
        work, touched = 0, set()
        for member in whiteouts:
            self.check_deadline()
            parent = require_parent(tree, member.path)
            work += len(tree)
            if work > MAX_SCAN_WORK:
                raise ValueError("overlay work limit exceeded")
            if member.kind == "opaque":
                prefix = f"{parent}/" if parent else ""
                doomed = [path for path in tree if path != parent and path.startswith(prefix)]
            else:
                victim = member.target
                doomed = [path for path in tree if path == victim or path.startswith(victim + "/")]
            for path in doomed:
                del tree[path]
            touched.add(parent)
        return work, touched

    def apply_additions(self, tree, additions, layer_index, work, touched):  # noqa: PLR0912 - closed dispatch
        for member in additions:
            self.check_deadline()
            path = member.path
            if not path:
                tree[path] = MetadataEntry("dir", member.mode, member.uid, member.gid, member.mtime)
                continue
            parent = require_parent(tree, path)
            prior = tree.get(path)
            if prior is None or prior.kind != "dir" or member.kind != "dir":
                touched.add(parent)
            if prior and prior.kind == "dir" and member.kind != "dir":
                work += len(tree)
                if work > MAX_SCAN_WORK:
                    raise ValueError("overlay work limit exceeded")
                if any(name.startswith(path + "/") for name in tree):
                    raise ValueError("nonempty directory replacement unsupported")
            if prior and prior.kind == "file":
                work += len(tree)
                if work > MAX_SCAN_WORK:
                    raise ValueError("overlay work limit exceeded")
                if sum(node.inode is prior.inode for node in tree.values()) > 1:
                    raise ValueError("ambiguous hardlinked replacement")
            attrs = member.mode, member.uid, member.gid, member.mtime
            if member.kind == "file":
                inode = SymbolicInode(
                    layer_index, member.data_offset, member.size, *attrs, member.capability_value
                )
                node = MetadataEntry("file", *attrs, inode=inode)
            elif member.kind == "hardlink":
                if member.target == path:
                    raise ValueError("self hardlink unsupported")
                target = tree.get(member.target)
                if target is None or target.kind != "file" or target.inode is None:
                    raise ValueError("unresolved or non-file hardlink")
                if attrs != (target.mode, target.uid, target.gid, target.mtime):
                    raise ValueError("hardlink metadata differs from target")
                node = target
            elif member.kind == "dir":
                node = MetadataEntry("dir", *attrs)
            elif member.kind == "symlink":
                node = MetadataEntry(
                    "symlink",
                    *attrs,
                    target=member.target,
                    capability_header=member.capability_value,
                )
            else:
                raise ValueError("unsupported changeset member")
            tree[path] = node
            if len(tree) > MAX_OVERLAY_ENTRIES:
                raise ValueError("overlay entry limit exceeded")

    def apply(self, members, layer_index, layer_size):
        """Apply an entire verified changeset or leave the model unchanged."""
        members = self.checked_members(members, layer_index, layer_size)
        tree = self.entries.copy()
        whiteouts = [member for member in members if member.kind in {"whiteout", "opaque"}]
        additions = [member for member in members if member.kind not in {"whiteout", "opaque"}]
        work, touched = self.apply_whiteouts(tree, whiteouts)
        self.apply_additions(tree, additions, layer_index, work, touched)
        for path in touched:
            node = tree.get(path)
            if node is not None and node.kind == "dir":
                tree[path] = replace(node, mtime=None)
        retained = 0
        for path, node in tree.items():
            self.check_deadline()
            retained += len(path.encode()) + len(node.target.encode())
            retained += len(node.capability_header or b"")
            if node.inode is not None:
                retained += len(node.inode.capability_header or b"")
            if retained > MAX_OVERLAY_BYTES:
                raise ValueError("overlay retained-data limit exceeded")
        self.entries = tree
        self.next_layer += 1


class _Receiver:
    def __init__(self, *, linux_literal_paths):
        self.root = MetadataRoot(linux_literal_paths=linux_literal_paths)
        self.reader = None
        self.count = 0
        self.tracked = 0
        self.retained = 0

    def begin(self):
        self.root.check_deadline()
        self.reader = ChangesetReader(linux_literal_paths=self.root.linux_literal_paths)
        self.count, self.tracked, self.retained = 0, 0, 0

    def write(self, data):
        self.root.check_deadline()
        self.count += len(data)
        if self.count > MAX_LAYER_BYTES:
            raise ValueError("uncompressed layer limit exceeded")
        self.reader.feed(data)
        if len(self.reader.members) > MAX_CHANGESET_RECORDS:
            raise ValueError("changeset member limit exceeded")
        while self.tracked < len(self.reader.members):
            member = self.reader.members[self.tracked]
            self.retained += len(member.path.encode()) + len(member.target.encode())
            self.retained += len(member.pax_payload or b"") + len(member.capability_value or b"")
            if self.retained > MAX_CHANGESET_RECORD_BYTES:
                raise ValueError("changeset retained-data limit exceeded")
            self.tracked += 1

    def finish(self):
        self.reader.complete()
        self.root.apply(self.reader.members, self.root.next_layer, self.count)
        self.reader = None


def model_verified_image(directory, manifest_digest, platform, *, linux_literal_paths=False):
    """Model ordered, locally verified layers; caller must authenticate the manifest.

    No files are extracted. This is a conservative metadata-only virtual model,
    not runtime parity, installed capability state, SBOM coverage, or release
    evidence. Caller must supervise blocked I/O and impose RSS/CPU/FD limits.
    """
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("unsupported platform")
    try:
        receiver = _Receiver(linux_literal_paths=linux_literal_paths)
        report = verify(directory, manifest_digest, platform, receiver=receiver)
        layers = tuple((item["digest"], item["diffId"], item["size"]) for item in report["layers"])
        return MetadataOverlayResult(
            report["manifestDigest"],
            report["configDigest"],
            platform,
            layers,
            MappingProxyType(receiver.root.entries.copy()),
        )
    except Exception:  # noqa: BLE001 - redact potentially sensitive parser details
        raise ValueError("metadata overlay incomplete") from None
