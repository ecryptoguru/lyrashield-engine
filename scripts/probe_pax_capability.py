"""Unwired, byte-exact probe for a narrowly supported PAX capability record."""

# ruff: noqa: INP001
import hashlib
import tarfile
import time
from dataclasses import dataclass, field

from scripts.check_sbom_inventory import StrictTarReader
from scripts.reconstruct_oci_layers import normalized_path, validate_member_trailing_slash
from scripts.verify_oci_layer_binding import DIGEST


KEY = b"SCHILY.xattr.security.capability"
MAX_PAX_BYTES = 16 * 1024
MAX_VALUE_BYTES = 4 * 1024
MAX_TOTAL_VALUE_BYTES = 1024 * 1024
MAX_OBSERVATIONS = 1024
MAX_ENTRIES = 100_000
MAX_PATH_BYTES = 16 * 1024 * 1024
MAX_LAYER_BYTES = 4 * 1024**3
MAX_SECONDS = 900


@dataclass(frozen=True)
class CapabilityObservation:
    path: str = field(repr=False)
    member_header_offset: int
    file_size: int
    value: bytes = field(repr=False)


def parse_capability_record(payload):
    """Accept exactly one canonical cap-only PAX record; return opaque bytes."""
    if not 0 < len(payload) <= MAX_PAX_BYTES:
        raise ValueError("PAX header byte limit exceeded")
    separator = payload.find(b" ")
    if separator < 0:
        raise ValueError("malformed PAX record")
    digits = payload[:separator]
    if not digits.isdigit() or len(digits) > 5:
        raise ValueError("invalid PAX record length")
    size = int(digits)
    if str(size).encode() != digits or size != len(payload):
        raise ValueError("invalid PAX record length")
    record = payload[separator + 1 :]
    if not record.endswith(b"\n") or b"=" not in record:
        raise ValueError("malformed PAX record")
    key, value = record[:-1].split(b"=", 1)
    if key != KEY:
        raise ValueError("unsupported PAX key")
    if not 0 < len(value) <= MAX_VALUE_BYTES:
        raise ValueError("capability value limit exceeded")
    return value


class CapabilityReader(StrictTarReader):
    def __init__(self):
        super().__init__(None)
        self.offset = 0
        self.awaiting_member = False
        self.pending_value = None
        self.observations = []
        self.value_bytes = 0
        self.paths = set()
        self.path_bytes = 0

    def consume_block(self, block):
        if self.pax_payload is not None and self.payload_remaining <= 512:
            payload = bytes(self.pax_payload) + bytes(block[: self.payload_remaining])
            self.pending_value = parse_capability_record(payload)
        super().consume_block(block)
        self.offset += 512

    def begin_header(self, block):
        try:
            entry = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
        except tarfile.HeaderError:
            raise ValueError("invalid tar header") from None
        if entry.type == tarfile.XHDTYPE:
            if self.awaiting_member or not 0 < entry.size <= MAX_PAX_BYTES:
                raise ValueError("stacked or invalid PAX header")
            self.awaiting_member = True
            self.pending_value = None
        else:
            if entry.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
                raise ValueError("unsupported tar entry type")
            validate_member_trailing_slash(entry.name, is_directory=entry.isdir())
            try:
                path = normalized_path(entry.name, allow_root=entry.isdir())
            except UnicodeError:
                raise ValueError("invalid member path encoding") from None
            if path.rpartition("/")[2].startswith(".wh."):
                raise ValueError("whiteouts are unsupported")
            if path in self.paths or len(self.paths) >= MAX_ENTRIES:
                raise ValueError("duplicate path or entry limit exceeded")
            self.paths.add(path)
            self.path_bytes += len(path.encode("utf-8"))
            if self.path_bytes > MAX_PATH_BYTES:
                raise ValueError("path byte limit exceeded")
            if self.awaiting_member:
                if not entry.isfile() or self.pending_value is None:
                    raise ValueError("capability requires immediately following regular file")
                self.value_bytes += len(self.pending_value)
                if (
                    len(self.observations) >= MAX_OBSERVATIONS
                    or self.value_bytes > MAX_TOTAL_VALUE_BYTES
                ):
                    raise ValueError("capability aggregate limit exceeded")
                self.observations.append(
                    CapabilityObservation(path, self.offset, entry.size, self.pending_value)
                )
                self.awaiting_member = False
                self.pending_value = None
        super().begin_header(block)

    def complete(self):
        if self.partial or self.payload_remaining or self.zero_blocks < 2 or self.awaiting_member:
            raise ValueError("incomplete tar framing or PAX association")


def inspect_layer(stream, expected_diff):
    """Return observations only after full framing and same-stream DiffID match.

    This does not authenticate the caller-supplied DiffID, compressed source,
    producer exit, image layers, runtime semantics or release readiness. It
    accepts only a deliberately narrow archive subset and never applies xattrs.
    """
    if not isinstance(expected_diff, str) or not DIGEST.fullmatch(expected_diff):
        raise ValueError("invalid expected diff ID")
    reader = CapabilityReader()
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + MAX_SECONDS
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("probe deadline exceeded")
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
    return tuple(reader.observations)
