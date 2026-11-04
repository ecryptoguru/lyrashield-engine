"""Experimental single-layer selective byte capture; not image reconstruction."""

# ruff: noqa: INP001
import hashlib
import shutil
import tarfile
import tempfile
import time

from scripts.reconstruct_oci_layers import (
    MAX_ENTRIES,
    MAX_PATH_BYTES,
    RestrictiveTarReader,
    metadata,
    normalized_path,
)
from scripts.verify_oci_layer_binding import verify_layer_stream


MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SECONDS = 900


def within(path, parent):
    return not parent or path == parent or path.startswith(parent + "/")


class SelectiveLayerReader(RestrictiveTarReader):
    def __init__(self, target, output):
        super().__init__(None)
        self.target = target
        self.output = output
        self.seen = set()
        self.path_bytes = 0
        self.selected = False
        self.capturing = False
        self.selected_size = 0
        self.digest = hashlib.sha256()
        self.deadline = time.monotonic() + MAX_SECONDS

    def feed(self, data):
        if time.monotonic() > self.deadline:
            raise TimeoutError("single-layer inspection deadline exceeded")
        super().feed(data)

    def reject_relevant_whiteout(self, path, header):
        parent, _, base = path.rpartition("/")
        if not base.startswith(".wh."):
            return False
        if not header.isfile() or header.size or base == ".wh.":
            raise ValueError("invalid whiteout marker")
        if base == ".wh..wh..opq":
            relevant = within(self.target, parent)
        else:
            victim = base[4:]
            if victim in {".", ".."} or victim.startswith(".wh."):
                raise ValueError("invalid whiteout target")
            relevant = within(self.target, (parent + "/" if parent else "") + victim)
        if relevant:
            raise ValueError("relevant whiteout requires overlay resolution")
        return True

    def begin_header(self, block):
        try:
            header = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
        except tarfile.HeaderError as exc:
            raise ValueError("invalid tar header") from exc
        super().begin_header(block)
        path = normalized_path(header.name, allow_root=header.isdir())
        if path in self.seen or len(self.seen) >= MAX_ENTRIES:
            raise ValueError("duplicate path or layer entry limit exceeded")
        self.seen.add(path)
        self.path_bytes += len(path.encode("utf-8"))
        if self.path_bytes > MAX_PATH_BYTES:
            raise ValueError("layer path limit exceeded")
        metadata(header)
        if header.issym() or header.islnk():
            raise ValueError("link requires overlay resolution")
        if self.reject_relevant_whiteout(path, header):
            return
        if path != self.target and within(self.target, path) and not header.isdir():
            raise ValueError("non-directory target ancestor")
        if path == self.target:
            if not header.isfile() or not 0 < header.size <= MAX_CAPTURE_BYTES:
                raise ValueError("selected entry type or size unsupported")
            free = shutil.disk_usage(tempfile.gettempdir()).free
            if free < MIN_FREE_BYTES + header.size:
                raise ValueError("insufficient temporary storage reserve")
            self.selected = self.capturing = True
            self.selected_size = header.size

    def consume_block(self, block):
        if self.capturing and self.payload_remaining:
            data = block[: min(self.payload_remaining, 512)]
            self.output.write(data)
            self.digest.update(data)
        super().consume_block(block)
        if self.capturing and not self.payload_remaining:
            self.capturing = False

    def finish_capture(self):
        if self.partial or self.payload_remaining or self.zero_blocks < 2:
            raise ValueError("incomplete tar framing or end marker")
        if not self.selected or self.output.tell() != self.selected_size:
            raise ValueError("selected entry missing or incomplete")


def capture_verified_layer(stream, item, expected_diff, target):
    """Capture one layer-local file after full byte and framing verification.

    Caller must authenticate the descriptor and close the returned temporary file.
    This function does not apply layers or establish an image filesystem.
    """
    target = normalized_path(target)
    if any(part.startswith(".wh.") for part in target.split("/")):
        raise ValueError("whiteout target is unsupported")
    output = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 - transferred on success, closed on failure
    try:
        reader = SelectiveLayerReader(target, output)
        layer, _ = verify_layer_stream(stream, item, expected_diff, 0, on_data=reader.feed)
        reader.finish_capture()
        output.seek(0)
        return {
            "scope": "verified-single-layer-entry-only",
            "layerDigest": layer["digest"],
            "diffId": layer["diffId"],
            "entrySize": reader.selected_size,
            "entrySha256": reader.digest.hexdigest(),
        }, output
    except BaseException:
        output.close()
        raise
