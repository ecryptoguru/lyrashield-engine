"""Unwired, no-spool verification of a single rejected PAX parser prefix.

The caller authenticates the expected descriptor and DiffID and supervises the
fetch process group with a wall deadline, including blocked reads. This never
accepts an archive or qualifies an image, SBOM, overlay, or release.
"""

# ruff: noqa: BLE001, INP001, TRY301
import os
import stat
import tarfile
import time

from scripts.catalog_pax_capability_headers import HeaderReader
from scripts.probe_pax_capability import MAX_LAYER_BYTES, MAX_SECONDS
from scripts.spool_verified_oci_layer import free_space, require_no_acl
from scripts.verify_oci_layer_binding import verify_layer_stream
from scripts.verify_pax_capability_stream import (
    FETCH_EXIT_SECONDS,
    MAX_COMPRESSED_BYTES,
    MIN_FREE_BYTES,
    cleanup_fetch,
)


def unsafe_syntax(value, *, absolute, backslash_allowed=False):
    """Return a fixed label; never return or retain the supplied path."""
    if not isinstance(value, str):
        return "invalid-type"
    if "\x00" in value:
        return "nul"
    if "\\" in value and not backslash_allowed:
        return "backslash"
    if absolute and value.startswith("/"):
        return "absolute"
    return None


class RejectionReader(HeaderReader):
    """Observe only a rejected header; never alter HeaderReader acceptance."""

    def __init__(self, *, linux_literal_paths=False):
        super().__init__(linux_literal_paths=linux_literal_paths)
        self.unsafe_detail = None

    def begin_header(self, block):
        try:
            super().begin_header(block)
        except ValueError as error:
            if error.args == ("unsafe path",):
                # The original parser already decoded this header and stopped
                # before clearing its pending PAX state. Repeat only bounded
                # header decoding, and retain no name or target in the result.
                entry = tarfile.TarInfo.frombuf(bytes(block), "utf-8", "surrogateescape")
                overrides = self.pending[0] if self.awaiting_member and self.pending else {}
                path = overrides.get(b"path", entry.name)
                syntax = unsafe_syntax(
                    path, absolute=True, backslash_allowed=self.linux_literal_paths
                )
                if syntax is not None:
                    self.unsafe_detail = ("member", syntax)
                elif entry.issym() or entry.islnk():
                    target = overrides.get(b"linkpath", entry.linkname)
                    syntax = unsafe_syntax(
                        target,
                        absolute=entry.islnk(),
                        backslash_allowed=self.linux_literal_paths and entry.islnk(),
                    )
                    if syntax is not None:
                        self.unsafe_detail = ("hardlink" if entry.islnk() else "symlink", syntax)
            raise


def diagnose_fetched_layer(fetch, item, diff_id, private_root, *, linux_literal_paths=False):
    """Return only a fixed rejection after same-stream byte and fetch checks.

    Once the first unsafe path is observed, no further tar parsing is done.
    Only descriptor bytes and DiffID are verified; tar framing remains unknown.
    No layer payload or archive-derived text is written or returned. The
    caller must authenticate the Linux platform before opting into literal
    backslash interpretation; this is never host-path resolution.
    """
    root = None
    try:
        root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        state = os.fstat(root)
        if (
            not stat.S_ISDIR(state.st_mode)
            or state.st_uid != os.geteuid()
            or stat.S_IMODE(state.st_mode) != 0o700
        ):
            raise ValueError("private root invalid")
        require_no_acl(root)
        if (
            not isinstance(item, dict)
            or type(item.get("size")) is not int
            or not 0 < item["size"] <= MAX_COMPRESSED_BYTES
        ):
            raise ValueError("compressed byte limit exceeded")
        reader = RejectionReader(linux_literal_paths=linux_literal_paths)
        detail = None
        deadline = time.monotonic() + MAX_SECONDS
        count = 0

        def consume(data):
            nonlocal count, detail, reader
            if time.monotonic() > deadline:
                raise TimeoutError("stream deadline exceeded")
            if free_space(root) < MIN_FREE_BYTES + 1024 * 1024:
                raise ValueError("temporary storage reserve insufficient")
            count += len(data)
            if count > MAX_LAYER_BYTES:
                raise ValueError("uncompressed byte limit exceeded")
            if reader is not None:
                try:
                    reader.feed(data)
                except ValueError as error:
                    candidate = reader.unsafe_detail
                    if (
                        error.args != ("unsafe path",)
                        or type(candidate) is not tuple
                        or len(candidate) != 2
                        or candidate[0] not in {"member", "hardlink", "symlink"}
                        or candidate[1] not in {"absolute", "backslash", "nul", "invalid-type"}
                        or (candidate[0] == "symlink" and candidate[1] == "absolute")
                    ):
                        raise
                    detail = candidate
                    reader = None

        _, size = verify_layer_stream(fetch.stdout, item, diff_id, 0, on_data=consume)
        if fetch.wait(timeout=FETCH_EXIT_SECONDS) != 0 or count != size or detail is None:
            raise ValueError("diagnostic incomplete")
        return {
            "scope": "verified-layer-bytes-rejected-parser-prefix-only",
            "status": "rejected",
            "reason": "unsafe-path",
            "role": detail[0],
            "syntax": detail[1],
            "bytesVerified": True,
            "tarFramingVerified": False,
            "finalImageVerified": False,
            "releaseQualified": False,
        }
    except Exception:
        raise ValueError("diagnostic incomplete") from None
    finally:
        cleanup_fetch(fetch, root)
