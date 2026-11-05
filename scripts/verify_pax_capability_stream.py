"""Unwired aggregate-only streamed PAX capability header observation."""

# ruff: noqa: INP001, BLE001, TRY301  # Sanitize all failures before returning data.
import os
import stat
import time

from scripts.catalog_pax_capability_headers import MAX_LAYER_BYTES, MAX_SECONDS, HeaderReader
from scripts.spool_verified_oci_layer import free_space, require_no_acl
from scripts.verify_oci_layer_binding import verify_layer_stream


MAX_COMPRESSED_BYTES = 4 * 1024**3
MIN_FREE_BYTES = 2 * 1024**3
FETCH_EXIT_SECONDS = 10


PREFIX_REASONS = {
    "unsupported or duplicate PAX key": "unsupported-pax-key",
    "unsupported tar entry type": "unsupported-tar-entry",
    "unsupported capability member type": "unsupported-capability-member",
    "invalid tar header": "invalid-tar-header",
    "duplicate path or entry limit exceeded": "duplicate-path-or-entry-limit",
    "invalid PAX record length": "invalid-pax-record",
    "malformed PAX record": "invalid-pax-record",
    "stacked or invalid PAX header": "invalid-pax-header",
    "unsafe path": "member-link-policy",
    "invalid path length": "member-link-policy",
    "ambiguous or traversing path": "member-link-policy",
    "non-directory path ends in slash": "member-link-policy",
    "invalid PAX linkpath": "member-link-policy",
    "invalid hardlink target": "member-link-policy",
    "invalid symlink target character": "member-link-policy",
    "invalid member encoding": "member-link-policy",
    "invalid PAX path value": "pax-value-or-encoding",
    "invalid PAX path character": "pax-value-or-encoding",
    "invalid PAX path encoding": "pax-value-or-encoding",
    "PAX byte limit exceeded": "parser-limit",
    "capability value limit exceeded": "parser-limit",
    "path byte limit exceeded": "parser-limit",
    "capability aggregate limit exceeded": "parser-limit",
    "archive byte limit exceeded": "parser-limit",
    "extended tar header exceeds byte limit": "parser-limit",
    "nonzero data after tar end marker": "tar-framing",
    "nonzero tar payload padding": "tar-framing",
    "negative tar payload size": "tar-framing",
    "non-file tar entry has payload": "tar-framing",
    "incomplete PAX association": "invalid-pax-header",
}
PREFIX_CATEGORIES = frozenset(PREFIX_REASONS.values()) | {"parser-rejected"}

MEMBER_LINK_REASONS = {
    "unsafe path": "unsafe-path",
    "invalid path length": "path-length",
    "ambiguous or traversing path": "ambiguous-path-components",
    "non-directory path ends in slash": "member-trailing-slash",
    "invalid PAX linkpath": "linkpath-on-non-link",
    "invalid hardlink target": "hardlink-target-trailing-slash",
    "invalid symlink target character": "symlink-target-character",
    "invalid member encoding": "member-or-link-encoding",
}
MEMBER_LINK_ROLES = {
    "unsafe-path": "unknown",
    "path-length": "unknown",
    "ambiguous-path-components": "member-or-hardlink",
    "member-trailing-slash": "member",
    "linkpath-on-non-link": "member",
    "hardlink-target-trailing-slash": "hardlink",
    "symlink-target-character": "symlink",
    "member-or-link-encoding": "unknown",
}


class UnverifiedPrefixRejectionError(ValueError):
    """A fixed local parser reason, never an authenticated layer observation."""

    def __init__(self, category, member_link_reason="unavailable"):
        super().__init__("capability stream incomplete")
        self._category = category
        self._member_link_reason = member_link_reason

    @property
    def category(self):
        category = self._category
        return (
            category
            if type(category) is str and category in PREFIX_CATEGORIES
            else "parser-rejected"
        )

    @property
    def byte_verified(self):
        return False

    @property
    def member_link_reason(self):
        reason = self._member_link_reason
        if self.category != "member-link-policy" or type(reason) is not str:
            return "unavailable"
        return reason if reason in MEMBER_LINK_ROLES else "unavailable"

    @property
    def member_link_role(self):
        return MEMBER_LINK_ROLES.get(self.member_link_reason, "unknown")


def inspect_fetched_layer(fetch, item, diff_id, private_root, *, diagnostic=False):
    """Return only aggregate counts after complete same-stream verification.

    The caller must authenticate the descriptor and DiffID and supervise the
    fetch process group with an external deadline. This is not a final image,
    inode, OCI runtime, capability validity, SBOM or release qualification.
    No input bytes or metadata are written, extracted or applied.
    """
    root = None
    prefix_reason = None
    member_link_reason = "unavailable"
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
        reader = HeaderReader()
        deadline = time.monotonic() + MAX_SECONDS
        count = 0

        def consume(data):
            nonlocal count, prefix_reason, member_link_reason
            if time.monotonic() > deadline:
                raise TimeoutError("stream deadline exceeded")
            if free_space(root) < MIN_FREE_BYTES + 1024 * 1024:
                raise ValueError("temporary storage reserve insufficient")
            count += len(data)
            if count > MAX_LAYER_BYTES:
                raise ValueError("uncompressed byte limit exceeded")
            try:
                reader.feed(data)
            except ValueError as error:
                if diagnostic is True:
                    message = error.args[0] if error.args and type(error.args[0]) is str else ""
                    prefix_reason = PREFIX_REASONS.get(message, "parser-rejected")
                    member_link_reason = MEMBER_LINK_REASONS.get(message, "unavailable")
                raise

        descriptor, size = verify_layer_stream(fetch.stdout, item, diff_id, 0, on_data=consume)
        reader.complete()
        if fetch.wait(timeout=FETCH_EXIT_SECONDS) != 0:
            raise ValueError("fetch process failed")
        if count != size:
            raise ValueError("stream byte count mismatch")
        files = sum(observation.kind == "file" for observation in reader.observations)
        links = sum(observation.kind == "symlink" for observation in reader.observations)
        if files + links != len(reader.observations):
            raise ValueError("unsupported observation kind")
        return {
            "scope": "verified-single-layer-pax-header-aggregate-only",
            "descriptorDigest": descriptor["digest"],
            "compressedBytes": descriptor["size"],
            "diffId": diff_id,
            "uncompressedBytes": size,
            "capabilityHeaders": files + links,
            "fileHeaders": files,
            "symlinkHeaders": links,
            "sourceRetained": False,
            "finalImageVerified": False,
            "releaseQualified": False,
        }
    except Exception:
        if diagnostic is True and prefix_reason is not None:
            raise UnverifiedPrefixRejectionError(prefix_reason, member_link_reason) from None
        raise ValueError("capability stream incomplete") from None
    finally:
        cleanup_fetch(fetch, root)


def cleanup_fetch(fetch, root):
    """Attempt every cleanup step and fail closed on unresolved errors."""
    cleanup_failed = False
    try:
        running = fetch.poll() is None
    except Exception:
        cleanup_failed = True
        running = True
    if running:
        try:
            fetch.kill()
        except ProcessLookupError:
            pass  # A process that exited between poll and kill is already stopped.
        except Exception:
            cleanup_failed = True
    try:
        fetch.wait(timeout=FETCH_EXIT_SECONDS)
    except Exception:
        cleanup_failed = True
    try:
        if fetch.stdout is not None:
            fetch.stdout.close()
    except Exception:
        cleanup_failed = True
    if root is not None:
        try:
            os.close(root)
        except Exception:
            cleanup_failed = True
    if cleanup_failed:
        raise ValueError("capability stream cleanup incomplete") from None
