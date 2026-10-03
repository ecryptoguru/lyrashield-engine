"""Validation and read-only staging for attachment (supporting-file) inputs.

Attachments are immutable *input evidence* — text, Markdown, JSON, YAML, and
OpenAPI files supplied by the operator/host to give the scan supporting
context (API specs, notes, expected behavior). They are not configuration,
not instructions, and not targets: an attachment's bytes must never change
target scope, credentials, model routes, permissions, or budget.

Guarantees enforced here:

* Admission: every declared path must resolve to an existing regular file
  (symlinks, directories, FIFOs/sockets/devices are rejected), carry an
  allowlisted text suffix, lack the executable bit, decode as UTF-8, and fit
  within per-file and aggregate byte caps. ``..`` path segments are refused.
* Staging: validated originals are copied into a per-run host directory under
  digest-prefixed names (``<sha256[:16]>-<basename>``), so two attachments
  sharing a basename can never collide and identical content dedupes to one
  staged file. Staged bytes are re-hashed against the recorded digest and
  bind-mounted read-only at
  :data:`ATTACHMENTS_CONTAINER_DIR` — separate from the ``/workspace`` source
  tree. POSIX host files also use mode ``0o444``; Windows relies on the
  read-only mount so ordinary sandbox cleanup can remove the files. A
  ``manifest.json`` of the staged originals rides the same mount so in-sandbox
  tools can map names to digests.
* Scratch-copy helper (currently used only by tests; no tool calls it):
  :func:`create_scratch_copy` re-verifies the staged digest, then
  writes a bounded copy into the writable in-container scratch area and
  returns a link record binding the scratch path to the original hash.
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import io
import json
import logging
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from agents.sandbox.session.sandbox_session import SandboxSession


logger = logging.getLogger(__name__)

# Read-only mount target inside the sandbox. Deliberately outside /workspace
# so input evidence is never confused with (writable) target source trees.
ATTACHMENTS_CONTAINER_DIR = "/input/attachments"

# Writable in-container area for bounded scratch copies. It lives under the
# container's own /workspace filesystem layer — not a host bind mount — so a
# scratch write can never reach back into a staged original on the host.
ATTACHMENTS_SCRATCH_DIR = "/workspace/.attachments-scratch"

# Name of the read-only manifest staged alongside the files.
ATTACHMENT_MANIFEST_NAME = "manifest.json"

# v1 accepts text evidence only: no archives and no active document formats.
# Compound OpenAPI suffixes are listed for clarity; they end with .json/.yaml
# and are covered by the same check.
ALLOWED_SUFFIXES: tuple[str, ...] = (
    ".txt",
    ".md",
    ".markdown",
    ".json",
    ".yaml",
    ".yml",
    ".openapi.json",
    ".openapi.yaml",
    ".openapi.yml",
)

# Bounded admission limits. Attachments are task context that also flows into
# prompts, so they are much smaller than the (already bounded) local-source
# copy budget — an OpenAPI spec of a few hundred KB is the expected ceiling.
MAX_ATTACHMENT_COUNT = 32
MAX_ATTACHMENT_FILE_BYTES = 1 * 1024 * 1024  # 1 MiB per file
MAX_ATTACHMENTS_TOTAL_BYTES = 4 * 1024 * 1024  # 4 MiB across all files

# Digest prefix length for staged names: 64 bits of the SHA-256 makes an
# accidental or adversarial same-basename collision unreachable.
_STAGED_DIGEST_PREFIX_LEN = 16

_CONTENT_TYPES: tuple[tuple[str, str], ...] = (
    (".openapi.json", "application/vnd.oai.openapi+json"),
    (".openapi.yaml", "application/vnd.oai.openapi"),
    (".openapi.yml", "application/vnd.oai.openapi"),
    (".json", "application/json"),
    (".yaml", "application/yaml"),
    (".yml", "application/yaml"),
    (".md", "text/markdown"),
    (".markdown", "text/markdown"),
    (".txt", "text/plain"),
)

_BASENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Manifest fields exposed to run provenance and the sandbox manifest. The host
# ``source_path`` is private execution configuration (like cloned_repo_path)
# and is never recorded in the public worker contract.
_PUBLIC_FIELDS = ("name", "staged_name", "sha256", "size", "content_type", "container_path")

# Win32 CreateFileW flag used to open the final path component itself when it
# is a reparse point. The handle is inspected and rejected before any bytes
# are read, matching POSIX O_NOFOLLOW semantics.
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class AttachmentInputError(ValueError):
    """Named admission/staging failure for a supporting-file input.

    ``reason`` is a stable machine-readable token (e.g. ``"symlink"``) so the
    CLI, worker, and tests can distinguish a fail-closed rejection from a
    generic error — mirroring ``SourcePreflightError`` for source acquisition.
    """

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"[{reason}] {message}")


def _sanitize_basename(name: str) -> str:
    """Reduce a declared basename to a sandbox-safe file name."""
    sanitized = _BASENAME_SAFE_RE.sub("-", name.strip())
    sanitized = sanitized.strip("-.")
    if not sanitized or sanitized in {".", ".."}:
        return "attachment"
    return sanitized[:128]


def _allowed_suffix(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in ALLOWED_SUFFIXES)


def _declared_content_type(name: str) -> str:
    lowered = name.lower()
    for suffix, content_type in _CONTENT_TYPES:
        if lowered.endswith(suffix):
            return content_type
    return "text/plain"


def _is_windows_platform() -> bool:
    return os.name == "nt"


def _safe_attachment_open_supported() -> bool:
    if _is_windows_platform():
        try:
            msvcrt = importlib.import_module("msvcrt")
        except ImportError:
            return False
        return hasattr(ctypes, "WinDLL") and hasattr(msvcrt, "open_osfhandle")
    return hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK")


def _safe_read_open_flags() -> int:
    """Return flags that refuse links and special-file blocking."""
    if _is_windows_platform() or not _safe_attachment_open_supported():
        raise AttachmentInputError(
            "unsupported_platform",
            "Safe attachment reads require a supported no-follow file-open strategy.",
        )
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _create_windows_file_handle(path: Path, flags: int) -> int:
    """Open an existing Windows path without following its final reparse point."""
    if not _is_windows_platform():
        raise OSError("Windows file handles are only available on Windows.")

    win_dll = cast("Callable[..., Any]", ctypes.WinDLL)  # type: ignore[attr-defined]
    kernel32 = win_dll("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002 | 0x00000004,  # FILE_SHARE_READ | WRITE | DELETE
        None,
        3,  # OPEN_EXISTING
        0x00000080 | flags,  # FILE_ATTRIBUTE_NORMAL | caller-supplied flags
        None,
    )
    handle_value = getattr(handle, "value", handle)
    if handle_value in (None, -1, ctypes.c_void_p(-1).value):
        get_last_error = cast("Callable[[], int]", ctypes.get_last_error)  # type: ignore[attr-defined]
        error = get_last_error()
        raise OSError(error, "CreateFileW failed to open attachment", str(path))
    return int(handle_value)


def _windows_handle_to_fd(handle: int) -> int:
    """Transfer a Win32 handle to a binary CRT descriptor."""
    msvcrt = importlib.import_module("msvcrt")
    open_osfhandle = cast("Callable[[int, int], int]", msvcrt.open_osfhandle)
    return open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))


def _close_windows_handle(handle: int) -> None:
    """Close a Win32 handle that was not transferred to a CRT descriptor."""
    win_dll = cast("Callable[..., Any]", ctypes.WinDLL)  # type: ignore[attr-defined]
    kernel32 = win_dll("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        get_last_error = cast("Callable[[], int]", ctypes.get_last_error)  # type: ignore[attr-defined]
        error = get_last_error()
        raise OSError(error, "CloseHandle failed for attachment")


def _open_attachment_fd(path: str | Path) -> int:
    """Open a regular-file candidate through a no-follow descriptor/handle."""
    if _is_windows_platform():
        if not _safe_attachment_open_supported():
            raise AttachmentInputError(
                "unsupported_platform", "Safe Windows attachment handles are unavailable."
            )
        handle = _create_windows_file_handle(Path(path), _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)
        try:
            return _windows_handle_to_fd(handle)
        except Exception:
            _close_windows_handle(handle)
            raise
    return os.open(path, _safe_read_open_flags())


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    return bool(getattr(file_stat, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)


def _attachment_file_identity(file_stat: os.stat_result) -> tuple[int, int]:
    """Return a usable device/file identity, rejecting missing Windows IDs."""
    identity = (file_stat.st_dev, file_stat.st_ino)
    if _is_windows_platform() and (identity[0] == 0 or identity[1] == 0):
        raise AttachmentInputError(
            "unsupported_identity",
            "This Windows filesystem does not expose a stable attachment file identity.",
        )
    return identity


def _open_staged_attachment(path: Path) -> int:
    """Create a new staged file without following an attacker-chosen entry."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if not _is_windows_platform():
        if not hasattr(os, "O_NOFOLLOW"):
            raise AttachmentInputError(
                "unsupported_platform", "Safe attachment staging requires no-follow file opens."
            )
        flags |= os.O_NOFOLLOW
    # O_EXCL makes the generated leaf create-only on Windows too, so a
    # pre-existing reparse point can never be opened for writing.
    return os.open(path, flags, 0o600)


def _make_staged_attachment_readonly(fd: int) -> None:
    if _is_windows_platform():
        # The bind mount is the Windows immutability boundary. Setting the
        # read-only attribute would prevent session cleanup from unlinking it.
        return
    os.fchmod(fd, 0o444)


def _read_attachment_bytes(source_fd: int, max_file_bytes: int, name: str) -> bytes:
    """Read no more than the configured limit plus one detection byte."""
    chunks: list[bytes] = []
    size = 0
    while size <= max_file_bytes:
        chunk = os.read(source_fd, min(64 * 1024, max_file_bytes + 1 - size))
        if not chunk:
            break
        size += len(chunk)
        if size > max_file_bytes:
            raise AttachmentInputError(
                "file_too_large",
                f"Attachment '{name}' grew past the {max_file_bytes}-byte limit while reading.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _read_open_attachment(
    path: Path,
    raw: str,
    name: str,
    inspected_stat: os.stat_result,
    max_file_bytes: int,
) -> bytes:
    """Read the inspected inode through a bounded no-follow descriptor."""
    inspected_identity = _attachment_file_identity(inspected_stat)
    try:
        source_fd = _open_attachment_fd(path)
    except OSError as exc:
        raise AttachmentInputError(
            "unreadable", f"Attachment '{raw}' could not be opened safely: {exc!s}"
        ) from exc
    try:
        opened_stat = os.fstat(source_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise AttachmentInputError(
                "not_regular_file",
                f"Attachment '{raw}' changed to a non-regular file while being opened.",
            )
        if _is_reparse_point(opened_stat):
            raise AttachmentInputError(
                "symlink", f"Attachment '{raw}' changed to a reparse point while being opened."
            )
        if _attachment_file_identity(opened_stat) != inspected_identity:
            raise AttachmentInputError(
                "source_changed",
                f"Attachment '{raw}' changed between inspection and read.",
            )
        if opened_stat.st_mode & 0o111:
            raise AttachmentInputError(
                "executable_file", f"Attachment '{raw}' became executable while being opened."
            )
        if opened_stat.st_size > max_file_bytes:
            raise AttachmentInputError(
                "file_too_large",
                f"Attachment '{name}' is {opened_stat.st_size} bytes; the per-file limit is "
                f"{max_file_bytes} bytes.",
            )
        try:
            return _read_attachment_bytes(source_fd, max_file_bytes, name)
        except OSError as exc:
            raise AttachmentInputError(
                "unreadable", f"Attachment '{raw}' could not be read: {exc!s}"
            ) from exc
    finally:
        os.close(source_fd)


def validate_attachment(
    path_str: str,
    *,
    max_file_bytes: int = MAX_ATTACHMENT_FILE_BYTES,
) -> dict[str, Any]:
    """Validate one declared attachment path and return its manifest entry.

    The returned entry carries the resolved host ``source_path`` for staging
    plus the public provenance fields (``name``, ``sha256``, ``size``,
    ``content_type``, ``staged_name``, ``container_path``). Raises
    :class:`AttachmentInputError` with a stable ``reason`` on any rejection.
    """
    if not path_str or not path_str.strip():
        raise AttachmentInputError("empty_path", "Attachment path must not be empty.")

    raw = path_str.strip()
    # Reject parent traversal in the declared path itself. The staged name is
    # basename-derived, so this also documents that the engine never lets a
    # caller-supplied path component wander outside the declared file.
    if ".." in PurePath(raw).parts:
        raise AttachmentInputError(
            "path_traversal",
            f"Attachment path '{raw}' contains a '..' segment; declare the file directly.",
        )

    # Make the path absolute but retain the final component so the no-follow
    # open can bind the opened file identity to the lstat result below.
    path = Path(raw).expanduser().absolute()
    # lstat first: the final component itself must be a plain file, not a link.
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise AttachmentInputError(
            "not_found", f"Attachment '{raw}' is not an existing file: {exc!s}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise AttachmentInputError(
            "symlink", f"Attachment '{raw}' is a symlink; only regular files are accepted."
        )
    if _is_reparse_point(st):
        raise AttachmentInputError(
            "symlink", f"Attachment '{raw}' is a reparse point; only regular files are accepted."
        )
    if not stat.S_ISREG(st.st_mode):
        raise AttachmentInputError(
            "not_regular_file",
            f"Attachment '{raw}' is not a regular file (directories, sockets, FIFOs, "
            "and devices are not accepted).",
        )
    if st.st_mode & 0o111:
        raise AttachmentInputError(
            "executable_file",
            f"Attachment '{raw}' has the executable bit set; attachments are "
            "passive text evidence, not programs.",
        )

    name = path.name
    if any(c in name for c in "\r\n\x85\u2028\u2029"):
        raise AttachmentInputError(
            "invalid_name",
            f"Attachment '{raw}' has a line terminator in its filename; names must be single-line.",
        )
    if not _allowed_suffix(name):
        allowed = ", ".join(s.lstrip(".") for s in ALLOWED_SUFFIXES)
        raise AttachmentInputError(
            "unsupported_extension",
            f"Attachment '{name}' has an unsupported extension. "
            f"Only text evidence is accepted: {allowed}.",
        )

    if st.st_size > max_file_bytes:
        raise AttachmentInputError(
            "file_too_large",
            f"Attachment '{name}' is {st.st_size} bytes; the per-file limit is "
            f"{max_file_bytes} bytes.",
        )

    content = _read_open_attachment(path, raw, name, st, max_file_bytes)
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AttachmentInputError(
            "not_text",
            f"Attachment '{name}' is not valid UTF-8 text; binary or encoded "
            "content is not accepted as input evidence.",
        ) from exc

    digest = hashlib.sha256(content).hexdigest()
    staged_name = f"{digest[:_STAGED_DIGEST_PREFIX_LEN]}-{_sanitize_basename(name)}"
    return {
        "name": name,
        "source_path": str(path),
        "sha256": digest,
        "size": len(content),
        "content_type": _declared_content_type(name),
        "staged_name": staged_name,
        "container_path": f"{ATTACHMENTS_CONTAINER_DIR}/{staged_name}",
    }


def collect_attachments(
    paths: list[str],
    *,
    max_count: int = MAX_ATTACHMENT_COUNT,
    max_file_bytes: int = MAX_ATTACHMENT_FILE_BYTES,
    max_total_bytes: int = MAX_ATTACHMENTS_TOTAL_BYTES,
) -> list[dict[str, Any]]:
    """Validate declared attachment paths into ordered, deduped manifest entries.

    Basename collisions are handled by digest-prefixed staged names: two
    different files named ``spec.yaml`` stage as distinct names, while the
    same file declared twice (same digest and basename) collapses to one
    staged original. Order follows declaration order.
    """
    if len(paths) > max_count:
        raise AttachmentInputError(
            "too_many",
            f"{len(paths)} attachments were declared; at most {max_count} are accepted.",
        )

    entries: list[dict[str, Any]] = []
    seen_staged: set[str] = set()
    total_bytes = 0
    for raw in paths:
        entry = validate_attachment(raw, max_file_bytes=max_file_bytes)
        staged_name = str(entry["staged_name"])
        if staged_name in seen_staged:
            continue
        seen_staged.add(staged_name)
        total_bytes += int(entry["size"])
        if total_bytes > max_total_bytes:
            raise AttachmentInputError(
                "total_too_large",
                f"Attachments total {total_bytes} bytes; the aggregate limit is "
                f"{max_total_bytes} bytes.",
            )
        entries.append(entry)
    return entries


def public_manifest(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the provenance/public shape of manifest entries (no host paths)."""
    return [{k: e[k] for k in _PUBLIC_FIELDS if k in e} for e in entries]


def restore_attachments(recorded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-validate recorded attachments for resume; digests must still match.

    A resumed run re-stages the same input evidence into a fresh sandbox. If a
    file vanished or changed since the original run, the digest differs and we
    fail closed rather than silently scanning against different evidence.
    """
    entries: list[dict[str, Any]] = []
    for record in recorded:
        if not isinstance(record, dict):
            raise AttachmentInputError(
                "invalid_record", "Recorded attachment entry is not an object."
            )
        source = record.get("source_path")
        if not isinstance(source, str) or not source:
            raise AttachmentInputError(
                "unavailable",
                "Recorded attachment has no restorable source path; the original "
                "run record cannot re-stage it.",
            )
        entry = validate_attachment(source)
        if entry["sha256"] != record.get("sha256"):
            raise AttachmentInputError(
                "checksum_mismatch",
                f"Attachment '{source}' no longer matches its recorded sha256; "
                "the original input evidence changed between runs.",
            )
        entries.append(entry)
    return entries


def _copy_attachment_bytes(source_fd: int, staged_fd: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(source_fd, 64 * 1024):
        size += len(chunk)
        if size > MAX_ATTACHMENT_FILE_BYTES:
            raise AttachmentInputError(
                "file_too_large", "Attachment source grew past the file limit."
            )
        digest.update(chunk)
        offset = 0
        while offset < len(chunk):
            written = os.write(staged_fd, chunk[offset:])
            if written <= 0:
                raise OSError("Attachment staging write made no progress.")
            offset += written
    return size, digest.hexdigest()


def _stage_one_attachment(entry: dict[str, Any], host_dir: str) -> None:
    """Copy one validated attachment into ``host_dir`` and verify its digest."""
    source_value = entry.get("source_path")
    staged_name = str(entry.get("staged_name") or "")
    digest_expected = entry.get("sha256")
    name = entry.get("name")
    size_expected = entry.get("size")
    if (
        not isinstance(source_value, str)
        or not source_value
        or not isinstance(name, str)
        or not isinstance(digest_expected, str)
        or not re.fullmatch(r"[a-f0-9]{64}", digest_expected)
        or staged_name
        != f"{digest_expected[:_STAGED_DIGEST_PREFIX_LEN]}-{_sanitize_basename(name)}"
        or not isinstance(size_expected, int)
        or isinstance(size_expected, bool)
        or not 0 <= size_expected <= MAX_ATTACHMENT_FILE_BYTES
    ):
        raise AttachmentInputError(
            "invalid_record",
            "Attachment entry lacks valid source/identity fields; entries must "
            "come from collect_attachments.",
        )
    staged = Path(host_dir) / staged_name
    source_fd = -1
    staged_fd = -1
    complete = False
    try:
        # O_NOFOLLOW binds the check to the opened inode, not a path that can
        # change between validation, copying, and chmod.
        source_fd = _open_attachment_fd(source_value)
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise AttachmentInputError(
                "not_regular_file", "Attachment source is not a regular file."
            )
        if _is_reparse_point(source_stat):
            raise AttachmentInputError(
                "symlink", "Attachment source changed to a reparse point before staging."
            )
        if source_stat.st_mode & 0o111:
            raise AttachmentInputError("executable_file", "Attachment source became executable.")
        if source_stat.st_size > MAX_ATTACHMENT_FILE_BYTES:
            raise AttachmentInputError(
                "file_too_large", "Attachment source grew past the file limit."
            )
        staged_fd = _open_staged_attachment(staged)
        size, digest = _copy_attachment_bytes(source_fd, staged_fd)
        if size != size_expected or digest != digest_expected:
            raise AttachmentInputError(
                "checksum_mismatch",
                f"Attachment '{name}' changed between validation and staging; "
                "refusing to mount content under a stale digest.",
            )
        _make_staged_attachment_readonly(staged_fd)
        complete = True
    except OSError as exc:
        raise AttachmentInputError(
            "staging_failed", f"Attachment '{name}' could not be staged."
        ) from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if staged_fd >= 0:
            os.close(staged_fd)
        if not complete and staged_fd >= 0:
            staged.unlink(missing_ok=True)


def stage_attachments(
    scan_id: str, attachments: list[dict[str, Any]]
) -> tuple[dict[str, Any], str]:
    """Materialize validated attachments into a read-only staging directory.

    Returns ``(bind_mount_spec, host_dir)`` where the spec mounts ``host_dir``
    read-only at :data:`ATTACHMENTS_CONTAINER_DIR`. Each staged file is a
    digest-prefixed copy of the declared original, re-hashed at copy time so a
    file that changed between validation and staging fails closed
    (``checksum_mismatch``) instead of being mounted under a stale identity.
    """
    host_dir = tempfile.mkdtemp(prefix=f"lyrashield-attachments-{scan_id}-")
    try:
        for entry in attachments:
            _stage_one_attachment(entry, host_dir)
        manifest_path = Path(host_dir) / ATTACHMENT_MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(public_manifest(attachments), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        if not _is_windows_platform():
            manifest_path.chmod(0o444)
    except Exception:
        shutil.rmtree(host_dir, ignore_errors=True)
        raise

    mount = {
        "source": host_dir,
        "target": ATTACHMENTS_CONTAINER_DIR,
        "read_only": True,
    }
    return mount, host_dir


async def create_scratch_copy(
    session: SandboxSession,
    entry: dict[str, Any],
    staged_root: str,
    *,
    scratch_dir: str = ATTACHMENTS_SCRATCH_DIR,
) -> dict[str, Any]:
    """Write a bounded, writable copy of a staged original into the sandbox.

    Originals under :data:`ATTACHMENTS_CONTAINER_DIR` are read-only and are
    never modified. The staged host copy is re-hashed before the write so the
    scratch copy is provably linked to the recorded original digest — a staged
    file that drifted from its manifest fails closed. Returns the link record.
    """
    staged_name = str(entry.get("staged_name") or "")
    expected_sha = entry.get("sha256")
    if not staged_name or not isinstance(expected_sha, str) or not expected_sha:
        raise AttachmentInputError(
            "invalid_record", "Attachment manifest entry lacks staged_name/sha256."
        )
    staged = Path(staged_root) / staged_name
    try:
        content = staged.read_bytes()
    except OSError as exc:
        raise AttachmentInputError(
            "unavailable", f"Staged attachment '{staged}' is not readable: {exc!s}"
        ) from exc
    digest = hashlib.sha256(content).hexdigest()
    if digest != expected_sha:
        raise AttachmentInputError(
            "checksum_mismatch",
            f"Staged attachment '{staged_name}' no longer matches its "
            "recorded sha256; refusing to derive a scratch copy.",
        )
    scratch_path = f"{scratch_dir}/{staged_name}"
    await session.write(Path(scratch_path), io.BytesIO(content))
    return {
        "scratch_path": scratch_path,
        "attachment_sha256": digest,
        "staged_name": staged_name,
        "name": str(entry.get("name") or staged_name),
        "size": len(content),
    }
