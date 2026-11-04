"""Build an unapplied, private disk catalog for one verified OCI tar stream."""

# ruff: noqa: INP001, PLR0912, PLR0915, TRY300, TRY301
import contextlib
import hashlib
import os
import secrets
import sqlite3
import stat
import tarfile
import time
from pathlib import Path

from scripts.check_sbom_inventory import BoundedTarInfo, iter_uncached_archive
from scripts.reconstruct_oci_layers import RestrictiveTarReader, metadata, normalized_path
from scripts.spool_verified_oci_layer import free_space, require_no_acl
from scripts.verify_oci_layer_binding import DIGEST


MAX_LAYER_BYTES = 4 * 1024**3
MAX_ENTRIES = 100_000
MAX_PATH_BYTES = 16 * 1024**2
MAX_DB_BYTES = 128 * 1024**2
MIN_FREE_BYTES = 2 * 1024**3
MAX_SECONDS = 900


class HashingReader:
    def __init__(self, stream, directory, deadline):
        self.stream = stream
        self.directory = directory
        self.deadline = deadline
        self.hasher = hashlib.sha256()
        self.count = 0

    def read(self, size):
        if time.monotonic() > self.deadline:
            raise TimeoutError("catalog deadline exceeded")
        if free_space(self.directory) < MIN_FREE_BYTES + 1024 * 1024:
            raise ValueError("temporary storage reserve insufficient")
        if size < 0 or size > 64 * 1024:
            raise ValueError("unbounded catalog read")
        data = self.stream.read(size)
        if not isinstance(data, bytes) or len(data) > size:
            raise ValueError("invalid layer stream")
        self.count += len(data)
        if self.count > MAX_LAYER_BYTES:
            raise ValueError("layer byte limit exceeded")
        self.hasher.update(data)
        return data


def entry_row(entry):
    if entry.name.endswith("/") and not entry.isdir():
        raise ValueError("non-directory path ends in slash")
    path = normalized_path(entry.name, allow_root=entry.isdir())
    mode, uid, gid, mtime = metadata(entry)
    target, offset, size = "", None, 0
    if entry.isfile():
        kind, offset, size = "file", entry.offset_data, entry.size
        if type(offset) is not int or offset < 0 or type(size) is not int or size < 0:
            raise ValueError("invalid file extent")
    elif entry.isdir():
        kind = "dir"
    elif entry.issym() or entry.islnk():
        if entry.linkname.endswith("/"):
            raise ValueError("link target ends in slash")
        target = normalized_path(entry.linkname)
        kind = "symlink" if entry.issym() else "hardlink"
    else:
        raise ValueError("unsupported entry type")
    base = path.rpartition("/")[2]
    if base.startswith(".wh."):
        if kind != "file" or size or base == ".wh.":
            raise ValueError("invalid whiteout")
        if base != ".wh..wh..opq" and (base[4:] in {".", ".."} or base[4:].startswith(".wh.")):
            raise ValueError("invalid whiteout target")
        kind = "opaque" if base == ".wh..wh..opq" else "whiteout"
    return path, kind, target, offset, size, mode, uid, gid, mtime


def catalog_layer(stream, expected_diff, private_root):
    """Publish metadata only after the complete stream matches expected_diff.

    This does not authenticate expected_diff or apply layers. Extents are only
    meaningful against the same uncompressed bytes after the caller re-verifies
    their identity. The caller owns the private child and source stream.
    """
    if not isinstance(expected_diff, str) or not DIGEST.fullmatch(expected_diff):
        raise ValueError("invalid expected diff ID")
    if not stream.seekable() or stream.tell() != 0:
        raise ValueError("layer stream must be seekable and start at zero")
    return catalog_forward_layer(stream, expected_diff, private_root, provisional=False)


def catalog_forward_layer(stream, expected_diff, private_root, *, provisional=True):
    """Catalog a forward-only stream; result remains provisional to its caller.

    If bytes are discarded, extent offsets cannot be used until the complete
    identical uncompressed stream is obtained and independently reverified.
    """
    if not isinstance(expected_diff, str) or not DIGEST.fullmatch(expected_diff):
        raise ValueError("invalid expected diff ID")
    root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    directory = None
    db = None
    published = False
    created = False
    try:
        info = os.fstat(root)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("private root invalid")
        require_no_acl(root)
        child = "catalog-" + secrets.token_hex(16)
        os.mkdir(child, 0o700, dir_fd=root)
        created = True
        directory = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        require_no_acl(directory)
        fd = os.open(
            "provisional.sqlite3",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            os.fchmod(fd, 0o600)
            require_no_acl(fd)
        finally:
            os.close(fd)
        # All host filenames are locally generated; archive paths enter SQL only.
        db_path = Path(private_root) / child / "provisional.sqlite3"
        db = sqlite3.connect(str(db_path))
        if db.execute("PRAGMA journal_mode=OFF").fetchone()[0] != "off":
            raise ValueError("catalog journal mode could not be disabled")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA cache_size=-4096")
        db.execute("PRAGMA page_size=4096")
        if db.execute("PRAGMA page_size").fetchone()[0] != 4096:
            raise ValueError("catalog page size could not be applied")
        if MAX_DB_BYTES < 4096:
            raise ValueError("catalog byte limit too small")
        page_limit = MAX_DB_BYTES // 4096
        actual_limit = db.execute(f"PRAGMA max_page_count={page_limit}").fetchone()[0]
        if actual_limit != page_limit:
            raise ValueError("catalog page limit could not be applied")
        db.execute(
            "CREATE TABLE entries (path TEXT PRIMARY KEY, kind TEXT NOT NULL, "
            "target TEXT NOT NULL, offset INTEGER, size INTEGER NOT NULL, "
            "mode INTEGER NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL, "
            "mtime INTEGER NOT NULL) WITHOUT ROWID"
        )
        deadline = time.monotonic() + MAX_SECONDS
        source = HashingReader(stream, directory, deadline)
        framed = RestrictiveTarReader(source)
        count, path_bytes = 0, 0
        with tarfile.open(fileobj=framed, mode="r|", tarinfo=BoundedTarInfo) as archive:
            for entry in iter_uncached_archive(archive):
                if time.monotonic() > deadline:
                    raise TimeoutError("catalog deadline exceeded")
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("entry limit exceeded")
                row = entry_row(entry)
                path_bytes += len(row[0].encode("utf-8")) + len(row[2].encode("utf-8"))
                if path_bytes > MAX_PATH_BYTES:
                    raise ValueError("path byte limit exceeded")
                if free_space(directory) < MIN_FREE_BYTES + 1024 * 1024:
                    raise ValueError("temporary storage reserve insufficient")
                try:
                    db.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?)", row)
                except sqlite3.IntegrityError as exc:
                    raise ValueError("duplicate normalized path") from exc
        framed.finish()
        if "sha256:" + source.hasher.hexdigest() != expected_diff:
            raise ValueError("layer diff ID mismatch")
        db.commit()
        db.close()
        db = None
        fd = os.open("provisional.sqlite3", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            os.fsync(fd)
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
        if not provisional:
            os.link(
                "provisional.sqlite3",
                "catalog.sqlite3",
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            published = True
            os.unlink("provisional.sqlite3", dir_fd=directory)
        os.fsync(directory)
        return {
            "scope": "verified-single-layer-catalog-only",
            "diffId": expected_diff,
            "uncompressedBytes": source.count,
            "entries": count,
            "privateChild": child,
            "provisional": provisional,
            "finalImageVerified": False,
            "releaseQualified": False,
        }
    except BaseException:
        if db is not None:
            db.close()
        if directory is not None:
            for name in ("provisional.sqlite3", "catalog.sqlite3"):
                if name == "catalog.sqlite3" and not published:
                    continue
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=directory)
            os.close(directory)
            directory = None
        if created:
            os.rmdir(child, dir_fd=root)
        raise
    finally:
        if directory is not None:
            os.close(directory)
        os.close(root)
