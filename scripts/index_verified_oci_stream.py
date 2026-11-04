"""Provisional catalog of one fetched OCI layer, without retaining its tar."""

# ruff: noqa: INP001, PLR0912, PLR0915, TRY301
import contextlib
import os
import secrets
import sqlite3
import stat
import threading
from pathlib import Path

from scripts.index_verified_oci_changeset import CatalogUnsafePathError, catalog_forward_layer
from scripts.spool_verified_oci_layer import require_no_acl, write_all
from scripts.verify_oci_layer_binding import verify_layer_stream


JOIN_SECONDS = 60
FETCH_EXIT_SECONDS = 10


class CatalogWorkerError(ValueError):
    """A fixed, non-content-bearing worker failure category."""

    def __init__(self, category):
        super().__init__(category)
        self.category = category


def worker_failure_category(error):
    """Map only known constant messages; never expose archive-derived text."""
    if isinstance(error, CatalogUnsafePathError):
        return error.category
    if isinstance(error, UnicodeError):
        return "invalid-utf8"
    if isinstance(error, ValueError):
        known = {
            "unsupported tar type or extension": "unsupported-tar-type",
            "unsupported or duplicate PAX key": "unsupported-pax-key",
            "unsupported metadata": "unsupported-metadata",
            "unsafe path": "unsafe-path",
            "invalid whiteout": "invalid-whiteout",
            "duplicate normalized path": "duplicate-path",
            "layer byte limit exceeded": "layer-limit",
            "entry limit exceeded": "entry-limit",
            "path byte limit exceeded": "path-limit",
            "temporary storage reserve insufficient": "storage-reserve",
        }
        message = error.args[0] if error.args and isinstance(error.args[0], str) else ""
        return known.get(message, "catalog-value-error")
    if isinstance(error, sqlite3.Error):
        return "catalog-storage-error"
    if isinstance(error, TimeoutError):
        return "catalog-timeout"
    if isinstance(error, OSError):
        return "catalog-io-error"
    return "catalog-worker-error"


def catalog_fetched_layer(fetch, descriptor, diff_id, private_root):
    """Return only after byte verification, catalog completion and fetch exit 0.

    The caller supplies a fresh fetch process and must supervise this entire
    process group with a wall timeout. A stuck worker may leave private stage
    files. This holds no source tar; future extent use requires a separately
    re-fetched, fully verified identical uncompressed stream.
    """
    root = None
    stage = None
    stage_created = False
    read_fd = write_fd = None
    worker = None
    result = {}
    try:
        root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(root)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("private root invalid")
        require_no_acl(root)
        stage = "stream-" + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=root)
        stage_created = True
        stage_path = Path(private_root) / stage
        read_fd, write_fd = os.pipe()

        def consume(fd):
            try:
                with os.fdopen(fd, "rb") as stream:
                    result["report"] = catalog_forward_layer(stream, diff_id, stage_path)
            except BaseException as error:  # noqa: BLE001 - report every worker failure to caller
                result["error"] = error

        worker = threading.Thread(target=consume, args=(read_fd,), daemon=True)
        worker.start()
        read_fd = None  # worker owns the descriptor
        try:
            layer, size = verify_layer_stream(
                fetch.stdout, descriptor, diff_id, 0, on_data=lambda data: write_all(write_fd, data)
            )
        finally:
            os.close(write_fd)
            write_fd = None
        if fetch.wait(timeout=FETCH_EXIT_SECONDS) != 0:
            raise ValueError("fetch process failed")
        worker.join(JOIN_SECONDS)
        if worker.is_alive():
            raise TimeoutError("catalog worker did not finish")
        if "error" in result:
            raise CatalogWorkerError(worker_failure_category(result["error"])) from None
        report = result["report"]
        if report["diffId"] != diff_id or report["uncompressedBytes"] != size:
            raise ValueError("catalog result identity mismatch")
        if report.get("provisional") is not True:
            raise ValueError("catalog was not provisional")
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        try:
            child_fd = os.open(
                report["privateChild"],
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=stage_fd,
            )
            try:
                os.link(
                    "provisional.sqlite3",
                    "catalog.sqlite3",
                    src_dir_fd=child_fd,
                    dst_dir_fd=child_fd,
                    follow_symlinks=False,
                )
                os.unlink("provisional.sqlite3", dir_fd=child_fd)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
        finally:
            os.close(stage_fd)
        return {
            "scope": "verified-single-layer-stream-catalog-only",
            "descriptorDigest": layer["digest"],
            "diffId": diff_id,
            "uncompressedBytes": size,
            "entries": report["entries"],
            "privateStage": stage,
            "privateChild": report["privateChild"],
            "sourceRetained": False,
            "finalImageVerified": False,
            "releaseQualified": False,
        }
    except BaseException as error:
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        if read_fd is not None:
            os.close(read_fd)
            read_fd = None
        if fetch.poll() is None:
            fetch.kill()
        fetch.wait()
        if worker is not None:
            worker.join(JOIN_SECONDS)
        if stage_created and (worker is None or not worker.is_alive()):
            report = result.get("report")
            if report is not None:
                child = Path(private_root) / stage / report["privateChild"]
                for name in ("provisional.sqlite3", "catalog.sqlite3"):
                    with contextlib.suppress(FileNotFoundError):
                        (child / name).unlink()
                child.rmdir()
            with contextlib.suppress(FileNotFoundError):
                os.rmdir(stage, dir_fd=root)
        if (
            isinstance(error, BrokenPipeError)
            and worker is not None
            and not worker.is_alive()
            and "error" in result
        ):
            raise CatalogWorkerError(worker_failure_category(result["error"])) from None
        raise
    finally:
        if fetch.stdout is not None:
            fetch.stdout.close()
        if root is not None:
            os.close(root)
