"""Authenticate a single layer stream after a catalog rejection; no overlay."""

# ruff: noqa: INP001, PLR0912, PLR0915
import contextlib
import os
import secrets
import stat
import threading
import time
from pathlib import Path

from scripts.index_verified_oci_changeset import catalog_forward_layer
from scripts.index_verified_oci_stream import worker_failure_category
from scripts.reconstruct_oci_layers import PaxKeyRejectionError
from scripts.spool_verified_oci_layer import free_space, require_no_acl, write_all
from scripts.verify_oci_layer_binding import verify_layer_stream


MAX_DRAIN_BYTES = 4 * 1024**3
MAX_COMPRESSED_BYTES = 4 * 1024**3
MIN_FREE_BYTES = 2 * 1024**3
MAX_SECONDS = 900
JOIN_SECONDS = 60
FETCH_EXIT_SECONDS = 10


def authenticated_worker_failure_category(error):
    """Expose only fixed PAX reasons after the caller verifies the whole stream."""
    if isinstance(error, PaxKeyRejectionError):
        reason = getattr(error, "reason", None)
        if type(reason) is str and reason in {
            "pax-duplicate-supported-key",
            "pax-unsupported-capability-key",
            "pax-unsupported-other-key",
        }:
            return reason
    return worker_failure_category(error)


def diagnose_fetched_layer(fetch, item, diff_id, private_root):
    """Authenticate stream bytes before exposing a fixed rejected-worker category.

    The supplied fetch belongs to this function. The caller must authenticate
    descriptor and DiffID and supervise the process group with a wall deadline.
    PAX reasons identify only the first local rejection; unsupported keys are
    rejected immediately, so their later duplicates cannot be classified. A
    successful diagnostic is not archive validation, reconstructed filesystem,
    package completeness or release qualification.
    """
    root = directory = None
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
        if (
            not isinstance(item, dict)
            or type(item.get("size")) is not int
            or not 0 < item["size"] <= MAX_COMPRESSED_BYTES
        ):
            raise ValueError("compressed byte limit exceeded")
        stage = "drain-" + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=root)
        stage_created = True
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        require_no_acl(directory)
        stage_path = Path(private_root) / stage
        read_fd, write_fd = os.pipe()

        def consume(fd):
            try:
                with os.fdopen(fd, "rb") as stream:
                    result["report"] = catalog_forward_layer(stream, diff_id, stage_path)
            except BaseException as error:  # noqa: BLE001 - record a category only after verification
                result["error"] = error

        worker = threading.Thread(target=consume, args=(read_fd,), daemon=True)
        worker.start()
        read_fd = None
        count = 0
        deadline = time.monotonic() + MAX_SECONDS

        def feed(data):
            nonlocal count, write_fd
            if time.monotonic() > deadline:
                raise TimeoutError("drain deadline exceeded")
            if free_space(directory) < MIN_FREE_BYTES + 1024 * 1024:
                raise ValueError("temporary storage reserve insufficient")
            count += len(data)
            if count > MAX_DRAIN_BYTES:
                raise ValueError("uncompressed byte limit exceeded")
            if write_fd is not None:
                try:
                    write_all(write_fd, data)
                except BrokenPipeError:
                    os.close(write_fd)
                    write_fd = None

        try:
            layer, size = verify_layer_stream(fetch.stdout, item, diff_id, 0, on_data=feed)
        finally:
            if write_fd is not None:
                os.close(write_fd)
                write_fd = None
        if fetch.wait(timeout=FETCH_EXIT_SECONDS) != 0:
            raise ValueError("fetch process failed")
        worker.join(JOIN_SECONDS)
        if worker.is_alive():
            raise TimeoutError("catalog worker did not finish")
        if "error" not in result:
            raise ValueError("catalog did not reject")
        if count != size:
            raise ValueError("drain size mismatch")
        return {
            "scope": "authenticated-single-layer-rejection-diagnostic-only",
            "category": authenticated_worker_failure_category(result["error"]),
            "descriptorDigest": layer["digest"],
            "compressedBytes": layer["size"],
            "diffId": diff_id,
            "uncompressedBytes": size,
            "catalogAccepted": False,
            "sourceRetained": False,
            "finalImageVerified": False,
            "releaseQualified": False,
        }
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)
        if fetch.poll() is None:
            fetch.kill()
        fetch.wait()
        if worker is not None:
            worker.join(JOIN_SECONDS)
        if stage_created and (worker is None or not worker.is_alive()):
            report = result.get("report")
            if report is not None:
                child = Path(private_root) / stage / report["privateChild"]
                with contextlib.suppress(FileNotFoundError):
                    (child / "provisional.sqlite3").unlink()
                child.rmdir()
            if directory is not None:
                os.close(directory)
                directory = None
            with contextlib.suppress(FileNotFoundError):
                os.rmdir(stage, dir_fd=root)
        if directory is not None:
            os.close(directory)
        if fetch.stdout is not None:
            fetch.stdout.close()
        if root is not None:
            os.close(root)
