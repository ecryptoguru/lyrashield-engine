"""Provisional catalog of one fetched OCI layer, without retaining its tar."""

# ruff: noqa: INP001, PLR0912, PLR0915, TRY301
import contextlib
import os
import secrets
import stat
import threading
from pathlib import Path

from scripts.index_verified_oci_changeset import catalog_forward_layer
from scripts.spool_verified_oci_layer import require_no_acl, write_all
from scripts.verify_oci_layer_binding import verify_layer_stream


JOIN_SECONDS = 60
FETCH_EXIT_SECONDS = 10


def catalog_fetched_layer(fetch, descriptor, diff_id, private_root):
    """Return only after byte verification, catalog completion and fetch exit 0.

    The caller supplies a fresh fetch process and must supervise this entire
    process group with a wall timeout. A stuck worker may leave private stage
    files. This holds no source tar; future extent use requires a separately
    re-fetched, fully verified identical uncompressed stream.
    """
    root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage = None
    stage_created = False
    read_fd = write_fd = None
    worker = None
    result = {}
    try:
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
            raise ValueError("catalog worker failed") from result["error"]
        report = result["report"]
        if report["diffId"] != diff_id or report["uncompressedBytes"] != size:
            raise ValueError("catalog result identity mismatch")
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
    except BaseException:
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
                (child / "catalog.sqlite3").unlink()
                child.rmdir()
            with contextlib.suppress(FileNotFoundError):
                os.rmdir(stage, dir_fd=root)
        raise
    finally:
        if fetch.stdout is not None:
            fetch.stdout.close()
        os.close(root)
