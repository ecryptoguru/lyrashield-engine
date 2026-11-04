"""Private verified layer spooling prototype; no OCI overlay is applied."""

# Keep acquisition, publication and cleanup in one visible transaction.
# ruff: noqa: INP001, PLR0912, PLR0915, TRY301
import contextlib
import os
import secrets
import stat
import time

from scripts.check_sbom_inventory import StrictTarReader
from scripts.verify_oci_layer_binding import verify_layer_stream


MAX_SPOOL_BYTES = 4 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_HEADERS = 1_000_000
MAX_SECONDS = 900


def free_space(directory_fd):
    values = os.fstatvfs(directory_fd)
    return values.f_bavail * values.f_frsize


class BoundedFrames(StrictTarReader):
    def __init__(self):
        super().__init__(None)
        self.header_count = 0

    def begin_header(self, block):
        self.header_count += 1
        if self.header_count > MAX_HEADERS:
            raise ValueError("tar header limit exceeded")
        super().begin_header(block)

    def complete(self):
        if self.partial or self.payload_remaining or self.zero_blocks < 2:
            raise ValueError("incomplete tar framing or end marker")


def write_all(fd, data):
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("short temporary write")
        remaining = remaining[written:]


def spool_verified_layer(stream, item, expected_diff, private_root):
    """Commit one private layer stream only after verification and tar framing.

    The root must be a trusted caller-owned 0700 directory. The returned file
    must be closed by the caller; the caller owns the created private child.
    This does not authenticate a descriptor, apply changesets or qualify images.
    """
    root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    job = None
    directory = None
    staging = None
    result_fd = None
    created = False
    published = False
    try:
        info = os.fstat(root)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("private root ownership or type invalid")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("private root permissions invalid")
        job = "layer-" + secrets.token_hex(16)
        os.mkdir(job, 0o700, dir_fd=root)
        created = True
        directory = os.open(job, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        staging = os.open(
            "provisional.tar",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        os.fchmod(staging, 0o600)
        frame = BoundedFrames()
        written = 0
        deadline = time.monotonic() + MAX_SECONDS

        def stage(data):
            nonlocal written
            if time.monotonic() > deadline:
                raise TimeoutError("layer spooling deadline exceeded")
            if written + len(data) > MAX_SPOOL_BYTES:
                raise ValueError("layer spool size limit exceeded")
            if free_space(directory) < MIN_FREE_BYTES + len(data):
                raise ValueError("temporary storage reserve insufficient")
            frame.feed(data)
            write_all(staging, data)
            written += len(data)

        layer, verified_size = verify_layer_stream(stream, item, expected_diff, 0, on_data=stage)
        frame.complete()
        if verified_size != written or not written:
            raise ValueError("spooled layer size mismatch")
        os.fsync(staging)
        os.close(staging)
        staging = None
        os.link(
            "provisional.tar",
            "verified.tar",
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        published = True
        os.unlink("provisional.tar", dir_fd=directory)
        result_fd = os.open("verified.tar", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        os.fsync(directory)
        result = os.fdopen(result_fd, "rb")
        result_fd = None
        return {
            "scope": "verified-layer-spool-only",
            "digest": layer["digest"],
            "diffId": layer["diffId"],
            "uncompressedBytes": written,
            "privateChild": job,
        }, result
    except BaseException:
        if result_fd is not None:
            os.close(result_fd)
        if staging is not None:
            os.close(staging)
        if directory is not None:
            for name in ("provisional.tar", "verified.tar"):
                if name == "verified.tar" and not published:
                    continue
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=directory)
        if directory is not None:
            os.close(directory)
            directory = None
        if created:
            os.rmdir(job, dir_fd=root)
        raise
    finally:
        if directory is not None:
            os.close(directory)
        os.close(root)
