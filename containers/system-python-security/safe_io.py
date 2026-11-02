"""Checked file topology and recoverable publication for the system repair.

Every directory is opened relative to a held descriptor with O_NOFOLLOW. Sources
must be regular, singly linked files. Replacements use rename within that held
directory, so neither a linked final name nor a switched parent redirects writes.
All output bytes and backups are staged before the first original is replaced.
Caught publication failures restore originals, including deletions and receipts.
"""

# ruff: noqa: INP001
from __future__ import annotations

import os
import stat
import uuid
from contextlib import suppress
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path


FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _parts(relative: str) -> list[str]:
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe relative publication path")
    return parts


def _parent(root: Path, relative: str, created: list[str] | None = None) -> tuple[int, str]:
    if root.is_symlink():
        raise ValueError("linked repair/cache root")
    parts = _parts(relative)
    descriptor = os.open("/", FLAGS)
    try:
        # Check the cache/root ancestry as well as paths beneath it. A linked
        # ancestor must not turn an apparent local cache into external writes.
        for component in root.absolute().parts[1:]:
            child = os.open(component, FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        prefix = []
        for part in parts[:-1]:
            prefix.append(part)
            try:
                child = os.open(part, FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if created is None:
                    raise
                os.mkdir(part, 0o755, dir_fd=descriptor)
                created.append("/".join(prefix))
                child = os.open(part, FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _existing(descriptor: int, name: str) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("linked or non-regular repair/cache file: " + name)
    return info


def preflight(root: Path, relative: str) -> None:
    """Reject unsafe existing prefixes or destinations, allowing absent outputs."""
    try:
        descriptor, name = _parent(root, relative)
    except FileNotFoundError:
        return
    try:
        _existing(descriptor, name)
    finally:
        os.close(descriptor)


def read_regular(root: Path, relative: str, *, max_bytes: int | None = None) -> bytes:
    descriptor, name = _parent(root, relative)
    try:
        info = _existing(descriptor, name)
        if info is None:
            raise FileNotFoundError(relative)
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        with os.fdopen(source, "rb") as stream:
            actual = os.fstat(stream.fileno())
            if actual.st_nlink != 1 or not stat.S_ISREG(actual.st_mode):
                raise ValueError("linked or non-regular input")
            if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("input topology changed during preflight")
            if max_bytes is not None and actual.st_size > max_bytes:
                raise ValueError("regular file exceeds read bound")
            data = stream.read() if max_bytes is None else stream.read(max_bytes + 1)
            if max_bytes is not None and len(data) > max_bytes:
                raise ValueError("regular file grew beyond read bound")
            return data
    finally:
        os.close(descriptor)


def _stage(descriptor: int, data: bytes, info: os.stat_result | None, *, backup: bool) -> str:
    name = ".lyrashield-" + uuid.uuid4().hex
    output = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
    )
    try:
        with os.fdopen(output, "wb") as stream:
            stream.write(data)
            stream.flush()
            if info is not None:
                os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode) if info is not None else 0o644)
            if backup and info is not None:
                os.utime(stream.fileno(), ns=(info.st_atime_ns, info.st_mtime_ns))
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(name, dir_fd=descriptor)
        raise
    return name


def publish(root: Path, writes: dict[str, bytes], removals=()) -> None:  # noqa: PLR0912, PLR0915
    """Prepare every output and backup, then publish with rollback on failure."""
    root = root.absolute()
    names = [*writes, *removals]
    if len(names) != len(set(names)):
        raise ValueError("duplicate transaction destination")
    for relative in names:
        preflight(root, relative)
    created = []
    staged = []
    committed = False
    try:
        for relative in names:
            descriptor, name = _parent(root, relative, created)
            item = {"fd": descriptor, "name": name, "stage": None, "backup": None, "applied": False}
            staged.append(item)
            info = _existing(descriptor, name)
            if info is not None:
                item["backup"] = _stage(descriptor, read_regular(root, relative), info, backup=True)
            if relative in writes:
                item["stage"] = _stage(descriptor, writes[relative], info, backup=False)
            elif info is None:
                raise ValueError("missing removal input: " + relative)  # noqa: TRY301
        for item in staged:
            if item["stage"] is None:
                os.unlink(item["name"], dir_fd=item["fd"])
            else:
                os.replace(
                    item["stage"], item["name"], src_dir_fd=item["fd"], dst_dir_fd=item["fd"]
                )
                item["stage"] = None
            item["applied"] = True
        committed = True
    except BaseException:
        for item in reversed(staged):
            if not item["applied"]:
                continue
            if item["backup"] is None:
                os.unlink(item["name"], dir_fd=item["fd"])
            else:
                os.replace(
                    item["backup"], item["name"], src_dir_fd=item["fd"], dst_dir_fd=item["fd"]
                )
                item["backup"] = None
            item["applied"] = False
        raise
    finally:
        for item in staged:
            for key in ("stage", "backup"):
                retain_original = key == "backup" and item["applied"] and not committed
                if item[key] is not None and not retain_original:
                    with suppress(OSError):
                        os.unlink(item[key], dir_fd=item["fd"])
            os.close(item["fd"])
        # Only new, empty publication directories may be removed after failure.
        for directory in reversed(created):
            with suppress(OSError):
                descriptor, name = _parent(root, directory)
                try:
                    os.rmdir(name, dir_fd=descriptor)
                finally:
                    os.close(descriptor)
