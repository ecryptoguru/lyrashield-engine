"""Owned, no-follow financial files; platform barriers are deliberately explicit."""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from lyrashield.artifacts.financial_windows import WindowsDirectory
from uuid import uuid4


class FinancialDirectory:
    """Keep verified directory handles open so replacement cannot retarget I/O."""

    def __init__(self, path: Path):
        self.path = path.absolute()
        self._fd = -1
        self._windows: WindowsDirectory | None = None
        if os.name == "nt":
            from lyrashield.artifacts.financial_windows import WindowsDirectory

            self._windows = WindowsDirectory(self.path)
            return
        self._windows = None
        fd = os.open(self.path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                info = os.fstat(fd)
                if info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX):
                    raise OSError("financial parent is writable by others")  # noqa: TRY301 - release verified handles before propagating failure
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise OSError("financial run directory must be owned and not writable by others")  # noqa: TRY301 - release verified handles before propagating failure
            self._fd = fd
        except BaseException:
            os.close(fd)
            raise

    def open(self, name: str, *, create: bool = False, private: bool = False) -> int:
        if self._windows is not None:
            fd = self._windows.open(name, create=create, private=private)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                os.close(fd)
                raise OSError("financial file is not a single regular file")
            return fd
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(name, flags, 0o600, dir_fd=self._fd)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)
            ):
                raise OSError("financial file is not an owned private regular file")  # noqa: TRY301 - release verified handles before propagating failure
        except BaseException:
            os.close(fd)
            raise
        else:
            return fd

    def read(self, name: str, maximum: int, *, private: bool = False) -> bytes | None:
        try:
            fd = self.open(name, private=private)
        except FileNotFoundError:
            return None
        try:
            if os.fstat(fd).st_size > maximum:
                raise OSError("financial file exceeds its bound")
            data = bytearray()
            while chunk := os.read(fd, min(65536, maximum + 1 - len(data))):
                data.extend(chunk)
                if len(data) > maximum:
                    raise OSError("financial file exceeds its bound")
            return bytes(data)
        finally:
            os.close(fd)

    def barrier(self) -> None:
        # Windows has no POSIX directory-fsync promise. Its backend qualifies
        # process-death atomic replacement, not OS/power-loss namespace ordering.
        if self._windows is None:
            os.fsync(self._fd)

    def replace(self, name: str, payload: bytes) -> None:
        temporary = f".{name}.{uuid4().hex}.tmp"
        try:
            fd = self.open(temporary, create=True, private=True)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short financial write")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            if self._windows is None:
                os.replace(temporary, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
            else:
                self._windows.replace(temporary, name)
            self.barrier()
        finally:
            if self._windows is None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=self._fd)
            else:
                (self.path / temporary).unlink(missing_ok=True)

    def lock(self, fd: int) -> None:
        if self._windows is not None:
            self._windows.lock(fd)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def close(self) -> None:
        if self._windows is not None:
            self._windows.close()
        elif self._fd >= 0:
            os.close(self._fd)
            self._fd = -1
