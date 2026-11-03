"""Owned, no-follow financial files; platform barriers are deliberately explicit."""

from __future__ import annotations

import contextlib
import os
import stat
import sys
from collections.abc import Iterator
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING

from filelock import FileLock


if TYPE_CHECKING:
    from lyrashield.artifacts.financial_windows import WindowsDirectory
from uuid import uuid4


def _qualify_posix_acl(fd: int, *, private: bool = False) -> None:
    if sys.platform == "darwin":
        from lyrashield.artifacts.financial_macos import qualify_acl

        qualify_acl(fd, private=private)


class FinancialDirectory:
    """Keep verified directory handles open so replacement cannot retarget I/O."""

    def __init__(self, path: Path, *, create: bool = False):
        self.path = path.absolute()
        self._fd = -1
        self._windows: WindowsDirectory | None = None
        if os.name == "nt":
            from lyrashield.artifacts.financial_windows import WindowsDirectory

            self._windows = WindowsDirectory(self.path, create=create)
            return
        self._windows = None
        fd = os.open(self.path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            _qualify_posix_acl(fd)
            for part in self.path.parts[1:]:
                try:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                _qualify_posix_acl(fd)
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

    def verify_current_path(self) -> None:
        """A detached POSIX owner must not send or mutate its old namespace.

        Rewalk every ancestor without following aliases and requalify its ACL.
        This is a last-check guarantee, not protection against privileged changes
        after the check or an administrator rolling back the entire directory.
        Windows holds all ancestors against rename in its native backend.
        """
        if self._windows is not None:
            return
        current = FinancialDirectory(self.path)
        try:
            if not os.path.samestat(os.fstat(self._fd), os.fstat(current._fd)):
                raise OSError("financial run directory identity changed")
        finally:
            current.close()

    def open(self, name: str, *, create: bool = False, private: bool = False) -> int:
        self.verify_current_path()
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
            _qualify_posix_acl(fd, private=private)
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

    def qualify_locked_handle(self, name: str, fd: int, expected_fd: int) -> None:
        """Qualify the held descriptor, not only a pre-lock pathname probe."""
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
            raise OSError("financial transition is not a single regular file")
        if self._windows is not None:
            self._windows.qualify_fd(fd, private=True)
        elif actual.st_uid != os.getuid() or actual.st_mode & 0o077:
            raise OSError("financial transition is not owned and private")
        if self._windows is None:
            _qualify_posix_acl(fd, private=True)
        named_fd = self.open(name, private=True)
        try:
            expected, named = os.fstat(expected_fd), os.fstat(named_fd)
            identity = (actual.st_dev, actual.st_ino)
            if identity != (expected.st_dev, expected.st_ino) or identity != (
                named.st_dev,
                named.st_ino,
            ):
                raise OSError("financial transition handle identity changed")
        finally:
            os.close(named_fd)

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
            self.verify_current_path()
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
                self.verify_current_path()
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


_TRANSITION_NAME = ".finite-budget-transition"
_transition_capture: ContextVar[int | None] = ContextVar("financial_transition_fd", default=None)
_transition_handles: ContextVar[dict[str, int] | None] = ContextVar(
    "financial_transition_handles", default=None
)


def _capture_transition_fd(fd: int) -> None:
    """FileLock's public hook exposes the actual acquired native descriptor."""
    _transition_capture.set(fd)


@contextlib.contextmanager
def transition_lock(path: Path, *, financial: bool = False) -> Iterator[None]:
    """Serialize cutover without altering an existing coordination inode."""
    directory = FinancialDirectory(path, create=True) if financial else None
    expected_fd = -1
    try:
        if directory is not None:
            try:
                expected_fd = directory.open(_TRANSITION_NAME, private=True)
            except FileNotFoundError:
                expected_fd = directory.open(_TRANSITION_NAME, create=True, private=True)
        else:
            path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                # FileLock's default mode never chmods an existing file. Create
                # only our missing POSIX inode privately; never truncate it.
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK
                try:
                    created = os.open(path / _TRANSITION_NAME, flags, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(created)
        key = str(path.absolute() / _TRANSITION_NAME)
        lock = FileLock(
            key,
            timeout=10,
            is_singleton=True,
            preserve_lock_file=True,
            fallback_to_soft=False,
            on_acquired=_capture_transition_fd,
        )
        with lock:
            handles = _transition_handles.get() or {}
            acquired_fd = _transition_capture.get() if lock.lock_counter == 1 else handles.get(key)
            if acquired_fd is None:
                raise OSError("financial transition has no acquired native handle")
            token = _transition_handles.set({**handles, key: acquired_fd})
            try:
                if directory is not None:
                    directory.qualify_locked_handle(_TRANSITION_NAME, acquired_fd, expected_fd)
                yield
            finally:
                _transition_handles.reset(token)
    finally:
        if expected_fd >= 0:
            os.close(expected_fd)
        if directory is not None:
            directory.close()
