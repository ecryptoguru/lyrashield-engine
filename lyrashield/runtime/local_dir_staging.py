"""Symlink-safe staging for ``LocalDir`` manifest uploads.

The sandbox SDK's ``LocalDir`` walker refuses to copy symlinks at all — it
raises ``LocalDirReadError(reason="symlink_not_supported")`` on the first one
as a path-escape / TOCTOU safeguard. Real source trees (especially JS/TS
monorepos with workspace or shared-config links) routinely commit symlinks, so
handing such a tree straight to ``LocalDir`` aborts the upload before the agent
even starts.

:func:`stage_symlink_safe_dir` returns a path that is always safe to hand to
``LocalDir``:

* a tree with no symlinks is used as-is (no copy);
* otherwise the tree is copied into a temp directory with symlinks resolved:

  - a link whose target stays inside the tree is *dereferenced* (its target
    content is materialized in place), so the agent still sees the file;
  - a link that escapes the tree, dangles, or forms a cycle is *dropped* and
    never followed. Refusing to follow out-of-tree links preserves the walker's
    path-escape safety and keeps host/out-of-tree content from leaking into the
    (hostile) sandbox.

Regular files are hard-linked when possible (falling back to a copy across
devices), so the staged tree adds negligible disk for the non-symlink bulk.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path


logger = logging.getLogger(__name__)

_STAGING_PREFIX = "strix-localdir-"


def _is_within(target: Path, root: Path) -> bool:
    """Return whether ``target`` is ``root`` itself or nested under it."""
    if target == root:
        return True
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def tree_has_symlink(root: Path) -> bool:
    """Return whether ``root`` contains any symlink (file or directory)."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in (*dirnames, *filenames):
            if (base / name).is_symlink():
                return True
    return False


def _link_or_copy(src: Path, dst: Path) -> None:
    """Hard-link ``src`` to ``dst``, falling back to a content copy."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst, follow_symlinks=True)


def _copy_open_regular_file(source_fd: int, dst: Path) -> None:
    """Copy a no-follow-opened regular file into an exclusive staged file."""
    source_stat = os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode):
        raise OSError(f"Source changed to a non-regular file: {dst.name}")
    dest_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with (
            os.fdopen(source_fd, "rb", closefd=False) as source_file,
            os.fdopen(dest_fd, "wb", closefd=False) as dest_file,
        ):
            shutil.copyfileobj(source_file, dest_file)
        os.fchmod(dest_fd, stat.S_IMODE(source_stat.st_mode))
    finally:
        os.close(dest_fd)


def _stage_dir(src: Path, dst: Path, root: Path, seen: frozenset[Path]) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in os.scandir(src):
        entry_path = Path(entry.path)
        dest_path = dst / entry.name

        if entry.is_symlink():
            target = Path(os.path.realpath(entry_path))
            if not _is_within(target, root):
                logger.warning("staging: dropping out-of-tree symlink %s -> %s", entry_path, target)
                continue
            if not target.exists():
                logger.warning("staging: dropping dangling symlink %s", entry_path)
                continue
            if target in seen:
                logger.warning("staging: dropping cyclic symlink %s -> %s", entry_path, target)
                continue
            if target.is_dir():
                _stage_dir(target, dest_path, root, seen | {target})
            else:
                _link_or_copy(target, dest_path)
        elif entry.is_dir(follow_symlinks=False):
            _stage_dir(entry_path, dest_path, root, seen)
        elif entry.is_file(follow_symlinks=False):
            _link_or_copy(entry_path, dest_path)
        else:
            # Sockets, FIFOs, devices — not part of a source tree; skip.
            logger.debug("staging: skipping non-regular entry %s", entry_path)


def _open_beneath(root_fd: int, parts: tuple[str, ...]) -> int:
    """Open an in-tree target without following a swapped parent component."""
    if any(part in {"", ".", ".."} for part in parts):
        raise OSError("Unsafe source component")
    fd = os.dup(root_fd)
    for index, part in enumerate(parts):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if index < len(parts) - 1:
            flags |= os.O_DIRECTORY
        try:
            next_fd = os.open(part, flags, dir_fd=fd)
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
        fd = next_fd
    return fd


def _stage_frozen_tree(
    source_fd: int,
    source_path: Path,
    dst: Path,
    root: Path,
    root_fd: int,
    seen: frozenset[tuple[int, int]],
) -> None:
    """Walk held directory descriptors so path swaps cannot escape the source."""
    dst.mkdir(parents=True, exist_ok=True)
    with os.scandir(source_fd) as entries:
        for entry in entries:
            name = entry.name
            dest_path = dst / name
            source_stat = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if stat.S_ISLNK(source_stat.st_mode):
                target = Path(os.path.realpath(source_path / name))
                if not _is_within(target, root):
                    logger.warning("staging: dropping out-of-tree symlink %s", source_path / name)
                    continue
                try:
                    target_fd = _open_beneath(root_fd, target.relative_to(root).parts)
                except OSError:
                    logger.warning("staging: dropping unresolved symlink %s", source_path / name)
                    continue
            elif stat.S_ISDIR(source_stat.st_mode):
                target_fd = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
                )
            elif stat.S_ISREG(source_stat.st_mode):
                target_fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd
                )
            else:
                logger.debug("staging: skipping non-regular entry %s", source_path / name)
                continue
            try:
                target_stat = os.fstat(target_fd)
                if stat.S_ISDIR(target_stat.st_mode):
                    identity = (target_stat.st_dev, target_stat.st_ino)
                    if identity in seen:
                        logger.warning(
                            "staging: dropping cyclic directory link %s", source_path / name
                        )
                        continue
                    _stage_frozen_tree(
                        target_fd,
                        source_path / name,
                        dest_path,
                        root,
                        root_fd,
                        seen | {identity},
                    )
                elif stat.S_ISREG(target_stat.st_mode):
                    _copy_open_regular_file(target_fd, dest_path)
                else:
                    logger.debug("staging: skipping non-regular entry %s", source_path / name)
            finally:
                os.close(target_fd)


def stage_symlink_safe_dir(src_root: Path) -> tuple[Path, Path | None]:
    """Return ``(upload_path, staged_temp)`` for uploading ``src_root``.

    ``upload_path`` is safe to hand to ``LocalDir``. When the tree contains no
    symlinks it is ``src_root`` itself and ``staged_temp`` is ``None``.
    Otherwise a symlink-safe copy is materialized in a temp directory and both
    returned values point at it; the caller owns removing ``staged_temp`` once
    the upload completes.
    """
    root = src_root.resolve()
    if not tree_has_symlink(root):
        return root, None

    staged = Path(tempfile.mkdtemp(prefix=_STAGING_PREFIX)).resolve()
    try:
        _stage_dir(root, staged, root, frozenset({root}))
    except OSError:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    logger.info("staging: materialized symlink-safe copy of %s at %s", root, staged)
    return staged, staged


def stage_frozen_dir(src_root: Path) -> Path:
    """Materialize independent bytes for a scan's copied local source."""
    root = src_root.resolve()
    staged = Path(tempfile.mkdtemp(prefix=_STAGING_PREFIX)).resolve()
    if _is_within(staged, root):
        shutil.rmtree(staged, ignore_errors=True)
        raise OSError("Source contains its own staging directory")
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_stat = os.fstat(root_fd)
            _stage_frozen_tree(
                root_fd,
                root,
                staged,
                root,
                root_fd,
                frozenset({(root_stat.st_dev, root_stat.st_ino)}),
            )
        finally:
            os.close(root_fd)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return staged


def staged_tree_digest(root: Path) -> str:
    """Hash exactly the regular paths and bytes staged for LocalDir upload."""
    digest = hashlib.sha256()
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in dirs:
            relative = (
                (Path(base) / name).relative_to(root).as_posix().encode("utf-8", "surrogateescape")
            )
            digest.update(b"D")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
        for name in sorted(files):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix().encode("utf-8", "surrogateescape")
            digest.update(b"F")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            with path.open("rb") as source:
                digest.update(os.fstat(source.fileno()).st_size.to_bytes(8, "big"))
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"
