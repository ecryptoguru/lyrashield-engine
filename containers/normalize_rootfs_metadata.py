#!/usr/bin/env python3
"""Normalize shipped rootfs bytes so the bounded SBOM scan sees no ambiguity.

The sandbox build installs system packages whose metadata is sometimes
ambiguous for machine readers:

- some npm ``package.json`` files repeat a key (e.g. ``"types"`` or
  ``"engines"``) with the same field, and
- some directory symlinks alias a tree that itself contains symlinks or
  package metadata, hiding unscanned content behind the alias.

The scan in ``scripts/check_sbom_inventory.py`` deliberately rejects
both (duplicate JSON field; directory link that can expose unscanned
metadata). Rather than weakening that policy, this build-time helper
rewrites the image bytes so they are unambiguous:

- only identical, top-level duplicate ``types`` in source-map 0.8.0 and
  ``engines`` in windows-release 6.0.0 are collapsed, plus the two exact
  checksum-bound original image manifests. Duplicate identities and all
  other conflicts fail closed. Files without duplicates are untouched.
- every directory symlink under a declared metadata root whose target
  fails the scanner's own metadata-safety predicate is materialized:
  the symlink is replaced with a real directory containing a
  dereferenced copy of its target, so the served bytes are identical
  and are now scanned in place. Aliases the scanner accepts (for example
  the Node ``node_modules`` convention links) are left untouched.

The script fails closed (exit status 1) on malformed JSON, unreadable
entries, symlink targets that escape the image root, cyclic links, or
budget overruns, and re-verifies the normalized tree before reporting
success. It never widens the scanner's policy: anything it cannot
normalize must still fail the qualification downstream, not be silently
accepted.

Like the neighbouring build helpers, this file lives beside Docker
inputs rather than in a Python package.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import time
from bisect import bisect_left
from collections import deque
from contextlib import contextmanager
from email.parser import BytesParser
from pathlib import Path


# Root-relative (POSIX) package scan roots, mirroring
# scripts/check_sbom_inventory.py so both agree on scope.
NPM_ROOTS = (
    "home/pentester/.npm-tools/node_modules",
    "usr/share/nodejs",
    "usr/local/lib/node_modules",
)
PYTHON_ROOT_PATTERNS = (
    "usr/lib/python*/dist-packages",
    "usr/local/lib/python*/dist-packages",
    "app/.venv/lib/python*/site-packages",
)
PYTHON_ROOT = re.compile(
    r"(?:(?:usr/lib|usr/local/lib)/python[^/]+/dist-packages|"
    r"app/\.venv/lib/python[^/]+/site-packages)(?=/|\Z)"
)
PYTHON_ANCESTOR = re.compile(
    r"(?:(?:app|app/\.venv|app/\.venv/lib|app/\.venv/lib/python[^/]+)|"
    r"(?:usr|usr/lib|usr/lib/python[^/]+|usr/local|usr/local/lib|"
    r"usr/local/lib/python[^/]+))\Z"
)
# Mirrors valid_identity in scripts/check_sbom_inventory.py.
MAX_IDENTITY_CHARS = 1024

# Bounds, mirroring the scanner budgets so the fix cannot do unbounded work.
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_METADATA_FILES = 200_000
MAX_TOTAL_METADATA_BYTES = 256 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 1_000_000
MAX_DIRECTORIES = 200_000
MAX_DIRECTORY_DEPTH = 256
MAX_PROCESS_SECONDS = 900
MAX_LINK_DEPTH = 64
MAX_MATERIALIZED_FILES = 100_000
MAX_MATERIALIZED_BYTES = 8 * 1024 * 1024 * 1024

METADATA_NAMES = ("package.json", "METADATA")
REVIEWED_DUPLICATES = {
    ("source-map", "0.8.0"): "types",
    ("windows-release", "6.0.0"): "engines",
}
# Exact originals from both native images in held run 42538824189; fixtures
# retain their bytes. This exception cannot normalize other identity/content.
REVIEWED_DUPLICATE_INPUTS = {
    ("source-map", "0.8.0"): "3982740d6a191217de9200430ec40ac7db82912801f9e318d20ed2420834b7ea",
    ("windows-release", "6.0.0"): (
        "4d30a8eaf0f3692f37b1ffd58170c7b739bc22748b84f613a370a069c3ae95c1"
    ),
}


class Budget:
    """One cumulative budget across discovery, normalization and verification."""

    def __init__(self):
        self.deadline = time.monotonic() + MAX_PROCESS_SECONDS
        self.entries = 0
        self.directories = 0
        self.metadata_files = 0
        self.metadata_bytes = 0
        self.copy_files = 0
        self.copy_bytes = 0

    def check(self):
        if time.monotonic() >= self.deadline:
            raise ValueError("metadata normalization processing deadline exceeded")

    def directory(self):
        self.check()
        self.directories += 1
        if self.directories > MAX_DIRECTORIES:
            raise ValueError("metadata directory count budget exceeded")

    def entry(self):
        self.check()
        self.entries += 1
        if self.entries > MAX_DIRECTORY_ENTRIES:
            raise ValueError("metadata directory entry budget exceeded")

    def metadata(self, size):
        self.check()
        self.metadata_files += 1
        self.metadata_bytes += size
        if self.metadata_files > MAX_METADATA_FILES:
            raise ValueError("too many package metadata candidates")
        if self.metadata_bytes > MAX_TOTAL_METADATA_BYTES:
            raise ValueError("total metadata size budget exceeded")

    def copy(self, size):
        self.check()
        self.copy_files += 1  # Directories, including empty ones, count too.
        self.copy_bytes += size
        if self.copy_files > MAX_MATERIALIZED_FILES:
            raise ValueError("materialized metadata exceeds total file budget")
        if self.copy_bytes > MAX_MATERIALIZED_BYTES:
            raise ValueError("materialized metadata exceeds total copy budget")


def image_root(root: Path) -> Path:
    if root.is_symlink():
        raise ValueError("image root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("image root must be a directory")
    _check_trusted_root(root.stat())
    return root


def _check_trusted_root(info):
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("trusted image root must be owned by euid and not group/world writable")


def _resolve_path(path: Path, root: Path, budget: Budget) -> Path:
    """Resolve every component without letting the host follow image symlinks.

    Absolute symlink targets are image-absolute, not host-absolute. Reject an
    escape before even stat'ing it, including through a symlinked ancestor.
    """
    budget.check()
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        raise ValueError(f"symlink target escapes image root: {path}") from None
    pending = deque(parts)
    current = root
    seen = set()
    while pending:
        budget.check()
        part = pending.popleft()
        if part == "..":
            if current == root:
                raise ValueError(f"symlink target escapes image root: {path}")
            current = current.parent
            continue
        candidate = current / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if seen:
                raise ValueError(f"symlink target does not exist: {path}") from None
            raise
        if stat.S_ISLNK(info.st_mode):
            if candidate in seen:
                raise ValueError(f"cyclic directory symlink: {path}")
            seen.add(candidate)
            if len(seen) > MAX_LINK_DEPTH:
                raise ValueError(f"directory symlink chain too deep: {path}")
            raw = candidate.readlink()
            if raw.is_absolute():
                current = root
                raw = raw.relative_to("/")
            pending.extendleft(reversed(raw.parts))
        else:
            current = candidate
    return current


def _open_relative(directory_fd: int, name: Path, flags: int) -> int:
    """Open a relative entry through held, no-follow directory descriptors."""
    if name.is_absolute() or ".." in name.parts:
        raise ValueError("descriptor-relative path escapes directory")
    parts = name.parts
    directory = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        if not parts:
            return os.dup(directory)
        return os.open(parts[-1], flags | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    finally:
        os.close(directory)


def _open_beneath(path: Path, root: Path, flags: int) -> int:
    """No-follow opens for the final entry AND each resolved parent."""
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _open_relative(root_fd, path.relative_to(root), flags)
    finally:
        os.close(root_fd)


@contextmanager
def _destination(path: Path, root: Path):
    """Hold the trusted staging root and the destination's verified parent."""
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _check_trusted_root(os.fstat(root_fd))
        parent_fd = _open_relative(
            root_fd, path.parent.relative_to(root), os.O_RDONLY | os.O_DIRECTORY
        )
        try:
            yield root_fd, parent_fd
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


@contextmanager
def _regular_file(path: Path, root: Path, budget: Budget):
    resolved = _resolve_path(path, root, budget)
    fd = _open_beneath(resolved, root, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"unsupported non-regular file: {path}")
        yield stream, info


def _read_metadata(path: Path, root: Path, budget: Budget) -> bytes:
    with _regular_file(path, root, budget) as (stream, info):
        if not 0 <= info.st_size <= MAX_METADATA_BYTES:
            raise ValueError(f"package metadata exceeds size budget: {path}")
        budget.metadata(info.st_size)
        data = stream.read(MAX_METADATA_BYTES + 1)
        budget.check()
        if len(data) > MAX_METADATA_BYTES:
            raise ValueError(f"package metadata exceeds size budget: {path}")
        if len(data) != info.st_size:
            raise ValueError(f"metadata changed during read: {path}")
        return data


def _children(path: Path, root: Path, budget: Budget):
    budget.directory()
    resolved = _resolve_path(path, root, budget)
    fd = _open_beneath(resolved, root, os.O_RDONLY | os.O_DIRECTORY)
    entries = []
    try:
        with os.scandir(fd) as scan:
            for entry in scan:
                budget.entry()
                child = path / entry.name
                info = entry.stat(follow_symlinks=False)
                entries.append((child, info))
    finally:
        os.close(fd)
    return sorted(entries, key=lambda entry: entry[0].name)


def _walk_entries(target: Path, root: Path, budget: Budget):
    stack = [(target, 0)]
    while stack:
        directory, depth = stack.pop()
        if depth > MAX_DIRECTORY_DEPTH:
            raise ValueError("metadata directory depth budget exceeded")
        children = _children(directory, root, budget)
        for path, info in children:
            if stat.S_ISLNK(info.st_mode):
                _resolve_path(path, root, budget)
            yield path, info
        stack.extend(
            (path, depth + 1) for path, info in reversed(children) if stat.S_ISDIR(info.st_mode)
        )


def _existing_directory(path: Path, root: Path, budget: Budget) -> bool:
    try:
        resolved = _resolve_path(path, root, budget)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(resolved.lstat().st_mode):
        raise ValueError(f"metadata root is not a directory: {path}")
    return True


def _staging(_path: Path, root: Path, *, directory: bool = False, _root_fd=None):
    """Stage only under the trusted root, never a package-controlled parent."""
    name = ".normalize-" + secrets.token_hex(16)
    root_fd = (
        os.dup(_root_fd)
        if _root_fd is not None
        else os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    )
    try:
        _check_trusted_root(os.fstat(root_fd))
        if directory:
            os.mkdir(name, mode=0o700, dir_fd=root_fd)
            try:
                fd = _open_relative(root_fd, Path(name), os.O_RDONLY | os.O_DIRECTORY)
            except OSError:
                os.rmdir(name, dir_fd=root_fd)
                raise
        else:
            fd = _open_relative(root_fd, Path(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        return root / name, fd
    finally:
        os.close(root_fd)


def _discard_staging(name: str, root_fd: int, *, directory: bool = False):
    if directory:
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError("descriptor-relative staging cleanup requires safe rmtree")
        shutil.rmtree(name, dir_fd=root_fd)
    else:
        os.unlink(name, dir_fd=root_fd)


def _preserve_file_info(fd, info):
    os.fchown(fd, info.st_uid, info.st_gid)
    os.fchmod(fd, stat.S_IMODE(info.st_mode))


def metadata_kind(name: str):
    """Root-relative POSIX name -> "npm"|"pypi"|"deb"|None.

    Mirrors ``metadata_kind`` in ``scripts/check_sbom_inventory.py``.
    """
    if name == "var/lib/dpkg/status":
        return "deb"
    if re.fullmatch(
        r"(?:(?:usr/lib|usr/local/lib)/python[^/]+/dist-packages|"
        r"app/\.venv/lib/python[^/]+/site-packages)/[^/]+\.dist-info/METADATA",
        name,
    ):
        return "pypi"
    for root in NPM_ROOTS:
        prefix = root + "/"
        if name.startswith(prefix):
            remaining = name[len(prefix) :]
            if "/node_modules/" in remaining:
                remaining = remaining.rsplit("/node_modules/", 1)[1]
            parts = remaining.split("/")
            package_shape = (len(parts) == 2 and not parts[0].startswith("@")) or (
                len(parts) == 3 and parts[0].startswith("@")
            )
            if package_shape and parts[-1] == "package.json":
                return "npm"
    return None


def is_npm_metadata(name: str) -> bool:
    return metadata_kind(name) == "npm"


def python_root(name: str):
    match = PYTHON_ROOT.match(name)
    return match.group(0) if match else None


def scope_inside(name: str):
    if name == "var/lib/dpkg/status":
        return "deb", name
    for root in NPM_ROOTS:
        if name == root or name.startswith(root + "/"):
            return "npm", root
    root = python_root(name)
    if root is not None:
        return "pypi", root
    return None


def guarded_scope(name: str):
    """Scope of ``name`` for link-policy purposes (no Go captures in build)."""
    inside = scope_inside(name)
    if inside is not None:
        return inside
    fixed_roots = (*NPM_ROOTS, "var/lib/dpkg/status")
    for root in fixed_roots:
        if root.startswith(name + "/"):
            return ("deb" if root == "var/lib/dpkg/status" else "npm"), root
    if PYTHON_ANCESTOR.fullmatch(name):
        return "pypi", name
    return None


def python_roots(root: Path, *, _budget: Budget | None = None) -> list[Path]:
    """Existing directories matching the declared python metadata roots."""
    root = image_root(root)
    budget = _budget or Budget()
    found = []
    seen = set()
    for pattern in PYTHON_ROOT_PATTERNS:
        candidates = [root]
        for component in pattern.split("/"):
            if "*" not in component:
                candidates = [
                    base / component
                    for base in candidates
                    if _existing_directory(base / component, root, budget)
                ]
            else:
                candidates = [
                    path
                    for base in candidates
                    for path, _info in _children(base, root, budget)
                    if fnmatch.fnmatchcase(path.name, component)
                    and _existing_directory(path, root, budget)
                ]
        for candidate in candidates:
            if str(candidate) not in seen:
                seen.add(str(candidate))
                found.append(candidate)
    return found


def last_wins_pairs(pairs):
    # ``dict(pairs)`` keeps the last value per key: exactly what every
    # JSON consumer (Node, jq, Python, Go) resolves duplicates to.
    return dict(pairs)


def canonical_with_last_wins(data: bytes) -> tuple[bytes, bool]:
    """Collapse identical reviewed fields or exact checksum-bound originals."""
    duplicates = []

    def pairs_hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                duplicates.append((result, key, result[key], value))
            result[key] = value
        return result

    parsed = json.loads(data.decode("utf-8"), object_pairs_hook=pairs_hook)
    if not isinstance(parsed, dict):
        raise TypeError("package metadata must be a JSON object")
    if not duplicates:
        return data, False
    identity = (parsed.get("name"), parsed.get("version"))
    allowed = REVIEWED_DUPLICATES.get(identity)
    exact_original = hashlib.sha256(data).hexdigest() == REVIEWED_DUPLICATE_INPUTS.get(identity)
    for document, key, previous, value in duplicates:
        if (
            document is not parsed
            or key != allowed
            or (
                not exact_original
                and json.dumps(previous, sort_keys=True, allow_nan=False)
                != json.dumps(value, sort_keys=True, allow_nan=False)
            )
        ):
            raise ValueError(f"unreviewed duplicate {key} JSON field")
    canonical = (json.dumps(parsed, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    # Internal invariant: canonical bytes must read back to the same value.
    if json.loads(canonical, object_pairs_hook=last_wins_pairs) != parsed:
        raise ValueError("canonical form does not round-trip")
    return canonical, True


def iter_npm_metadata_files(root: Path, *, _budget: Budget | None = None):
    """Yield (relative_posix_name, absolute_path) for scanned npm metadata."""
    root = image_root(root)
    budget = _budget or Budget()
    for rel_root in NPM_ROOTS:
        base = root / rel_root
        if not _existing_directory(base, root, budget):
            continue
        for path, info in _walk_entries(base, root, budget):
            relative = path.relative_to(root).as_posix()
            if is_npm_metadata(relative) and not stat.S_ISLNK(info.st_mode):
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f"unsupported package metadata entry: {relative}")
                yield relative, _resolve_path(path, root, budget)


def canonicalize_npm_metadata(root: Path, *, _budget: Budget | None = None) -> list[str]:
    """Canonicalize duplicate-key package.json files under the npm roots."""
    root = image_root(root)
    budget = _budget or Budget()
    changed = []
    for relative, path in iter_npm_metadata_files(root, _budget=budget):
        data = _read_metadata(path, root, budget)
        try:
            canonical, changed_flag = canonical_with_last_wins(data)
        except (UnicodeDecodeError, TypeError, ValueError, RecursionError) as error:
            raise ValueError(f"malformed package metadata: {relative}: {error}") from None
        budget.check()
        if changed_flag:
            if len(canonical) > MAX_METADATA_BYTES:
                raise ValueError(f"canonical metadata exceeds size budget: {relative}")
            with _destination(path, root) as (root_fd, parent_fd):
                info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                temporary, fd = _staging(path, root, _root_fd=root_fd)
                published = False
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(canonical)
                        stream.flush()
                        os.rename(
                            temporary.name, path.name, src_dir_fd=root_fd, dst_dir_fd=parent_fd
                        )
                        published = True
                        _preserve_file_info(stream.fileno(), info)
                finally:
                    if not published:
                        _discard_staging(temporary.name, root_fd)
            changed.append(relative)
    return changed


def resolve_link(link: Path, root: Path) -> Path:
    """Resolve a symlink's final target inside ``root``.

    Follows symlink chains (bounded, cycle-checked). Raises
    ``ValueError`` if the chain escapes the root, is cyclic, is too deep,
    or ends at a path that does not exist. Returns the resolved path,
    which may be a file or a directory.
    """
    return _resolve_path(link, image_root(root), Budget())


def paths_below(sorted_paths, target):
    prefix = target + "/"
    start = bisect_left(sorted_paths, prefix)
    for path in sorted_paths[start:]:
        if not path.startswith(prefix):
            return
        yield path


def directory_alias_is_metadata_safe(
    name,
    target,
    *,
    entry_types,
    parsed_paths,
    metadata_paths,
    symlink_paths,
) -> bool:
    """Faithful port of ``directory_alias_is_metadata_safe``.

    Mirrors ``scripts/check_sbom_inventory.py`` (without Go-capture roots,
    which can only make the scanner's scope check *less* strict, so this
    port errs toward materializing — never toward keeping an alias the
    scanner would reject).
    """
    if entry_types.get(target) != "directory":
        return False
    sorted_metadata = sorted(metadata_paths)
    sorted_symlinks = sorted(symlink_paths)
    for nested_link in paths_below(sorted_symlinks, target):
        if guarded_scope(nested_link) is None:
            return False
    for physical_path in paths_below(sorted_metadata, target):
        alias = name + physical_path[len(target) :]
        alias_kind = metadata_kind(alias)
        if alias_kind is None:
            continue
        if (
            metadata_kind(physical_path) != alias_kind
            or entry_types.get(physical_path) != "regular"
            or physical_path not in parsed_paths
        ):
            return False
    return True


def collect_target_tree(target: Path, root: Path, *, _budget: Budget | None = None):
    """Index a target subtree for the safety predicate.

    Returns ``(entry_types, metadata_paths, symlink_paths, parsed_paths)``
    keyed by root-relative POSIX names. ``parsed_paths`` contains the
    metadata files that parse cleanly (npm metadata is already
    canonicalized by the caller before linking checks run).
    """
    root = image_root(root)
    budget = _budget or Budget()
    target = _resolve_path(target, root, budget)
    entry_types = {}
    metadata_paths = set()
    symlink_paths = set()
    parsed_paths = set()
    for path, info in _walk_entries(target, root, budget):
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            entry_types[relative] = "symlink"
            symlink_paths.add(relative)
        elif stat.S_ISDIR(info.st_mode):
            entry_types[relative] = "directory"
        elif stat.S_ISREG(info.st_mode):
            entry_types[relative] = "regular"
        else:
            raise ValueError(f"unsupported directory alias entry: {relative}")
        if path.name in METADATA_NAMES:
            metadata_paths.add(relative)
            if entry_types.get(relative) == "regular":
                data = _read_metadata(path, root, budget)
                if data and _parses_as_scanned_metadata(relative, data):
                    parsed_paths.add(relative)
                budget.check()
    entry_types[target.relative_to(root).as_posix()] = "directory"
    return entry_types, metadata_paths, symlink_paths, parsed_paths


def strict_pairs_check(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate {key} JSON field")
        result[key] = value
    return result


def _parse_scanned_metadata(kind: str | None, data: bytes) -> tuple[str | None, str | None]:
    """Extract (package, version) like the scanner's collect_metadata."""
    if kind == "npm":
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=strict_pairs_check)
        return parsed.get("name"), parsed.get("version")
    if kind == "pypi":
        message = BytesParser().parsebytes(data)
        for field in ("Name", "Version"):
            if len(message.get_all(field, [])) != 1:
                raise ValueError("duplicate metadata header")
        return message.get("Name"), message.get("Version")
    return None, None


def _parses_as_scanned_metadata(relative: str, data: bytes) -> bool:
    try:
        package, version = _parse_scanned_metadata(metadata_kind(relative), data)
    except (UnicodeDecodeError, ValueError, AttributeError, RecursionError):
        return False
    return all(
        isinstance(value, str) and value.strip() and len(value) <= MAX_IDENTITY_CHARS
        for value in (package, version)
    )


def _copy_entries(target: Path, root: Path, budget: Budget, ancestors: set[str]):
    stack = [(target, Path(), frozenset(ancestors))]
    while stack:
        source, relative, parents = stack.pop()
        resolved = _resolve_path(source, root, budget)
        info = resolved.lstat()
        if stat.S_ISDIR(info.st_mode):
            if str(resolved) in parents:
                raise ValueError(f"cyclic directory symlink: {source}")
            if len(parents) >= MAX_DIRECTORY_DEPTH:
                raise ValueError("directory copy depth budget exceeded")
            yield resolved, relative, info
            parents = parents | {str(resolved)}
            stack.extend(
                (child, relative / child.name, parents)
                for child, _info in reversed(_children(resolved, root, budget))
            )
        elif stat.S_ISREG(info.st_mode):
            yield resolved, relative, info
        else:
            raise ValueError(f"unsupported directory alias entry: {source}")


def plan_copy(
    target: Path,
    relative: str,
    ancestors: set[str],
    *,
    root: Path | None = None,
    _budget: Budget | None = None,
) -> tuple[int, int]:
    """Count all copied entries/bytes, resolving every descendant inside root."""
    root = image_root(root if root is not None else target)
    budget = _budget or Budget()
    n_files = n_bytes = 0
    for _source, _name, info in _copy_entries(target, root, budget, ancestors):
        n_files += 1
        if stat.S_ISREG(info.st_mode):
            n_bytes += info.st_size
        if n_files > MAX_MATERIALIZED_FILES:
            raise ValueError(f"directory alias exceeds file budget: {relative}")
        if n_bytes > MAX_MATERIALIZED_BYTES:
            raise ValueError(f"directory alias exceeds copy budget: {relative}")
    return n_files, n_bytes


def _copy_regular(source: Path, name: Path, root: Path, budget: Budget, *, destination_fd: int):
    with _regular_file(source, root, budget) as (reader, info):
        budget.copy(info.st_size)
        fd = _open_relative(destination_fd, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "wb") as writer:
            size = 0
            while True:
                budget.check()
                chunk = reader.read(min(1024 * 1024, info.st_size + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > info.st_size:
                    raise ValueError(f"source changed during copy: {source}")
                writer.write(chunk)
            if size != info.st_size:
                raise ValueError(f"source changed during copy: {source}")
            _preserve_file_info(writer.fileno(), info)


def _copy_tree(target: Path, staging_fd: int, root: Path, budget: Budget):
    directories = []
    for source, name, info in _copy_entries(target, root, budget, set()):
        if stat.S_ISDIR(info.st_mode):
            budget.copy(0)
            if name.parts:
                parent_fd = _open_relative(staging_fd, name.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.mkdir(name.name, mode=0o700, dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            directories.append((name, info))
        else:
            _copy_regular(source, name, root, budget, destination_fd=staging_fd)
    for name, info in reversed(directories[1:]):
        fd = _open_relative(staging_fd, name, os.O_RDONLY | os.O_DIRECTORY)
        try:
            _preserve_file_info(fd, info)
        finally:
            os.close(fd)
    return directories[0][1]


def _scanner_safe_node_cycle(source: Path, target: Path, root: Path, budget: Budget) -> bool:
    name = source.relative_to(root).as_posix()
    destination = target.relative_to(root).as_posix()
    scope = scope_inside(name)
    if (
        scope is None
        or scope[0] != "npm"
        or scope != scope_inside(destination)
        or "/node_modules/" not in name[len(scope[1]) :]
    ):
        return False
    entry_types, metadata_paths, symlink_paths, parsed_paths = collect_target_tree(
        target, root, _budget=budget
    )
    return directory_alias_is_metadata_safe(
        name,
        destination,
        entry_types=entry_types,
        parsed_paths=parsed_paths,
        metadata_paths=metadata_paths,
        symlink_paths=symlink_paths,
    )


def _validate_target(target: Path, root: Path, budget: Budget):
    # Ancestor cycles are checked before DAG deduplication. Only scanner-safe
    # node_modules cycle edges within the same npm scope may remain aliases.
    pending = [(target, ())]
    visited = set()
    while pending:
        source, parents = pending.pop()
        resolved = _resolve_path(source, root, budget)
        info = resolved.lstat()
        if stat.S_ISREG(info.st_mode):
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"unsupported directory alias entry: {source}")
        ancestors = [path for path, _source in parents]
        if resolved in ancestors:
            cycle = (*parents[ancestors.index(resolved) + 1 :], (resolved, source))
            edges = [(path, edge) for path, edge in cycle if edge.is_symlink()]
            if not edges or not all(
                _scanner_safe_node_cycle(edge, path, root, budget) for path, edge in edges
            ):
                raise ValueError(f"cyclic directory symlink: {source}")
            continue
        if resolved in visited:
            continue
        if len(parents) > MAX_DIRECTORY_DEPTH:
            raise ValueError("directory alias depth budget exceeded")
        visited.add(resolved)
        parents = (*parents, (resolved, source))
        pending.extend((child, parents) for child, _info in _children(resolved, root, budget))


def link_roots(root: Path, *, _budget: Budget | None = None) -> list[Path]:
    """Declared metadata roots that can contain directory aliases."""
    root = image_root(root)
    budget = _budget or Budget()
    found = python_roots(root, _budget=budget)
    seen = {str(path) for path in found}
    for rel_root in NPM_ROOTS:
        base = root / rel_root
        if _existing_directory(base, root, budget) and str(base) not in seen:
            seen.add(str(base))
            found.append(base)
    return found


def _metadata_links(base: Path, root: Path, budget: Budget):
    physical = _resolve_path(base.parent, root, budget) / base.name
    if physical.is_symlink():
        yield base
    for path, info in _walk_entries(base, root, budget):
        if stat.S_ISLNK(info.st_mode):
            yield path


def materialize_directory_symlinks(root: Path, *, _budget: Budget | None = None) -> list[str]:
    """Replace unsafe directory symlinks under metadata roots with copies."""
    root = image_root(root)
    budget = _budget or Budget()
    materialized = []
    for base in link_roots(root, _budget=budget):
        links = list(_metadata_links(base, root, budget))
        for path in sorted(links):
            physical_link = _resolve_path(path.parent, root, budget) / path.name
            if not physical_link.is_symlink():
                # A previously materialized ancestor made this path real.
                continue
            relative = path.relative_to(root).as_posix()
            target = _resolve_path(path, root, budget)
            if not target.is_dir():
                # File links are validated by the scanner itself; this
                # helper only neutralizes ambiguous directory aliases.
                continue
            _validate_target(target, root, budget)
            entry_types, metadata_paths, symlink_paths, parsed_paths = collect_target_tree(
                target, root, _budget=budget
            )
            if directory_alias_is_metadata_safe(
                relative,
                target.relative_to(root).as_posix(),
                entry_types=entry_types,
                parsed_paths=parsed_paths,
                metadata_paths=metadata_paths,
                symlink_paths=symlink_paths,
            ):
                continue
            n_files, n_bytes = plan_copy(target, relative, set(), root=root, _budget=budget)
            if (
                budget.copy_files + n_files > MAX_MATERIALIZED_FILES
                or budget.copy_bytes + n_bytes > MAX_MATERIALIZED_BYTES
            ):
                raise ValueError("materialized metadata exceeds total copy budget")
            with _destination(physical_link, root) as (root_fd, parent_fd):
                link_stat = os.stat(physical_link.name, dir_fd=parent_fd, follow_symlinks=False)
                staging, fd = _staging(physical_link, root, directory=True, _root_fd=root_fd)
                published = False
                try:
                    target_info = _copy_tree(target, fd, root, budget)
                    os.unlink(physical_link.name, dir_fd=parent_fd)
                    os.rename(
                        staging.name, physical_link.name, src_dir_fd=root_fd, dst_dir_fd=parent_fd
                    )
                    published = True
                    os.fchown(fd, link_stat.st_uid, link_stat.st_gid)
                    os.fchmod(fd, stat.S_IMODE(target_info.st_mode))
                finally:
                    os.close(fd)
                    if not published:
                        _discard_staging(staging.name, root_fd, directory=True)
            materialized.append(relative)
    return materialized


def verify_clean(root: Path, *, _budget: Budget | None = None) -> None:
    """Re-check the normalized tree with the scanner's own strict rules."""
    root = image_root(root)
    budget = _budget or Budget()
    for relative, path in iter_npm_metadata_files(root, _budget=budget):
        data = _read_metadata(path, root, budget)
        try:
            parsed = json.loads(data.decode("utf-8"), object_pairs_hook=strict_pairs_check)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise ValueError(f"unresolved package metadata remains: {relative}") from None
        if not isinstance(parsed, dict):
            raise TypeError(f"unresolved package metadata remains: {relative}")
        budget.check()
    for base in link_roots(root, _budget=budget):
        for path in _metadata_links(base, root, budget):
            relative = path.relative_to(root).as_posix()
            target = _resolve_path(path, root, budget)
            if not target.is_dir():
                continue
            _validate_target(target, root, budget)
            entry_types, metadata_paths, symlink_paths, parsed_paths = collect_target_tree(
                target, root, _budget=budget
            )
            if not directory_alias_is_metadata_safe(
                relative,
                target.relative_to(root).as_posix(),
                entry_types=entry_types,
                parsed_paths=parsed_paths,
                metadata_paths=metadata_paths,
                symlink_paths=symlink_paths,
            ):
                raise ValueError(f"unsafe directory symlink remains: {relative}")
    budget.check()


def normalize(root: Path) -> tuple[list[str], list[str]]:
    """Normalize one image rootfs; returns (canonicalized, materialized)."""
    root = image_root(root)
    budget = Budget()
    canonicalized = canonicalize_npm_metadata(root, _budget=budget)
    materialized = materialize_directory_symlinks(root, _budget=budget)
    # Materialization can expose package.json files that then need
    # canonicalization; canonicalization never creates links, so a single
    # canonical pass afterwards (idempotent for already-canonical files)
    # followed by verification is sufficient.
    canonicalized += canonicalize_npm_metadata(root, _budget=budget)
    verify_clean(root, _budget=budget)
    return canonicalized, materialized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    args = parser.parse_args(argv)
    root = args.root
    if not root.is_dir():
        sys.stderr.write(f"image root does not exist: {root}\n")
        return 1
    try:
        canonicalized, materialized = normalize(root)
    except (OSError, ValueError) as error:
        sys.stderr.write(f"normalize_rootfs_metadata: {error}\n")
        return 1
    out = sys.stdout
    out.write(
        f"normalize_rootfs_metadata: canonicalized={len(canonicalized)} "
        f"materialized={len(materialized)}\n"
    )
    for relative in canonicalized:
        out.write(f"  canonicalized {relative}\n")
    for relative in materialized:
        out.write(f"  materialized {relative}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
