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

- every ``package.json`` under the declared npm metadata roots is parsed
  strictly; if it contains duplicate keys it is rewritten in canonical
  form, keeping the LAST value for each duplicated key. That is exactly
  what every JSON consumer (Node's ``JSON.parse``, jq, Python ``json``,
  Go) already resolves to, so the effective document is unchanged and
  only the ambiguity is removed. Files without duplicates are untouched.
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
import json
import os
import re
import shutil
import sys
from bisect import bisect_left
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
MAX_LINK_DEPTH = 64
MAX_MATERIALIZED_FILES = 100_000
MAX_MATERIALIZED_BYTES = 8 * 1024 * 1024 * 1024

METADATA_NAMES = ("package.json", "METADATA")


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


def python_roots(root: Path) -> list[Path]:
    """Existing directories matching the declared python metadata roots."""
    found = []
    seen = set()
    for pattern in PYTHON_ROOT_PATTERNS:
        for candidate in sorted(root.glob(pattern)):
            if candidate.is_dir() and str(candidate) not in seen:
                seen.add(str(candidate))
                found.append(candidate)
    return found


def last_wins_pairs(pairs):
    # ``dict(pairs)`` keeps the last value per key: exactly what every
    # JSON consumer (Node, jq, Python, Go) resolves duplicates to.
    return dict(pairs)


def canonical_with_last_wins(data: bytes) -> tuple[bytes, bool]:
    """Canonicalize JSON bytes, resolving duplicate keys last-wins.

    Returns ``(canonical_bytes, changed)``. Raises ``ValueError`` on
    malformed JSON or a non-object top level. ``changed`` is True only
    when the input actually contains duplicate keys; the canonical form
    is the value every JSON consumer already parses the input to (last
    occurrence wins), so the effective document is unchanged. Files
    without duplicates are reported unchanged so their bytes stay
    untouched.
    """
    duplicates = []

    def pairs_hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    parsed = json.loads(data.decode("utf-8"), object_pairs_hook=pairs_hook)
    if not isinstance(parsed, dict):
        raise TypeError("package metadata must be a JSON object")
    if not duplicates:
        return data, False
    canonical = (json.dumps(parsed, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    # Internal invariant: canonical bytes must read back to the same value.
    if json.loads(canonical, object_pairs_hook=last_wins_pairs) != parsed:
        raise ValueError("canonical form does not round-trip")
    return canonical, True


def iter_npm_metadata_files(root: Path):
    """Yield (relative_posix_name, absolute_path) for scanned npm metadata."""
    for rel_root in NPM_ROOTS:
        base = root / rel_root
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames.sort()
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                relative = path.relative_to(root).as_posix()
                if is_npm_metadata(relative) and path.is_file() and not path.is_symlink():
                    yield relative, path


def canonicalize_npm_metadata(root: Path) -> list[str]:
    """Canonicalize duplicate-key package.json files under the npm roots."""
    changed = []
    for seen, (relative, path) in enumerate(iter_npm_metadata_files(root)):
        if seen >= MAX_METADATA_FILES:
            raise ValueError("too many package metadata candidates")
        data = path.read_bytes()
        if len(data) > MAX_METADATA_BYTES:
            raise ValueError(f"package metadata exceeds size budget: {relative}")
        try:
            canonical, changed_flag = canonical_with_last_wins(data)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"malformed package metadata: {relative}: {error}") from None
        if changed_flag:
            info = os.lstat(path)
            temporary = path.with_name(path.name + ".normalize-tmp")
            temporary.write_bytes(canonical)
            temporary.chmod(info.st_mode & 0o777)
            os.chown(temporary, info.st_uid, info.st_gid)
            temporary.replace(path)
            changed.append(relative)
    return changed


def resolve_link(link: Path, root: Path) -> Path:
    """Resolve a symlink's final target inside ``root``.

    Follows symlink chains (bounded, cycle-checked). Raises
    ``ValueError`` if the chain escapes the root, is cyclic, is too deep,
    or ends at a path that does not exist. Returns the resolved path,
    which may be a file or a directory.
    """
    seen = {Path(link)}
    current = link
    for _ in range(MAX_LINK_DEPTH + 1):
        raw = str(current.readlink())
        base = current.parent / raw if not raw.startswith("/") else root / raw.lstrip("/")
        current = Path(os.path.normpath(base))
        if current in seen:
            raise ValueError(f"cyclic directory symlink: {link.relative_to(root)}")
        seen.add(current)
        if not current.is_symlink():
            break
    else:
        raise ValueError(f"directory symlink chain too deep: {link.relative_to(root)}")
    try:
        current.resolve().relative_to(root.resolve())
    except ValueError:
        raise ValueError(f"symlink target escapes image root: {link.relative_to(root)}") from None
    if not current.exists():
        raise ValueError(f"symlink target does not exist: {link.relative_to(root)}")
    return current


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


def collect_target_tree(target: Path, root: Path):
    """Index a target subtree for the safety predicate.

    Returns ``(entry_types, metadata_paths, symlink_paths, parsed_paths)``
    keyed by root-relative POSIX names. ``parsed_paths`` contains the
    metadata files that parse cleanly (npm metadata is already
    canonicalized by the caller before linking checks run).
    """
    entry_types = {}
    metadata_paths = set()
    symlink_paths = set()
    parsed_paths = set()
    entries = 0
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        for entry in dirnames + filenames:
            entries += 1
            if entries > MAX_METADATA_FILES:
                raise ValueError("directory alias subtree exceeds entry budget")
            path = Path(dirpath) / entry
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                entry_types[relative] = "symlink"
                symlink_paths.add(relative)
            elif path.is_dir():
                entry_types[relative] = "directory"
            else:
                entry_types[relative] = "regular"
            if entry in METADATA_NAMES:
                metadata_paths.add(relative)
                if entry_types.get(relative) == "regular":
                    data = path.read_bytes()
                    if data and _parses_as_scanned_metadata(relative, data):
                        parsed_paths.add(relative)
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
    except (UnicodeDecodeError, ValueError, AttributeError):
        return False
    return all(
        isinstance(value, str) and value.strip() and len(value) <= MAX_IDENTITY_CHARS
        for value in (package, version)
    )


def plan_copy(target: Path, relative: str, ancestors: set[str]) -> tuple[int, int]:
    """Count files/bytes a dereferenced copy of ``target`` would produce.

    Follows symlinks, tracks ancestor realpaths per recursion stack so a
    directory cycle fails closed instead of recursing forever, and
    enforces the copy budgets while counting. Returns ``(files, bytes)``.
    """
    real = str(target.resolve())
    if real in ancestors:
        raise ValueError(f"cyclic directory symlink: {relative}")
    ancestors.add(real)
    n_files = 0
    n_bytes = 0
    try:
        with os.scandir(target) as scan:
            for entry in scan:
                if entry.is_dir(follow_symlinks=True):
                    files, size = plan_copy(Path(entry.path), relative, ancestors)
                    n_files += files
                    n_bytes += size
                elif entry.is_symlink() or entry.is_file(follow_symlinks=True):
                    n_files += 1
                    n_bytes += Path(entry.path).stat().st_size
                if n_files > MAX_MATERIALIZED_FILES:
                    raise ValueError(f"directory alias exceeds file budget: {relative}")
                if n_bytes > MAX_MATERIALIZED_BYTES:
                    raise ValueError(f"directory alias exceeds copy budget: {relative}")
    finally:
        ancestors.discard(real)
    return n_files, n_bytes


def link_roots(root: Path) -> list[Path]:
    """Declared metadata roots that can contain directory aliases."""
    found = python_roots(root)
    seen = {str(path) for path in found}
    for rel_root in NPM_ROOTS:
        base = root / rel_root
        if base.is_dir() and str(base) not in seen:
            seen.add(str(base))
            found.append(base)
    return found


def materialize_directory_symlinks(root: Path) -> list[str]:
    """Replace unsafe directory symlinks under metadata roots with copies."""
    materialized = []
    total_files = 0
    total_bytes = 0
    for base in link_roots(root):
        if not base.exists():
            continue
        links = []
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for entry in list(dirnames) + list(filenames):
                path = Path(dirpath) / entry
                if path.is_symlink():
                    links.append(path)
        for path in sorted(links):
            if not path.is_symlink():
                # A previously materialized ancestor made this path real.
                continue
            relative = path.relative_to(root).as_posix()
            target = resolve_link(path, root)
            if not target.is_dir():
                # File links are validated by the scanner itself; this
                # helper only neutralizes ambiguous directory aliases.
                continue
            entry_types, metadata_paths, symlink_paths, parsed_paths = collect_target_tree(
                target, root
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
            link_stat = os.lstat(path)
            staging = path.with_name(path.name + ".normalize-tmp")
            if staging.exists() or staging.is_symlink():
                raise ValueError(f"staging path already exists: {path}")
            n_files, n_bytes = plan_copy(target, relative, set())
            total_files += n_files
            total_bytes += n_bytes
            if total_files > MAX_MATERIALIZED_FILES or total_bytes > MAX_MATERIALIZED_BYTES:
                raise ValueError("materialized metadata exceeds total copy budget")
            shutil.copytree(target, staging, symlinks=False)
            staging.chmod(target.stat().st_mode & 0o777)
            os.chown(staging, link_stat.st_uid, link_stat.st_gid)
            path.unlink()
            staging.rename(path)
            materialized.append(relative)
    return materialized


def verify_clean(root: Path) -> None:
    """Re-check the normalized tree with the scanner's own strict rules."""
    for seen, (relative, path) in enumerate(iter_npm_metadata_files(root)):
        if seen >= MAX_METADATA_FILES:
            raise ValueError("too many package metadata candidates")
        data = path.read_bytes()
        if len(data) > MAX_METADATA_BYTES:
            raise ValueError(f"oversized package metadata remains: {relative}")

        def strict_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate {key} JSON field")
                result[key] = value
            return result

        try:
            json.loads(data.decode("utf-8"), object_pairs_hook=strict_pairs)
        except (UnicodeDecodeError, ValueError):
            raise ValueError(f"unresolved package metadata remains: {relative}") from None
    for base in link_roots(root):
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for entry in list(dirnames) + list(filenames):
                path = Path(dirpath) / entry
                if not path.is_symlink():
                    continue
                relative = path.relative_to(root).as_posix()
                target = resolve_link(path, root)
                if not target.is_dir():
                    continue
                entry_types, metadata_paths, symlink_paths, parsed_paths = collect_target_tree(
                    target, root
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


def normalize(root: Path) -> tuple[list[str], list[str]]:
    """Normalize one image rootfs; returns (canonicalized, materialized)."""
    canonicalized = canonicalize_npm_metadata(root)
    materialized = materialize_directory_symlinks(root)
    # Materialization can expose package.json files that then need
    # canonicalization; canonicalization never creates links, so a single
    # canonical pass afterwards (idempotent for already-canonical files)
    # followed by verification is sufficient.
    canonicalized += canonicalize_npm_metadata(root)
    verify_clean(root)
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
