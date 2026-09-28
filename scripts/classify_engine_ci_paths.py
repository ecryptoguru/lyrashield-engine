"""Classify documentation-only pull request changes for Engine CI."""

# This is a direct-execution script rather than an importable package module.
# ruff: noqa: INP001

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import PurePosixPath


_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def is_documentation_path(value: str) -> bool:
    """Return whether a changed repository path is documentation content."""
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.suffix.lower() not in {".md", ".mdx"}:
        return False
    return path.parts[0] == "docs" or len(path.parts) == 1


def is_documentation_only(paths: list[str]) -> bool:
    """Classify a nonempty path list; unknown or mixed changes run full CI."""
    return bool(paths) and all(is_documentation_path(path) for path in paths)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Base commit SHA for a pull request")
    args = parser.parse_args()
    if not args.base:
        sys.stdout.write("docs_only=false\n")
        return
    if not _GIT_SHA_RE.fullmatch(args.base):
        parser.error("--base must be a 40-character lowercase commit SHA")

    git = shutil.which("git")
    if git is None:
        parser.error("git executable was not found")
    changed = subprocess.run(  # noqa: S603 - executable and fixed arguments are controlled
        [git, "diff", "--no-renames", "--name-only", "--diff-filter=ACMRTD", f"{args.base}...HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    sys.stdout.write(f"docs_only={str(is_documentation_only(changed)).lower()}\n")


if __name__ == "__main__":
    main()
