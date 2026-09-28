"""Report owned Python modules with same-path upstream twins; drift is informational."""

# Direct-execution script, not an importable package module.
# ruff: noqa: INP001

from __future__ import annotations

import argparse
import csv
import difflib
import sys
from pathlib import Path


def twin_rows(root: Path) -> list[tuple[str, str, str, int, int, int]]:
    """Return a stable line-level inventory of same-path owned/upstream modules."""
    owned_root = root / "lyrashield"
    upstream_root = root / "strix"
    rows: list[tuple[str, str, str, int, int, int]] = []
    for owned in sorted(owned_root.rglob("*.py")):
        relative = owned.relative_to(owned_root)
        upstream = upstream_root / relative
        if not upstream.is_file():
            continue
        owned_bytes = owned.read_bytes()
        upstream_bytes = upstream.read_bytes()
        owned_lines = owned_bytes.splitlines()
        upstream_lines = upstream_bytes.splitlines()
        if owned_bytes == upstream_bytes:
            matching_lines = len(owned_lines)
        else:
            matcher = difflib.SequenceMatcher(None, owned_lines, upstream_lines, autojunk=False)
            matching_lines = sum(block.size for block in matcher.get_matching_blocks())
        rows.append(
            (
                owned.relative_to(root).as_posix(),
                upstream.relative_to(root).as_posix(),
                "yes" if owned_bytes == upstream_bytes else "no",
                matching_lines,
                len(owned_lines),
                len(upstream_lines),
            )
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    if not (root / "lyrashield").is_dir() or not (root / "strix").is_dir():
        parser.error("--root must contain lyrashield/ and strix/")
    writer = csv.writer(sys.stdout)
    writer.writerow(
        ("owned", "upstream", "byte_identical", "matching_lines", "owned_lines", "upstream_lines")
    )
    writer.writerows(twin_rows(root))


if __name__ == "__main__":
    main()
