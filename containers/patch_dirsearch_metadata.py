"""Apply LyraShield's one-dependency metadata override to pinned Dirsearch 0.5.0.

The upstream wheel locks PyOpenSSL to 26.1.0 even though its Python source does
not use OpenSSL APIs. The sandbox pins the tested PyOpenSSL 26.4.0 line instead.
Keep the override limited to that exact METADATA field and refresh RECORD so
installed-package integrity checks remain valid. No upstream source is changed.
"""

# This build helper lives beside Docker inputs rather than in a Python package.
# ruff: noqa: INP001

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import sysconfig
from pathlib import Path


UPSTREAM_REQUIREMENT = b"Requires-Dist: pyopenssl==26.1.0"
OVERRIDDEN_REQUIREMENT = b"Requires-Dist: pyopenssl>=26.1.0"


def patch_dist_info(dist_info: Path) -> None:
    """Relax only Dirsearch's exact PyOpenSSL metadata pin and repair RECORD."""
    metadata_path = dist_info / "METADATA"
    record_path = dist_info / "RECORD"
    metadata = metadata_path.read_bytes()

    if b"Name: dirsearch\n" not in metadata or b"Version: 0.5.0\n" not in metadata:
        raise ValueError("expected the pinned dirsearch 0.5.0 distribution")
    if metadata.count(UPSTREAM_REQUIREMENT) != 1:
        raise ValueError("expected exactly one upstream pyopenssl==26.1.0 requirement")

    site_packages = dist_info.parent
    record_name = metadata_path.relative_to(site_packages).as_posix()
    with record_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    matching_rows = [row for row in rows if row and row[0] == record_name]
    if len(matching_rows) != 1 or len(matching_rows[0]) != 3:
        raise ValueError("Dirsearch RECORD must contain one METADATA row")

    old_hash = (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(metadata).digest()).rstrip(b"=").decode()
    )
    old_size = str(len(metadata))
    if matching_rows[0][1:] != [old_hash, old_size]:
        raise ValueError("Dirsearch METADATA does not match its RECORD entry")

    patched_metadata = metadata.replace(UPSTREAM_REQUIREMENT, OVERRIDDEN_REQUIREMENT)
    patched_hash = (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(patched_metadata).digest()).rstrip(b"=").decode()
    )
    matching_rows[0][1:] = [patched_hash, str(len(patched_metadata))]
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)

    metadata_tmp = metadata_path.with_suffix(".METADATA.tmp")
    record_tmp = record_path.with_suffix(".RECORD.tmp")
    metadata_tmp.write_bytes(patched_metadata)
    record_tmp.write_text(output.getvalue(), encoding="utf-8", newline="")
    metadata_tmp.replace(metadata_path)
    record_tmp.replace(record_path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--site-packages",
        type=Path,
        default=Path(sysconfig.get_paths()["purelib"]),
        help="venv site-packages directory (defaults to this interpreter's purelib)",
    )
    args = parser.parse_args()
    matches = sorted(args.site_packages.glob("dirsearch-0.5.0.dist-info"))
    if len(matches) != 1:
        raise SystemExit("expected exactly one dirsearch-0.5.0.dist-info directory")
    patch_dist_info(matches[0])


if __name__ == "__main__":
    main()
