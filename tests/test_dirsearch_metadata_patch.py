"""The sandbox's Dirsearch metadata exception stays exact and hash-consistent."""

from __future__ import annotations

import base64
import csv
import hashlib
from typing import TYPE_CHECKING

import pytest

from containers.patch_dirsearch_metadata import patch_dist_info


if TYPE_CHECKING:
    from pathlib import Path


def _record_hash(content: bytes) -> str:
    return (
        "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    )


def _make_dist_info(tmp_path: Path, requirement: bytes) -> tuple[Path, bytes]:
    dist_info = tmp_path / "dirsearch-0.5.0.dist-info"
    dist_info.mkdir()
    metadata = b"Name: dirsearch\nVersion: 0.5.0\n" + requirement + b"\n"
    (dist_info / "METADATA").write_bytes(metadata)
    with (dist_info / "RECORD").open("w", encoding="utf-8", newline="") as stream:
        csv.writer(stream, lineterminator="\n").writerows(
            [
                ["dirsearch-0.5.0.dist-info/METADATA", _record_hash(metadata), str(len(metadata))],
                ["dirsearch-0.5.0.dist-info/RECORD", "", ""],
            ]
        )
    return dist_info, metadata


def test_patch_relaxes_only_the_exact_pin_and_refreshes_record(tmp_path: Path) -> None:
    dist_info, _ = _make_dist_info(tmp_path, b"Requires-Dist: pyopenssl==26.1.0")

    patch_dist_info(dist_info)

    patched = (dist_info / "METADATA").read_bytes()
    assert b"Requires-Dist: pyopenssl>=26.1.0\n" in patched
    assert b"pyopenssl==26.1.0" not in patched
    with (dist_info / "RECORD").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    metadata_row = next(row for row in rows if row[0].endswith("/METADATA"))
    assert metadata_row[1:] == [_record_hash(patched), str(len(patched))]


def test_patch_fails_closed_on_any_other_dependency_metadata(tmp_path: Path) -> None:
    dist_info, original = _make_dist_info(tmp_path, b"Requires-Dist: pyopenssl>=26.2.0")
    original_record = (dist_info / "RECORD").read_bytes()

    with pytest.raises(ValueError, match="exactly one upstream"):
        patch_dist_info(dist_info)

    assert (dist_info / "METADATA").read_bytes() == original
    assert (dist_info / "RECORD").read_bytes() == original_record
