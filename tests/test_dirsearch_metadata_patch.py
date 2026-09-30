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


def _make_dist_info(
    tmp_path: Path, requirement: bytes, package: str = "dirsearch", version: str = "0.5.0"
) -> tuple[Path, bytes]:
    dist_info = tmp_path / f"{package}-{version}.dist-info"
    dist_info.mkdir()
    metadata = f"Name: {package}\nVersion: {version}\n".encode() + requirement + b"\n"
    (dist_info / "METADATA").write_bytes(metadata)
    with (dist_info / "RECORD").open("w", encoding="utf-8", newline="") as stream:
        csv.writer(stream, lineterminator="\n").writerows(
            [
                [f"{dist_info.name}/METADATA", _record_hash(metadata), str(len(metadata))],
                [f"{dist_info.name}/RECORD", "", ""],
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


def test_semgrep_patch_changes_only_pyjwt_and_updates_record(tmp_path: Path) -> None:
    dist_info, original = _make_dist_info(
        tmp_path,
        b"Requires-Dist: pyjwt[crypto]~=2.13.0\nRequires-Dist: requests>=2",
        "semgrep",
        "1.178.0",
    )

    patch_dist_info(dist_info, "semgrep")

    patched = (dist_info / "METADATA").read_bytes()
    assert patched == original.replace(
        b"Requires-Dist: pyjwt[crypto]~=2.13.0\n", b"Requires-Dist: pyjwt[crypto]>=2.14.0,<2.15.0\n"
    )
    with (dist_info / "RECORD").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    assert rows[0][1:] == [_record_hash(patched), str(len(patched))]


@pytest.mark.parametrize(
    "version,requirement",
    [
        ("1.177.0", b"Requires-Dist: pyjwt[crypto]~=2.13.0"),
        ("1.178.0", b"Requires-Dist: pyjwt[crypto]>=2.13.0"),
        ("1.178.0", b"Requires-Dist: pyjwt[crypto]~=2.13.0; extra == 'mcp'"),
        ("1.178.0", b"Name: semgrep\nRequires-Dist: pyjwt[crypto]~=2.13.0"),
        ("1.178.0", b"Requires-Dist: pyjwt[crypto]~=2.13.0\nRequires-Dist: pyjwt[crypto]~=2.13.0"),
    ],
)
def test_semgrep_patch_rejects_unreviewed_metadata(
    tmp_path: Path, version: str, requirement: bytes
) -> None:
    dist_info, original = _make_dist_info(tmp_path, requirement, "semgrep", version)
    original_record = (dist_info / "RECORD").read_bytes()

    with pytest.raises(ValueError):
        patch_dist_info(dist_info, "semgrep")

    assert (dist_info / "METADATA").read_bytes() == original
    assert (dist_info / "RECORD").read_bytes() == original_record


def test_semgrep_patch_rejects_tampered_record_without_writes(tmp_path: Path) -> None:
    dist_info, original = _make_dist_info(
        tmp_path, b"Requires-Dist: pyjwt[crypto]~=2.13.0", "semgrep", "1.178.0"
    )
    record = (
        (dist_info / "RECORD").read_bytes().replace(_record_hash(original).encode(), b"sha256=bad")
    )
    (dist_info / "RECORD").write_bytes(record)

    with pytest.raises(ValueError, match="does not match"):
        patch_dist_info(dist_info, "semgrep")

    assert (dist_info / "METADATA").read_bytes() == original
    assert (dist_info / "RECORD").read_bytes() == record
