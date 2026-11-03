"""Apply reviewed dependency metadata overrides to pinned sandbox tools.

The upstream wheel locks PyOpenSSL to 26.1.0 even though its Python source does
not use OpenSSL APIs. The sandbox pins the tested PyOpenSSL 26.4.0 line instead.
Semgrep 1.178.0 restricts PyJWT to the vulnerable 2.13 line; its verified JWT
contract supports the security-fixed 2.15 line. Runtime security overrides pin
MCP and the matching OpenTelemetry graph to exact tested versions. Every original
METADATA field and RECORD hash is checked before any write. No tool source changes.
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
from email.parser import BytesParser
from pathlib import Path


PATCHES = {
    "dirsearch": (
        "0.5.0",
        b"Requires-Dist: pyopenssl==26.1.0",
        b"Requires-Dist: pyopenssl>=26.1.0",
    ),
    "semgrep": (
        "1.178.0",
        b"Requires-Dist: pyjwt[crypto]~=2.13.0",
        b"Requires-Dist: pyjwt[crypto]>=2.15.1,<2.16.0",
    ),
}


SEMGREP_RUNTIME_PATCHES = (
    (b"Requires-Dist: mcp==1.29.0", b"Requires-Dist: mcp==1.30.0"),
    (b"Requires-Dist: opentelemetry-api~=1.37.0", b"Requires-Dist: opentelemetry-api==1.45.1"),
    (b"Requires-Dist: opentelemetry-sdk~=1.37.0", b"Requires-Dist: opentelemetry-sdk==1.45.1"),
    (
        b"Requires-Dist: opentelemetry-exporter-otlp-proto-http~=1.37.0",
        b"Requires-Dist: opentelemetry-exporter-otlp-proto-http==1.45.1",
    ),
    (
        b"Requires-Dist: opentelemetry-instrumentation-requests~=0.58b0",
        b"Requires-Dist: opentelemetry-instrumentation-requests==0.66b1",
    ),
    (
        b"Requires-Dist: opentelemetry-instrumentation-threading~=0.58b0",
        b"Requires-Dist: opentelemetry-instrumentation-threading==0.66b1",
    ),
)


def patch_dist_info(
    dist_info: Path, package: str = "dirsearch", *, runtime_dependencies: bool = False
) -> None:
    """Patch one exact reviewed dependency field and repair its RECORD entry."""
    version, upstream_requirement, overridden_requirement = PATCHES[package]
    metadata_path = dist_info / "METADATA"
    record_path = dist_info / "RECORD"
    metadata = metadata_path.read_bytes()
    headers = BytesParser().parsebytes(metadata)

    if headers.get_all("Name", []) != [package] or headers.get_all("Version", []) != [version]:
        raise ValueError(f"expected the pinned {package} {version} distribution")
    requirements = [(upstream_requirement, overridden_requirement)]
    if runtime_dependencies:
        if package != "semgrep":
            raise ValueError("runtime dependency overrides require the reviewed Semgrep wheel")
        requirements.extend(SEMGREP_RUNTIME_PATCHES)
    for old, _new in requirements:
        requirement_value = old.split(b": ", 1)[1].decode("ascii")
        if (
            headers.get_all("Requires-Dist", []).count(requirement_value) != 1
            or metadata.count(old + b"\n") != 1
        ):
            raise ValueError("expected exactly one upstream dependency requirement")

    site_packages = dist_info.parent
    record_name = metadata_path.relative_to(site_packages).as_posix()
    with record_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    matching_rows = [row for row in rows if row and row[0] == record_name]
    if len(matching_rows) != 1 or len(matching_rows[0]) != 3:
        raise ValueError("Distribution RECORD must contain one METADATA row")

    old_hash = (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(metadata).digest()).rstrip(b"=").decode()
    )
    old_size = str(len(metadata))
    if matching_rows[0][1:] != [old_hash, old_size]:
        raise ValueError("Distribution METADATA does not match its RECORD entry")

    patched_metadata = metadata
    for old, new in requirements:
        patched_metadata = patched_metadata.replace(old + b"\n", new + b"\n")
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
    parser.add_argument("--package", choices=PATCHES, default="dirsearch")
    parser.add_argument("--runtime-dependencies", action="store_true")
    parser.add_argument(
        "--site-packages",
        type=Path,
        default=Path(sysconfig.get_paths()["purelib"]),
        help="venv site-packages directory (defaults to this interpreter's purelib)",
    )
    args = parser.parse_args()
    version = PATCHES[args.package][0]
    matches = sorted(args.site_packages.glob(f"{args.package}-{version}.dist-info"))
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {args.package}-{version}.dist-info directory")
    patch_dist_info(matches[0], args.package, runtime_dependencies=args.runtime_dependencies)


if __name__ == "__main__":
    main()
