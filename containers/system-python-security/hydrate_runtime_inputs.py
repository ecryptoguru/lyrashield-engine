#!/usr/bin/python3
"""Hydrate the exact v1 runtime cache from a reviewed local or fixed GitHub asset.

No archive extraction API is used: only canonical USTAR regular-file headers and
bounded byte slices are accepted. Transport checks supplement the installer's
unchanged official signature, index, source identity and binary checks.
"""

# Only fixed gh argv is executed, without a shell. CLI output is intentional.
# ruff: noqa: S603, T201
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import resource
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zlib
from functools import partial
from pathlib import Path

from safe_io import preflight, publish, read_regular


HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "runtime-inputs.json"
REPOSITORY = "ecryptoguru/lyrashield-engine"
TAG = "runtime-inputs-20261102-v1"
ASSET = "strix-runtime-inputs-20261102-v1.tar.gz"
RAW_BYTES = 69_409_899


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def header(name: str, size: int) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = size
    member.mode = 0o644
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    return member


def tar_size(files: dict) -> int:
    used = sum(512 + ((record["bytes"] + 511) // 512) * 512 for record in files.values())
    return ((used + 1024 + 10239) // 10240) * 10240


def encode(files: dict[str, bytes]) -> bytes:
    """Sorted USTAR, fixed metadata, empty gzip filename/mtime and stored deflate."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            archive.addfile(header(name, len(data)), io.BytesIO(data))
    raw_bytes = raw.getvalue()
    # RFC 1951 stored blocks make the bytes independent of zlib's version and
    # block-partition choices. These inputs are already compressed archives.
    parts = [b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"]
    for start in range(0, len(raw_bytes), 65535):
        chunk = raw_bytes[start : start + 65535]
        final = int(start + len(chunk) == len(raw_bytes))
        parts.extend((struct.pack("<BHH", final, len(chunk), len(chunk) ^ 0xFFFF), chunk))
    parts.append(struct.pack("<II", zlib.crc32(raw_bytes), len(raw_bytes)))
    return b"".join(parts)


def _read_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def load_manifest() -> dict:
    """Refuse a transport manifest detached from the qualified publisher pins."""
    manifest = _read_manifest()
    leaves_bytes = (HERE / "leaves.json").read_bytes()
    leaves = json.loads(leaves_bytes)
    if (
        manifest["schema"] != 1
        or manifest["repository"] != REPOSITORY
        or manifest["release_tag"] != TAG
        or manifest["asset"] != ASSET
        or manifest["format"] != "ustar-gzip-store-v1"
        or manifest["leaves_sha256"] != sha(leaves_bytes)
    ):
        raise ValueError("transport qualification identity mismatch")
    expected = {}
    releases = {}
    for archive, release in leaves["releases"].items():
        data = (HERE / "provenance" / (archive + ".InRelease")).read_bytes()
        if sha(data) != release["release_sha256"]:
            raise ValueError("signed Release qualification mismatch")
        releases[archive] = sha(data)
        section = data.decode().split("\nSHA256:\n", 1)[1].split("\nSHA512:", 1)[0]
        for arch, index in release["indexes"].items():
            relative = index["path"].split("/", 2)[2]
            match = re.search(
                r"^ " + index["sha256"] + r" +([0-9]+) +" + re.escape(relative) + r"$",
                section,
                re.M,
            )
            if match is None:
                raise ValueError("index has no qualified signed Release binding")
            name = f"{archive}-{arch}-Packages." + ("xz" if archive == "sid" else "gz")
            expected[name] = {"bytes": int(match[1]), "sha256": index["sha256"]}
    for packages in leaves["packages"].values():
        for package in packages:
            expected.setdefault(Path(package["Filename"]).name, {"sha256": package["SHA256"]})
    if (
        len(manifest["files"]) != 14
        or set(manifest["files"]) != set(expected)
        or manifest["signed_releases"] != releases
    ):
        raise ValueError("transport qualification file coverage mismatch")
    for name, record in manifest["files"].items():
        if (
            not isinstance(record["bytes"], int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] <= 0
            or record["sha256"] != expected[name]["sha256"]
            or ("bytes" in expected[name] and record["bytes"] != expected[name]["bytes"])
        ):
            raise ValueError("transport qualification member mismatch: " + name)
    if (
        manifest["raw_bytes"] != RAW_BYTES
        or sum(r["bytes"] for r in manifest["files"].values()) != RAW_BYTES
    ):
        raise ValueError("transport qualification raw size mismatch")
    if (
        not isinstance(manifest["bundle"]["bytes"], int)
        or not 0 < manifest["bundle"]["bytes"] <= tar_size(manifest["files"]) + 1_048_576
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["bundle"]["sha256"])
    ):
        raise ValueError("invalid qualified bundle bound")
    return manifest


def checked_outer(data: bytes, manifest: dict) -> None:
    if len(data) != manifest["bundle"]["bytes"] or sha(data) != manifest["bundle"]["sha256"]:
        raise ValueError("bundle transport size/hash mismatch")


def decode(data: bytes, manifest: dict) -> dict[str, bytes]:
    """Validate all members, types, padding and totals before any cache write."""
    checked_outer(data, manifest)
    expected_size = tar_size(manifest["files"])
    decompressor = zlib.decompressobj(31)
    try:
        raw = decompressor.decompress(data, expected_size + 1)
    except zlib.error as error:
        raise ValueError("invalid gzip transport") from error
    if (
        len(raw) != expected_size
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise ValueError("gzip expansion/trailing data exceeds exact archive contract")
    files = {}
    offset = 0
    for name, record in sorted(manifest["files"].items()):
        expected_header = header(name, record["bytes"]).tobuf(
            tarfile.USTAR_FORMAT, "ascii", "strict"
        )
        if raw[offset : offset + 512] != expected_header:
            raise ValueError("unexpected, linked or noncanonical archive member: " + name)
        start = offset + 512
        end = start + record["bytes"]
        content = raw[start:end]
        if len(content) != record["bytes"] or sha(content) != record["sha256"]:
            raise ValueError("archive member size/hash mismatch: " + name)
        offset = start + ((record["bytes"] + 511) // 512) * 512
        if any(raw[end:offset]):
            raise ValueError("nonzero archive member padding")
        files[name] = content
    if any(raw[offset:]) or sum(map(len, files.values())) != manifest["raw_bytes"]:
        raise ValueError("extra archive members or invalid trailer")
    return files


def existing_cache(cache: Path, manifest: dict, *, complete: bool = False) -> dict[str, bytes]:
    preflight(cache, ".hydration-preflight")
    names = {p.name for p in cache.iterdir()}
    if names - set(manifest["files"]) - {".gitignore"}:
        raise ValueError("unexpected existing cache entry")
    if ".gitignore" in names:
        read_regular(cache, ".gitignore", max_bytes=4096)
    files = {}
    for name, record in manifest["files"].items():
        if name not in names:
            if complete:
                raise ValueError("missing qualified cache member: " + name)
            continue
        data = read_regular(cache, name, max_bytes=record["bytes"])
        if len(data) != record["bytes"] or sha(data) != record["sha256"]:
            raise ValueError("existing cache size/hash mismatch: " + name)
        files[name] = data
    return files


def hydrate(data: bytes, manifest: dict, cache: Path) -> None:
    files = decode(data, manifest)
    present = existing_cache(cache, manifest)
    publish(cache, {name: content for name, content in files.items() if name not in present})


def local_bundle(path: Path, manifest: dict) -> bytes:
    # Resolve only the read-only parent (e.g. macOS /tmp); the final file must
    # still be regular and singly linked. Publication roots are never resolved.
    return read_regular(
        path.absolute().parent.resolve(strict=True),
        path.name,
        max_bytes=manifest["bundle"]["bytes"],
    )


def download(manifest: dict) -> bytes:
    gh = shutil.which("gh")
    if gh is None:
        raise ValueError("gh CLI is required for the fixed repository download")
    environment = os.environ.copy()
    environment["GH_HOST"] = "github.com"
    for key in (
        "GH_REPO",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_DEBUG",
        "GITHUB_API_URL",
        "GITHUB_SERVER_URL",
    ):
        environment.pop(key, None)
    bound = manifest["bundle"]["bytes"]
    with tempfile.TemporaryDirectory(prefix="runtime-input-download-") as temporary:
        subprocess.run(
            [
                gh,
                "release",
                "download",
                TAG,
                "--repo",
                "github.com/" + REPOSITORY,
                "--pattern",
                ASSET,
                "--dir",
                temporary,
            ],
            check=True,
            timeout=120,
            env=environment,
            preexec_fn=partial(resource.setrlimit, resource.RLIMIT_FSIZE, (bound, bound)),
        )
        data = local_bundle(Path(temporary) / ASSET, manifest)
        checked_outer(data, manifest)
        return data


def create(cache: Path, output: Path, manifest: dict) -> None:
    """Reproduce only the already committed bundle, never regenerate pins."""
    if output.name != ASSET:
        raise ValueError("output must use the fixed reviewed asset basename")
    data = encode(existing_cache(cache, manifest, complete=True))
    checked_outer(data, manifest)
    publish(output.absolute().parent, {output.name: data})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle", type=Path, help="reviewed local bundle; no network")
    source.add_argument("--download", action="store_true", help="fixed repository/tag/asset via gh")
    source.add_argument(
        "--create-bundle", type=Path, help="reproduce the pinned bundle from exact cache"
    )
    parser.add_argument("--cache", type=Path, default=HERE / "cache")
    args = parser.parse_args()
    manifest = load_manifest()
    if args.create_bundle:
        create(args.cache, args.create_bundle, manifest)
        print(
            f"Reproduced {ASSET}: "
            f"{manifest['bundle']['bytes']} bytes {manifest['bundle']['sha256']}"
        )
    else:
        data = download(manifest) if args.download else local_bundle(args.bundle, manifest)
        hydrate(data, manifest, args.cache)
        print(f"Verified cache hydrated: 14 files, {RAW_BYTES} payload bytes")


if __name__ == "__main__":
    main()
