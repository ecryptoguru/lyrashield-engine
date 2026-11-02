#!/usr/bin/python3
"""Apply exact, reproducible downstream amendments to Debian-owned Python files.

This deliberately does not relax the application pip RECORD/BOM verifier.
Original dpkg metadata remains intact; the separate receipt identifies amended
bytes, original versions and upstream commits without inventing vendor versions.
"""

# Command arguments and input URLs come only from the pinned reviewed manifest.
# ruff: noqa: S603
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import subprocess
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from safe_io import publish, read_regular


HERE = Path(__file__).resolve().parent


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def wheel_files(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        names = wheel.namelist()
        if len(names) != len(set(names)) or any(
            PurePosixPath(n).is_absolute() or ".." in PurePosixPath(n).parts for n in names
        ):
            raise ValueError("unsafe wheel member")
        files = {n: wheel.read(n) for n in names if not n.endswith("/")}
    records = [n for n in files if n.endswith(".dist-info/RECORD") and n.count("/") == 1]
    if len(records) != 1:
        raise ValueError("expected one wheel RECORD")
    rows = list(csv.reader(io.StringIO(files[records[0]].decode())))
    if len(rows) != len({r[0] for r in rows}) or set(files) != {r[0] for r in rows}:
        raise ValueError("incomplete or duplicate wheel RECORD")
    for row in rows:
        if len(row) != 3:
            raise ValueError("malformed wheel RECORD")
        if row[0] == records[0]:
            if row[1:] != ["", ""]:
                raise ValueError("invalid RECORD self entry")
        elif row[1:] != [record_hash(files[row[0]]), str(len(files[row[0]]))]:
            raise ValueError("wheel RECORD mismatch: " + row[0])
    return files


def pack_wheel(files: dict[str, bytes]) -> bytes:
    record = next(n for n in files if n.endswith(".dist-info/RECORD") and n.count("/") == 1)
    stream = io.StringIO(newline="")
    csv.writer(stream).writerows(
        [n, record_hash(data), str(len(data))] if n != record else [n, "", ""]
        for n, data in sorted(files.items())
    )
    files[record] = stream.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for n, data in sorted(files.items()):
            info = zipfile.ZipInfo(n, (2026, 11, 2, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            wheel.writestr(info, data)
    result = output.getvalue()
    wheel_files(result)
    return result


def patched(data: bytes, patch: dict) -> bytes:
    if sha(data) != patch["before_sha256"]:
        raise ValueError("source precondition mismatch: " + patch["path"])
    for before, after in patch["replacements"]:
        if data.count(before.encode()) != 1:
            raise ValueError("source anchor mismatch")
        data = data.replace(before.encode(), after.encode())
    if sha(data) != patch["after_sha256"]:
        raise ValueError("source postcondition mismatch")
    return data


def owner(root: Path, relative: str, package: str, version: str, data: bytes) -> None:
    installed = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package], text=True
    )
    if installed != version:
        raise ValueError("unexpected original package version: " + package)
    lines = read_regular(root, "var/lib/dpkg/info/" + package + ".md5sums").decode().splitlines()
    md5s = {line.split(None, 1)[1]: line.split(None, 1)[0] for line in lines}
    if md5s.get(relative) != hashlib.md5(data, usedforsecurity=False).hexdigest():
        raise ValueError("original dpkg ownership/MD5 mismatch: " + relative)


def urllib3_files(wheel: bytes, expected: str) -> dict[str, bytes]:
    if sha(wheel) != expected:
        raise ValueError("unreviewed urllib3 wheel")
    files = wheel_files(wheel)
    result = {n: data for n, data in files.items() if n.startswith("urllib3/")}
    if any(Path(n).suffix in {".so", ".pyd", ".dylib", ".dll"} for n in result):
        raise ValueError("unexpected ABI extension in pure-Python urllib3 input")
    license_name = "urllib3-2.8.0.dist-info/licenses/LICENSE.txt"
    result["urllib3/LICENSE.txt"] = files[license_name]
    path = "urllib3/contrib/emscripten/__init__.py"
    before = b"import urllib3.connection\n"
    if result[path].count(before) != 1:
        raise ValueError("unexpected urllib3 self import")
    result[path] = result[path].replace(
        before, b"from pip._vendor import urllib3\nfrom pip._vendor.urllib3 import connection\n"
    )
    return {"pip/_vendor/" + n: data for n, data in result.items()}


def amend(root: Path, replacement: bytes, *, check_owners: bool = True) -> dict:  # noqa: PLR0912, PLR0915
    """Keep all validation in one preparation phase before the write phase."""
    manifest = json.loads((HERE / "amendments.json").read_text())
    writes = {}
    originals = {}
    patches = manifest["patches"]
    for patch in patches:
        data = read_regular(root, patch["path"])
        if check_owners:
            owner(root, patch["path"], patch["package"], patch["version"], data)
        originals[patch["path"]] = data
        writes[patch["path"]] = patched(data, patch)
    pip = manifest["pip"]
    site = root / "usr/lib/python3/dist-packages"
    actual = {
        str(p.relative_to(site))
        for p in (site / "pip").rglob("*")
        if p.is_file() and p.suffix != ".pyc"
    }
    if actual != set(pip["files"]):
        raise ValueError("unexpected system pip file inventory")
    for relative, expected in pip["files"].items():
        data = read_regular(root, "usr/lib/python3/dist-packages/" + relative)
        if sha(data) != expected:
            raise ValueError("original pip source mismatch: " + relative)
        if check_owners:
            owner(
                root,
                "usr/lib/python3/dist-packages/" + relative,
                "python3-pip",
                pip["package_version"],
                data,
            )
    replacement_files = urllib3_files(replacement, manifest["urllib3"]["sha256"])
    vendor_manifest = "pip/_vendor/vendor.txt"
    vendor = (site / vendor_manifest).read_bytes()
    if vendor.count(b"urllib3==2.7.0") != 1:
        raise ValueError("unexpected original pip vendor version")
    replacement_files[vendor_manifest] = vendor.replace(b"urllib3==2.7.0", b"urllib3==2.8.0")
    seed_outputs = {}
    for name, package, version, expected in [
        ("seed_path", "python3-pip-whl", pip["package_version"], pip["seed_sha256"]),
        (
            "setuptools_seed_path",
            "python3-setuptools-whl",
            "78.1.1-0.1",
            pip["setuptools_seed_sha256"],
        ),
    ]:
        relative = pip[name]
        data = read_regular(root, relative)
        if sha(data) != expected:
            raise ValueError("unreviewed original seed: " + relative)
        if check_owners:
            owner(root, relative, package, version, data)
        files = wheel_files(data)
        originals[relative] = data
        if name == "seed_path":
            # The seed and installed sources must have the same reviewed inputs.
            for n, expected_hash in pip["files"].items():
                if sha(files[n]) != expected_hash:
                    raise ValueError("seed differs from installed pip input: " + n)
            files = {n: d for n, d in files.items() if not n.startswith("pip/_vendor/urllib3/")}
            files.update(replacement_files)
        else:
            patch = next(p for p in patches if p["package"] == "python3-setuptools")
            n = "setuptools/_vendor/jaraco/context.py"
            files[n] = patched(files[n], patch)
            inner_record = "setuptools/_vendor/jaraco.context-5.3.0.dist-info/RECORD"
            rows = list(csv.reader(io.StringIO(files[inner_record].decode())))
            matches = [r for r in rows if r[0] == "jaraco/context.py"]
            if len(matches) != 1:
                raise ValueError("unexpected private jaraco RECORD")
            matches[0][1:] = [record_hash(files[n]), str(len(files[n]))]
            stream = io.StringIO(newline="")
            csv.writer(stream).writerows(rows)
            files[inner_record] = stream.getvalue().encode()
        seed_outputs[relative] = pack_wheel(files)
    old_vendor = {n for n in pip["files"] if n.startswith("pip/_vendor/urllib3/")}
    new_vendor = {n for n in replacement_files if n.startswith("pip/_vendor/urllib3/")}
    removed = ["usr/lib/python3/dist-packages/" + n for n in sorted(old_vendor - new_vendor)]
    for n, data in replacement_files.items():
        relative = "usr/lib/python3/dist-packages/" + n
        if (root / relative).exists():
            originals[relative] = read_regular(root, relative)
        writes[relative] = data
    writes.update(seed_outputs)
    cleanup_roots = {
        site / "pip/_vendor/urllib3",
        *((root / p["path"]).parent for p in patches),
    }
    compiled = {
        str(path.relative_to(root)): sha(read_regular(root, str(path.relative_to(root))))
        for directory in cleanup_roots
        for path in directory.rglob("*.pyc")
    }
    receipt = {
        "schema": 1,
        "qualification_sha256": manifest["qualification_sha256"],
        "amendment": manifest["amendment"],
        "manifest_sha256": sha((HERE / "amendments.json").read_bytes()),
        "original_versions": {p["package"]: p["version"] for p in patches},
        "urllib3": manifest["urllib3"],
        "upstream_commits": sorted({c for p in patches for c in p["upstream_commits"]}),
        "files": {
            n: {
                "before_sha256": sha(originals[n]) if n in originals else None,
                "after_sha256": sha(d),
            }
            for n, d in sorted(writes.items())
        },
        "removed": removed,
        "removed_compiled_sha256": dict(sorted(compiled.items())),
    }
    if {name: sha(data) for name, data in writes.items()} != manifest["expected_outputs"]:
        raise ValueError("computed amendment differs from trusted output contract")
    if removed != manifest["expected_removed"]:
        raise ValueError("computed removal differs from trusted output contract")
    receipt_path = "usr/share/lyrashield/security/system-python-amendments.json"
    writes[receipt_path] = (json.dumps(receipt, indent=2) + "\n").encode()
    # Publication prepares all paths, bytes and backups before replacing originals.
    publish(root, writes, [*removed, *compiled])
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--urllib3-wheel", type=Path)
    args = parser.parse_args()
    manifest = json.loads((HERE / "amendments.json").read_text())
    if args.urllib3_wheel:
        replacement = read_regular(args.urllib3_wheel.absolute().parent, args.urllib3_wheel.name)
    else:
        with urllib.request.urlopen(manifest["urllib3"]["url"], timeout=60) as response:  # noqa: S310
            replacement = response.read()
    amend(Path("/"), replacement)


if __name__ == "__main__":
    main()
