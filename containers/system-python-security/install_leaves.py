#!/usr/bin/python3
"""Install only qualified Debian/Kali leaf packages; never add an APT source.

The archived signed Release authenticates a pinned compressed Packages index,
which authenticates every binary. A changing archive fails closed. --cache may
supply the same verified artifacts for an offline build/test.
"""

# Fixed argv, no shell; only manifest-pinned archive URLs and local debs are used.
# ruff: noqa: S603, T201
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import lzma
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from safe_io import preflight, publish, read_regular


HERE = Path(__file__).resolve().parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def obtain(url: str, expected: str, cache: Path, filename: str) -> Path:
    path = cache / filename
    preflight(cache, filename)
    if not path.exists():
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
            data = response.read()
        if digest(data) != expected:
            raise ValueError(f"download digest mismatch: {filename}")
        publish(cache, {filename: data})
    if digest(read_regular(cache, filename)) != expected:
        raise ValueError(f"cached digest mismatch: {filename}")
    return path


def fields(stanza: str) -> dict[str, str]:
    return dict(
        line.split(": ", 1)
        for line in stanza.splitlines()
        if ": " in line and not line.startswith(" ")
    )


def prepare(manifest: dict, arch: str, cache: Path) -> list[Path]:
    packages = manifest["packages"][arch]
    indexes = {}
    for name, release in manifest["releases"].items():
        signed = HERE / "provenance" / f"{name}.InRelease"
        if digest(signed.read_bytes()) != release["release_sha256"]:
            raise ValueError("signed Release digest mismatch")
        with tempfile.TemporaryDirectory(prefix="lyrashield-release-") as verified:
            plaintext = Path(verified) / "Release"
            subprocess.run(
                [
                    "/usr/bin/sqv",
                    "--keyring",
                    release["keyring"],
                    "--cleartext",
                    "--output",
                    str(plaintext),
                    str(signed),
                ],
                check=True,
            )
            authenticated = plaintext.read_text()
        index = release["indexes"][arch]
        relative = index["path"].split("/", 2)[2]
        # Verify the selected index is actually a SHA256 entry in this Release.
        sha_section = authenticated.split("\nSHA256:\n", 1)[1].split("\nSHA512:", 1)[0]
        if not re.search(
            r"^ " + index["sha256"] + r" +[0-9]+ +" + re.escape(relative) + r"$", sha_section, re.M
        ):
            raise ValueError("index is not authenticated by signed Release")
        path = obtain(
            release["base"] + index["path"],
            index["sha256"],
            cache,
            f"{name}-{arch}-Packages." + ("xz" if name == "sid" else "gz"),
        )
        data = (
            lzma.decompress(path.read_bytes())
            if name == "sid"
            else gzip.decompress(path.read_bytes())
        )
        selected = {p["Package"] for p in packages if p["archive"] == name}
        indexes[name] = {
            f["Package"]: f
            for s in data.decode().split("\n\n")
            if (f := fields(s)).get("Package") in selected
        }
    paths = []
    for package in packages:
        record = indexes[package["archive"]][package["Package"]]
        if any(
            record.get(k) != package[k]
            for k in ("Package", "Version", "Architecture", "Filename", "SHA256")
        ):
            raise ValueError("package differs from authenticated index")
        if record.get("Source", record["Package"]) != package["Source"]:
            raise ValueError("source identity differs from authenticated index")
        release = manifest["releases"][package["archive"]]
        path = obtain(
            release["base"] + package["Filename"],
            package["SHA256"],
            cache,
            Path(package["Filename"]).name,
        )
        identity = subprocess.check_output(
            ["/usr/bin/dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"], text=True
        )
        if fields(identity) != {k: package[k] for k in ("Package", "Version", "Architecture")}:
            raise ValueError("binary package identity mismatch")
        paths.append(path)
    return paths


def install(manifest: dict, arch: str, paths: list[Path]) -> None:
    packages = manifest["packages"][arch]
    preflight(Path("/"), "usr/share/lyrashield/security/system-python-leaves.json")
    for package in packages:
        # An absent leaf is an unexpected base, not permission to add it.
        subprocess.run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Status}", package["Package"]],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    cmd = [
        "/usr/bin/apt-get",
        "-s",
        "--no-remove",
        "--no-install-recommends",
        "install",
        *map(str, paths),
    ]
    plan = subprocess.check_output(cmd, text=True)
    print(plan, end="")
    if not re.search(r"^8 upgraded, 0 newly installed, 0 to remove", plan, re.M):
        raise ValueError("leaf installation must upgrade exactly eight existing packages")
    changed = set(re.findall(r"^Inst (\S+)", plan, re.M))
    if changed != {p["Package"] for p in packages} or re.search(r"^Remv ", plan, re.M):
        raise ValueError("unexpected APT package plan")
    subprocess.run(["/usr/bin/dpkg", "--install", *map(str, paths)], check=True)
    for package in packages:
        actual = subprocess.check_output(
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package["Package"]], text=True
        )
        if actual != package["Version"]:
            raise ValueError("installed leaf version mismatch")
    receipt = "usr/share/lyrashield/security/system-python-leaves.json"
    publish(
        Path("/"),
        {
            receipt: (
                json.dumps(
                    {
                        "architecture": arch,
                        "packages": packages,
                        "release_sha256": {
                            n: r["release_sha256"] for n, r in manifest["releases"].items()
                        },
                    },
                    indent=2,
                )
                + "\n"
            ).encode()
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    manifest = json.loads((HERE / "leaves.json").read_text())
    arch = subprocess.check_output(["/usr/bin/dpkg", "--print-architecture"], text=True).strip()
    if arch not in manifest["packages"]:
        raise ValueError("unsupported architecture")
    with tempfile.TemporaryDirectory(prefix="lyrashield-system-python-") as temporary:
        cache = args.cache or Path(temporary)
        paths = prepare(manifest, arch, cache)
        if not args.verify_only:
            install(manifest, arch, paths)


if __name__ == "__main__":
    main()
