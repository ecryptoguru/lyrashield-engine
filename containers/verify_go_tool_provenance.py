"""Bind upstream application coordinates and security overlays to installed Go bytes."""

# ruff: noqa: INP001
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import quote


ROOT = Path("/usr/local/share/lyrashield/go-tools")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def make_sbom(manifest: dict, provenance: Path, filesystem: Path = Path("/")) -> dict:
    """Verify builder bytes before describing the accurate, locally overlaid source."""
    applications = manifest.get("applications", [])
    if manifest.get("schema_version") != 1 or not applications:
        raise ValueError("missing application inventory")
    names: set[str] = set()
    components = []
    for app in applications:
        name = app["name"]
        if not re.fullmatch(r"[a-z0-9-]+", name) or name in names:
            raise ValueError("invalid or duplicate application name")
        names.add(name)
        module, version = app["module"], app["version"]
        if not module or not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?", version):
            raise ValueError(f"missing accurate module/version: {name}")
        path = Path(app["binary"])
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("invalid installed binary path")
        binary = filesystem / str(path).lstrip("/")
        meta = provenance / name
        expected, recorded_name = (meta / "binary.sha256").read_text().split()
        actual = digest(binary)
        if recorded_name != name or actual != expected:
            raise ValueError(f"installed bytes differ from builder: {name}")
        buildinfo = (meta / "buildinfo.txt").read_text()
        if not re.search(r"^\s*mod\s+" + re.escape(module) + r"\s", buildinfo, re.MULTILINE):
            raise ValueError(f"application module differs from builder: {name}")
        archive = app["archive_sha256"]
        if not re.fullmatch("[0-9a-f]{64}", archive):
            raise ValueError("invalid source archive digest")
        properties = {
            "lyrashield:tool": name,
            "lyrashield:binary:path": str(path),
            "lyrashield:source:archive-sha256": archive,
            "lyrashield:overlay:kind": "local-security-rebuild",
            "lyrashield:overlay:go.mod-sha256": digest(meta / "go.mod"),
            "lyrashield:overlay:go.sum-sha256": digest(meta / "go.sum"),
        }
        if app.get("commit"):
            if not re.fullmatch("[0-9a-f]{40}", app["commit"]):
                raise ValueError("invalid source commit")
            source = (meta / "source.txt").read_text()
            source_url = f"https://codeload.github.com/{app['repository']}/tar.gz/{app['commit']}"
            if source.splitlines() != [source_url, f"SHA256 {archive}"]:
                raise ValueError(f"source provenance differs: {name}")
            properties["lyrashield:source:commit"] = app["commit"]
        if (meta / "source.patch").exists():
            properties["lyrashield:overlay:source.patch-sha256"] = digest(meta / "source.patch")
        purl = f"pkg:golang/{quote(module, safe='/')}@{quote(version, safe='.+-')}"
        components.append(
            {
                "type": "application",
                "bom-ref": purl,
                "name": module,
                "version": version,
                "purl": purl,
                "hashes": [{"alg": "SHA-256", "content": actual}],
                "properties": [{"name": k, "value": v} for k, v in sorted(properties.items())],
            }
        )
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def verify_sbom(expected: dict, actual: dict) -> None:
    """Reject missing coordinates, altered versions, hashes, or overlay identities."""
    if actual != expected:
        raise ValueError("application SBOM differs from verified source/binary inventory")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "applications.json")
    parser.add_argument("--provenance", type=Path, default=ROOT)
    parser.add_argument("--filesystem", type=Path, default=Path("/"))
    parser.add_argument("--sbom", type=Path, default=ROOT / "applications.cdx.json")
    parser.add_argument("--write-sbom", type=Path)
    parser.add_argument("--emit-verified-sbom", action="store_true")
    args = parser.parse_args()
    sbom = make_sbom(json.loads(args.manifest.read_text()), args.provenance, args.filesystem)
    if args.write_sbom:
        args.write_sbom.write_text(json.dumps(sbom, indent=2) + "\n")
    else:
        verify_sbom(sbom, json.loads(args.sbom.read_text()))
    if args.emit_verified_sbom:
        print(json.dumps(sbom))  # noqa: T201 - machine-readable release audit input


if __name__ == "__main__":
    main()
