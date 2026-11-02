"""Replace two vulnerable pip 26.2.2 vendors with verified locked package sources.

Pip remains self contained (DEBUNDLED=False). Only pure Python sources and license
files are copied, using pip's import namespace; no platform extension is vendored.
All inputs are checked before mutation. The vendor manifest, CycloneDX inventory,
and pip RECORD describe the actual replacement bytes. See the public qualification
receipt for the narrow downstream exception and official wheel provenance.
"""

# ruff: noqa: INP001
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import shutil
import sysconfig
from email.parser import BytesParser
from pathlib import Path


REPLACEMENTS = {"urllib3": ("2.7.0", "2.8.0"), "msgpack": ("1.1.2", "1.2.3")}
VENDOR_SHA256 = "2b44b4bc5b7da9dcda38099dc92c52cc3dda2a714cd189b439c0668401418630"
BOM_SHA256 = "7be976001ba70fe6b38530af13063bea96e1bd894c271c4e57908c737079ef93"


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def checked_distribution(site: Path, name: str, version: str) -> tuple[Path, dict[str, list[str]]]:
    """Reject unexpected versions, ambiguous paths and edited distribution bytes."""
    dist = site / f"{name}-{version}.dist-info"
    metadata = BytesParser().parsebytes((dist / "METADATA").read_bytes())
    if metadata.get_all("Name") != [name] or metadata.get_all("Version") != [version]:
        raise ValueError(f"expected the pinned {name} {version}")
    rows = list(csv.reader(io.StringIO((dist / "RECORD").read_text())))
    records = {row[0]: row for row in rows}
    if len(records) != len(rows):
        raise ValueError("duplicate distribution RECORD entry")
    for name_in_record, row in records.items():
        if len(row) != 3:
            raise ValueError("malformed distribution RECORD")
        # Entry-point scripts may live outside site-packages. They are not inputs.
        if name_in_record.startswith("../") or not row[1]:
            continue
        path = site / name_in_record
        data = path.read_bytes()
        if [record_hash(data), str(len(data))] != row[1:]:
            raise ValueError(f"distribution RECORD mismatch: {name_in_record}")
    return dist, records


def replacement_sources(
    site: Path, vendor: Path
) -> tuple[dict[Path, bytes], dict[str, str], list[dict[str, str]]]:
    """Prepare only verified upstream source and license files."""
    writes: dict[Path, bytes] = {}
    replacements: dict[str, str] = {}
    provenance = []
    for name, (old, new) in REPLACEMENTS.items():
        source_dist, source_records = checked_distribution(site, name, new)
        source = site / name
        files = [p for p in source.rglob("*") if p.is_file() and p.suffix in {".py", ".pyi"}]
        if not files or not (source / "__init__.py").is_file():
            raise ValueError("missing vendor replacement source")
        for path in files:
            relative = path.relative_to(site).as_posix()
            if relative not in source_records or not source_records[relative][1]:
                raise ValueError("replacement source missing from verified RECORD")
            data = path.read_bytes()
            # The only absolute self-import in these exact upstream source trees.
            # Preserve urllib3's local binding while loading its nested module.
            if (
                name == "urllib3"
                and path.relative_to(source).as_posix() == "contrib/emscripten/__init__.py"
            ):
                old_import = b"import urllib3.connection\n"
                if data.count(old_import) != 1:
                    raise ValueError("unreviewed urllib3 namespace import")
                data = data.replace(
                    old_import,
                    b"from pip._vendor import urllib3\n"
                    b"from pip._vendor.urllib3 import connection\n",
                )
            writes[vendor / name / path.relative_to(source)] = data
        licenses = list((source_dist / "licenses").rglob("*"))
        license_files = [p for p in licenses if p.is_file()]
        if len(license_files) != 1:
            raise ValueError("expected one upstream package license")
        writes[vendor / name / "LICENSE.txt"] = license_files[0].read_bytes()
        if (source / "py.typed").is_file():
            writes[vendor / name / "py.typed"] = (source / "py.typed").read_bytes()
        replacements[f"pkg:pypi/{name}@{old}"] = f"pkg:pypi/{name}@{new}"
        provenance.append(
            {
                "name": name,
                "original_version": old,
                "replacement_version": new,
                "source_record_sha256": hashlib.sha256(
                    (source_dist / "RECORD").read_bytes()
                ).hexdigest(),
                "mode": "pure-python",
            }
        )
    return writes, replacements, provenance


def repair(site: Path) -> None:
    """Validate all inputs, then apply the exact reviewed two-package repair."""
    dist, records = checked_distribution(site, "pip", "26.2.2")
    vendor = site / "pip/_vendor"
    manifest = vendor / "vendor.txt"
    bom_path = vendor / "bom.cdx.json"
    for path, expected in ((manifest, VENDOR_SHA256), (bom_path, BOM_SHA256)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("unreviewed original pip vendor manifest")
    if "DEBUNDLED = False" not in (vendor / "__init__.py").read_text():
        raise ValueError("pip must retain its self-contained vendoring mode")
    writes, replacements, provenance = replacement_sources(site, vendor)
    vendor_text = manifest.read_text()
    for name, (old, new) in REPLACEMENTS.items():
        needle = f"{name}=={old}"
        if vendor_text.count(needle) != 1:
            raise ValueError("unexpected pip vendor version")
        vendor_text = vendor_text.replace(needle, f"{name}=={new}")
    bom_text = bom_path.read_text()
    bom = json.loads(bom_text)
    for name, (old, new) in REPLACEMENTS.items():
        components = [c for c in bom["components"] if c.get("name") == name]
        if len(components) != 1 or components[0].get("version") != old:
            raise ValueError("unexpected pip BOM component")
        component = components[0]
        component["version"] = new
        component["properties"] = [
            {
                "name": "lyrashield:vendor-repair",
                "value": "verified locked upstream pure-Python source",
            }
        ]

    def replace_refs(value: object) -> object:
        if isinstance(value, str):
            return replacements.get(value, value)
        if isinstance(value, list):
            return [replace_refs(v) for v in value]
        if isinstance(value, dict):
            return {k: replace_refs(v) for k, v in value.items()}
        return value

    writes[manifest] = vendor_text.encode()
    writes[bom_path] = (json.dumps(replace_refs(bom), indent=2) + "\n").encode()
    writes[vendor / "lyrashield-vendor-repair.json"] = (
        json.dumps({"pip": "26.2.2", "replacements": provenance}, indent=2) + "\n"
    ).encode()
    # No writes have occurred before every original and replacement is validated.
    prefixes = tuple(f"pip/_vendor/{name}/" for name in REPLACEMENTS)
    records = {k: v for k, v in records.items() if not k.startswith(prefixes)}
    for name in REPLACEMENTS:
        shutil.rmtree(vendor / name)
    for path, data in writes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        relative = path.relative_to(site).as_posix()
        records[relative] = [relative, record_hash(data), str(len(data))]
    output = io.StringIO(newline="")
    csv.writer(output).writerows(records[k] for k in sorted(records))
    (dist / "RECORD").write_text(output.getvalue())
    checked_distribution(site, "pip", "26.2.2")


if __name__ == "__main__":
    repair(Path(sysconfig.get_path("purelib")))
