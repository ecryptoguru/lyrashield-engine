"""Offline chain checks for BuildKit SBOM statements; no signature/coverage claims."""

import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/inspect_buildkit_sbom.py"
IMAGE = "ghcr.io/ecryptoguru/lyrashield-sandbox"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INTOTO = "application/vnd.in-toto+json"
SPDX_TYPE = "https://spdx.dev/Document"
NATIVE = "sha256:" + "1" * 64
EMPTY_CONFIG = {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2,
    "data": "e30=",
}


def encoded(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def descriptor(raw, media):
    return {"mediaType": media, "size": len(raw), "digest": digest(raw)}


def make_fixture(tmp_path):
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": SPDX_TYPE,
        "subject": [
            {
                "name": f"pkg:docker/{IMAGE}@candidate?platform=linux%2Famd64",
                "digest": {"sha256": NATIVE[7:]},
            }
        ],
        "predicate": {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "name": "fixture",
                    "SPDXID": "SPDXRef-fixture",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                }
            ],
        },
    }
    return build_fixture(tmp_path, statement)


def build_fixture(tmp_path, statement, *, attestation_extra=None, index_extra=None):
    raw = encoded(statement)
    spdx = descriptor(raw, INTOTO)
    spdx["annotations"] = {"in-toto.io/predicate-type": SPDX_TYPE}
    att = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": "application/vnd.docker.attestation.manifest.v1+json",
        "config": EMPTY_CONFIG,
        "subject": {"mediaType": OCI_MANIFEST, "digest": NATIVE, "size": 200},
        "layers": [spdx],
    }
    if attestation_extra:
        attestation_extra(att)
    att_raw = encoded(att)
    child = descriptor(att_raw, OCI_MANIFEST)
    child["platform"] = {"os": "unknown", "architecture": "unknown"}
    child["annotations"] = {
        "vnd.docker.reference.digest": NATIVE,
        "vnd.docker.reference.type": "attestation-manifest",
    }
    native = {
        "mediaType": OCI_MANIFEST,
        "digest": NATIVE,
        "size": 200,
        "platform": {"os": "linux", "architecture": "amd64"},
    }
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [native, child]}
    if index_extra:
        index_extra(index)
    index_raw = encoded(index)
    for name, content in [("index", index_raw), ("attestation", att_raw), ("statement", raw)]:
        (tmp_path / name).write_bytes(content)
    return digest(index_raw), statement


def invoke(tmp_path, index_digest, arch="amd64"):
    return subprocess.run(  # noqa: S603 - fixed local interpreter and script
        [
            sys.executable,
            str(SCRIPT),
            "--index",
            str(tmp_path / "index"),
            "--index-digest",
            index_digest,
            "--attestation-manifest",
            str(tmp_path / "attestation"),
            "--statement",
            str(tmp_path / "statement"),
            "--image",
            IMAGE,
            "--arch",
            arch,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_binds_index_attestation_manifest_spdx_and_subject(tmp_path):
    anchor, _ = make_fixture(tmp_path)
    result = invoke(tmp_path, anchor)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["scope"] == "index_bound_buildkit_sbom_inspection_only"
    assert report["nativeManifestDigest"] == NATIVE
    assert report["packageCount"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "index_bytes",
        "attestation_bytes",
        "statement_bytes",
        "subject",
        "arch",
        "duplicates",
        "missing_sbom",
        "wrong_platform",
        "not_spdx",
    ],
)
def test_rejects_broken_or_ambiguous_chain(tmp_path, mutation):
    anchor, statement = make_fixture(tmp_path)
    if mutation == "index_bytes":
        (tmp_path / "index").write_bytes(b"{}")
    elif mutation == "attestation_bytes":
        (tmp_path / "attestation").write_bytes(b"{}")
    elif mutation == "statement_bytes":
        (tmp_path / "statement").write_bytes(b"{}")
    elif mutation == "subject":
        statement["subject"][0]["digest"]["sha256"] = "2" * 64
        anchor, _ = build_fixture(tmp_path, statement)
    elif mutation == "duplicates":
        anchor, _ = build_fixture(
            tmp_path, statement, index_extra=lambda x: x["manifests"].append(x["manifests"][0])
        )
    elif mutation == "missing_sbom":
        anchor, _ = build_fixture(
            tmp_path, statement, attestation_extra=lambda x: x.update(layers=[])
        )
    elif mutation == "wrong_platform":
        statement["subject"][0]["name"] = f"pkg:docker/{IMAGE}@candidate?platform=linux%2Farm64"
        anchor, _ = build_fixture(tmp_path, statement)
    elif mutation == "not_spdx":
        statement["predicate"]["spdxVersion"] = "SPDX-1.0"
        anchor, _ = build_fixture(tmp_path, statement)
    result = invoke(tmp_path, anchor, "arm64" if mutation == "arch" else "amd64")
    assert result.returncode != 0
    assert result.stdout == ""


def test_rejects_duplicate_json_keys_even_with_matching_index_digest(tmp_path):
    make_fixture(tmp_path)
    raw = b'{"schemaVersion":2,"schemaVersion":2,"mediaType":"invalid","manifests":[]}'
    (tmp_path / "index").write_bytes(raw)
    result = invoke(tmp_path, digest(raw))
    assert result.returncode != 0
    assert result.stdout == ""
    assert "duplicate JSON key" in result.stderr


def test_rejects_index_symlink(tmp_path):
    anchor, _ = make_fixture(tmp_path)
    index = tmp_path / "index"
    original = tmp_path / "original"
    index.rename(original)
    index.symlink_to(original)
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""


def test_rejects_ambiguous_attestation_descriptors(tmp_path):
    _, statement = make_fixture(tmp_path)
    anchor, _ = build_fixture(
        tmp_path, statement, index_extra=lambda x: x["manifests"].append(x["manifests"][1])
    )
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "ambiguous BuildKit attestation" in result.stderr


def test_rejects_rehashed_statement_without_packages(tmp_path):
    _, statement = make_fixture(tmp_path)
    statement["predicate"]["packages"] = []
    anchor, _ = build_fixture(tmp_path, statement)
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "missing SPDX packages" in result.stderr


@pytest.mark.parametrize("mutation", ["wrong_attestation_subject", "wrong_attestation_config"])
def test_rejects_invalid_attestation_manifest_even_when_index_bound(tmp_path, mutation):
    _, statement = make_fixture(tmp_path)

    def change(att):
        if mutation == "wrong_attestation_subject":
            att["subject"].update(digest="sha256:" + "2" * 64)
        else:
            att.update(config={"mediaType": "unexpected"})

    anchor, _ = build_fixture(tmp_path, statement, attestation_extra=change)
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""


def test_rejects_same_length_statement_tampering(tmp_path):
    anchor, _ = make_fixture(tmp_path)
    path = tmp_path / "statement"
    raw = path.read_bytes()
    altered = raw.replace(b"fixture", b"foxture")
    assert len(altered) == len(raw) and altered != raw
    path.write_bytes(altered)
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "digest mismatch" in result.stderr


def test_bounded_reader_rejects_oversize_before_json_parse(tmp_path):
    module = runpy.run_path(str(SCRIPT))
    path = tmp_path / "blob"
    raw = b"12345"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="input size limit"):
        module["read_bound"](str(path), digest(raw), 4)


@pytest.mark.parametrize("mutation", ["null", "missing_name", "missing_id", "duplicate_id"])
def test_rejects_invalid_package_shapes_after_rehash(tmp_path, mutation):
    _, statement = make_fixture(tmp_path)
    package = statement["predicate"]["packages"][0]
    if mutation == "null":
        statement["predicate"]["packages"] = [None]
    elif mutation == "missing_name":
        del package["name"]
    elif mutation == "missing_id":
        del package["SPDXID"]
    else:
        statement["predicate"]["packages"].append(package.copy())
    anchor, _ = build_fixture(tmp_path, statement)
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "field,value", [("variant", "v999"), ("variant", "v8"), ("os.version", "other")]
)
def test_rejects_unsupported_native_platform_qualifiers_after_rehash(tmp_path, field, value):
    _, statement = make_fixture(tmp_path)
    anchor, _ = build_fixture(
        tmp_path,
        statement,
        index_extra=lambda index: index["manifests"][0]["platform"].update({field: value}),
    )
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""


def test_accepts_explicit_arm64_v8_and_missing_optional_version(tmp_path):
    _, statement = make_fixture(tmp_path)
    statement["subject"][0]["name"] = f"pkg:docker/{IMAGE}@candidate?platform=linux%2Farm64"
    anchor, _ = build_fixture(
        tmp_path,
        statement,
        index_extra=lambda index: index["manifests"][0]["platform"].update(
            {"architecture": "arm64", "variant": "v8"}
        ),
    )
    result = invoke(tmp_path, anchor, "arm64")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "key,value",
    [
        ("name", "a\u0000b"),
        ("name", "a\u0085b"),
        ("versionInfo", "1.0\nother"),
        ("downloadLocation", "not a URI"),
        ("downloadLocation", "file:///etc/passwd"),
        ("downloadLocation", "https://"),
        ("downloadLocation", "https://example.invalid/%zz"),
        ("downloadLocation", "https://example.invalid/%00"),
        ("downloadLocation", "https://example.invalid/with space"),
        ("downloadLocation", "https://example.invalid/|file"),
        ("downloadLocation", "https://example.invalid/{file}"),
        ("downloadLocation", "https://example.invalid/\\evil"),
        ("downloadLocation", "https://-invalid.example/repo"),
        ("downloadLocation", "https://bad..example/repo"),
        ("downloadLocation", "https://example.invalid:99999/repo"),
        ("downloadLocation", "https://bad@user@example.invalid/repo"),
        ("downloadLocation", "https://[::1]bad/repo"),
    ],
)
def test_rejects_unsafe_package_text_after_rehash(tmp_path, key, value):
    _, statement = make_fixture(tmp_path)
    statement["predicate"]["packages"][0][key] = value
    anchor, _ = build_fixture(tmp_path, statement)
    result = invoke(tmp_path, anchor)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "location",
    [
        "NONE",
        "NOASSERTION",
        "https://example.invalid/repo",
        "git+ssh://git@example.invalid/repo",
        "https://[::1]:8443/repo",
    ],
)
def test_accepts_supported_download_location_forms(tmp_path, location):
    _, statement = make_fixture(tmp_path)
    statement["predicate"]["packages"][0]["downloadLocation"] = location
    anchor, _ = build_fixture(tmp_path, statement)
    result = invoke(tmp_path, anchor)
    assert result.returncode == 0, result.stderr
