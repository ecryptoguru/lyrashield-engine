"""Verify complete per-platform SBOM evidence is bound to the native images."""

import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts/prepare_sandbox_sbom.py"
IMAGE = "ghcr.io/example/sandbox"
INDEX = "sha256:" + "1" * 64
EMPTY = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
ARTIFACT_TYPE = "application/vnd.lyrashield.sandbox-sbom.v1"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def setup_evidence(tmp_path):
    documents, children = {}, {}
    (tmp_path / "sboms").mkdir()
    for arch, config in (("amd64", "a"), ("arm64", "b")):
        config_digest = "sha256:" + config * 64
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "digest": config_digest,
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": 123,
                },
            }
        ).encode()
        manifest_digest = digest(manifest)
        (tmp_path / f"{arch}.manifest").write_bytes(manifest)
        children[arch] = manifest_digest
        root_id = "SPDXRef-Image"
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"creators": ["Tool: syft-1.56.0"]},
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": root_id,
                }
            ],
            "packages": [
                {
                    "name": IMAGE,
                    "SPDXID": root_id,
                    "versionInfo": manifest_digest,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": manifest_digest[7:]}],
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": (
                                "pkg:oci/ghcr.io%2Fexample%2Fsandbox@"
                                f"sha256%3A{manifest_digest[7:]}?arch={arch}"
                            ),
                        }
                    ],
                },
                {"SPDXID": "SPDXRef-Package-example", "name": "example"},
            ],
        }
        name = f"sandbox-{arch}.spdx.json"
        raw = json.dumps(sbom).encode()
        (tmp_path / "sboms" / name).write_bytes(raw)
        documents[arch] = {"name": name, "raw": raw, "config": config_digest}
    qualification = {
        "schema": "lyrashield.sandbox.qualification.v1",
        "engineRevision": "a" * 40,
        "workflowRevision": "b" * 40,
        "runId": "123",
        "runAttempt": "1",
        "indexDigest": INDEX,
        "platformManifests": children,
    }
    (tmp_path / "qualification.json").write_text(json.dumps(qualification))
    (tmp_path / "index-metadata.json").write_text(
        json.dumps(
            {
                "containerimage.descriptor": {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": INDEX,
                    "size": 123,
                }
            }
        )
    )
    artifact = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": ARTIFACT_TYPE,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": EMPTY, "size": 2},
        "subject": {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": INDEX,
            "size": 123,
        },
        "layers": [
            {
                "mediaType": "application/spdx+json",
                "digest": digest(item["raw"]),
                "size": len(item["raw"]),
                "annotations": {"org.opencontainers.image.title": item["name"]},
            }
            for item in documents.values()
        ],
    }
    artifact_raw = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(artifact_raw)
    return qualification, documents, artifact, digest(artifact_raw)


def invoke(tmp_path, artifact_digest):
    return subprocess.run(  # noqa: S603 - fixed local script and test-owned paths
        [
            sys.executable,
            str(SCRIPT),
            "--qualification",
            str(tmp_path / "qualification.json"),
            "--index-metadata",
            str(tmp_path / "index-metadata.json"),
            "--amd64-manifest",
            str(tmp_path / "amd64.manifest"),
            "--arm64-manifest",
            str(tmp_path / "arm64.manifest"),
            "--artifact-manifest",
            str(tmp_path / "artifact.json"),
            "--artifact-digest",
            artifact_digest,
            "--image",
            IMAGE,
            "--sbom-dir",
            str(tmp_path / "sboms"),
            "--output",
            str(tmp_path / "predicate.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_predicate_binds_full_documents_and_qualified_manifests(tmp_path):
    qualification, docs, _, artifact_digest = setup_evidence(tmp_path)
    result = invoke(tmp_path, artifact_digest)
    assert result.returncode == 0, result.stderr
    actual = json.loads((tmp_path / "predicate.json").read_text())
    assert actual["schema"] == "lyrashield.sandbox.sbom.v1"
    assert actual["indexDigest"] == INDEX
    assert actual["artifact"] == {"digest": artifact_digest, "mediaType": ARTIFACT_TYPE}
    for arch in ("amd64", "arm64"):
        assert actual["platforms"][arch] == {
            "manifestDigest": qualification["platformManifests"][arch],
            "configDigest": docs[arch]["config"],
            "documentDigest": digest(docs[arch]["raw"]),
            "size": len(docs[arch]["raw"]),
            "filename": docs[arch]["name"],
        }


def test_accepts_standard_inline_empty_artifact_config(tmp_path):
    _, _, artifact, _ = setup_evidence(tmp_path)
    artifact["config"]["data"] = "e30="
    raw = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(raw)
    result = invoke(tmp_path, digest(raw))
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("manifest_type", "config_type"),
    [
        ("application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.config.v1+json"),
        (
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.container.image.v1+json",
        ),
    ],
)
def test_config_descriptor_is_correct_for_image_manifest(tmp_path, manifest_type, config_type):
    api = runpy.run_path(str(SCRIPT))
    doc = {
        "schemaVersion": 2,
        "mediaType": manifest_type,
        "config": {"mediaType": config_type, "digest": "sha256:" + "c" * 64, "size": 123},
    }
    path = tmp_path / "manifest.json"

    def check():
        raw = json.dumps(doc).encode()
        path.write_bytes(raw)
        return api["config_for_manifest"](path, digest(raw))

    assert check() == "sha256:" + "c" * 64
    doc["config"]["mediaType"] = "application/json"
    with pytest.raises(ValueError):
        check()
    doc["config"]["mediaType"] = config_type
    doc["config"]["size"] = 0
    with pytest.raises(ValueError):
        check()


@pytest.mark.parametrize("field", ["urls", "data"])
def test_rejects_external_or_inline_native_config(tmp_path, field):
    api = runpy.run_path(str(SCRIPT))
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:" + "c" * 64,
            "size": 123,
            field: [] if field == "urls" else "",
        },
    }
    raw = json.dumps(manifest).encode()
    path = tmp_path / "manifest.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        api["config_for_manifest"](path, digest(raw))


@pytest.mark.parametrize(
    ("descriptor", "field"),
    [
        ("config", "urls"),
        ("subject", "urls"),
        ("subject", "data"),
        ("layer", "urls"),
        ("layer", "data"),
    ],
)
def test_rejects_external_or_inline_artifact_descriptors(tmp_path, descriptor, field):
    _, _, artifact, _ = setup_evidence(tmp_path)
    target = artifact["layers"][0] if descriptor == "layer" else artifact[descriptor]
    target[field] = [] if field == "urls" else ""
    raw = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(raw)
    assert invoke(tmp_path, digest(raw)).returncode != 0
    assert not (tmp_path / "predicate.json").exists()


def test_rejects_noncanonical_but_equivalent_root_purl(tmp_path):
    _, docs, artifact, _ = setup_evidence(tmp_path)
    path = tmp_path / "sboms" / docs["amd64"]["name"]
    document = json.loads(path.read_text())
    ref = document["packages"][0]["externalRefs"][0]
    ref["referenceLocator"] = ref["referenceLocator"].replace("%2F", "%2f")
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    artifact["layers"][0]["digest"] = digest(raw)
    artifact["layers"][0]["size"] = len(raw)
    artifact_raw = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(artifact_raw)
    assert invoke(tmp_path, digest(artifact_raw)).returncode != 0
    assert not (tmp_path / "predicate.json").exists()


def test_rejects_conflicting_root_sha256(tmp_path):
    _, docs, artifact, _ = setup_evidence(tmp_path)
    path = tmp_path / "sboms" / docs["amd64"]["name"]
    document = json.loads(path.read_text())
    document["packages"][0]["checksums"].append(
        {"algorithm": "SHA256", "checksumValue": "f" * 64}
    )
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    artifact["layers"][0]["digest"] = digest(raw)
    artifact["layers"][0]["size"] = len(raw)
    artifact_raw = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(artifact_raw)
    assert invoke(tmp_path, digest(artifact_raw)).returncode != 0


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_rejects_non_json_numeric_constants(tmp_path, constant):
    _, docs, artifact, _ = setup_evidence(tmp_path)
    path = tmp_path / "sboms" / docs["amd64"]["name"]
    raw = docs["amd64"]["raw"][:-1] + (', "extra": ' + constant + "}").encode()
    path.write_bytes(raw)
    artifact["layers"][0]["digest"] = digest(raw)
    artifact["layers"][0]["size"] = len(raw)
    artifact_raw = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(artifact_raw)
    assert invoke(tmp_path, digest(artifact_raw)).returncode != 0


@pytest.mark.parametrize(
    "tamper",
    [
        "document",
        "manifest",
        "wrong_subject",
        "wrong_subject_size",
        "missing_platform",
        "wrong_arch",
        "wrong_tool",
        "empty_packages",
        "artifact_digest",
        "oversized",
    ],
)
def test_rejects_incomplete_or_mismatched_sbom_evidence(tmp_path, tamper):
    _, docs, artifact, artifact_digest = setup_evidence(tmp_path)
    if tamper == "document":
        (tmp_path / "sboms" / docs["amd64"]["name"]).write_bytes(docs["amd64"]["raw"] + b" ")
    elif tamper == "manifest":
        (tmp_path / "amd64.manifest").write_bytes(b"{}")
    elif tamper == "wrong_subject":
        artifact["subject"]["digest"] = "sha256:" + "f" * 64
    elif tamper == "wrong_subject_size":
        artifact["subject"]["size"] += 1
    elif tamper == "missing_platform":
        artifact["layers"].pop()
    elif tamper == "wrong_arch":
        p = tmp_path / "sboms" / docs["amd64"]["name"]
        p.write_bytes(docs["amd64"]["raw"].replace(b"arch=amd64", b"arch=arm64"))
        artifact["layers"][0]["digest"] = digest(p.read_bytes())
        artifact["layers"][0]["size"] = p.stat().st_size
    elif tamper == "wrong_tool":
        p = tmp_path / "sboms" / docs["amd64"]["name"]
        p.write_bytes(docs["amd64"]["raw"].replace(b"syft-1.56.0", b"syft-1.42.3"))
        artifact["layers"][0]["digest"] = digest(p.read_bytes())
        artifact["layers"][0]["size"] = p.stat().st_size
    elif tamper == "empty_packages":
        p = tmp_path / "sboms" / docs["amd64"]["name"]
        document = json.loads(p.read_text())
        document["packages"].pop()
        p.write_text(json.dumps(document))
        artifact["layers"][0]["digest"] = digest(p.read_bytes())
        artifact["layers"][0]["size"] = p.stat().st_size
    elif tamper == "artifact_digest":
        artifact_digest = "sha256:" + "e" * 64
    elif tamper == "oversized":
        with (tmp_path / "sboms" / docs["amd64"]["name"]).open("ab") as f:
            f.truncate(256 * 1024 * 1024 + 1)
    if tamper in (
        "wrong_subject",
        "wrong_subject_size",
        "missing_platform",
        "wrong_arch",
        "wrong_tool",
        "empty_packages",
    ):
        raw = json.dumps(artifact).encode()
        (tmp_path / "artifact.json").write_bytes(raw)
        artifact_digest = digest(raw)
    assert invoke(tmp_path, artifact_digest).returncode != 0
    assert not (tmp_path / "predicate.json").exists()
