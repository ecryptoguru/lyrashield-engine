import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote
from urllib.request import Request

import pytest

from scripts import acquire_sandbox_inventory as acquire


class AcquisitionTests(unittest.TestCase):
    def test_stream_requires_expected_digest_and_size(self):
        digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "blob"
            acquire.write_verified(io.BytesIO(b"abc"), destination, digest, 3)
            self.assertEqual(destination.read_bytes(), b"abc")
            with self.assertRaises(FileExistsError):
                acquire.write_verified(io.BytesIO(b"abc"), destination, digest, 3)
            self.assertEqual(destination.read_bytes(), b"abc")
            for contents in (b"abd", b"abcd", b"ab"):
                with self.assertRaises(ValueError):
                    acquire.write_verified(
                        io.BytesIO(contents), Path(tmp) / ("wrong" + str(len(contents))), digest, 3
                    )

    def test_receipts_only_extract_expected_byte_bound_files(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("amd64/receipt.json", b"abc")
            archive.writestr("arm64/receipt.json", b"abc")
            archive.writestr("../escape", b"ignored")
        digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "receipts"
            acquire.extract_receipts(
                data.getvalue(),
                {"amd64": {"receiptDigest": digest}, "arm64": {"receiptDigest": digest}},
                root,
            )
            self.assertEqual((root / "amd64/receipt.json").read_bytes(), b"abc")
            self.assertFalse((Path(tmp) / "escape").exists())
            with self.assertRaises(ValueError):
                acquire.extract_receipts(
                    data.getvalue(),
                    {
                        "amd64": {"receiptDigest": "sha256:" + "0" * 64},
                        "arm64": {"receiptDigest": digest},
                    },
                    Path(tmp) / "other",
                )

    def test_compressed_plan_rejects_conflicts_and_excess(self):
        plan = {}
        digest = "sha256:" + "1" * 64
        acquire.add_plan(plan, digest, 2)
        acquire.add_plan(plan, digest, 2)
        self.assertEqual(plan, {digest: 2})
        with self.assertRaises(ValueError):
            acquire.add_plan(plan, digest, 3)
        with self.assertRaises(ValueError):
            acquire.add_plan({}, digest, acquire.MAX_TOTAL + 1)

    def test_archive_rejects_duplicate_receipt_name(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("amd64/receipt.json", b"abc")
            with self.assertWarns(UserWarning):
                archive.writestr("amd64/receipt.json", b"abc")
            archive.writestr("arm64/receipt.json", b"abc")
        digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            acquire.extract_receipts(
                data.getvalue(),
                {"amd64": {"receiptDigest": digest}, "arm64": {"receiptDigest": digest}},
                Path(tmp) / "receipts",
            )

    def test_redirect_cannot_forward_registry_token_or_escape_trusted_hosts(self):
        handler = acquire.RegistryRedirect()
        request = Request("https://ghcr.io/v2/x", headers={"Authorization": "Bearer secret"})
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "",
            {},
            "https://pkg-containers.githubusercontent.com/asset?sig=secret",
        )
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, "", {}, "https://attacker.example/asset")


class PublisherHoldTests(unittest.TestCase):
    def jobs(self):
        def step(number, name, conclusion):
            return {"number": number, "name": name, "status": "completed", "conclusion": conclusion}

        def job(name, conclusion, steps):
            return {"name": name, "status": "completed", "conclusion": conclusion, "steps": steps}

        jobs = [
            job(name, "success", [step(1, "Complete job", "success")])
            for name in (
                "Resolve qualified engine revision",
                "Build sandbox (amd64)",
                "Build sandbox (arm64)",
            )
        ]
        names = [
            "Assemble and verify qualified platform index",
            "Generate per-platform SPDX SBOMs",
            "Attach and validate complete SBOM artifact",
            "Sign provenance for the immutable image digest",
            "Sign selected runtime and qualified platform binding",
            "Sign per-platform SBOM binding",
            "Verify signed sandbox publication",
            "Qualify bounded SBOM coverage on both native images",
            "Assemble bounded SBOM coverage predicate",
            "Sign bounded SBOM coverage qualification",
            "Verify signed sandbox publication coverage",
            "Upload bounded SBOM coverage evidence",
        ]
        steps = [step(i + 1, name, "success") for i, name in enumerate(names)]
        steps += [
            step(13, "Hold promotion pending independent package coverage", "failure"),
            step(14, "Promote the smoke-qualified digest", "skipped"),
            step(15, "Record deployable immutable reference", "skipped"),
            step(16, "Complete job", "success"),
        ]
        jobs.append(job("Publish qualified sandbox index", "failure", steps))
        return {"total_count": 4, "jobs": jobs}

    def test_only_documented_hold_failure_is_accepted(self):
        acquire.verify_publisher_jobs(self.jobs())
        for mutation in (
            "evidence-failed",
            "hold-skipped",
            "promoted",
            "cleanup-failed",
            "build-failed",
        ):
            record = self.jobs()
            if mutation == "evidence-failed":
                record["jobs"][3]["steps"][9]["conclusion"] = "failure"
            elif mutation == "hold-skipped":
                record["jobs"][3]["steps"][12]["conclusion"] = "skipped"
            elif mutation == "promoted":
                record["jobs"][3]["steps"][13]["conclusion"] = "success"
            elif mutation == "cleanup-failed":
                record["jobs"][3]["steps"][15]["conclusion"] = "failure"
            else:
                record["jobs"][1]["conclusion"] = "failure"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                acquire.verify_publisher_jobs(record)


def test_complete_acquisition_preflights_before_fetching_layers(tmp_path, monkeypatch):
    objects = {}
    revision = "ddb1c5ea6a5014cfc5e1cfadac03a5db7e8cc25d"
    layer_raw = b"a-small-compressed-layer-fixture"

    def obj(value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        digest = acquire.sha256(raw)
        objects[digest] = raw
        return digest, len(raw)

    layer_digest, layer_size = obj(layer_raw)
    index_entries, bindings = [], {}
    for arch in ("amd64", "arm64"):
        config_digest, config_size = obj(
            {
                "os": "linux",
                "architecture": arch,
                "config": {
                    "Labels": {
                        "org.opencontainers.image.revision": revision,
                        "org.opencontainers.image.source": "https://github.com/"
                        + acquire.REPOSITORY,
                    }
                },
            }
        )
        manifest_digest, manifest_size = obj(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "digest": config_digest,
                    "size": config_size,
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                },
                "layers": [
                    {
                        "digest": layer_digest,
                        "size": layer_size,
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    }
                ],
            }
        )
        index_entries.append(
            {
                "digest": manifest_digest,
                "size": manifest_size,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"os": "linux", "architecture": arch},
            }
        )
        safe_purl = "-_.!~*'()"
        purl = (
            f"pkg:oci/{quote(acquire.IMAGE, safe=safe_purl)}@"
            f"{quote(manifest_digest, safe=safe_purl)}?arch={arch}"
        )
        doc_digest, doc_size = obj(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {"creators": ["Tool: syft-1.56.0"]},
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-Image",
                    }
                ],
                "packages": [
                    {
                        "name": acquire.IMAGE,
                        "SPDXID": "SPDXRef-Image",
                        "versionInfo": manifest_digest,
                        "checksums": [
                            {"algorithm": "SHA256", "checksumValue": manifest_digest[7:]}
                        ],
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": purl,
                            }
                        ],
                    },
                    {"SPDXID": "SPDXRef-Package-example", "name": "example"},
                ],
            }
        )
        bindings[arch] = {
            "manifestDigest": manifest_digest,
            "configDigest": config_digest,
            "documentDigest": doc_digest,
            "size": doc_size,
            "filename": f"sandbox-{arch}.spdx.json",
        }
    index_digest, index_size = obj(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": index_entries,
        }
    )
    artifact_digest, _ = obj(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": acquire.ARTIFACT_TYPE,
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "size": 2,
            },
            "subject": {
                "digest": index_digest,
                "size": index_size,
                "mediaType": "application/vnd.oci.image.index.v1+json",
            },
            "layers": [
                {
                    "mediaType": "application/spdx+json",
                    "digest": item["documentDigest"],
                    "size": item["size"],
                    "annotations": {"org.opencontainers.image.title": item["filename"]},
                }
                for item in bindings.values()
            ],
        }
    )
    identity = {
        "engineRevision": revision,
        "workflowRevision": revision,
        "runId": "123",
        "runAttempt": "1",
        "indexDigest": index_digest,
    }
    qualification = {
        "schema": "lyrashield.sandbox.qualification.v1",
        **identity,
        "platformManifests": {a: bindings[a]["manifestDigest"] for a in bindings},
    }
    sbom = {
        "schema": "lyrashield.sandbox.sbom.v1",
        **identity,
        "artifact": {"digest": artifact_digest, "mediaType": acquire.ARTIFACT_TYPE},
        "platforms": bindings,
    }
    coverage = {
        "schema": "lyrashield.sandbox.sbom-coverage.v1",
        **identity,
        "platforms": {"amd64": {}, "arm64": {}},
    }
    verified = {
        acquire.QUAL_TYPE: qualification,
        acquire.SBOM_TYPE: sbom,
        acquire.COVERAGE_TYPE: coverage,
    }
    calls = []

    class Registry:
        def fetch(self, kind, digest, destination, size=None, limit=None):
            assert kind in ("manifests", "blobs")
            calls.append(digest)
            acquire.write_verified(
                io.BytesIO(objects[digest]), destination, digest, size=size, limit=limit
            )

    monkeypatch.setattr(acquire, "Registry", Registry)
    monkeypatch.setattr(acquire, "trusted_tool", lambda *_: None)
    monkeypatch.setattr(acquire, "authenticate", lambda *_: verified)
    monkeypatch.setattr(acquire, "fetch_receipts", lambda *args: args[-1].mkdir())
    monkeypatch.setattr(acquire.shutil, "disk_usage", lambda *_: SimpleNamespace(free=20 * 1024**3))
    args = SimpleNamespace(
        revision=revision,
        index_digest=index_digest,
        run_id="123",
        run_attempt="1",
        source_repository=Path(__file__).parents[1],
    )
    root = tmp_path / "good"
    root.mkdir()
    blobs, _, _ = acquire.prepare(args, root)
    assert (blobs / layer_digest[7:]).read_bytes() == layer_raw
    assert calls[-1] == layer_digest
    calls.clear()
    sbom["platforms"]["amd64"]["configDigest"] = "sha256:" + "0" * 64
    bad = tmp_path / "bad"
    bad.mkdir()
    with pytest.raises(ValueError):
        acquire.prepare(args, bad)
    assert layer_digest not in calls
