"""Verify policy evaluation of already cryptographically verified gh output."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts/check_sandbox_attestations.py"
REPO = "example/engine"
IMAGE = "ghcr.io/example/sandbox"
DIGEST = "sha256:" + "a" * 64
SHA = "b" * 40
REF = "refs/heads/main"
URI = f"https://github.com/{REPO}/actions/runs/123/attempts/2"
QUAL_TYPE = "https://lyrashieldai.com/attestations/sandbox-qualification/v1"
SBOM_TYPE = "https://lyrashieldai.com/attestations/sandbox-sbom/v1"
COVERAGE_TYPE = "https://lyrashieldai.com/attestations/sandbox-sbom-coverage/v1"
PROV_TYPE = "https://slsa.dev/provenance/v1"


def verified(predicate_type, predicate):
    return [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "issuer": "https://token.actions.githubusercontent.com",
                        "buildSignerURI": f"https://github.com/{REPO}/.github/workflows/publish-sandbox.yml@{REF}",
                        "buildSignerDigest": SHA,
                        "sourceRepositoryURI": f"https://github.com/{REPO}",
                        "sourceRepositoryDigest": SHA,
                        "sourceRepositoryRef": REF,
                        "runnerEnvironment": "github-hosted",
                        "runInvocationURI": URI,
                    }
                },
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": IMAGE, "digest": {"sha256": DIGEST[7:]}}],
                    "predicateType": predicate_type,
                    "predicate": predicate,
                },
            }
        }
    ]


def invoke(tmp_path, phase="coverage", *, include_coverage=True):
    command = [
        sys.executable,
        str(SCRIPT),
        "--repo",
        REPO,
        "--image",
        IMAGE,
        "--digest",
        DIGEST,
        "--revision",
        SHA,
        "--ref",
        REF,
        "--run-id",
        "123",
        "--run-attempt",
        "2",
        "--phase",
        phase,
        "--provenance",
        str(tmp_path / "provenance.json"),
        "--qualification",
        str(tmp_path / "qualification.json"),
        "--sbom",
        str(tmp_path / "sbom.json"),
        "--expected-qualification",
        str(tmp_path / "expected-qualification.json"),
        "--expected-sbom",
        str(tmp_path / "expected-sbom.json"),
    ]
    if include_coverage:
        command.extend(
            [
                "--coverage",
                str(tmp_path / "coverage.json"),
                "--expected-coverage",
                str(tmp_path / "expected-coverage.json"),
            ]
        )
    return subprocess.run(  # noqa: S603 - fixed local script and test-owned paths
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def prepare(tmp_path):
    qualifier = {"runId": "123", "runAttempt": "2", "indexDigest": DIGEST}
    sbom = {
        "runId": "123",
        "runAttempt": "2",
        "indexDigest": DIGEST,
        "artifact": {"digest": "sha256:" + "c" * 64},
    }
    provenance = {"runDetails": {"metadata": {"invocationId": URI}}}
    coverage = {
        "runId": "123",
        "runAttempt": "2",
        "indexDigest": DIGEST,
        "platforms": {"amd64": {}, "arm64": {}},
    }
    for name, data in (
        ("expected-qualification", qualifier),
        ("expected-sbom", sbom),
        ("provenance", verified(PROV_TYPE, provenance)),
        ("qualification", verified(QUAL_TYPE, qualifier)),
        ("sbom", verified(SBOM_TYPE, sbom)),
        ("expected-coverage", coverage),
        ("coverage", verified(COVERAGE_TYPE, coverage)),
    ):
        (tmp_path / f"{name}.json").write_text(json.dumps(data))


def test_accepts_matching_verified_attestations(tmp_path):
    prepare(tmp_path)
    result = invoke(tmp_path)
    assert result.returncode == 0, result.stderr


def test_publication_phase_does_not_require_coverage_attestation(tmp_path):
    prepare(tmp_path)
    (tmp_path / "coverage.json").unlink()
    (tmp_path / "expected-coverage.json").unlink()
    result = invoke(tmp_path, "publication", include_coverage=False)
    assert result.returncode == 0, result.stderr


def test_coverage_phase_requires_coverage_attestation(tmp_path):
    prepare(tmp_path)
    result = invoke(tmp_path, "coverage", include_coverage=False)
    assert result.returncode != 0


@pytest.mark.parametrize(
    "drift",
    [
        "subject",
        "predicate",
        "workflow",
        "certificate_run",
        "provenance_run",
        "missing",
        "wrong_type",
        "coverage_predicate",
    ],
)
def test_refuses_wrong_verified_identity_or_content(tmp_path, drift):
    prepare(tmp_path)
    path = tmp_path / (
        "provenance.json"
        if drift == "provenance_run"
        else "coverage.json"
        if drift == "coverage_predicate"
        else "sbom.json"
    )
    data = json.loads(path.read_text())
    v = data[0]["verificationResult"]
    if drift == "subject":
        v["statement"]["subject"][0]["digest"]["sha256"] = "d" * 64
    elif drift == "predicate":
        v["statement"]["predicate"]["runAttempt"] = "1"
    elif drift == "workflow":
        v["signature"]["certificate"]["buildSignerDigest"] = "e" * 40
    elif drift == "certificate_run":
        v["signature"]["certificate"]["runInvocationURI"] = URI.removesuffix("2") + "1"
    elif drift == "provenance_run":
        v["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            URI.removesuffix("2") + "1"
        )
    elif drift == "missing":
        data = []
    elif drift == "coverage_predicate":
        v["statement"]["predicate"]["runAttempt"] = "1"
    else:
        v["statement"]["predicateType"] = QUAL_TYPE
    path.write_text(json.dumps(data))
    assert invoke(tmp_path).returncode != 0
