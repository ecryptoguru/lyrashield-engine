"""Causal gates for native sandbox assembly and immutable runtime binding."""

import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/verify_sandbox_platform_index.py"))
VERIFY = MODULE["verify"]
MEDIA = "application/vnd.oci.image.index.v1+json"


def index(*descriptors):
    return {"schemaVersion": 2, "mediaType": MEDIA, "manifests": list(descriptors)}


def descriptor(arch, value, os_name="linux"):
    return {
        "digest": "sha256:" + value * 64,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "size": 100,
        "platform": {"architecture": arch, "os": os_name},
    }


def test_exact_native_children_are_required_in_the_combined_index():
    amd, arm, attestation = (
        descriptor("amd64", "a"),
        descriptor("arm64", "b"),
        descriptor("unknown", "c", "unknown"),
    )
    attestation["annotations"] = {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": amd["digest"],
    }
    assert VERIFY(index(amd, attestation), index(arm), index(arm, amd, attestation)) == {
        "amd64": amd["digest"],
        "arm64": arm["digest"],
    }
    for altered in (
        index(amd),
        index(amd, descriptor("arm64", "d")),
        index(amd, arm, arm),
        index(amd, arm, descriptor("s390x", "e")),
    ):
        with pytest.raises(ValueError):
            VERIFY(index(amd), index(arm), altered)
    with pytest.raises(ValueError):
        VERIFY(index(amd, arm), index(arm), index(amd, arm))
    foreign_attestation = deepcopy(attestation)
    foreign_attestation["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError):
        VERIFY(index(amd), index(arm), index(amd, arm, foreign_attestation))
    with pytest.raises(ValueError):
        VERIFY(index(amd), index(arm), index(amd, arm, attestation))
    with pytest.raises(ValueError):
        VERIFY(index(amd, attestation), index(arm), index(amd, arm))
    with pytest.raises(ValueError):
        VERIFY(index(amd, attestation), index(arm), index(amd, arm, attestation, attestation))
    with pytest.raises(ValueError):
        VERIFY(index(amd), index(arm), {"mediaType": "application/json", "manifests": [amd, arm]})


@pytest.mark.parametrize("field", ["size", "mediaType", "platform_constraint"])
def test_combined_index_preserves_qualified_runnable_descriptor_metadata(field):
    amd, arm = descriptor("amd64", "a"), descriptor("arm64", "b")
    changed = deepcopy(arm)
    if field == "size":
        changed["size"] += 1
    elif field == "mediaType":
        changed["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
    else:
        changed["platform"]["os.features"] = ["unexpected"]
    with pytest.raises(ValueError):
        VERIFY(index(amd), index(arm), index(amd, changed))


def test_buildx_arm64_v8_normalization_and_annotation_removal_are_supported():
    amd, arm = descriptor("amd64", "a"), descriptor("arm64", "b")
    arm["platform"]["variant"] = "v8"
    arm["annotations"] = {"example": "native metadata"}
    combined_arm = deepcopy(arm)
    combined_arm["platform"].pop("variant")
    combined_arm.pop("annotations")
    assert VERIFY(index(amd), index(arm), index(amd, combined_arm))["arm64"] == arm["digest"]


def assert_workflow_contract(workflow):
    jobs = workflow["jobs"]
    resolve, build, publish = jobs["resolve"], jobs["build"], jobs["publish"]
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert build["permissions"] == {"contents": "read", "packages": "write"}
    assert publish["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    assert build["needs"] == "resolve"
    assert set(publish["needs"]) == {"resolve", "build"}
    matrix = build["strategy"]["matrix"]["include"]
    assert matrix == [
        {"arch": "amd64", "runner": "ubuntu-24.04"},
        {"arch": "arm64", "runner": "ubuntu-24.04-arm"},
    ]
    assert build["runs-on"] == "${{ matrix.runner }}"
    assert build["name"] == "Build sandbox (${{ matrix.arch }})"
    assert publish["name"] == "Publish qualified sandbox index"
    resolve_source = next(step for step in resolve["steps"] if step.get("id") == "source")["run"]
    for required in (
        "git merge-base --is-ancestor",
        "actions/workflows/ci.yml/runs",
        '.head_branch == "main"',
        '.conclusion == "success"',
        "^[0-9a-f]{40}$",
        'qualified_historical="992b3d9df696753c7b62a31ea58f1ca5d21055c1"',
        '"$revision" == "$GITHUB_SHA" || "$revision" == "$qualified_historical"',
        "attempt: .run_attempt",
    ):
        assert required in resolve_source
    steps = build["steps"]
    names = [step.get("name", "") for step in steps]
    first = names.index("Build and push an unqualified native candidate")
    assert (
        first
        < names.index("Smoke the exact native candidate digest")
        < names.index("Audit byte-bound Go application coordinates")
        < names.index("Record qualified native digest")
    )
    assert all(not step.get("continue-on-error") and not step.get("if") for step in steps[first:])
    build_action = steps[first]
    assert build_action["with"]["platforms"] == "linux/${{ matrix.arch }}"
    assert (
        "github.run_id" in build_action["with"]["tags"]
        and "github.run_attempt" in build_action["with"]["tags"]
    )
    upload = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert (
        "matrix.arch" in upload["with"]["name"] and "github.run_attempt" in upload["with"]["name"]
    )
    pubnames = [step.get("name", "") for step in publish["steps"]]
    assert (
        pubnames.index("Assemble and verify qualified platform index")
        < pubnames.index("Generate per-platform SPDX SBOMs")
        < pubnames.index("Attach and validate complete SBOM artifact")
        < pubnames.index("Sign selected runtime and qualified platform binding")
        < pubnames.index("Sign per-platform SBOM binding")
        < pubnames.index("Verify signed sandbox publication")
        < pubnames.index("Install checksum-pinned Go metadata inspector")
        < pubnames.index("Qualify bounded SBOM coverage on both native images")
        < pubnames.index("Assemble bounded SBOM coverage predicate")
        < pubnames.index("Sign bounded SBOM coverage qualification")
        < pubnames.index("Verify signed sandbox publication coverage")
        < pubnames.index("Upload bounded SBOM coverage evidence")
        < pubnames.index("Hold promotion pending independent package coverage")
        < pubnames.index("Promote the smoke-qualified digest")
    )
    assert all(
        not step.get("continue-on-error") and not step.get("if") for step in publish["steps"]
    )
    attestations = [
        step for step in publish["steps"] if step.get("uses", "").startswith("actions/attest@")
    ]
    assert len(attestations) == 4
    sbom_sign = next(
        step for step in attestations if step.get("name") == "Sign per-platform SBOM binding"
    )
    assert (
        sbom_sign["with"]["predicate-type"]
        == "https://lyrashieldai.com/attestations/sandbox-sbom/v1"
    )
    assert sbom_sign["with"]["predicate-path"] == "evidence/sbom-predicate.json"
    assert sbom_sign["with"]["subject-digest"] == "${{ steps.index.outputs.digest }}"
    coverage_sign = next(
        step
        for step in attestations
        if step.get("name") == "Sign bounded SBOM coverage qualification"
    )
    assert (
        coverage_sign["with"]["predicate-type"]
        == "https://lyrashieldai.com/attestations/sandbox-sbom-coverage/v1"
    )
    assert coverage_sign["with"]["predicate-path"] == "evidence/coverage/coverage-predicate.json"
    assert coverage_sign["with"]["subject-digest"] == "${{ steps.index.outputs.digest }}"
    assert all(step["with"].get("create-storage-record") is False for step in attestations)
    assembly = next(step for step in publish["steps"] if step.get("id") == "index")["run"]
    assert "scripts/verify_sandbox_platform_index.py" in assembly
    assert '"engineRevision"' in assembly and '"workflowRevision"' in assembly
    assert '"engineCiRun"' in assembly and '"engineCiAttempt"' in assembly
    assert '"platformIndexes"' in assembly and '"platformManifests"' in assembly
    publication_verify = next(
        step for step in publish["steps"] if step.get("name") == "Verify signed sandbox publication"
    )["run"]
    assert "--phase publication" in publication_verify
    assert "--coverage" not in publication_verify
    coverage_verify = next(
        step
        for step in publish["steps"]
        if step.get("name") == "Verify signed sandbox publication coverage"
    )["run"]
    assert "--phase coverage" in coverage_verify


@pytest.mark.parametrize(
    ("status", "conclusion", "accepted"),
    [
        ("completed", "success", True),
        ("completed", "failure", False),
        ("completed", "cancelled", False),
        ("completed", "skipped", False),
        ("completed", "neutral", False),
        ("in_progress", None, False),
        ("queued", None, False),
        ("waiting", None, False),
    ],
)
def test_native_source_resolver_requires_latest_ci_attempt(tmp_path, status, conclusion, accepted):
    """Run the shipped resolver with an older success and a newer authoritative run."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-sandbox.yml").read_text())
    resolver = next(s for s in workflow["jobs"]["resolve"]["steps"] if s.get("id") == "source")[
        "run"
    ]
    revision = "a" * 40
    base = {"head_sha": revision, "head_branch": "main", "event": "push"}
    runs = [
        {**base, "id": 1, "run_attempt": 1, "status": "completed", "conclusion": "success"},
        {**base, "id": 2, "run_attempt": 3, "status": status, "conclusion": conclusion},
        {
            **base,
            "id": 99,
            "run_attempt": 1,
            "head_branch": "feature",
            "status": "completed",
            "conclusion": "success",
        },
    ]
    fixture = tmp_path / "runs.json"
    fixture.write_text(json.dumps({"workflow_runs": runs}))
    tools = tmp_path / "bin"
    tools.mkdir()
    # These mocks only supply remote/source observations; jq and the complete
    # production resolver execute unchanged. No network or real Git mutation.
    for name, script in {
        "gh": '#!/bin/bash\n[[ "$*" != *"status="* ]] || exit 90\ncat "$CI_FIXTURE"\n',
        "git": '#!/bin/bash\nif [[ "$1" == rev-parse ]]; then echo "$GITHUB_SHA"; fi\n',
    }.items():
        path = tools / name
        path.write_text(script)
        path.chmod(0o700)
    output = tmp_path / "output"
    result = subprocess.run(  # noqa: S603 - fixed shell and exact repository resolver with fake observations
        ["/bin/bash", "-euo", "pipefail", "-c", resolver],
        env={
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "GITHUB_SHA": revision,
            "GITHUB_REPOSITORY": "ecryptoguru/lyrashield-engine",
            "GITHUB_OUTPUT": str(output),
            "REQUESTED_RUNTIME": revision,
            "CI_FIXTURE": str(fixture),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if accepted:
        assert result.returncode == 0, result.stderr
        assert output.read_text() == f"revision={revision}\nci_run=2\nci_attempt=3\n"
    else:
        assert result.returncode != 0
        assert not output.exists()


def test_native_workflow_binds_source_and_cannot_promote_before_qualification():
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-sandbox.yml").read_text())
    assert_workflow_contract(workflow)
    for drift in ("no_smoke", "skip_audit", "wrong_arch", "early_publish", "unqualified_source"):
        altered = deepcopy(workflow)
        if drift == "no_smoke":
            altered["jobs"]["build"]["steps"] = [
                s
                for s in altered["jobs"]["build"]["steps"]
                if s.get("name") != "Smoke the exact native candidate digest"
            ]
        elif drift == "skip_audit":
            next(
                s
                for s in altered["jobs"]["build"]["steps"]
                if s.get("name") == "Audit byte-bound Go application coordinates"
            )["if"] = "false"
        elif drift == "wrong_arch":
            altered["jobs"]["build"]["strategy"]["matrix"]["include"][1]["runner"] = "ubuntu-24.04"
        elif drift == "early_publish":
            altered["jobs"]["publish"]["needs"] = ["resolve"]
        else:
            next(s for s in altered["jobs"]["resolve"]["steps"] if s.get("id") == "source")[
                "run"
            ] = "echo unsafe"
        with pytest.raises((AssertionError, ValueError)):
            assert_workflow_contract(altered)


def test_missing_independent_coverage_keeps_promotion_held():
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-sandbox.yml").read_text())
    hold = next(
        step
        for step in workflow["jobs"]["publish"]["steps"]
        if step.get("name") == "Hold promotion pending independent package coverage"
    )
    assert not hold.get("if") and not hold.get("continue-on-error")
    result = subprocess.run(  # noqa: S603 - fixed shell and reviewed workflow body
        ["/bin/bash", "-euo", "pipefail", "-c", hold["run"]],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_coverage_qualification_uses_created_containers_and_bounded_exports_before_hold():
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-sandbox.yml").read_text())
    steps = workflow["jobs"]["publish"]["steps"]
    install = next(
        step
        for step in steps
        if step.get("name") == "Install checksum-pinned Go metadata inspector"
    )
    assert "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40" in install["run"]
    assert "go1.27.3" in install["run"]
    qualify = next(
        step
        for step in steps
        if step.get("name") == "Qualify bounded SBOM coverage on both native images"
    )
    assert "for arch in amd64 arm64" in qualify["run"]
    assert "docker create" in qualify["run"]
    assert "docker run" not in qualify["run"]
    assert "timeout 900" in qualify["run"]
    assert "8589934593" in qualify["run"]
    assert "docker export" in qualify["run"]
    # The gate must run as a module: it imports scripts.* and script-style
    # invocation would fail with ModuleNotFoundError before producing receipts.
    assert "python3 -m scripts.check_sandbox_sbom_coverage platform" in qualify["run"]
    assert "platformManifests" in qualify["run"]
    assert "--container-id" in qualify["run"]
    assert "--expected-rootfs-digest" in qualify["run"]
    assert "--spdx" in qualify["run"]
    assemble = next(
        step for step in steps if step.get("name") == "Assemble bounded SBOM coverage predicate"
    )
    assert assemble["run"].count("aggregate") == 1
    assert "python3 -m scripts.check_sandbox_sbom_coverage aggregate" in assemble["run"]
    assert "--applications" in assemble["run"]
    assert "--expected-go-tool-digest" in assemble["run"]
    assert "--docker-server" in assemble["run"]
    coverage_verify = next(
        step for step in steps if step.get("name") == "Verify signed sandbox publication coverage"
    )
    assert "sandbox-sbom-coverage/v1" in coverage_verify["run"]
    assert "--coverage" in coverage_verify["run"]
    assert "--expected-coverage" in coverage_verify["run"]
    upload = next(
        step for step in steps if step.get("name") == "Upload bounded SBOM coverage evidence"
    )
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["path"] == "evidence/coverage"
    assert upload["with"]["if-no-files-found"] == "error"
    names = [step.get("name") for step in steps]
    assert names.index("Upload bounded SBOM coverage evidence") < names.index(
        "Hold promotion pending independent package coverage"
    )


def run_publisher_step(tmp_path, name, drift=""):
    """Run the real shell/helper; only registry operations use a local CLI fixture."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    payloads = {
        "amd64": json.dumps(index(descriptor("amd64", "a"))).encode(),
        "arm64": json.dumps(index(descriptor("arm64", "b"))).encode(),
        "combined": json.dumps(index(descriptor("amd64", "a"), descriptor("arm64", "b"))).encode(),
    }
    digests = {key: "sha256:" + hashlib.sha256(raw).hexdigest() for key, raw in payloads.items()}
    for arch in ("amd64", "arm64"):
        (evidence / arch).mkdir()
        (evidence / arch / "digest").write_text(digests[arch])
    metadata = {
        "containerimage.descriptor": {
            "mediaType": MEDIA,
            "digest": digests["combined"],
            "size": len(payloads["combined"]),
        },
        "image.name": "ghcr.io/fixture/sandbox",
    }
    # Exact `--format '{{json .Manifest}}'` shape: digest/size are added fields,
    # unlike --raw registry bytes and unlike imagetools-create metadata.
    formatted = {**json.loads(payloads["combined"]), **metadata["containerimage.descriptor"]}
    descriptor_changes = {
        "zero_size": ("size", 0),
        "negative_size": ("size", -1),
        "bool_size": ("size", True),
        "wrong_size": ("size", 1),
        "size_shape": ("size", "123"),
        "wrong_media": ("mediaType", "application/json"),
        "media_type_shape": ("mediaType", []),
        "digest_shape": ("digest", [digests["combined"]]),
        "malformed_digest": ("digest", "not-a-digest"),
    }
    if drift == "appended_lf":
        payloads = {key: raw + b"\n" for key, raw in payloads.items()}
    elif drift == "native_bytes":
        payloads["amd64"] += b"\n\n"
    elif drift == "combined_bytes":
        payloads["combined"] += b"\n\n"
    elif drift == "formatted_as_raw":
        payloads["combined"] = json.dumps(formatted).encode()
    elif drift == "legacy_metadata":
        metadata = {"containerimage.digest": digests["combined"]}
    elif drift == "conflicting_legacy":
        metadata["containerimage.digest"] = "sha256:" + "f" * 64
    elif drift in descriptor_changes:
        field, value = descriptor_changes[drift]
        metadata["containerimage.descriptor"][field] = value
    elif drift == "descriptor_shape":
        metadata["containerimage.descriptor"] = []
    elif drift == "promoted_digest":
        formatted["digest"] = "sha256:" + "f" * 64
    registry = {
        "digests": digests,
        "metadata": metadata,
        "formatted": formatted,
        "payloads": {key: raw.decode() for key, raw in payloads.items()},
    }
    (tmp_path / "registry.json").write_text(json.dumps(registry))
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(ROOT / "scripts/verify_sandbox_platform_index.py", scripts)
    docker = tmp_path / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        r"""
import json, pathlib, sys
p=pathlib.Path.cwd(); s=json.loads((p/'registry.json').read_text()); a=sys.argv[1:]
assert a[:2]==['buildx','imagetools'],a
image='ghcr.io/fixture/sandbox'
if a[2]=='create':
    if '--metadata-file' in a:
        assert a[a.index('--tag')+1]==image+':candidate-index-42-1'
        assert a[-2:]==[image+'@'+s['digests']['amd64'],image+'@'+s['digests']['arm64']]
        pathlib.Path(a[a.index('--metadata-file')+1]).write_text(json.dumps(s['metadata']))
    else:
        assert a[-1]==image+'@'+s['digests']['combined']
elif a[2]=='inspect':
    if '--raw' in a:
        key=next(k for k,v in s['digests'].items() if a[3]==image+'@'+v)
        sys.stdout.write(s['payloads'][key])
    else:
        assert a[3] in [image+':sandbox-v-test',image+':'+'e'*40]
        assert a[4:]==['--format','{{json .Manifest}}'],a
        print(json.dumps(s['formatted']))
else: raise AssertionError(a)
"""
    )
    docker.chmod(0o700)
    output = tmp_path / "output"
    output.write_text("")
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-sandbox.yml").read_text())
    code = next(
        step["run"] for step in workflow["jobs"]["publish"]["steps"] if step.get("name") == name
    )
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(  # noqa: S603 - exact repository shell with private fake registry CLI
        [bash, "-e", "-c", code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "REGISTRY": "ghcr.io",
            "IMAGE_NAME": "fixture/sandbox",
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "d" * 40,
            "GITHUB_OUTPUT": str(output),
            "RUNTIME_REVISION": "e" * 40,
            "ENGINE_CI_RUN": "500",
            "ENGINE_CI_ATTEMPT": "2",
            "RELEASE_TAG": "sandbox-v-test",
            "DIGEST": digests["combined"],
        },
    )
    return result, output.read_text(), evidence, digests


@pytest.mark.parametrize("drift", ["", "appended_lf"])
def test_assembly_accepts_imagetools_create_descriptor_metadata(tmp_path, drift):
    result, output, evidence, digests = run_publisher_step(
        tmp_path, "Assemble and verify qualified platform index", drift
    )
    assert result.returncode == 0, result.stderr
    assert output == f"digest={digests['combined']}\n"
    assert (
        json.loads((evidence / "qualification.json").read_text())["indexDigest"]
        == digests["combined"]
    )


@pytest.mark.parametrize(
    "drift",
    [
        "native_bytes",
        "combined_bytes",
        "formatted_as_raw",
        "legacy_metadata",
        "conflicting_legacy",
        "zero_size",
        "negative_size",
        "bool_size",
        "wrong_size",
        "wrong_media",
        "malformed_digest",
        "media_type_shape",
        "digest_shape",
        "size_shape",
        "descriptor_shape",
    ],
)
def test_assembly_rejects_unbound_registry_bytes_and_invalid_create_metadata(tmp_path, drift):
    result, output, evidence, _ = run_publisher_step(
        tmp_path, "Assemble and verify qualified platform index", drift
    )
    assert result.returncode != 0
    assert output == ""
    assert not (evidence / "qualification.json").exists()


def test_promotion_reads_documented_formatted_manifest_digest(tmp_path):
    result, _, _, _ = run_publisher_step(tmp_path, "Promote the smoke-qualified digest")
    assert result.returncode == 0, result.stderr


def test_promotion_refuses_changed_formatted_tag_digest(tmp_path):
    result, _, _, _ = run_publisher_step(
        tmp_path, "Promote the smoke-qualified digest", "promoted_digest"
    )
    assert result.returncode != 0
