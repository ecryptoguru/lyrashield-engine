"""Causal gates for native sandbox assembly and immutable runtime binding."""

import runpy
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
        < pubnames.index("Sign selected runtime and qualified platform binding")
        < pubnames.index("Promote the smoke-qualified digest")
    )
    assert all(
        not step.get("continue-on-error") and not step.get("if") for step in publish["steps"]
    )
    attestations = [
        step for step in publish["steps"] if step.get("uses", "").startswith("actions/attest@")
    ]
    assert len(attestations) == 3
    assert all(step["with"].get("create-storage-record") is False for step in attestations)
    assembly = next(step for step in publish["steps"] if step.get("id") == "index")["run"]
    assert "scripts/verify_sandbox_platform_index.py" in assembly
    assert '"engineRevision"' in assembly and '"workflowRevision"' in assembly
    assert '"engineCiRun"' in assembly and '"engineCiAttempt"' in assembly
    assert '"platformIndexes"' in assembly and '"platformManifests"' in assembly


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
