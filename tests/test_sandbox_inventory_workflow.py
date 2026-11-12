"""Isolate untrusted acquisition and bind the signer to its exact receipt."""

# The subprocesses run fixed test fixtures and the workflow's own validator.
# ruff: noqa: S603
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts.bind_sandbox_inventory import VERIFIER_FILES, WORKFLOW
from scripts.verify_sandbox_package_inventory import SOURCE_FILES


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / WORKFLOW


def workflow():
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def named(job, name):
    return next(step for step in job["steps"] if step.get("name") == name)


def test_acquisition_is_read_only_and_signing_requires_the_exact_artifact():
    jobs = workflow()["jobs"]
    acquisition, publication = jobs["independent-inventory"], jobs["publish-inventory-attestation"]
    assert acquisition["runs-on"] == publication["runs-on"] == "ubuntu-24.04"
    assert acquisition["permissions"] == {"contents": "read", "actions": "read", "packages": "read"}
    assert publication["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    assert publication["needs"] == "independent-inventory"
    assert acquisition["if"] == publication["if"]
    assert all(
        not step.get("continue-on-error") and not step.get("if")
        for step in acquisition["steps"] + publication["steps"]
    )
    assert not any(
        "attest@" in step.get("uses", "") or "login-action@" in step.get("uses", "")
        for step in acquisition["steps"]
    )
    upload = next(step for step in acquisition["steps"] if step.get("id") == "upload")
    assert upload["uses"] == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    assert (
        upload["with"]["name"]
        == "independent-sandbox-inventory-${{ github.run_id }}-${{ github.run_attempt }}"
    )
    assert upload["with"]["if-no-files-found"] == "error"
    assert acquisition["outputs"] == {
        "artifact-id": "${{ steps.upload.outputs.artifact-id }}",
        "artifact-digest": "${{ steps.upload.outputs.artifact-digest }}",
        "receipt-digest": "${{ steps.receipt.outputs.digest }}",
    }
    download = next(
        step for step in publication["steps"] if "download-artifact@" in step.get("uses", "")
    )
    assert download["uses"] == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    assert (
        download["with"]["artifact-ids"] == "${{ needs.independent-inventory.outputs.artifact-id }}"
    )
    assert download["with"]["skip-decompress"] is True
    assert download["with"]["digest-mismatch"] == "error"
    steps = publication["steps"]
    assert steps.index(download) < steps.index(
        named(publication, "Validate transferred receipt before signing")
    )
    assert (
        steps.index(named(publication, "Validate transferred receipt before signing"))
        < steps.index(named(publication, "Authenticate inventory evidence publication"))
        < steps.index(named(publication, "Attest independently measured inventory"))
    )
    sign = named(publication, "Attest independently measured inventory")["with"]
    assert sign["subject-digest"] == "${{ inputs.index_digest }}"
    assert sign["predicate-path"] == "${{ runner.temp }}/independent-sandbox-inventory.json"
    assert sign["create-storage-record"] is False
    assert not any("acquire_sandbox_inventory" in step.get("run", "") for step in steps)


@pytest.fixture
def transfer(tmp_path):
    workspace = tmp_path / "source"
    workspace.mkdir()
    subprocess.run(
        ["/usr/bin/git", "init", "-q", "--initial-branch=main", str(workspace)], check=True
    )
    for name in set(VERIFIER_FILES) | set(SOURCE_FILES):
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture " + name + "\n")
    subprocess.run(["/usr/bin/git", "-C", str(workspace), "add", "."], check=True)
    subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )

    def git(*args):
        return (
            subprocess.check_output(["/usr/bin/git", "-C", str(workspace), *args]).decode().strip()
        )

    revision, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")

    def hashes(names):
        return {
            name: "sha256:" + hashlib.sha256((workspace / name).read_bytes()).hexdigest()
            for name in names
        }

    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_REPOSITORY": "ecryptoguru/lyrashield-engine",
        "GITHUB_REPOSITORY_ID": "1297157605",
        "GITHUB_REPOSITORY_OWNER_ID": "116722580",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": "ecryptoguru/lyrashield-engine/" + WORKFLOW + "@refs/heads/main",
        "GITHUB_SHA": revision,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "INDEX_DIGEST": "sha256:" + "a" * 64,
        "ENGINE_REVISION": revision,
        "PUBLISH_RUN_ID": "456",
        "PUBLISH_ATTEMPT": "1",
    }
    receipt = {
        "schema": "lyrashield.sandbox.independent-package-inventory.v1",
        "status": "bounded_scope_matched",
        "releaseQualified": False,
        "indexDigest": env["INDEX_DIGEST"],
        "engineRevision": revision,
        "workflowRevision": revision,
        "image": "ghcr.io/ecryptoguru/lyrashield-sandbox",
        "runId": env["PUBLISH_RUN_ID"],
        "runAttempt": env["PUBLISH_ATTEMPT"],
        "sourceFiles": hashes(SOURCE_FILES),
        "verifier": {
            "repositoryId": env["GITHUB_REPOSITORY_ID"],
            "ownerId": env["GITHUB_REPOSITORY_OWNER_ID"],
            "revision": revision,
            "tree": tree,
            "workflow": WORKFLOW,
            "runId": env["GITHUB_RUN_ID"],
            "runAttempt": env["GITHUB_RUN_ATTEMPT"],
            "sourceFiles": hashes(VERIFIER_FILES),
        },
    }
    return tmp_path, env, receipt


def run_validator(transfer, receipt, *, extra=False, altered_hash=None, raw_override=None):
    tmp_path, environment, _ = transfer
    raw = json.dumps(receipt).encode() if raw_override is None else raw_override
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("independent-sandbox-inventory.json", raw)
        if extra:
            zf.writestr("other", b"unexpected")
    data = archive.getvalue()
    directory = tmp_path / "inventory-transfer"
    directory.mkdir(exist_ok=True)
    (directory / "artifact.zip").write_bytes(data)
    env = {
        **environment,
        "ARTIFACT_DIGEST": hashlib.sha256(data).hexdigest(),
        "RECEIPT_DIGEST": hashlib.sha256(raw).hexdigest(),
    }
    if altered_hash:
        env[altered_hash] = "0" * 64
    script = (
        named(
            workflow()["jobs"]["publish-inventory-attestation"],
            "Validate transferred receipt before signing",
        )["run"]
        .split("python3 - <<'PY'\n", 1)[1]
        .rsplit("\nPY", 1)[0]
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_transferred_receipt_is_verified_before_writing_signing_input(transfer):
    result = run_validator(transfer, transfer[2])
    assert result.returncode == 0, result.stderr
    assert (transfer[0] / "independent-sandbox-inventory.json").is_file()


@pytest.mark.parametrize(
    "mutation",
    [
        "subject",
        "publisher_run",
        "attempt",
        "verifier_run",
        "verifier_attempt",
        "verifier_revision",
        "source",
        "publisher_source",
        "qualification",
        "archive_hash",
        "receipt_hash",
        "extra_file",
    ],
)
def test_transfer_mutations_fail_closed(transfer, mutation):
    receipt = copy.deepcopy(transfer[2])
    if mutation == "subject":
        receipt["indexDigest"] = "sha256:" + "b" * 64
    elif mutation == "publisher_run":
        receipt["runId"] = "999"
    elif mutation == "attempt":
        receipt["runAttempt"] = "2"
    elif mutation == "verifier_run":
        receipt["verifier"]["runId"] = "999"
    elif mutation == "verifier_attempt":
        receipt["verifier"]["runAttempt"] = "1"
    elif mutation == "verifier_revision":
        receipt["verifier"]["revision"] = "b" * 40
    elif mutation == "source":
        receipt["verifier"]["sourceFiles"].pop(VERIFIER_FILES[0])
    elif mutation == "publisher_source":
        receipt["sourceFiles"][SOURCE_FILES[0]] = "sha256:" + "0" * 64
    elif mutation == "qualification":
        receipt["releaseQualified"] = True
    result = run_validator(
        transfer,
        receipt,
        extra=mutation == "extra_file",
        altered_hash={"archive_hash": "ARTIFACT_DIGEST", "receipt_hash": "RECEIPT_DIGEST"}.get(
            mutation
        ),
    )
    assert result.returncode != 0
    expected = {
        "subject": "publication selector mismatch",
        "publisher_run": "publication selector mismatch",
        "attempt": "publication selector mismatch",
        "verifier_run": "verifier identity mismatch",
        "verifier_attempt": "verifier identity mismatch",
        "verifier_revision": "verifier identity mismatch",
        "source": "verifier source mismatch",
        "publisher_source": "publisher source mismatch",
        "qualification": "receipt is not a bounded result",
        "archive_hash": "artifact digest mismatch",
        "receipt_hash": "receipt digest mismatch",
        "extra_file": "unexpected artifact contents",
    }
    assert expected[mutation] in result.stderr
    assert not (transfer[0] / "independent-sandbox-inventory.json").exists()


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("oversized", "receipt size invalid"),
        ("duplicate", "duplicate"),
    ],
)
def test_oversized_or_ambiguous_receipt_is_rejected(transfer, case, error):
    raw = b" " * (16 * 1024**2 + 1) if case == "oversized" else b'{"schema":"one","schema":"two"}'
    result = run_validator(transfer, transfer[2], raw_override=raw)
    assert result.returncode != 0
    assert error in result.stderr.lower()
    assert not (transfer[0] / "independent-sandbox-inventory.json").exists()


def test_protected_go_installation_matches_verifier_and_checks_ancestry():
    acquisition = workflow()["jobs"]["independent-inventory"]
    command = named(acquisition, "Authenticate and independently verify exact publication")["run"]
    go_tool = "/usr/local/lib/lyrashield-inventory/go/bin/go"
    assert "--go-tool " + go_tool in command
    installer = (ROOT / "scripts/prepare_independent_inventory_tools.sh").read_text()
    assert "for parent in / /usr /usr/local /usr/local/lib" in installer
    assert "trusted_tool(Path(" in installer
    assert "/opt/lyrashield-inventory" not in installer
