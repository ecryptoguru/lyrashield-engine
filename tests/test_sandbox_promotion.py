"""Strict promotion selectors, evidence transport and registry acknowledgement."""

import copy
import io
import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import qualify_sandbox_promotion as gate


def selection():
    return {
        "indexDigest": "sha256:" + "a" * 64,
        "engineRevision": "b" * 40,
        "publisherRunId": "42",
        "publisherAttempt": "1",
        "inventoryRunId": "43",
        "inventoryAttempt": "1",
        "verifierRevision": "c" * 40,
        "artifactId": "44",
        "artifactDigest": "sha256:" + "d" * 64,
        "receiptDigest": "sha256:" + "e" * 64,
    }


def test_selector_accepts_only_full_immutable_identities():
    value = selection()
    assert gate.selector(value) == value
    for field, wrong in [
        ("indexDigest", "main"),
        ("engineRevision", "main"),
        ("artifactId", "../44"),
        ("inventoryAttempt", "0"),
    ]:
        changed = {**value, field: wrong}
        with pytest.raises(ValueError):
            gate.selector(changed)
    with pytest.raises(ValueError):
        gate.selector({**value, "passed": True})


def test_latest_current_main_ci_cannot_fall_back_to_old_success(monkeypatch):
    revision = "b" * 40
    success = {
        "id": 40,
        "run_attempt": 1,
        "head_sha": revision,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }
    records = {"workflow_runs": [success]}
    monkeypatch.setattr(gate, "api", lambda _path: json.dumps(records).encode())
    assert gate.qualified_ci(revision) == {"runId": "40", "runAttempt": "1"}
    records["workflow_runs"].append(
        {**success, "id": 41, "status": "in_progress", "conclusion": None}
    )
    with pytest.raises(ValueError, match="latest main CI"):
        gate.qualified_ci(revision)


def test_current_source_checks_the_executed_closure_and_fixed_workflow(tmp_path, monkeypatch):
    revision = "b" * 40
    environment = {
        "GITHUB_REPOSITORY": gate.REPOSITORY,
        "GITHUB_REPOSITORY_ID": "1297157605",
        "GITHUB_REPOSITORY_OWNER_ID": "116722580",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": gate.REPOSITORY + "/" + gate.PROMOTION_WORKFLOW + "@refs/heads/main",
        "GITHUB_SHA": revision,
    }
    for source in (
        *gate.VERIFIER_FILES,
        gate.PROMOTION_WORKFLOW,
        "scripts/qualify_sandbox_promotion.py",
    ):
        path = tmp_path / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"source")
    monkeypatch.setattr(
        gate,
        "git",
        lambda _repository, *arguments: (
            revision.encode() if arguments[0] == "rev-parse" else b"source"
        ),
    )
    monkeypatch.setattr(
        gate, "api", lambda _path: json.dumps({"object": {"sha": revision}}).encode()
    )
    assert gate.current_source(tmp_path, environment) == revision
    (tmp_path / "scripts/qualify_sandbox_promotion.py").write_bytes(b"changed")
    with pytest.raises(ValueError, match="executed promotion source differs"):
        gate.current_source(tmp_path, environment)
    with pytest.raises(ValueError, match="workflow identity"):
        gate.current_source(tmp_path, {**environment, "GITHUB_REF": "refs/heads/feature"})


def test_independent_run_requires_both_real_successful_jobs(monkeypatch):
    value = selection()
    run = {
        "id": 43,
        "run_attempt": 1,
        "head_sha": value["verifierRevision"],
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": gate.WORKFLOW,
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": 1297157605},
        "head_repository": {"id": 1297157605},
    }
    jobs = {
        "total_count": 2,
        "jobs": [
            {
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "steps": [{"status": "completed", "conclusion": "success"}],
            }
            for name in ("independent-inventory", "publish-inventory-attestation")
        ],
    }
    monkeypatch.setattr(
        gate,
        "api",
        lambda path: json.dumps(jobs if path.endswith("per_page=100") else run).encode(),
    )
    gate.inventory_run(value)
    run["run_attempt"] = 2
    with pytest.raises(ValueError, match="identity"):
        gate.inventory_run(value)
    run["run_attempt"] = 1
    jobs["jobs"][0]["steps"][0]["conclusion"] = "skipped"
    with pytest.raises(ValueError, match="step unsuccessful"):
        gate.inventory_run(value)


def test_artifact_reader_hashes_real_zip_and_rejects_substitution(monkeypatch):
    value = selection()
    receipt = b'{"bounded":true}'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("independent-sandbox-inventory.json", receipt)
    raw = archive.getvalue()
    value.update(artifactDigest=gate.sha256(raw), receiptDigest=gate.sha256(receipt))
    metadata = {
        "id": 44,
        "expired": False,
        "name": "independent-sandbox-inventory-43-1",
        "digest": gate.sha256(raw),
        "size_in_bytes": len(raw),
        "workflow_run": {
            "id": 43,
            "head_sha": value["verifierRevision"],
            "head_branch": "main",
            "repository_id": 1297157605,
            "head_repository_id": 1297157605,
        },
    }
    monkeypatch.setattr(
        gate,
        "api",
        lambda path, _maximum=None: raw if path.endswith("/zip") else json.dumps(metadata).encode(),
    )
    assert gate.inventory_artifact(value) == {"bounded": True}
    metadata["workflow_run"]["head_repository_id"] = 1
    with pytest.raises(ValueError, match="identity differs"):
        gate.inventory_artifact(value)
    metadata["workflow_run"]["head_repository_id"] = 1297157605
    raw = raw[:-1] + bytes([raw[-1] ^ 1])
    with pytest.raises(ValueError, match="archive differs"):
        gate.inventory_artifact(value)


def test_attestation_policy_requires_exact_independent_certificate_and_body(monkeypatch):
    value = selection()
    receipt = {"bounded": True}
    certificate = {
        "issuer": "https://token.actions.githubusercontent.com",
        "buildSignerURI": "https://github.com/"
        + gate.REPOSITORY
        + "/"
        + gate.WORKFLOW
        + "@refs/heads/main",
        "buildSignerDigest": value["verifierRevision"],
        "sourceRepositoryURI": "https://github.com/" + gate.REPOSITORY,
        "sourceRepositoryDigest": value["verifierRevision"],
        "sourceRepositoryRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": "https://github.com/" + gate.REPOSITORY + "/actions/runs/43/attempts/1",
    }
    result = [
        {
            "verificationResult": {
                "signature": {"certificate": certificate},
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": gate.INVENTORY_TYPE,
                    "subject": [{"name": gate.IMAGE, "digest": {"sha256": "a" * 64}}],
                    "predicate": receipt,
                },
            }
        }
    ]

    def verified_stdout(command, _limit, _timeout):
        assert "--bundle-from-oci" in command and "--deny-self-hosted-runners" in command
        assert command[command.index("--signer-digest") + 1] == value["verifierRevision"]
        assert (
            command[command.index("--signer-workflow") + 1] == gate.REPOSITORY + "/" + gate.WORKFLOW
        )
        return json.dumps(result).encode()

    monkeypatch.setattr(gate, "bounded_command", verified_stdout)
    gate.authenticate_inventory(value, receipt)
    certificate["runInvocationURI"] = (
        "https://github.com/" + gate.REPOSITORY + "/actions/runs/45/attempts/1"
    )
    with pytest.raises(ValueError, match="attestation missing"):
        gate.authenticate_inventory(value, receipt)
    certificate["runInvocationURI"] = (
        "https://github.com/" + gate.REPOSITORY + "/actions/runs/43/attempts/1"
    )
    result.append(copy.deepcopy(result[0]))
    with pytest.raises(ValueError, match="ambiguous"):
        gate.authenticate_inventory(value, receipt)


@pytest.mark.parametrize("changed_engine_ci", [False, True])
def test_qualification_retains_and_refreshes_engine_ci(tmp_path, monkeypatch, changed_engine_ci):
    value = selection()
    source = "f" * 40
    source_ci = {"runId": "46", "runAttempt": "1"}
    engine_ci = {"runId": "40", "runAttempt": "1"}
    engine_reads = []

    def latest_ci(revision):
        if revision == source:
            return source_ci
        assert revision == value["engineRevision"]
        engine_reads.append(1)
        return (
            {**engine_ci, "runAttempt": "2"}
            if changed_engine_ci and len(engine_reads) > 1
            else engine_ci
        )

    class RegistryStub:
        def fetch(self, _kind, _digest, destination, *, limit):
            assert limit == 65536
            destination.write_bytes(b"{}")

    platforms = {
        arch: "sha256:" + str(index) * 64 for index, arch in enumerate(("amd64", "arm64"), 1)
    }
    predicate = {
        "engineRevision": value["engineRevision"],
        "workflowRevision": value["engineRevision"],
        "runId": value["publisherRunId"],
        "runAttempt": value["publisherAttempt"],
        "indexDigest": value["indexDigest"],
        "platformManifests": platforms,
    }
    monkeypatch.setattr(gate, "trusted_tool", lambda *_args: None)
    monkeypatch.setattr(gate, "current_source", lambda *_args: source)
    monkeypatch.setattr(gate, "qualified_ci", latest_ci)
    monkeypatch.setattr(gate, "git", lambda *_args: gate.PUBLISHER_WORKFLOW_BLOB.encode())
    monkeypatch.setattr(gate, "inventory_run", lambda *_args: None)
    monkeypatch.setattr(gate, "inventory_artifact", lambda *_args: {})
    monkeypatch.setattr(gate, "authenticate_inventory", lambda *_args: None)
    monkeypatch.setattr(gate, "Registry", RegistryStub)
    monkeypatch.setattr(
        gate,
        "authenticate",
        lambda *_args: dict.fromkeys(
            (gate.QUAL_TYPE, gate.SBOM_TYPE, gate.COVERAGE_TYPE), predicate
        ),
    )
    monkeypatch.setattr(
        gate,
        "platform_manifests",
        lambda *_args: ({arch: (digest,) for arch, digest in platforms.items()}, None),
    )
    monkeypatch.setattr(gate, "fetch_receipts", lambda *_args: None)
    monkeypatch.setattr(gate, "validate_receipt", lambda *_args: None)
    if changed_engine_ci:
        with pytest.raises(ValueError, match="engine CI changed during qualification"):
            gate.qualify(value, tmp_path, {}, tmp_path)
    else:
        result = gate.qualify(value, tmp_path, {}, tmp_path)
        assert result["engineCi"] == engine_ci and result["ci"] == source_ci
    assert len(engine_reads) == 2


def test_promotion_requires_exact_registry_ack_and_fresh_main_before_mutation(monkeypatch):
    value = selection()
    result = {
        "selector": value,
        "promotionSource": "f" * 40,
        "ci": {"runId": "46", "runAttempt": "1"},
        "engineCi": {"runId": "40", "runAttempt": "1"},
        "packageCoverage": "bounded_scope_matched",
        "productionRuntimeQualified": False,
    }
    calls = []
    answers = iter((False, True))
    monkeypatch.setattr(gate, "Registry", object)
    monkeypatch.setattr(gate, "qualified_reference", lambda _registry, _value: next(answers))
    monkeypatch.setattr(
        gate, "current_source", lambda _repository, _environment: result["promotionSource"]
    )
    monkeypatch.setattr(
        gate,
        "qualified_ci",
        lambda revision: (
            result["ci"] if revision == result["promotionSource"] else result["engineCi"]
        ),
    )
    monkeypatch.setattr(
        gate, "bounded_command", lambda command, _limit, _timeout: calls.append(command)
    )
    promoted = gate.promote(result, Path("/repo"), {})
    assert promoted["status"] == "qualified_reference_recorded"
    assert promoted["productionRuntimeQualified"] is False
    assert calls == [
        [
            "/usr/bin/docker",
            "buildx",
            "imagetools",
            "create",
            "--tag",
            gate.IMAGE + ":" + value["engineRevision"],
            gate.IMAGE + "@" + value["indexDigest"],
        ]
    ]
    answers = iter((False,))
    monkeypatch.setattr(
        gate,
        "qualified_ci",
        lambda revision: (
            result["ci"]
            if revision == result["promotionSource"]
            else {**result["engineCi"], "runAttempt": "2"}
        ),
    )
    with pytest.raises(ValueError, match="engine CI changed before promotion"):
        gate.promote(result, Path("/repo"), {})
    assert len(calls) == 1
    answers = iter((False,))
    monkeypatch.setattr(gate, "current_source", lambda _repository, _environment: "0" * 40)
    with pytest.raises(ValueError, match="main changed before"):
        gate.promote(result, Path("/repo"), {})
    assert len(calls) == 1


def test_conflicting_commit_tag_is_not_overwritten():
    class Opener:
        def open(self, _request, timeout):
            assert timeout == 30
            return io.BytesIO(b"another-index")

    registry = SimpleNamespace(authorization="ephemeral-test-token", opener=Opener())
    with pytest.raises(ValueError, match="revision tag conflicts"):
        gate.qualified_reference(registry, selection())


def test_unacknowledged_mutation_retains_pending_and_unknown_without_replay(tmp_path, monkeypatch):
    receipt = {
        "selector": selection(),
        "packageCoverage": "bounded_scope_matched",
        "productionRuntimeQualified": False,
    }
    destination = tmp_path / "receipt.json"
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("SANDBOX_PROMOTION_SELECTOR", json.dumps(selection()))
    monkeypatch.setattr(
        gate.sys,
        "argv",
        ["qualify_sandbox_promotion.py", "--promote", "--output", str(destination)],
    )
    monkeypatch.setattr(gate, "qualify", lambda *_args: receipt)
    attempts = []

    def lost_acknowledgement(*_args):
        attempts.append(1)
        raise RuntimeError("Lost registry acknowledgement")

    monkeypatch.setattr(gate, "promote", lost_acknowledgement)
    with pytest.raises(RuntimeError, match="Lost registry"):
        gate.main()
    pending = destination.with_name(destination.name + ".pending.json").read_bytes()
    outcome = json.loads(destination.with_name(destination.name + ".unconfirmed.json").read_bytes())
    assert outcome["outcome"] == "UNKNOWN" and outcome["pendingReceiptDigest"] == gate.sha256(
        pending
    )
    assert json.loads(pending) == receipt and not destination.exists()
    with pytest.raises(FileExistsError):
        gate.main()
    assert attempts == [1]
    assert destination.with_name(destination.name + ".pending.json").read_bytes() == pending


def test_existing_receipt_is_rejected_before_qualification_or_mutation(tmp_path, monkeypatch):
    destination = tmp_path / "receipt.json"
    destination.write_bytes(b"original qualification receipt")
    calls = []
    monkeypatch.setattr(
        gate.sys,
        "argv",
        ["qualify_sandbox_promotion.py", "--promote", "--output", str(destination)],
    )
    monkeypatch.setattr(gate, "qualify", lambda *_args: calls.append("qualification"))
    monkeypatch.setattr(gate, "promote", lambda *_args: calls.append("mutation"))
    with pytest.raises(FileExistsError, match="receipt already exists"):
        gate.main()
    assert calls == [] and destination.read_bytes() == b"original qualification receipt"


@pytest.mark.parametrize("late_failure", ["storage_error", "competing_receipt"])
def test_final_receipt_failure_after_mutation_is_unknown(tmp_path, monkeypatch, late_failure):
    destination = tmp_path / "receipt.json"
    receipt = {"selector": selection(), "packageCoverage": "bounded_scope_matched"}
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("SANDBOX_PROMOTION_SELECTOR", json.dumps(selection()))
    monkeypatch.setattr(
        gate.sys,
        "argv",
        ["qualify_sandbox_promotion.py", "--promote", "--output", str(destination)],
    )
    monkeypatch.setattr(gate, "qualify", lambda *_args: receipt)
    attempts = []

    def acknowledged_promotion(*_args):
        attempts.append(1)
        if late_failure == "competing_receipt":
            destination.write_bytes(b"competing receipt")
        return receipt

    original_open = Path.open

    def storage_open(path, mode="r", *args, **kwargs):
        if path == destination and mode == "x" and late_failure == "storage_error":
            raise OSError("Late receipt persistence failure")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(gate, "promote", acknowledged_promotion)
    monkeypatch.setattr(Path, "open", storage_open)
    with pytest.raises(OSError):
        gate.main()
    pending = destination.with_name(destination.name + ".pending.json").read_bytes()
    unknown = json.loads(destination.with_name(destination.name + ".unconfirmed.json").read_bytes())
    assert attempts == [1] and unknown["outcome"] == "UNKNOWN"
    assert unknown["pendingReceiptDigest"] == gate.sha256(pending)
    assert json.loads(pending) == receipt
    assert (
        destination.read_bytes() == b"competing receipt"
        if late_failure == "competing_receipt"
        else not destination.exists()
    )


def test_cli_reports_unconfirmed_outcome_without_claiming_no_promotion(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_PROMOTION_SELECTOR", "{}")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    result = subprocess.run(  # noqa: S603 - current interpreter, fixed module, owned temporary output
        [
            gate.sys.executable,
            "-m",
            "scripts.qualify_sandbox_promotion",
            "--promote",
            "--output",
            str(tmp_path / "receipt.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == "Sandbox promotion outcome unconfirmed; inspect retained receipts.\n"
    assert "no image promoted" not in result.stderr


def test_workflow_is_main_only_and_always_invokes_evidence_gate_before_tagging():
    workflow = yaml.safe_load((Path(__file__).parents[1] / gate.PROMOTION_WORKFLOW).read_text())
    job = workflow["jobs"]["promote"]
    assert all(
        value in job["if"]
        for value in ("1297157605", "116722580", "refs/heads/main", "workflow_dispatch")
    )
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert job["timeout-minutes"] == 15
    assert job["permissions"] == {"contents": "read", "actions": "read", "packages": "write"}
    commands = [step["run"] for step in job["steps"] if "run" in step]
    assert commands == [
        "bash scripts/prepare_independent_inventory_tools.sh",
        "python3 -m scripts.qualify_sandbox_promotion --promote "
        '--output "$RUNNER_TEMP/sandbox-promotion-receipt.json"',
    ]
    assert not any("build-push" in step.get("uses", "") for step in job["steps"])
    assert "id-token" not in job["permissions"] and "attestations" not in job["permissions"]
    assert job["steps"][-1]["if"] == "always()"
