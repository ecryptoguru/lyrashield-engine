"""Strict promotion selectors, evidence transport and registry acknowledgement."""

import copy
import io
import json
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


def test_promotion_requires_exact_registry_ack_and_fresh_main_before_mutation(monkeypatch):
    value = selection()
    result = {
        "selector": value,
        "promotionSource": "f" * 40,
        "ci": {"runId": "46", "runAttempt": "1"},
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
    monkeypatch.setattr(gate, "qualified_ci", lambda _revision: result["ci"])
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
