"""Executable public-claim gates for exact evaluation evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.corpus.v3.validate import validate as validate_v3
from benchmarks.evaluation_v3 import corpus_contract_hashes, score_v3
from benchmarks.report_signature import sign_payload
from benchmarks.validate_claims import _receipt_errors, _runtime_errors, validate_ledger
from tests import test_evaluation_v3 as evaluation_fixture


CORPUS_DIR = Path(__file__).resolve().parents[1] / "benchmarks" / "corpus" / "v3"


def _independent_development_corpus(repo_root: Path) -> Path:
    benchmarks = repo_root / "benchmarks"
    corpus_dir = benchmarks / "corpus" / "v3"
    shutil.copytree(CORPUS_DIR, corpus_dir)
    shutil.copytree(CORPUS_DIR.parent / "v2", benchmarks / "corpus" / "v2")
    shutil.copytree(
        CORPUS_DIR.parents[1] / "profiles",
        benchmarks / "profiles",
    )
    adjudications_path = corpus_dir / "adjudications.json"
    adjudications = json.loads(adjudications_path.read_text(encoding="utf-8"))
    adjudications["review"].update(
        {
            "status": "INDEPENDENTLY_REVIEWED",
            "reviewers": [{"id": "reviewer-a"}, {"id": "reviewer-b"}],
            "reviewedAt": "2026-11-05T00:00:00+00:00",
        }
    )
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")
    profile_path = benchmarks / "profiles" / "v1" / "paths.json"
    profile_record = json.loads(profile_path.read_text(encoding="utf-8"))
    for profile in profile_record["profiles"]:
        if profile["id"] == "deterministic_core":
            profile["status"] = "MEASURED"
    profile_path.write_text(json.dumps(profile_record), encoding="utf-8")
    corpus_path = corpus_dir / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["provenance"]["independentReviewStatus"] = "INDEPENDENTLY_REVIEWED"
    corpus["contracts"]["adjudications"]["sha256"] = hashlib.sha256(
        adjudications_path.read_bytes()
    ).hexdigest()
    corpus["contracts"]["pathProfiles"]["sha256"] = hashlib.sha256(
        profile_path.read_bytes()
    ).hexdigest()
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    validate_v3(corpus_dir)
    return corpus_dir


def _valid_claim(repo_root: Path, corpus_dir: Path) -> dict[str, Any]:
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    case = next(item for item in corpus["pairs"] if item["id"] == "SECRET-01")
    result_dir, manifest = evaluation_fixture._result_fixture(
        repo_root,
        [
            evaluation_fixture._finding(case, "vulnerable"),
            evaluation_fixture._finding(case, "clean"),
        ],
        corpus_dir=corpus_dir,
    )
    assert manifest["corpusContractsSha256"] == corpus_contract_hashes(corpus_dir, corpus)
    score_v3(result_dir, corpus_dir, corpus)
    signature_path = result_dir / "results.sig.json"
    signature = sign_payload(
        (result_dir / "results.json").read_bytes(),
        Ed25519PrivateKey.generate(),
    )
    signature_path.write_text(json.dumps(signature), encoding="utf-8")
    receipts = [
        {
            "path": (result_dir / name).relative_to(repo_root).as_posix(),
            "sha256": hashlib.sha256((result_dir / name).read_bytes()).hexdigest(),
        }
        for name in ("results.json", "RESULTS.md", "findings.jsonl", "run-manifest.json")
    ]
    return {
        "id": "claim-fixture-precision",
        "statement": "Synthetic SECRET-01 development precision fixture.",
        "metric": "precision",
        "claimedValue": 0.5,
        "numerator": 1,
        "denominator": 2,
        "profileId": "deterministic_core",
        "corpusPath": corpus_dir.relative_to(repo_root).as_posix(),
        "resultsPath": result_dir.relative_to(repo_root).as_posix(),
        "productRevision": "a" * 40,
        "engineRevision": "a" * 40,
        "scannerContractVersion": "fixture/3",
        "executableSha256": None,
        "modelRoute": None,
        "receipts": receipts,
        "limitations": ["Synthetic development corpus only; no held-out or production claim."],
        "founderSignoff": {
            "status": "APPROVED",
            "founder": "fixture-founder",
            "date": "2026-11-05T00:00:00+00:00",
        },
        "reportSignaturePath": signature_path.relative_to(repo_root).as_posix(),
        "reportSignatureSha256": hashlib.sha256(signature_path.read_bytes()).hexdigest(),
        "evaluationScope": "development",
        "heldOutChecksum": None,
    }


def test_claims_gate_accepts_only_complete_independently_adjudicated_evidence(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    assert validate_ledger(ledger_path, repo_root=repo_root)["valid"] is True

    claim["founderSignoff"] = None
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )
    result = validate_ledger(ledger_path, repo_root=repo_root)
    assert result["valid"] is False
    assert any("founder signoff" in error for error in result["errors"])


def test_engine_claim_requires_three_runs_and_exact_route() -> None:
    claim = {
        "id": "engine-claim",
        "profileId": "local_engine_cli",
        "modelRoute": {"provider": "wrong", "model": "wrong", "receiptSha256": "0" * 64},
        "executableSha256": "0" * 64,
        "scannerContractVersion": None,
    }
    manifest = {
        "detectors": "engine",
        "engineRuns": 2,
        "modelRoute": {
            "provider": "openai",
            "model": "gpt-6-sol",
            "receiptSha256": "1" * 64,
        },
        "executable": {"sha256": "2" * 64},
    }
    errors = _runtime_errors(claim, manifest)
    assert any("three declared runs" in error for error in errors)
    assert any("modelRoute.provider" in error for error in errors)
    assert any("executable checksum" in error for error in errors)


def test_deterministic_claim_requires_the_retained_scanner_contract() -> None:
    claim = {
        "id": "deterministic-claim",
        "profileId": "deterministic_core",
        "modelRoute": None,
        "executableSha256": None,
        "scannerContractVersion": "claimed/2",
    }
    manifest = {
        "detectors": "deterministic",
        "scannerContractVersion": "retained/1",
    }

    errors = _runtime_errors(claim, manifest)

    assert any("scannerContractVersion does not match" in error for error in errors)


def test_claim_receipts_must_be_distinct(tmp_path: Path) -> None:
    receipt = tmp_path / "run-manifest.json"
    receipt.write_text("{}\n", encoding="utf-8")
    entry = {
        "path": receipt.name,
        "sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
    }
    claim = {"id": "duplicate-receipts", "receipts": [entry, dict(entry), dict(entry)]}

    errors = _receipt_errors(claim, tmp_path, engine_required=True)

    assert any("distinct" in error for error in errors)


def test_claim_requires_every_retained_evaluation_artifact(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    claim["receipts"] = [
        receipt for receipt in claim["receipts"] if receipt["path"].endswith("run-manifest.json")
    ]
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    result = validate_ledger(ledger_path, repo_root=repo_root)

    assert result["valid"] is False
    assert any("RESULTS.md" in error for error in result["errors"])
    assert any("findings.jsonl" in error for error in result["errors"])


def test_claim_requires_a_measured_path_profile(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    profile_path = repo_root / "benchmarks" / "profiles" / "v1" / "paths.json"
    profiles = json.loads(profile_path.read_text(encoding="utf-8"))
    for profile in profiles["profiles"]:
        if profile["id"] == "deterministic_core":
            profile["status"] = "NOT_MEASURED"
    profile_path.write_text(json.dumps(profiles), encoding="utf-8")
    corpus_path = corpus_dir / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["contracts"]["pathProfiles"]["sha256"] = hashlib.sha256(
        profile_path.read_bytes()
    ).hexdigest()
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    result = validate_ledger(ledger_path, repo_root=repo_root)

    assert any("path profile is NOT_MEASURED" in error for error in result["errors"])


def test_unknown_claim_metric_fails_closed_without_an_exception(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    claim["metric"] = "accuracy"
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    result = validate_ledger(ledger_path, repo_root=repo_root)

    assert result["valid"] is False
    assert any("metric must be precision or recall" in error for error in result["errors"])


def test_claim_value_must_match_the_recomputed_metric(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    claim["claimedValue"] = 0.9
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    result = validate_ledger(ledger_path, repo_root=repo_root)

    assert result["valid"] is False
    assert any("claimed value does not match" in error for error in result["errors"])


def test_founder_signoff_requires_a_named_founder(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    claim["founderSignoff"]["founder"] = " "
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    result = validate_ledger(ledger_path, repo_root=repo_root)

    assert result["valid"] is False
    assert any("founder signoff is not approved" in error for error in result["errors"])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("metric", ["precision"], "metric must be precision or recall"),
        ("profileId", ["deterministic_core"], "invalid profileId"),
        ("evaluationScope", ["development"], "invalid evaluationScope"),
    ],
)
def test_malformed_claim_fields_fail_closed(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    repo_root = tmp_path / "repo"
    corpus_dir = _independent_development_corpus(repo_root)
    claim = _valid_claim(repo_root, corpus_dir)
    claim[field] = value
    ledger_path = repo_root / "claims.json"
    ledger_path.write_text(
        json.dumps({"schemaVersion": "lyrashield-claims-ledger/1.0.0", "claims": [claim]}),
        encoding="utf-8",
    )

    result = validate_ledger(ledger_path, repo_root=repo_root)

    assert result["valid"] is False
    assert any(message in error for error in result["errors"])
