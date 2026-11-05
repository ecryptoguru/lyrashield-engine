"""Validate every public evaluation claim against retained, exact evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.evaluation_v3 import score_v3
from benchmarks.report_signature import verify_file
from benchmarks.score import source_identity_complete


HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
ENGINE_PROFILES = {"url_api", "local_engine_cli", "product_integration"}
REQUIRED_FIELDS = {
    "id",
    "statement",
    "metric",
    "profileId",
    "corpusPath",
    "resultsPath",
    "productRevision",
    "engineRevision",
    "scannerContractVersion",
    "executableSha256",
    "modelRoute",
    "receipts",
    "limitations",
    "founderSignoff",
    "reportSignaturePath",
    "reportSignatureSha256",
    "evaluationScope",
    "heldOutChecksum",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve(repo_root: Path, value: str) -> Path | None:
    path = (repo_root / value).resolve()
    return path if path.is_relative_to(repo_root) else None


def _identity_errors(
    claim: dict[str, Any],
    corpus_dir: Path,
    manifest: dict[str, Any],
) -> list[str]:
    claim_id = claim["id"]
    errors: list[str] = []
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    if corpus.get("schemaVersion") != "lyrashield-evaluation-corpus/3.0.0":
        return [f"{claim_id}: public claims require evaluation corpus v3"]
    if manifest.get("pathProfile") != claim["profileId"]:
        errors.append(f"{claim_id}: path profile does not match the run manifest")
    if manifest.get("corpusSha256") != _sha256(corpus_dir / "corpus.json"):
        errors.append(f"{claim_id}: corpus checksum does not match the run manifest")
    if not source_identity_complete(manifest):
        errors.append(
            f"{claim_id}: source identity is dirty, incomplete, or changed during the run"
        )
    sources = manifest.get("sources") or {}
    if (sources.get("product") or {}).get("revision") != claim["productRevision"]:
        errors.append(f"{claim_id}: productRevision does not match the clean run")
    if claim["engineRevision"] != (sources.get("engine") or {}).get("revision"):
        errors.append(f"{claim_id}: engineRevision does not match the clean run")
    return errors


def _runtime_errors(claim: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    claim_id = claim["id"]
    errors: list[str] = []
    engine_required = (
        manifest.get("detectors") in {"engine", "all"} or claim["profileId"] in ENGINE_PROFILES
    )
    if engine_required:
        engine_runs = manifest.get("engineRuns")
        if type(engine_runs) is not int or engine_runs < 3:
            errors.append(f"{claim_id}: engine claims require at least three declared runs")
        if not isinstance(claim["modelRoute"], dict):
            errors.append(f"{claim_id}: engine claims require an exact model route")
        else:
            route = manifest.get("modelRoute") or {}
            errors.extend(
                f"{claim_id}: modelRoute.{field} does not match the run"
                for field in ("provider", "model", "receiptSha256")
                if claim["modelRoute"].get(field) != route.get(field)
            )
        if claim["executableSha256"] != (manifest.get("executable") or {}).get("sha256"):
            errors.append(f"{claim_id}: executable checksum does not match the run")
    else:
        if claim["modelRoute"] is not None:
            errors.append(
                f"{claim_id}: deterministic claims must explicitly set modelRoute to null"
            )
        if claim["executableSha256"] is not None:
            errors.append(
                f"{claim_id}: deterministic claims must explicitly set executableSha256 to null"
            )
    if claim["profileId"] in {"deterministic_core", "offline_sca"} and (
        not isinstance(claim["scannerContractVersion"], str)
        or not claim["scannerContractVersion"].strip()
    ):
        errors.append(f"{claim_id}: scannerContractVersion is required")
    return errors


def _receipt_errors(claim: dict[str, Any], repo_root: Path, *, engine_required: bool) -> list[str]:
    claim_id = claim["id"]
    errors: list[str] = []
    receipts = claim["receipts"]
    if not isinstance(receipts, list) or not receipts:
        return [f"{claim_id}: at least one retained receipt is required"]
    for receipt in receipts:
        path = _resolve(repo_root, str(receipt.get("path", "")))
        if path is None or not path.is_file():
            errors.append(f"{claim_id}: receipt is outside the repository or missing")
            continue
        if receipt.get("sha256") != _sha256(path):
            errors.append(f"{claim_id}: receipt checksum mismatch for {receipt.get('path')}")
    minimum_receipts = 3 if engine_required else 1
    if len(receipts) < minimum_receipts:
        errors.append(f"{claim_id}: {minimum_receipts} retained receipt(s) required for this scope")
    return errors


def _governance_errors(claim: dict[str, Any], corpus_dir: Path) -> list[str]:
    claim_id = claim["id"]
    errors: list[str] = []
    if not isinstance(claim["limitations"], list) or not any(
        isinstance(item, str) and item.strip() for item in claim["limitations"]
    ):
        errors.append(f"{claim_id}: limitations must be explicit")
    signoff = claim["founderSignoff"]
    if not isinstance(signoff, dict):
        errors.append(f"{claim_id}: founder signoff is missing")
    else:
        if signoff.get("status") != "APPROVED" or not isinstance(signoff.get("founder"), str):
            errors.append(f"{claim_id}: founder signoff is not approved")
        try:
            signed_at = datetime.fromisoformat(str(signoff.get("date")))
        except ValueError:
            errors.append(f"{claim_id}: founder signoff date is invalid")
        else:
            if signed_at.tzinfo is None:
                errors.append(f"{claim_id}: founder signoff date must include a timezone")

    held_out = json.loads((corpus_dir / "held-out.json").read_text(encoding="utf-8"))
    if claim["evaluationScope"] == "held_out":
        if held_out.get("status") != "VERIFIED":
            errors.append(f"{claim_id}: held-out contract is not verified")
        if claim["heldOutChecksum"] != (held_out.get("checksums") or {}).get("labels"):
            errors.append(f"{claim_id}: held-out label checksum does not match")
    elif claim["heldOutChecksum"] is not None:
        errors.append(f"{claim_id}: development claims must set heldOutChecksum to null")
    return errors


def _metric_errors(
    claim: dict[str, Any],
    corpus_dir: Path,
    results_dir: Path,
) -> list[str]:
    claim_id = claim["id"]
    errors: list[str] = []
    corpus = json.loads((corpus_dir / "corpus.json").read_text(encoding="utf-8"))
    result = score_v3(results_dir, corpus_dir, corpus, write_results=False)
    if result["status"] != "COMPLETE":
        errors.append(f"{claim_id}: scorer status is {result['status']}, not COMPLETE")
    metric = result[claim["metric"]]
    if metric["status"] != "REPORTABLE":
        reasons = "; ".join(metric["reasons"]) or "no reason recorded"
        errors.append(f"{claim_id}: {claim['metric']} is NOT_REPORTABLE: {reasons}")
        return errors
    raw = metric["raw"]
    if claim.get("numerator") != raw["numerator"] or claim.get("denominator") != raw["denominator"]:
        errors.append(f"{claim_id}: claimed raw numerator/denominator do not match")
    return errors


def _signature_errors(claim: dict[str, Any], repo_root: Path, results_dir: Path) -> list[str]:
    claim_id = claim["id"]
    signature_path = _resolve(repo_root, str(claim["reportSignaturePath"]))
    payload_path = results_dir / "results.json"
    if signature_path is None or not signature_path.is_file():
        return [f"{claim_id}: report signature is outside the repository or missing"]
    errors: list[str] = []
    if claim["reportSignatureSha256"] != _sha256(signature_path):
        errors.append(f"{claim_id}: report signature checksum does not match")
    if not payload_path.is_file() or not verify_file(payload_path, signature_path):
        errors.append(f"{claim_id}: report signature does not verify results.json")
    return errors


def _claim_errors(claim: dict[str, Any], repo_root: Path) -> list[str]:
    missing = REQUIRED_FIELDS - set(claim)
    if missing:
        return [f"{claim.get('id', '<unknown>')}: missing fields: {sorted(missing)}"]

    claim_id = claim["id"]
    errors: list[str] = []
    if not isinstance(claim_id, str) or not claim_id.strip():
        errors.append("claim id must be non-empty")
    if not isinstance(claim["statement"], str) or not claim["statement"].strip():
        errors.append(f"{claim_id}: statement is empty")
    if claim["metric"] not in {"precision", "recall"}:
        errors.append(f"{claim_id}: metric must be precision or recall")
    if claim["evaluationScope"] not in {"development", "held_out"}:
        errors.append(f"{claim_id}: invalid evaluationScope")

    corpus_dir = _resolve(repo_root, str(claim["corpusPath"]))
    results_dir = _resolve(repo_root, str(claim["resultsPath"]))
    if corpus_dir is None or not (corpus_dir / "corpus.json").is_file():
        return [*errors, f"{claim_id}: corpusPath is outside the repository or unreadable"]
    if results_dir is None or not (results_dir / "run-manifest.json").is_file():
        return [*errors, f"{claim_id}: resultsPath is outside the repository or unreadable"]

    manifest = json.loads((results_dir / "run-manifest.json").read_text(encoding="utf-8"))
    errors.extend(_identity_errors(claim, corpus_dir, manifest))
    errors.extend(_runtime_errors(claim, manifest))
    engine_required = (
        manifest.get("detectors") in {"engine", "all"} or claim["profileId"] in ENGINE_PROFILES
    )
    errors.extend(_receipt_errors(claim, repo_root, engine_required=engine_required))
    errors.extend(_governance_errors(claim, corpus_dir))
    errors.extend(_signature_errors(claim, repo_root, results_dir))
    errors.extend(_metric_errors(claim, corpus_dir, results_dir))
    return errors


def validate_ledger(ledger_path: Path, *, repo_root: Path | None = None) -> dict[str, Any]:
    root = (repo_root or Path(__file__).resolve().parent.parent).resolve()
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if ledger.get("schemaVersion") != "lyrashield-claims-ledger/1.0.0":
        errors.append("unsupported claims ledger schema")
    claims = ledger.get("claims")
    if not isinstance(claims, list):
        errors.append("claims must be an array")
        claims = []
    ids = [claim.get("id") for claim in claims if isinstance(claim, dict)]
    if len(ids) != len(set(ids)):
        errors.append("claim ids must be unique")
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("claim must be an object")
            continue
        errors.extend(_claim_errors(claim, root))
    return {
        "valid": not errors,
        "claimCount": len(claims),
        "errors": errors,
        "publishableClaims": 0 if errors else len(claims),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default="benchmarks/claims.json")
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args()
    result = validate_ledger(Path(args.ledger), repo_root=Path(args.repo_root))
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
