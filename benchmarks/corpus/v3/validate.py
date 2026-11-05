"""Validate the v3 corpus, adjudication, held-out, and path contracts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
PROFILE_IDS = {
    "deterministic_core",
    "offline_sca",
    "url_api",
    "local_engine_cli",
    "product_integration",
}
OUTCOMES = {
    "true_positive",
    "false_positive",
    "false_negative",
    "ambiguous",
    "unreachable",
    "incomplete",
}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), f"{path} is not a JSON object"
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_adjudications(root: Path, corpus: dict[str, Any]) -> dict[str, Any]:
    record = _load(root / "adjudications.json")
    assert record["schemaVersion"] == "lyrashield-adjudication/1.0.0"
    assert record["corpus"] == {"name": corpus["name"], "revision": corpus["revision"]}
    assert set(record["allowedOutcomes"]) == OUTCOMES
    review = record["review"]
    status = review["status"]
    assert status in {
        "NOT_INDEPENDENTLY_REVIEWED",
        "IN_PROGRESS",
        "INDEPENDENTLY_REVIEWED",
    }
    required = review["requiredReviewerCount"]
    assert type(required) is int and required >= 2
    authors = review["implementationAuthors"]
    reviewers = review["reviewers"]
    assert isinstance(authors, list) and all(isinstance(item, str) and item for item in authors)
    assert isinstance(reviewers, list)
    assert all(isinstance(item, dict) for item in reviewers)
    reviewer_ids = [item.get("id") for item in reviewers]
    assert all(isinstance(item, str) and item for item in reviewer_ids)
    assert len(set(reviewer_ids)) == len(reviewer_ids)
    assert not set(reviewer_ids) & set(authors)
    decisions = record["decisions"]
    assert isinstance(decisions, list)
    if status == "INDEPENDENTLY_REVIEWED":
        assert len(reviewers) >= required
        assert isinstance(review["reviewedAt"], str) and review["reviewedAt"]
        for decision in decisions:
            assert decision["outcome"] in OUTCOMES
            assert isinstance(decision.get("findingSha256"), str)
            assert HEX_SHA256.fullmatch(decision["findingSha256"])
            assigned = decision.get("reviewerIds")
            assert isinstance(assigned, list)
            assert len(set(assigned)) >= required
            assert set(assigned) <= set(reviewer_ids)
            assert isinstance(decision.get("rationale"), str) and decision["rationale"].strip()
    else:
        # An unreviewed author cannot pre-label findings and call the result
        # adjudicated. Decisions become eligible only under the independent
        # review contract above.
        assert decisions == []
    return record


def _validate_held_out(root: Path, corpus: dict[str, Any]) -> dict[str, Any]:
    record = _load(root / "held-out.json")
    assert record["schemaVersion"] == "lyrashield-held-out-contract/1.0.0"
    assert record["corpus"] == {"name": corpus["name"], "revision": corpus["revision"]}
    assert record["developmentAccess"] is False
    assert record["storage"] == "SEPARATE_REVIEWER_ONLY"
    assert record["status"] in {"NOT_PROVIDED", "READY", "VERIFIED"}
    checksums = record["checksums"]
    assert checksums["algorithm"] == "sha256"
    values = [checksums["manifest"], checksums["fixtures"], checksums["labels"]]
    if record["status"] == "NOT_PROVIDED":
        assert values == [None, None, None]
        assert record["limitations"]
    else:
        assert all(isinstance(value, str) and HEX_SHA256.fullmatch(value) for value in values)
    return record


def _validate_profiles(root: Path) -> dict[str, Any]:
    record = _load(root / "../../profiles/v1/paths.json")
    assert record["schemaVersion"] == "lyrashield-evaluation-paths/1.0.0"
    profiles = record["profiles"]
    assert isinstance(profiles, list)
    ids = [profile["id"] for profile in profiles]
    assert set(ids) == PROFILE_IDS
    assert len(ids) == len(set(ids))
    for profile in profiles:
        assert profile["status"] in {"NOT_MEASURED", "MEASURED", "INCOMPLETE"}
        assert profile["requiredBindings"]
        assert profile["forbiddenEvidence"]
    return record


def _validate_advisories(root: Path) -> dict[str, Any]:
    record = _load(root / "advisories/frozen.json")
    assert record["schemaVersion"] == "lyrashield-frozen-advisories/1.0.0"
    assert record["networkRequired"] is False
    advisory_ids = [item["id"] for item in record["advisories"]]
    assert advisory_ids and len(advisory_ids) == len(set(advisory_ids))
    for item in record["advisories"]:
        assert item["ecosystem"] == "packagist"
        assert item["package"] == "example/legacy-router"
        assert item["fixed"] == "2.4.1"
    return record


def validate(root: Path = ROOT) -> None:
    corpus = _load(root / "corpus.json")
    assert corpus["schemaVersion"] == "lyrashield-evaluation-corpus/3.0.0"
    assert corpus["revision"] == "v3"
    assert corpus["extends"] == "v2"
    assert corpus["provenance"]["independentReviewStatus"] == "NOT_INDEPENDENTLY_REVIEWED"
    pairs = corpus["pairs"]
    scenarios = corpus["scenarios"]
    assert pairs and scenarios
    pair_ids = [case["id"] for case in pairs]
    assert len(pair_ids) == len(set(pair_ids))
    assert all(case["split"] == "development" for case in pairs)

    v2 = _load(root.parent / "v2" / "corpus.json")
    v2_ids = {case["id"] for case in v2["pairs"]}
    assert v2_ids <= set(pair_ids)
    assert {"PHP-AUTH-01", "PHP-COMPOSER-01"} <= set(pair_ids)

    profile_record = _validate_profiles(root)
    profile_ids = {profile["id"] for profile in profile_record["profiles"]}
    for case in pairs:
        assert case["requiredControl"]
        assert case["expectedRemediation"]
        assert case["supportedProfiles"]
        assert set(case["supportedProfiles"]) <= profile_ids
        paths = {}
        for variant in ("vulnerable", "clean"):
            path = (root / case[variant]).resolve()
            assert path.is_relative_to(root.resolve())
            assert path.is_file(), f"{case['id']} missing {variant} fixture"
            paths[variant] = path
        assert paths["vulnerable"] != paths["clean"]
        marker = case.get("markerLine")
        if marker is None:
            content = paths["vulnerable"].read_text(encoding="utf-8")
            assert f"CASE:{case['id']}" in content
        else:
            assert type(marker) is int and marker >= 1
        if "rulePrefixes" in case:
            assert case["rulePrefixes"]

    scenario_ids = [item["id"] for item in scenarios]
    assert len(scenario_ids) == len(set(scenario_ids))
    for scenario in scenarios:
        assert scenario["profile"] in profile_ids
        assert scenario["expectedCategory"] in OUTCOMES
        assert scenario["status"] in {"NOT_MEASURED", "MEASURED", "INCOMPLETE"}
    assert {
        "IDENTITY-RETEST-01",
        "STALE-EVIDENCE-01",
        "PARTIAL-RESULT-01",
    } <= set(scenario_ids)

    contracts = corpus["contracts"]
    expected_contracts = {
        "adjudications": root / "adjudications.json",
        "heldOut": root / "held-out.json",
        "frozenAdvisories": root / "advisories/frozen.json",
        "pathProfiles": root / "../../profiles/v1/paths.json",
    }
    for name, path in expected_contracts.items():
        contract = contracts[name]
        assert contract["sha256"] == _sha256(path.resolve()), f"{name} checksum drift"
        assert contract["schemaVersion"] == _load(path.resolve())["schemaVersion"]

    _validate_adjudications(root, corpus)
    _validate_held_out(root, corpus)
    _validate_advisories(root)


if __name__ == "__main__":
    validate()
