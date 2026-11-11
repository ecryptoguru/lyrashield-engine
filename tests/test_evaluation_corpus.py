import hashlib
import json
from pathlib import Path
from shutil import copytree

import pytest

from benchmarks.corpus.v1.validate import ROOT, validate
from benchmarks.corpus.v2.validate import validate as validate_v2
from benchmarks.corpus.v3.validate import _validate_adjudications, _validate_held_out
from benchmarks.corpus.v3.validate import validate as validate_v3


def test_versioned_evaluation_corpus() -> None:
    validate()


def test_v2_evaluation_corpus() -> None:
    validate_v2()


@pytest.mark.parametrize("mode", ["duplicate", "swapped"])
def test_corpus_rejects_invalid_fixture_polarity(tmp_path: Path, mode: str) -> None:
    root = tmp_path / "v1"
    copytree(ROOT, root)
    manifest_path = root / "corpus.json"
    corpus = json.loads(manifest_path.read_text(encoding="utf-8"))
    case = corpus["pairs"][0]
    if mode == "duplicate":
        case["clean"] = case["vulnerable"]
    else:
        case["clean"], case["vulnerable"] = case["vulnerable"], case["clean"]
    manifest_path.write_text(json.dumps(corpus), encoding="utf-8")

    with pytest.raises(AssertionError):
        validate(root)


def test_v3_evaluation_contracts_and_fixture_inheritance() -> None:
    validate_v3()


def test_v3_rejects_prelabelled_or_incomplete_independent_contracts(tmp_path: Path) -> None:
    benchmarks = tmp_path / "benchmarks"
    copytree(ROOT.parents[1], benchmarks)
    root = benchmarks / "corpus" / "v3"
    adjudications_path = root / "adjudications.json"
    adjudications = json.loads(adjudications_path.read_text(encoding="utf-8"))
    adjudications["review"]["status"] = "INDEPENDENTLY_REVIEWED"
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")

    with pytest.raises(AssertionError):
        validate_v3(root)

    adjudications["review"]["status"] = "NOT_INDEPENDENTLY_REVIEWED"
    adjudications["decisions"] = [
        {
            "findingSha256": "a" * 64,
            "outcome": "false_positive",
            "reviewerIds": ["implementation"],
            "rationale": "author label",
        }
    ]
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")
    with pytest.raises(AssertionError):
        validate_v3(root)


def test_v3_rejects_duplicate_adjudication_decisions(tmp_path: Path) -> None:
    benchmarks = tmp_path / "benchmarks"
    copytree(ROOT.parents[1], benchmarks)
    root = benchmarks / "corpus" / "v3"
    adjudications_path = root / "adjudications.json"
    adjudications = json.loads(adjudications_path.read_text(encoding="utf-8"))
    adjudications["review"].update(
        {
            "status": "INDEPENDENTLY_REVIEWED",
            "reviewers": [{"id": "reviewer-a"}, {"id": "reviewer-b"}],
            "reviewedAt": "2026-11-05T00:00:00+00:00",
        }
    )
    adjudications["decisions"] = [
        {
            "findingSha256": "a" * 64,
            "outcome": "true_positive",
            "reviewerIds": ["reviewer-a", "reviewer-b"],
            "rationale": "first decision",
        },
        {
            "findingSha256": "a" * 64,
            "outcome": "false_positive",
            "reviewerIds": ["reviewer-a", "reviewer-b"],
            "rationale": "conflicting duplicate",
        },
    ]
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")
    corpus_path = root / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["contracts"]["adjudications"]["sha256"] = hashlib.sha256(
        adjudications_path.read_bytes()
    ).hexdigest()
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    with pytest.raises(AssertionError):
        _validate_adjudications(root, corpus)


def test_v3_requires_timezone_aware_adjudication_review_time(tmp_path: Path) -> None:
    benchmarks = tmp_path / "benchmarks"
    copytree(ROOT.parents[1], benchmarks)
    root = benchmarks / "corpus" / "v3"
    adjudications_path = root / "adjudications.json"
    adjudications = json.loads(adjudications_path.read_text(encoding="utf-8"))
    adjudications["review"].update(
        {
            "status": "INDEPENDENTLY_REVIEWED",
            "reviewers": [{"id": "reviewer-a"}, {"id": "reviewer-b"}],
            "reviewedAt": "2026-11-05T00:00:00",
        }
    )
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")
    corpus = json.loads((root / "corpus.json").read_text(encoding="utf-8"))

    with pytest.raises(AssertionError):
        _validate_adjudications(root, corpus)


def test_v3_requires_manifest_provenance_to_match_review_status(tmp_path: Path) -> None:
    benchmarks = tmp_path / "benchmarks"
    copytree(ROOT.parents[1], benchmarks)
    root = benchmarks / "corpus" / "v3"
    adjudications_path = root / "adjudications.json"
    adjudications = json.loads(adjudications_path.read_text(encoding="utf-8"))
    adjudications["review"].update(
        {
            "status": "INDEPENDENTLY_REVIEWED",
            "reviewers": [{"id": "reviewer-a"}, {"id": "reviewer-b"}],
            "reviewedAt": "2026-11-05T00:00:00+00:00",
        }
    )
    adjudications_path.write_text(json.dumps(adjudications), encoding="utf-8")
    corpus_path = root / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["contracts"]["adjudications"]["sha256"] = hashlib.sha256(
        adjudications_path.read_bytes()
    ).hexdigest()
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    with pytest.raises(AssertionError):
        validate_v3(root)


def test_verified_held_out_contract_records_who_checked_checksums(
    tmp_path: Path,
) -> None:
    benchmarks = tmp_path / "benchmarks"
    copytree(ROOT.parents[1], benchmarks)
    root = benchmarks / "corpus" / "v3"
    held_out_path = root / "held-out.json"
    held_out = json.loads(held_out_path.read_text(encoding="utf-8"))
    held_out["status"] = "VERIFIED"
    held_out["checksums"].update({"manifest": "a" * 64, "fixtures": "b" * 64, "labels": "c" * 64})
    held_out_path.write_text(json.dumps(held_out), encoding="utf-8")
    corpus = json.loads((root / "corpus.json").read_text(encoding="utf-8"))

    with pytest.raises(AssertionError):
        _validate_held_out(root, corpus)
