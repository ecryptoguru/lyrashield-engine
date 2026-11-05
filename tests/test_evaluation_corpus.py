import json
from pathlib import Path
from shutil import copytree

import pytest

from benchmarks.corpus.v1.validate import ROOT, validate
from benchmarks.corpus.v2.validate import validate as validate_v2
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
