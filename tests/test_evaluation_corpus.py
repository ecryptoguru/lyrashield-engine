import json
from pathlib import Path
from shutil import copytree

import pytest

from benchmarks.corpus.v1.validate import ROOT, validate


def test_versioned_evaluation_corpus() -> None:
    validate()


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
