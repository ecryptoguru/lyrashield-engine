from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def validate() -> None:
    corpus = json.loads((ROOT / "corpus.json").read_text(encoding="utf-8"))
    pairs = corpus["pairs"]
    failures = corpus["failureScenarios"]
    assert corpus["schemaVersion"] == "lyrashield-evaluation-corpus/1.0.0"
    assert len(pairs) == 24
    assert len(failures) == 8
    assert len({case["id"] for case in pairs}) == len(pairs)
    assert len({case["id"] for case in failures}) == len(failures)
    assert {case["class"] for case in pairs} == {
        "authorization",
        "secrets",
        "injection",
        "dependency",
    }

    for case in pairs:
        assert case["requiredControl"]
        assert case["expectedRemediation"]
        marker = f"CASE:{case['id']}"
        for projection in ("vulnerable", "clean"):
            path = ROOT / case[projection]
            assert path.is_file(), f"{case['id']} missing {projection} fixture"
            assert marker in path.read_text(encoding="utf-8"), (
                f"{case['id']} marker missing from {projection} fixture"
            )

    assert all(case["expectedState"] != "READY" for case in failures)


if __name__ == "__main__":
    validate()
