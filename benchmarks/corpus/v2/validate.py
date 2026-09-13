from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent

EXPECTED_CLASSES = {
    "authorization",
    "secrets",
    "injection",
    "dependency",
    "service_keys",
    "rls",
    "iac",
}


def validate(root: Path = ROOT) -> None:
    corpus = json.loads((root / "corpus.json").read_text(encoding="utf-8"))
    pairs = corpus["pairs"]
    failures = corpus["failureScenarios"]
    live = corpus["liveTargets"]
    assert corpus["schemaVersion"] == "lyrashield-evaluation-corpus/2.0.0"
    assert len(pairs) == 39
    assert len(failures) == 10
    assert len(live) == 1
    assert len({case["id"] for case in pairs}) == len(pairs)
    assert len({case["id"] for case in failures}) == len(failures)
    assert {case["class"] for case in pairs} == EXPECTED_CLASSES

    for case in pairs:
        assert case["requiredControl"], f"{case['id']} missing requiredControl"
        assert case["expectedRemediation"], f"{case['id']} missing expectedRemediation"
        marker = f"CASE:{case['id']}"
        paths: dict[str, Path] = {}
        for projection in ("vulnerable", "clean"):
            path = (root / case[projection]).resolve()
            expected_root = (root / "fixtures" / projection).resolve()
            assert path.is_relative_to(expected_root), (
                f"{case['id']} {projection} fixture is outside {projection} root"
            )
            assert path.is_file(), f"{case['id']} missing {projection} fixture"
            paths[projection] = path
        assert paths["vulnerable"] != paths["clean"], (
            f"{case['id']} uses the same vulnerable and clean fixture"
        )
        # v1 file-level cases mark their fixture with a CASE comment; v2 IaC and
        # AI-app cases locate via markerLine/matchFile or the marker comment.
        content = paths["vulnerable"].read_text(encoding="utf-8")
        has_marker = marker in content
        has_locator = "markerLine" in case or "matchFile" in case
        assert has_marker or has_locator, (
            f"{case['id']} has no CASE marker and no markerLine/matchFile locator"
        )
        if "markerLine" in case:
            assert isinstance(case["markerLine"], int) and case["markerLine"] >= 1
        if "rulePrefixes" in case:
            assert case["rulePrefixes"], f"{case['id']} has empty rulePrefixes"

    for target in live:
        assert target["expectedFindings"], f"{target['id']} missing expectedFindings"

    assert all(case["expectedState"] != "READY" for case in failures)


if __name__ == "__main__":
    validate()
