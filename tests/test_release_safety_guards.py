"""Regression checks for release artifact smoke and sandbox publish refs."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_release_workflow_smokes_the_packaged_binary_version_and_help() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/build-release.yml").read_text(encoding="utf-8"),
    )
    steps = workflow["jobs"]["build"]["steps"]
    build = next(step for step in steps if step.get("name") == "Build")
    script = build["run"]

    assert 'BINARY_PATH="dist/release/strix-${VERSION}-${{ matrix.target }}.exe"' in script
    assert 'BINARY_PATH="dist/release/strix-${VERSION}-${{ matrix.target }}"' in script
    assert 'uv run python scripts/smoke_release.py "$BINARY_PATH" "$VERSION"' in script


def test_sandbox_publish_ref_guard_keeps_tag_and_main_dispatch_boundaries() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/publish-sandbox.yml").read_text(encoding="utf-8"),
    )
    publish = workflow["jobs"]["publish"]
    triggers = workflow.get("on", workflow.get(True))

    assert triggers["push"]["tags"] == ["sandbox-v*"]
    assert "github.event_name == 'push'" in publish["if"]
    assert "startsWith(github.ref, 'refs/tags/sandbox-v')" in publish["if"]
    assert "github.event_name == 'workflow_dispatch'" in publish["if"]
    assert "github.ref == 'refs/heads/main'" in publish["if"]
