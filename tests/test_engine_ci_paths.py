from __future__ import annotations

from pathlib import Path

from scripts.classify_engine_ci_paths import is_documentation_only


CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def _verify_step(workflow: str, name: str) -> str:
    marker = f"name: {name}"
    assert marker in workflow, name
    return workflow.split(marker, 1)[1].split("\n      - ", 1)[0]


def test_markdown_docs_only_changes_can_skip_long_engine_jobs() -> None:
    assert is_documentation_only(["docs/llm-providers/overview.mdx", "README.md", "AGENTS.md"])


def test_runtime_workflow_dependency_or_test_changes_require_full_ci() -> None:
    assert not is_documentation_only(
        [
            "docs/llm-providers/overview.mdx",
            "lyrashield/policy/models.py",
            "tests/test_models.py",
            ".github/workflows/ci.yml",
            "uv.lock",
        ]
    )


def test_runtime_file_renamed_to_documentation_still_requires_full_ci() -> None:
    # --no-renames reports both the deleted source and added destination.
    assert not is_documentation_only(["lyrashield/interface/main.py", "README.md"])


def test_empty_or_unknown_path_sets_run_full_ci() -> None:
    assert not is_documentation_only([])
    assert not is_documentation_only(["docs/engine-diagram.svg"])


def test_branding_gate_runs_on_docs_only_pull_requests() -> None:
    """docs/** is inside the branding scope, so the fast gate must not be
    skipped by the docs-only classification, and its stdlib-only interpreter
    must be provisioned without pulling in the expensive gates."""
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    branding = _verify_step(workflow, "Verify customer branding")
    assert "python scripts/verify-customer-branding.py" in branding
    assert "docs_only" not in branding

    python_setup = workflow.split("actions/setup-python", 1)[1].split("\n      - ", 1)[0]
    assert "docs_only" not in python_setup
    assert 'python-version: "3.12"' in python_setup

    # uv, Node, and the heavyweight gates remain skipped on the docs-only route.
    assert workflow.count("steps.changed_paths.outputs.docs_only != 'true'") > 0
