from __future__ import annotations

from scripts.classify_engine_ci_paths import is_documentation_only


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
