from __future__ import annotations

from pathlib import Path

from scripts.classify_engine_ci_paths import is_documentation_only, is_native_boundary_relevant


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


def test_viewer_ci_preserves_full_gates_with_a_qualified_local_browser() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    dependencies = _verify_step(workflow, "Install owned viewer dependencies")
    assert "run: npm ci" in dependencies
    assert "--with-deps" not in workflow
    assert "Cache Playwright browser download" in workflow

    browser_contract = _verify_step(workflow, "Test viewer browser CI lifecycle contracts")
    assert "node --test scripts/tests/ci-viewer-browser.test.mjs" in browser_contract
    start = _verify_step(workflow, "Prepare qualified local viewer browser")
    assert "run: node scripts/ci-viewer-browser.mjs start" in start
    assert "steps.changed_paths.outputs.docs_only != 'true'" in start
    viewer = _verify_step(workflow, "Verify owned viewer source and committed build")
    for gate in (
        "node --test --test-concurrency=1 tests/*.mjs",
        "npm run typecheck",
        "npm run build",
        "git diff --exit-code -- ../static",
        "git ls-files --others --exclude-standard ../static",
    ):
        assert gate in viewer
    assert (
        workflow.index("Install owned viewer dependencies")
        < workflow.index("Prepare qualified local viewer browser")
        < workflow.index("Verify owned viewer source and committed build")
    )
    stop = _verify_step(workflow, "Stop owned viewer font source")
    assert "if: always() && steps.changed_paths.outputs.docs_only != 'true'" in stop
    assert "run: node scripts/ci-viewer-browser.mjs stop" in stop
    assert "continue-on-error" not in start + viewer + stop


def test_viewer_browser_suites_retain_the_original_local_launches() -> None:
    root = CI_WORKFLOW.parents[2]
    frontend = root / "lyrashield/interface/viewer/frontend/tests"
    for name in ("navigation", "recovery", "steering", "window"):
        source = (frontend / f"{name}-browser.test.mjs").read_text(encoding="utf-8")
        assert 'import { chromium } from "playwright";' in source
        assert "chromium.launch({ headless: true })" in source
        assert "browser?.close()" in source
        assert "launchViewerBrowser" not in source


def test_native_boundary_runs_for_runtime_tests_build_and_locks() -> None:
    assert is_native_boundary_relevant(["lyrashield/artifacts/finite_budget.py"])
    assert is_native_boundary_relevant(["strix/runtime/docker_client.py"])
    assert is_native_boundary_relevant(["tests/test_finite_budget_windows.py"])
    assert is_native_boundary_relevant(["scripts/build.sh"])
    assert is_native_boundary_relevant(["strix.spec"])
    assert is_native_boundary_relevant(["uv.lock", "docs/notes.mdx"])
    assert is_native_boundary_relevant([".github/workflows/ci.yml"])
    assert is_native_boundary_relevant(["lyrashield/interface/viewer/static/app.js"])


def test_native_boundary_skips_viewer_frontend_source_only() -> None:
    frontend = "lyrashield/interface/viewer/frontend"
    paths = [f"{frontend}/src/App.tsx", f"{frontend}/package-lock.json"]
    assert not is_native_boundary_relevant(paths)


def test_native_boundary_skips_docs_only_and_runs_for_unknown_inputs() -> None:
    assert not is_native_boundary_relevant(["docs/llm-providers/overview.mdx", "README.md"])
    assert is_native_boundary_relevant([])
    assert is_native_boundary_relevant(["some-unclassified-output.svg"])


def test_native_boundary_jobs_require_the_classified_output() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    windows = workflow.split("windows-attachment-boundary:", 1)[1].split(
        "\n  macos-financial-boundary:", 1
    )[0]
    macos = workflow.split("macos-financial-boundary:", 1)[1]
    for job in (windows, macos):
        assert "needs: changes" in job
        assert "if: needs.changes.outputs.native_boundary != 'false'" in job
    assert "native_boundary=true" in workflow
    changes_job = workflow.split("jobs:", 1)[1].split("  python-audit:", 1)[0]
    assert "native_boundary: ${{ steps.changed_paths.outputs.native_boundary }}" in changes_job
