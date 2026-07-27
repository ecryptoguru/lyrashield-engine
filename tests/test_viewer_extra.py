"""Regression tests for the optional ``viewer`` extra packaging.

Issue #27: reportlab/pypdf must stay out of the base install but be present
for release builds and the ``verify-thin-fork.sh`` gate.
"""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
BUILD_SCRIPT = PROJECT_ROOT / "scripts" / "build.sh"
VERIFY_SCRIPT = PROJECT_ROOT / "scripts" / "verify-thin-fork.sh"
BUILD_RELEASE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-release.yml"

_PDF_AVAILABLE = (
    importlib.util.find_spec("pypdf") is not None
    and importlib.util.find_spec("reportlab") is not None
)


def _read_pyproject() -> dict[str, Any]:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_viewer_extra_is_optional_and_includes_pdf_packages() -> None:
    """pypdf/reportlab live only in [project.optional-dependencies] viewer."""
    data = _read_pyproject()
    deps = data["project"]["dependencies"]
    extras = data["project"]["optional-dependencies"]

    base_names = {d.split("[")[0].split(">=")[0].split("<")[0].strip() for d in deps}
    assert "pypdf" not in base_names, "pypdf must not be in base dependencies"
    assert "reportlab" not in base_names, "reportlab must not be in base dependencies"

    assert "viewer" in extras, "the 'viewer' extra must be declared"
    viewer = " ".join(extras["viewer"])
    assert "pypdf" in viewer, "the 'viewer' extra must include pypdf"
    assert "reportlab" in viewer, "the 'viewer' extra must include reportlab"

    assert "cryptography" in base_names, "cryptography must remain a base dependency"
    cryptography = next(d for d in deps if d.startswith("cryptography"))
    assert "<49" in cryptography, "cryptography must keep its <49 cap"


def test_build_and_ci_sync_with_viewer_extra() -> None:
    """Every release build path and the verify gate syncs --extra viewer."""
    for path in (BUILD_SCRIPT, VERIFY_SCRIPT, BUILD_RELEASE_WORKFLOW):
        text = path.read_text(encoding="utf-8")
        assert "uv sync --frozen --extra viewer" in text, f"{path} must sync with --extra viewer"
        assert "uv sync --frozen" in text  # guard against the search being vacuous
        for line in text.splitlines():
            if "uv sync --frozen" in line and "--extra viewer" not in line:
                pytest.fail(f"{path} has a bare uv sync without --extra viewer: {line}")


@pytest.mark.skipif(_PDF_AVAILABLE, reason="extra is present, not testing base install")
def test_base_install_does_not_import_pdf_packages() -> None:
    """With the base sync neither PDF package is importable."""
    assert importlib.util.find_spec("pypdf") is None
    assert importlib.util.find_spec("reportlab") is None
    assert importlib.util.find_spec("cryptography") is not None


@pytest.mark.skipif(not _PDF_AVAILABLE, reason="requires the optional 'viewer' extra")
def test_viewer_extra_imports_both_pdf_packages() -> None:
    """With the viewer extra both PDF packages are importable."""
    assert importlib.util.find_spec("pypdf") is not None
    assert importlib.util.find_spec("reportlab") is not None
    assert importlib.util.find_spec("cryptography") is not None
