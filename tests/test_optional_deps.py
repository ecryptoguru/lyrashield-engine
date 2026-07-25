"""Tests for the optional-dependency extras declared in pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast


PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _optional_dependencies() -> dict[str, list[str]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return cast("dict[str, list[str]]", data["project"]["optional-dependencies"])


def test_vertex_extra_pins_google_auth() -> None:
    extras = _optional_dependencies()
    assert "vertex" in extras
    assert any(req.startswith("google-auth") for req in extras["vertex"])


def test_bedrock_extra_pins_boto3() -> None:
    extras = _optional_dependencies()
    assert "bedrock" in extras
    assert any(req.startswith("boto3") for req in extras["bedrock"])


def test_viewer_extra_carries_the_pdf_dependencies() -> None:
    extras = _optional_dependencies()
    assert "viewer" in extras
    assert any(req.startswith("reportlab") for req in extras["viewer"])
    assert any(req.startswith("pypdf") for req in extras["viewer"])


def test_pdf_dependencies_are_not_in_the_base_install() -> None:
    """The worker never runs the viewer, so its scan image should not carry these."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    base = cast("list[str]", data["project"]["dependencies"])
    assert not [req for req in base if req.startswith(("reportlab", "pypdf"))]


def test_cryptography_stays_in_the_base_install() -> None:
    """Used outside the viewer, and the <49 cap keeps the Intel macOS wheel."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    base = cast("list[str]", data["project"]["dependencies"])
    assert any(req.startswith("cryptography") for req in base)
