"""Tests for the optional-dependency extras declared in pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast


PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _optional_dependencies() -> dict[str, list[str]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return cast("dict[str, list[str]]", data["project"]["optional-dependencies"])


def _base_dependencies() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return cast("list[str]", data["project"]["dependencies"])


def test_viewer_extra_pins_reportlab_and_pypdf() -> None:
    extras = _optional_dependencies()
    assert "viewer" in extras
    assert any(req == "reportlab>=4.0" for req in extras["viewer"])
    assert any(req == "pypdf>=5.0" for req in extras["viewer"])


def test_reportlab_and_pypdf_are_not_base_dependencies() -> None:
    deps = _base_dependencies()
    assert not any(req.startswith("reportlab") for req in deps)
    assert not any(req.startswith("pypdf") for req in deps)


def test_cryptography_remains_a_base_dependency() -> None:
    deps = _base_dependencies()
    assert any(req.startswith("cryptography") for req in deps)


def test_vertex_extra_pins_google_auth() -> None:
    extras = _optional_dependencies()
    assert "vertex" in extras
    assert any(req.startswith("google-auth") for req in extras["vertex"])


def test_bedrock_extra_pins_boto3() -> None:
    extras = _optional_dependencies()
    assert "bedrock" in extras
    assert any(req.startswith("boto3") for req in extras["bedrock"])
