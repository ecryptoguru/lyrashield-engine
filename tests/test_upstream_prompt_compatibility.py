"""Imported skill metadata must retain the product prompt and tool contract."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from lyrashield.agents import prompt
from lyrashield_adapter.cli import _register_lyrashield_skills
from strix.skills import validate_requested_skills


if TYPE_CHECKING:
    import pytest


def test_product_prompt_renders_qualified_skill_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        prompt,
        "get_available_skills",
        lambda: {"tooling": [{"name": "widget", "description": "Inspect a widget."}]},
    )
    rendered = prompt.render_system_prompt(is_root=True)
    assert "- tooling/widget: Inspect a widget." in rendered
    assert "{'name':" not in rendered


def test_registered_product_skills_keep_owned_lifecycle_and_schema() -> None:
    _register_lyrashield_skills()
    rendered = prompt.render_system_prompt(is_root=True, interactive=True)
    assert "respond_to_user" in rendered
    assert "wait_for_user" not in rendered
    assert "create_agent(skills=[...])" in rendered
    assert "load_skill(skills=[...])" in rendered
    assert "`inherit_context` false" in rendered
    assert "get_threat_model" not in rendered
    for category, skills in prompt.get_available_skills().items():
        for skill in skills:
            assert validate_requested_skills([f"{category}/{skill['name']}"]) is None


def test_reviewed_unshipped_skill_references_stay_removed() -> None:
    root = Path(__file__).resolve().parents[1]
    body = (root / "strix/skills/vulnerabilities/semantic_confusion.md").read_text()
    assert "load `hurl`" not in body
    assert "load `hypothesis`" not in body
    for name in ("hurl", "hypothesis"):
        assert not (root / f"strix/skills/tooling/{name}.md").exists()
