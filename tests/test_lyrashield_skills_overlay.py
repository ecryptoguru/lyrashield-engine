"""LyraShield skill overlays shadow built-in strix skills through register_skill_dir."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.skills import _EXTRA_SKILL_DIRS, load_skills, register_skill_dir


SKILLS_DIR = Path(__file__).resolve().parents[1] / "lyrashield" / "skills"


def _content_for(skill_name: str) -> str:
    content = load_skills([skill_name])
    assert content, f"Skill {skill_name} not found"
    return next(iter(content.values()))


@pytest.fixture(scope="module", autouse=True)
def _register_overlay() -> None:
    register_skill_dir(SKILLS_DIR)


@pytest.mark.parametrize(
    ("skill", "marker"),
    [
        ("tooling/ffuf", "use `ffuf -h` and retain the installed-version output"),
        ("tooling/httpx", "httpx -h"),
        ("tooling/katana", "katana -h"),
        ("tooling/naabu", "naabu -h"),
        ("tooling/nmap", "nmap --help"),
        ("tooling/nuclei", "nuclei -h"),
        ("tooling/semgrep", "semgrep --help"),
        ("tooling/sqlmap", "sqlmap -h"),
        ("tooling/subfinder", "subfinder -h"),
        ("coordination/root_agent", "Root-Owned Delegation"),
        ("scan_modes/deep", "root spawns specialized agents at the level"),
        ("custom/source_aware_sast", "ponytail"),
        ("custom/dependency_cve_scanning", "from locally available lockfiles"),
        ("vulnerabilities/subdomain_takeover", "rely on direct, reproducible provider responses"),
    ],
)
def test_lyrashield_skill_overlay_shadows_builtin(skill: str, marker: str) -> None:
    content = _content_for(skill)
    assert marker in content, f"Expected product marker for {skill} not found in overlay"


def test_builtin_skill_reverted_to_no_web_search(tool: str = "tooling/ffuf") -> None:
    """The built-in tooling skill is the upstream content (no product overlay)."""
    # This test uses the *same* register_skill_dir state, so the registered directory
    # is still searched first. To test the built-in content, we temporarily clear the
    # registry and then restore it.
    saved = _EXTRA_SKILL_DIRS[:]
    _EXTRA_SKILL_DIRS.clear()
    try:
        content = _content_for(tool)
        assert "use `ffuf -h`" not in content
        assert "web_search" in content
    finally:
        _EXTRA_SKILL_DIRS[:] = saved
