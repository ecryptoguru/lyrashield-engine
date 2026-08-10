# 2026 LyraShield --- controlled-derivative seam: delegates prompt resolution and rendering.
"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from lyrashield.agents.prompt import _resolve_skills as _lyra_resolve_skills
from lyrashield.agents.prompt import render_system_prompt as _lyra_render_system_prompt


logger = logging.getLogger(__name__)

__all__ = ["_resolve_skills", "render_system_prompt"]


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. ``scan_modes/<mode>`` (always).
    3. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    4. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``caido_api`` for Caido automation).
    5. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    6. Whitebox-specific skills if applicable.
    """
    return _lyra_resolve_skills(
        requested=requested,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=is_root,
    )


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> str:
    """Render the system prompt. Returns empty string on template failure."""
    try:
        return _lyra_render_system_prompt(
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            interactive=interactive,
            system_prompt_context=system_prompt_context,
        )
    except RuntimeError:
        logger.exception("render_system_prompt failed; returning empty prompt")
        return ""
