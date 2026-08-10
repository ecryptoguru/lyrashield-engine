# 2026 LyraShield --- controlled-derivative seam: delegates agent factory and tool registration.
"""Build SandboxAgents for root + child Strix runs."""

from __future__ import annotations

from lyrashield.agents.factory import (
    _EXTRA_TOOLS,
    _TOOL_OVERRIDES,
    _apply_tool_overrides,
    _configure_filesystem_tools,
    _model_policy,
    _wrap_exec_command,
    _wrap_write_stdin,
    build_strix_agent,
    make_child_factory,
    register_agent_tools,
    register_model_policy,
    register_tool_override,
    registered_agent_tools,
)


__all__ = [
    "_EXTRA_TOOLS",
    "_TOOL_OVERRIDES",
    "_apply_tool_overrides",
    "_configure_filesystem_tools",
    "_model_policy",
    "_wrap_exec_command",
    "_wrap_write_stdin",
    "build_strix_agent",
    "make_child_factory",
    "register_agent_tools",
    "register_model_policy",
    "register_tool_override",
    "registered_agent_tools",
]
