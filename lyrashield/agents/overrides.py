# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Deferred product registrations for the agent factory.

The product entry point registers tool overrides and model policies here as
loader callables instead of importing their modules at CLI startup. Non-scan
subcommands (auth, view, provider-contract) never build an agent, so those
imports are deferred until the factory first needs a registration.

Keeping these queues in a module with no product-tool imports is what lets
the entry point register everything without importing the factory, which
itself imports the full product toolset at module load.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable

    from agents.tool import Tool


_tool_override_loaders: dict[str, Callable[[], Tool]] = {}
_model_policy_loaders: dict[str, Callable[[], Callable[..., object]]] = {}


def register_tool_override_loader(name: str, load: Callable[[], Tool]) -> None:
    """Queue a tool override; ``load`` imports and returns the tool on demand."""
    _tool_override_loaders[name] = load


def register_model_policy_loader(name: str, load: Callable[[], Callable[..., object]]) -> None:
    """Queue a model-policy helper; ``load`` imports it on demand."""
    _model_policy_loaders[name] = load


def drain_tool_override_loaders() -> dict[str, Callable[[], Tool]]:
    """Return and forget the queued tool overrides (resolved by the factory)."""
    pending = dict(_tool_override_loaders)
    _tool_override_loaders.clear()
    return pending


def drain_model_policy_loaders() -> dict[str, Callable[[], Callable[..., object]]]:
    """Return and forget the queued model policies (resolved by the factory)."""
    pending = dict(_model_policy_loaders)
    _model_policy_loaders.clear()
    return pending
