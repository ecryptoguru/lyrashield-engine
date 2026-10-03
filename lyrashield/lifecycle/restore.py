# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Restore scan coordination state before sandbox bring-up."""

from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING, Any

from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.tools.notes.tools import hydrate_notes_from_disk
from lyrashield.tools.todo.tools import hydrate_todos_from_disk
from strix.tools.coverage.tools import hydrate_coverage_from_disk
from strix.tools.threat_model.tools import hydrate_threat_models_from_disk


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_MODE_AGENT_LIMITS = {"quick": 4, "standard": 4, "deep": 6}


def _coordinator_for_scan_mode(
    coordinator: Any | None,
    scan_mode: str,
    *,
    coordinator_factory: Callable[..., Any] = AgentCoordinator,
) -> Any:
    mode_agent_limit = _MODE_AGENT_LIMITS.get(scan_mode, 4)
    if coordinator is None:
        return coordinator_factory(max_agents=mode_agent_limit)
    if len(coordinator.statuses) > mode_agent_limit:
        raise RuntimeError(
            f"Existing coordinator has {len(coordinator.statuses)} agents, "
            f"above the {scan_mode} mode limit ({mode_agent_limit})",
        )
    coordinator.max_agents = min(coordinator.max_agents, mode_agent_limit)
    return coordinator


async def restore_coordinator(
    *,
    coordinator: Any | None,
    coordinator_factory: Callable[..., Any],
    scan_mode: str,
    state_dir: Path,
    agents_path: Path,
    agents_db: Path,
    scan_id: str,
    is_resume: bool,
    max_budget_usd: float | None,
    interactive: bool,
    report_state_getter: Callable[[], Any | None],
    recomputed_budget_flags: Callable[..., tuple[bool, bool]],
) -> tuple[Any, str]:
    """Hydrate persistent stores and return a mode-limited coordinator/root."""
    if coordinator is None:
        coordinator = coordinator_factory()
    coordinator.set_snapshot_path(agents_path)

    # The coverage ledger and threat-model store are module-global; hydrating
    # every run binds them to this run's state dir and clears prior scan state.
    hydrate_coverage_from_disk(state_dir)
    hydrate_threat_models_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)

    root_id: str | None = None
    if is_resume:
        hydrate_todos_from_disk(state_dir)
        if agents_path.is_symlink() or not agents_path.is_file():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is not a regular file",
            )
        if agents_db.is_symlink() or not agents_db.is_file():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.db is not a regular file",
            )
        try:
            snapshot = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snapshot)
        report_state = report_state_getter()
        if report_state is not None:
            hydrated_cost = report_state.get_total_llm_cost()
            budget_stopped, reserve_stopped = recomputed_budget_flags(
                hydrated_cost,
                max_budget_usd,
                interactive=interactive,
            )
            at_budget = max_budget_usd is not None and hydrated_cost >= max_budget_usd
            await coordinator.reset_budget_stops(
                budget_stopped=budget_stopped,
                reserve_stopped=reserve_stopped,
                budget_paused=interactive and (coordinator.budget_paused or at_budget),
            )
        for agent_id, parent_id in coordinator.parent_of.items():
            if parent_id is None:
                root_id = agent_id
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    return _coordinator_for_scan_mode(
        coordinator,
        scan_mode,
        coordinator_factory=coordinator_factory,
    ), root_id
