"""AgentMessageBus — peer-to-peer multi-agent state owned by Strix.

Replaces the legacy harness's _agent_graph / _agent_messages / _agent_instances
globals (in strix/tools/agents_graph/agents_graph_actions.py) with a single
asyncio.Lock-protected dataclass that lives for the lifetime of one Strix scan.

References:
    - PLAYBOOK.md §2.3
    - AUDIT_R2.md §1.4 (cancel_descendants)
    - AUDIT_R2.md §1.7 (stats snapshot under lock)
    - AUDIT_R3.md C13 (finalize cleans up state to avoid orphaned-message leak)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentMessageBus:
    """Shared state for multi-agent orchestration.

    All mutations happen under ``_lock``; readers also take the lock for
    consistent snapshots. The bus owns:

    - ``inboxes``: per-agent FIFO list of pending messages (drained by the
      ``inject_messages_filter`` at the top of each LLM turn).
    - ``tasks``: per-agent ``asyncio.Task`` handle so the parent (or signal
      handler) can cancel descendants.
    - ``statuses``: per-agent lifecycle state — ``running | waiting |
      completed | crashed | stopped``.
    - ``parent_of``: tree edges; root agents have ``None``.
    - ``names``: human-readable per-agent names.
    - ``stats_live`` / ``stats_completed``: token + call counters that hooks
      keep up to date for live and finalized agents respectively.
    """

    inboxes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    tasks: dict[str, asyncio.Task[Any]] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    parent_of: dict[str, str | None] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    stats_live: dict[str, dict[str, Any]] = field(default_factory=dict)
    stats_completed: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def register(
        self,
        agent_id: str,
        name: str,
        parent_id: str | None,
    ) -> None:
        """Add a new agent to the bus before its Runner.run task starts."""
        async with self._lock:
            self.inboxes[agent_id] = []
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name
            self.stats_live[agent_id] = {
                "in": 0,
                "out": 0,
                "cached": 0,
                "cost": 0.0,
                "calls": 0,
            }

    async def send(self, target: str, msg: dict[str, Any]) -> None:
        """Append a message to ``target``'s inbox.

        Idempotent if target was never registered: creates an empty inbox.
        Messages addressed to a finalized agent are dropped silently — the
        target's inbox was cleared in :meth:`finalize` (C13).
        """
        async with self._lock:
            if target not in self.statuses:
                return
            if self.statuses[target] in ("completed", "crashed", "stopped"):
                return
            self.inboxes.setdefault(target, []).append(msg)

    async def drain(self, agent_id: str) -> list[dict[str, Any]]:
        """Atomically read and clear ``agent_id``'s pending messages.

        Called by ``inject_messages_filter`` before every model call.
        Filter output is captured by SDK in a lambda closure for retries
        (verified `model_retry.py:34-35`), so a single drain per turn does
        not lose messages on retry.
        """
        async with self._lock:
            msgs = self.inboxes.get(agent_id, [])
            self.inboxes[agent_id] = []
            return msgs

    async def record_usage(self, agent_id: str, usage: Any) -> None:
        """Accumulate per-call usage from RunHooks.on_llm_end.

        Tolerates ``usage=None`` (some providers omit usage on streaming).
        """
        if usage is None:
            return
        async with self._lock:
            stats = self.stats_live.setdefault(
                agent_id,
                {"in": 0, "out": 0, "cached": 0, "cost": 0.0, "calls": 0},
            )
            stats["in"] += getattr(usage, "input_tokens", 0) or 0
            stats["out"] += getattr(usage, "output_tokens", 0) or 0
            details = getattr(usage, "input_tokens_details", None)
            if details is not None:
                stats["cached"] += getattr(details, "cached_tokens", 0) or 0
            stats["calls"] += 1

    async def finalize(self, agent_id: str, status: str) -> None:
        """Move an agent from live to completed; clean up routing state.

        C13 (AUDIT_R3): also clears ``inboxes``, ``parent_of``, ``names`` so
        sibling agents that try to send to a finished agent don't accumulate
        orphan messages forever.
        """
        async with self._lock:
            self.statuses[agent_id] = status
            self.stats_completed[agent_id] = self.stats_live.pop(agent_id, {})
            self.inboxes.pop(agent_id, None)
            self.parent_of.pop(agent_id, None)
            self.names.pop(agent_id, None)

    async def total_stats(self) -> dict[str, Any]:
        """Snapshot of live + completed stats. Lock-protected (C12)."""
        async with self._lock:
            agg = {"in": 0, "out": 0, "cached": 0, "cost": 0.0, "calls": 0}
            for stats in (*self.stats_live.values(), *self.stats_completed.values()):
                for key, value in stats.items():
                    agg[key] = agg.get(key, 0) + value
            return agg

    async def cancel_descendants(self, root_agent_id: str) -> None:
        """Cancel ``root_agent_id`` and every transitive child, leaves first.

        Wired into the CLI Ctrl+C handler and TUI stop button so a root cancel
        actually propagates (C9 — SDK's ``result.cancel`` does not cascade
        to children spawned via ``asyncio.create_task``).
        """
        async with self._lock:
            queue = [root_agent_id]
            order: list[str] = []
            while queue:
                aid = queue.pop()
                order.append(aid)
                queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
            tasks_to_cancel = [self.tasks[a] for a in reversed(order) if a in self.tasks]
        for task in tasks_to_cancel:
            if not task.done():
                task.cancel()
        # Wait for cancellations to settle so on_agent_end can mark statuses.
        await asyncio.gather(
            *(t for t in tasks_to_cancel if not t.done()),
            return_exceptions=True,
        )
