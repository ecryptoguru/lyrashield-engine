"""``AgentMessageBus`` — peer-to-peer multi-agent state for one scan.

A single ``asyncio.Lock``-protected dataclass that owns inboxes,
parent edges, statuses, and per-agent stats for the lifetime of one
Strix scan.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from agents.result import RunResultStreaming


logger = logging.getLogger(__name__)


@dataclass
class AgentMessageBus:
    """Shared state for multi-agent orchestration.

    All mutations happen under ``_lock``; readers also take the lock for
    consistent snapshots. The bus owns:

    - ``inboxes``: per-agent FIFO list of pending messages (drained by the
      ``inject_messages_filter`` at the top of each LLM turn).
    - ``tasks``: per-agent ``asyncio.Task`` handle so the parent (or signal
      handler) can cancel descendants.
    - ``streams``: per-agent ``RunResultStreaming`` handle so callers can
      request graceful ``cancel(mode="after_turn")`` mid-stream — the SDK
      saves the current turn to session before honoring the cancel.
    - ``statuses``: per-agent lifecycle state — ``running | waiting |
      completed | crashed | stopped | llm_failed``.
    - ``parent_of``: tree edges; root agents have ``None``.
    - ``names``: human-readable per-agent names.
    - ``stats_live`` / ``stats_completed``: token + call counters that hooks
      keep up to date for live and finalized agents respectively. Also
      carries per-agent-lifetime warning flags (``warned_85``,
      ``warned_final``).
    - ``stopping``: agent ids whose interactive outer-loop should exit on
      next iteration instead of waiting for more messages.
    """

    inboxes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    tasks: dict[str, asyncio.Task[Any]] = field(default_factory=dict)
    streams: dict[str, RunResultStreaming] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    parent_of: dict[str, str | None] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    stats_live: dict[str, dict[str, Any]] = field(default_factory=dict)
    stats_completed: dict[str, dict[str, Any]] = field(default_factory=dict)
    stopping: set[str] = field(default_factory=set)
    _events: dict[str, asyncio.Event] = field(default_factory=dict)
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
                "warned_85": False,
                "warned_final": False,
            }
        logger.info("bus.register %s (%s) parent=%s", agent_id, name, parent_id or "-")

    async def send(self, target: str, msg: dict[str, Any]) -> None:
        """Append a message to ``target``'s inbox.

        Messages addressed to a finalized agent are dropped silently —
        :meth:`finalize` clears the inbox so they can't accumulate.
        """
        async with self._lock:
            if target not in self.statuses:
                logger.debug("bus.send dropped (unknown target=%s)", target)
                return
            if self.statuses[target] in ("completed", "crashed", "stopped"):
                logger.debug(
                    "bus.send dropped (target=%s status=%s)",
                    target,
                    self.statuses[target],
                )
                return
            self.inboxes.setdefault(target, []).append(msg)
            event = self._events.get(target)
            if event is not None:
                event.set()
        sender = msg.get("from", "?")
        msg_type = msg.get("type", "message")
        content = str(msg.get("content", ""))
        logger.debug(
            "bus.send %s -> %s (type=%s len=%d): %s",
            sender,
            target,
            msg_type,
            len(content),
            content[:200],
        )

    async def wait_for_message(self, agent_id: str) -> None:
        """Block until ``agent_id``'s inbox has at least one pending message.

        Used by the interactive-mode outer loop in :func:`run_strix_scan` to
        wake on the next user message between ``Runner.run`` cycles. Cheap
        if the inbox already has content (returns immediately).
        """
        async with self._lock:
            if self.inboxes.get(agent_id):
                return
            event = self._events.setdefault(agent_id, asyncio.Event())
            event.clear()
        await event.wait()

    async def wait_for_user_message(self, agent_id: str) -> None:
        """Block until ``agent_id``'s inbox has a message with ``from='user'``.

        Used by the ``llm_failed`` recovery path: after a hard model failure,
        only direct user input should resume the agent — peer messages can't
        unstick a stuck model. Re-checks the inbox after each event in case
        only peer messages arrived.
        """
        while True:
            async with self._lock:
                for msg in self.inboxes.get(agent_id, []):
                    if msg.get("from") == "user":
                        return
                event = self._events.setdefault(agent_id, asyncio.Event())
                event.clear()
            await event.wait()

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
        if msgs:
            logger.debug("bus.drain %s -> %d message(s)", agent_id, len(msgs))
        return msgs

    async def record_usage(self, agent_id: str, usage: Any) -> None:
        """Accumulate per-call usage from RunHooks.on_llm_end.

        Tolerates ``usage=None`` (some providers omit usage on streaming).
        Increments ``calls`` unconditionally so it doubles as a per-agent
        lifetime turn counter (legacy ``state.iteration`` parity).
        """
        async with self._lock:
            stats = self.stats_live.setdefault(
                agent_id,
                {
                    "in": 0,
                    "out": 0,
                    "cached": 0,
                    "cost": 0.0,
                    "calls": 0,
                    "warned_85": False,
                    "warned_final": False,
                },
            )
            stats["calls"] += 1
            if usage is None:
                return
            stats["in"] += getattr(usage, "input_tokens", 0) or 0
            stats["out"] += getattr(usage, "output_tokens", 0) or 0
            details = getattr(usage, "input_tokens_details", None)
            if details is not None:
                stats["cached"] += getattr(details, "cached_tokens", 0) or 0

    async def finalize(self, agent_id: str, status: str) -> None:
        """Move an agent from live to completed; clean up routing state.

        Also clears ``inboxes``, ``parent_of``, ``names`` so siblings
        that send to a finished agent can't accumulate orphan messages.
        """
        async with self._lock:
            self.statuses[agent_id] = status
            self.stats_completed[agent_id] = self.stats_live.pop(agent_id, {})
            self.inboxes.pop(agent_id, None)
            self.parent_of.pop(agent_id, None)
            self.names.pop(agent_id, None)
            self.streams.pop(agent_id, None)
            self.stopping.discard(agent_id)
            self._events.pop(agent_id, None)
        logger.info("bus.finalize %s status=%s", agent_id, status)

    async def park(self, agent_id: str) -> None:
        """Mark an agent as ``waiting`` without finalizing.

        Used in interactive mode for the root agent between ``Runner.run``
        cycles: the run completed, but the agent stays alive on the bus
        so user messages still land in its inbox until the next cycle
        starts. Stats stay live (will be merged on actual finalize at
        scan teardown).
        """
        async with self._lock:
            if agent_id in self.statuses:
                self.statuses[agent_id] = "waiting"
        logger.debug("bus.park %s", agent_id)

    async def mark_llm_failed(self, agent_id: str) -> None:
        """Mark an agent as ``llm_failed`` after retries exhausted.

        Mirrors legacy ``state.llm_failed`` semantics: only direct user
        input can resume the agent (see :meth:`wait_for_user_message`).
        Status survives until the next ``Runner.run`` cycle starts and
        ``on_agent_start`` mirrors it back to ``running``, or finalize
        clears it.
        """
        async with self._lock:
            if agent_id in self.statuses:
                self.statuses[agent_id] = "llm_failed"
        logger.warning("bus.mark_llm_failed %s — awaiting user resume", agent_id)

    @contextlib.asynccontextmanager
    async def attach_stream(
        self,
        agent_id: str,
        streamed: RunResultStreaming,
    ) -> AsyncIterator[None]:
        """Register ``streamed`` so ``request_interrupt`` can find it; clean up after."""
        async with self._lock:
            self.streams[agent_id] = streamed
        try:
            yield
        finally:
            async with self._lock:
                if self.streams.get(agent_id) is streamed:
                    self.streams.pop(agent_id, None)

    async def request_interrupt(
        self,
        agent_id: str,
        mode: str = "after_turn",
    ) -> bool:
        """Ask the agent's active streaming run to cancel gracefully.

        Returns True if a streaming run was attached (so a cancel request
        was issued), False otherwise. ``mode='after_turn'`` lets the SDK
        finish the current turn — including saving items to session — so
        cancellation never leaves orphan tool outputs or truncated
        assistant messages. ``mode='immediate'`` is the hard variant.
        """
        async with self._lock:
            streamed = self.streams.get(agent_id)
        if streamed is None:
            logger.debug("bus.request_interrupt %s — no active stream", agent_id)
            return False
        streamed.cancel(mode=mode)  # type: ignore[arg-type]  # mode is a Literal
        logger.info("bus.request_interrupt %s mode=%s", agent_id, mode)
        return True

    async def total_stats(self) -> dict[str, Any]:
        """Snapshot of live + completed stats. Excludes warning flags."""
        async with self._lock:
            agg = {"in": 0, "out": 0, "cached": 0, "cost": 0.0, "calls": 0}
            for stats in (*self.stats_live.values(), *self.stats_completed.values()):
                for key in agg:
                    agg[key] += stats.get(key, 0)
            return agg

    async def cancel_descendants(self, root_agent_id: str) -> None:
        """Cancel ``root_agent_id`` and every transitive child, leaves first.

        Wired into the CLI Ctrl+C handler and TUI stop button —
        the SDK's ``result.cancel`` doesn't cascade to children spawned
        via ``asyncio.create_task``, so we walk the tree ourselves.

        This is the **hard** path: ``task.cancel()`` raises ``CancelledError``
        immediately, which may truncate a turn mid-stream. For graceful
        cascading stops use :meth:`cancel_descendants_graceful`.
        """
        async with self._lock:
            queue = [root_agent_id]
            order: list[str] = []
            while queue:
                aid = queue.pop()
                order.append(aid)
                queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
            tasks_to_cancel = [self.tasks[a] for a in reversed(order) if a in self.tasks]
        logger.info(
            "bus.cancel_descendants %s (hard, %d task(s))",
            root_agent_id,
            len(tasks_to_cancel),
        )
        for task in tasks_to_cancel:
            if not task.done():
                task.cancel()
        # Wait for cancellations to settle so on_agent_end can mark statuses.
        await asyncio.gather(
            *(t for t in tasks_to_cancel if not t.done()),
            return_exceptions=True,
        )

    async def cancel_descendants_graceful(self, root_agent_id: str) -> None:
        """Graceful cascade: ``request_interrupt`` per node, leaves-first.

        Each node's current turn finishes (and is saved to session) before
        the run loop honors the cancel. The interactive outer loop sees
        the agent in ``stopping`` and returns instead of awaiting more
        messages, so finalize fires with status="stopped".
        """
        async with self._lock:
            queue = [root_agent_id]
            order: list[str] = []
            while queue:
                aid = queue.pop()
                order.append(aid)
                queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
            for aid in order:
                self.stopping.add(aid)
            streams_to_cancel = [
                (aid, self.streams[aid]) for aid in reversed(order) if aid in self.streams
            ]
        logger.info(
            "bus.cancel_descendants_graceful %s (%d active stream(s), %d total)",
            root_agent_id,
            len(streams_to_cancel),
            len(order),
        )
        for _aid, streamed in streams_to_cancel:
            streamed.cancel(mode="after_turn")
