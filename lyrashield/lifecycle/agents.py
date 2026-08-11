# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK-native state for Strix's addressable agent graph."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from lyrashield.lifecycle.sessions import session_write_lock


if TYPE_CHECKING:
    from collections.abc import Callable

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)

Status = Literal["running", "waiting", "completed", "stopped", "crashed", "failed", "budget_paused"]

# Why an agent parked. The user can message any agent, so this - not the agent's
# position in the tree - decides whether waiting is bounded: only an agent waiting
# on other agents is re-checked on a timer.
WaitKind = Literal["user", "agents", "stalled"]

_ACTIVE_STATUSES: frozenset[str] = frozenset({"running", "waiting"})

_SNAPSHOT_SCHEMA: dict[str, type] = {
    "statuses": dict,
    "parent_of": dict,
    "names": dict,
    "metadata": dict,
    "pending_counts": dict,
    "recovery_counts": dict,
    "idle_resume_counts": dict,
    "wait_kinds": dict,
    "mailboxes": dict,
    "errors": dict,
    "conversation_ids": dict,
}


@dataclass(slots=True)
class AgentRuntime:
    session: Session | None = None
    task: asyncio.Task[Any] | None = None
    stream: Any | None = None
    interrupt_on_message: bool = False
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    mailbox: list[dict[str, Any]] = field(default_factory=list)
    user_wake_required: bool = False


class AgentCoordinator:
    """Single owner for graph state, SDK runtimes, messages, and resume snapshots."""

    def __init__(self, *, max_agents: int = 64) -> None:
        self.statuses: dict[str, Status] = {}
        self.parent_of: dict[str, str | None] = {}
        self.names: dict[str, str] = {}
        self.metadata: dict[str, dict[str, Any]] = {}
        self.pending_counts: dict[str, int] = {}
        self.errors: dict[str, str] = {}
        self.conversation_ids: dict[str, str] = {}
        self.recovery_counts: dict[str, int] = {}
        self.idle_resume_counts: dict[str, int] = {}
        self.wait_kinds: dict[str, WaitKind] = {}
        self.runtimes: dict[str, AgentRuntime] = {}
        self._lock = asyncio.Lock()
        self._snapshot_lock = asyncio.Lock()
        self._snapshot_path: Path | None = None
        self.is_shutting_down = False
        self._budget_stopped = False
        self._reserve_stopped = False
        self._budget_paused = False
        self._extend_budget: Callable[[], None] | None = None
        self.max_agents = max(1, max_agents)

    async def can_spawn_agent(self) -> bool:
        async with self._lock:
            return len(self.statuses) < self.max_agents

    async def get_status(self, agent_id: str) -> Status | None:
        async with self._lock:
            return self.statuses.get(agent_id)

    async def get_parent_and_name(self, agent_id: str) -> tuple[str | None, str]:
        async with self._lock:
            return self.parent_of.get(agent_id), self.names.get(agent_id, agent_id)

    async def agents_with_metadata(
        self,
    ) -> list[tuple[str, Status, str | None, str, dict[str, Any]]]:
        async with self._lock:
            return [
                (
                    aid,
                    status,
                    self.parent_of.get(aid),
                    self.names.get(aid, aid),
                    dict(self.metadata.get(aid, {})),
                )
                for aid, status in self.statuses.items()
            ]

    async def maybe_snapshot(self) -> None:
        await self._maybe_snapshot()

    def set_snapshot_path(self, path: Path) -> None:
        self._snapshot_path = path

    def mark_shutting_down(self) -> None:
        self.is_shutting_down = True

    @property
    def budget_stopped(self) -> bool:
        return self._budget_stopped

    async def trigger_budget_stop(self) -> None:
        """Signal a scan-wide budget stop and wake every parked agent so it exits."""
        async with self._lock:
            self._budget_stopped = True
            for runtime in self.runtimes.values():
                runtime.wake.set()

    @property
    def reserve_stopped(self) -> bool:
        return self._reserve_stopped

    @property
    def budget_paused(self) -> bool:
        return self._budget_paused

    def set_budget_extender(self, extend: Callable[[], None]) -> None:
        self._extend_budget = extend

    async def pause_for_budget(self, agent_id: str) -> None:
        async with self._lock:
            self._budget_paused = True
        await self.set_status(agent_id, "budget_paused")

    async def resume_from_budget_pause(self, *, exclude: str | None = None) -> None:
        async with self._lock:
            if not self._budget_paused:
                return
            self._budget_paused = False
            paused = [aid for aid, status in self.statuses.items() if status == "budget_paused"]
        if self._extend_budget is not None:
            self._extend_budget()
        for aid in paused:
            await self.set_status(aid, "waiting")
            if aid != exclude:
                await self.send(
                    aid,
                    {
                        "from": "system",
                        "type": "budget_extended",
                        "content": (
                            "[Budget] The user extended the scan budget \u2014 continue your "
                            "current task."
                        ),
                    },
                )

    async def reset_budget_stops(
        self,
        *,
        budget_stopped: bool,
        reserve_stopped: bool,
        budget_paused: bool = False,
    ) -> None:
        async with self._lock:
            self._budget_stopped = budget_stopped
            self._reserve_stopped = reserve_stopped
            if not budget_paused:
                self._budget_paused = False
                for aid, status in self.statuses.items():
                    if status == "budget_paused":
                        self.statuses[aid] = "waiting"
        await self._maybe_snapshot()

    async def claim_reserve_notification(self) -> str | None:
        async with self._lock:
            if self._reserve_stopped:
                return None
            self._reserve_stopped = True
            for runtime in self.runtimes.values():
                runtime.wake.set()
            return next((aid for aid, parent in self.parent_of.items() if parent is None), None)

    async def register(
        self,
        agent_id: str,
        name: str,
        parent_id: str | None,
        *,
        task: str | None = None,
        skills: list[str] | None = None,
    ) -> None:
        async with self._lock:
            if agent_id not in self.statuses and len(self.statuses) >= self.max_agents:
                raise RuntimeError(f"Scan agent limit reached ({self.max_agents})")
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name
            self.pending_counts.setdefault(agent_id, 0)
            self.metadata[agent_id] = {
                "task": task or "",
                "skills": list(skills or []),
            }
            self.runtimes.setdefault(agent_id, AgentRuntime())
        logger.info("agent.register %s (%s) parent=%s", agent_id, name, parent_id or "-")
        await self._maybe_snapshot()

    async def attach_runtime(
        self,
        agent_id: str,
        *,
        session: Session | None = None,
        task: asyncio.Task[Any] | None = None,
        interrupt_on_message: bool | None = None,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if session is not None:
                runtime.session = session
            if task is not None:
                runtime.task = task
            if interrupt_on_message is not None:
                runtime.interrupt_on_message = interrupt_on_message

    async def mark_running(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id in self.statuses and self.statuses[agent_id] in _ACTIVE_STATUSES:
                self.statuses[agent_id] = "running"
                self.errors.pop(agent_id, None)
                self.wait_kinds.pop(agent_id, None)
                self.runtimes.setdefault(agent_id, AgentRuntime()).user_wake_required = False
        await self._maybe_snapshot()

    async def park_waiting(self, agent_id: str, *, wait_kind: WaitKind) -> None:
        """Park an agent, recording what it is waiting on so the driver can time it."""
        async with self._lock:
            if agent_id in self.statuses:
                self.wait_kinds[agent_id] = wait_kind
        await self.set_status(agent_id, "waiting")

    async def wait_kind_of(self, agent_id: str) -> WaitKind | None:
        async with self._lock:
            return self.wait_kinds.get(agent_id)

    async def record_recovery(self, agent_id: str) -> int:
        """Count a turn that ended without a lifecycle tool call; return the new total.

        Persisted so a resumed agent cannot earn a fresh nudge budget on every
        auto-resume and loop forever.
        """
        async with self._lock:
            count = self.recovery_counts.get(agent_id, 0) + 1
            self.recovery_counts[agent_id] = count
        await self._maybe_snapshot()
        return count

    async def reset_recovery(self, agent_id: str) -> None:
        """Clear the nudge budget after real progress (new message or a lifecycle tool)."""
        async with self._lock:
            if self.recovery_counts.pop(agent_id, None) is None:
                return
        await self._maybe_snapshot()

    async def record_idle_resume(self, agent_id: str) -> int:
        """Count an auto-resume that no message triggered; return the new total.

        An agent that parks again after every auto-resume would otherwise burn a
        model turn per timeout for the rest of the scan.
        """
        async with self._lock:
            count = self.idle_resume_counts.get(agent_id, 0) + 1
            self.idle_resume_counts[agent_id] = count
        await self._maybe_snapshot()
        return count

    async def reset_idle_resumes(self, agent_id: str) -> None:
        async with self._lock:
            if self.idle_resume_counts.pop(agent_id, None) is None:
                return
        await self._maybe_snapshot()

    async def set_status(self, agent_id: str, status: Status, *, error: str | None = None) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = status
            if error is not None:
                self.errors[agent_id] = error
            elif status == "running":
                self.errors.pop(agent_id, None)
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.user_wake_required = status in {"failed", "crashed"}
            runtime.wake.set()
        logger.info("agent.status %s=%s", agent_id, status)
        await self._maybe_snapshot()

    async def send(
        self, target_agent_id: str, message: dict[str, Any], *, interrupt: bool = True
    ) -> bool:
        """Queue a user/peer message in the target's mailbox and wake it."""
        from_user = message.get("from") == "user"
        if from_user and self._budget_paused:
            await self.resume_from_budget_pause(exclude=target_agent_id)
        async with self._lock:
            if target_agent_id not in self.statuses:
                logger.debug("agent.send dropped unknown target=%s", target_agent_id)
                return False
            runtime = self.runtimes.setdefault(target_agent_id, AgentRuntime())
            # Follow-up work is valid after a child has reported completion.
            # Without reactivation the sender can wait forever on a mailbox no
            # execution loop will ever consume.
            if self.statuses[target_agent_id] in {"completed", "stopped"}:
                self.statuses[target_agent_id] = "running"
                self.errors.pop(target_agent_id, None)
                runtime.user_wake_required = False
            runtime.mailbox.append(dict(message))
            self.pending_counts[target_agent_id] = self.pending_counts.get(target_agent_id, 0) + 1
            if from_user:
                runtime.user_wake_required = False
            runtime.wake.set()
            stream = runtime.stream
            interrupt_on_message = runtime.interrupt_on_message
        if stream is not None and interrupt and interrupt_on_message:
            stream.cancel(mode="immediate")
        await self._maybe_snapshot()
        return True

    async def wait_for_message(self, agent_id: str, *, timeout: float | None = None) -> bool:
        """Wait until a message is ready for ``agent_id``; False on ``timeout``."""
        while True:
            async with self._lock:
                runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
                reserve_exit = self._reserve_stopped and self.parent_of.get(agent_id) is not None
                pending_ready = (
                    self.pending_counts.get(agent_id, 0) > 0 and not runtime.user_wake_required
                )
                if self._budget_stopped or reserve_exit or pending_ready:
                    return True
                wake = runtime.wake
                wake.clear()
            if timeout is None:
                await wake.wait()
            else:
                try:
                    await asyncio.wait_for(wake.wait(), timeout)
                except TimeoutError:
                    return False

    async def consume_pending(
        self,
        agent_id: str,
        *,
        include_items: bool = False,
    ) -> tuple[int, list[Any]]:
        """Drain the agent's mailbox into its own SDK session."""
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            queued = list(runtime.mailbox)
            runtime.mailbox.clear()
            count = max(self.pending_counts.get(agent_id, 0), len(queued))
            self.pending_counts[agent_id] = 0
            session = runtime.session
        if count <= 0:
            return 0, []
        try:
            items = [self._message_to_session_item(m) for m in queued]
        except Exception:
            async with self._lock:
                runtime.mailbox[:0] = queued
            logger.exception("failed to convert queued messages for %s", agent_id)
            return 0, []
        if not items:
            return 0, []
        if session is None:
            logger.debug(
                "agent %s has no SDK session attached; "
                "%d queued messages returned to caller without persistence",
                agent_id,
                len(items),
            )
            await self._maybe_snapshot()
            if not include_items:
                return count, []
            return count, items
        try:
            async with session_write_lock(session):
                await session.add_items(items)
        except Exception:
            async with self._lock:
                runtime.mailbox[:0] = queued
            logger.exception(
                "failed to append %d queued messages to the session of %s",
                len(items),
                agent_id,
            )
            return 0, []
        await self._maybe_snapshot()
        if not include_items:
            return count, []
        return count, items

    async def _notify_parent(
        self,
        agent_id: str,
        status: str,
        *,
        content: str | None = None,
    ) -> bool:
        """Wake the parent with a terminal-status note for one of its children."""
        if self.budget_stopped:
            return False
        if status not in {"crashed", "failed", "stopped", "completed"}:
            return False
        async with self._lock:
            parent_id = self.parent_of.get(agent_id)
            agent_name = self.names.get(agent_id, agent_id)
        if parent_id is None:
            return False
        if content is None:
            content = (
                f"[Agent {status}] {agent_name} ({agent_id}) is no longer active. "
                "Stop waiting on this child unless you want to message it again."
            )
        return await self.send(
            parent_id,
            {
                "id": f"notify_{uuid.uuid4().hex[:8]}",
                "from": agent_id,
                "type": status,
                "priority": "high",
                "content": content,
            },
        )

    async def request_stop(self, agent_id: str) -> None:
        parent_id: str | None = None
        was_active = False
        async with self._lock:
            status = self.statuses.get(agent_id)
            if status is None:
                return
            was_active = status in _ACTIVE_STATUSES
            if was_active:
                self.statuses[agent_id] = "stopped"
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.wake.set()
            stream = runtime.stream
            parent_id = self.parent_of.get(agent_id)
        if stream is not None:
            stream.cancel(mode="after_turn")
        if was_active and parent_id is not None:
            await self._notify_parent(agent_id, "stopped")
        await self._maybe_snapshot()

    async def cancel_descendants(self, agent_id: str) -> None:
        tasks: list[asyncio.Task[Any]] = []
        order: list[str] = []
        async with self._lock:
            order = list(reversed(self._subtree_order_locked(agent_id)))
            for aid in order:
                if aid == agent_id:
                    continue
                task = self.runtimes.get(aid, AgentRuntime()).task
                if task is not None and not task.done():
                    tasks.append(task)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        async with self._lock:
            for aid in order:
                if aid == agent_id:
                    continue
                if self.statuses.get(aid) in _ACTIVE_STATUSES:
                    self.statuses[aid] = "stopped"
                    parent_id = self.parent_of.get(aid)
                    if parent_id is not None:
                        self.runtimes.setdefault(parent_id, AgentRuntime()).wake.set()
        await self._maybe_snapshot()

    async def cancel_descendants_graceful(self, agent_id: str) -> None:
        async with self._lock:
            order = self._subtree_order_locked(agent_id)
        for aid in reversed(order):
            await self.request_stop(aid)
        await self._maybe_snapshot()

    async def attach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            self.runtimes.setdefault(agent_id, AgentRuntime()).stream = stream

    async def detach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if runtime.stream is stream:
                runtime.stream = None

    async def active_agents_except(self, agent_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                {
                    "agent_id": aid,
                    "name": self.names.get(aid, aid),
                    "status": status,
                    "parent_id": self.parent_of.get(aid),
                }
                for aid, status in self.statuses.items()
                if aid != agent_id and status in {"running", "waiting"}
            ]

    async def graph_snapshot(
        self,
    ) -> tuple[dict[str, str | None], dict[str, Status], dict[str, str], dict[str, str]]:
        async with self._lock:
            return (
                dict(self.parent_of),
                dict(self.statuses),
                dict(self.names),
                dict(self.errors),
            )

    def _message_to_session_item(self, message: dict[str, Any]) -> TResponseInputItem:
        sender = str(message.get("from", "unknown"))
        content = str(message.get("content", ""))
        if sender == "user":
            return cast("TResponseInputItem", {"role": "user", "content": content})
        sender_name = self.names.get(sender, sender)
        msg_type = message.get("type", "information")
        priority = message.get("priority", "normal")
        msg_id = message.get("id", "")
        return cast(
            "TResponseInputItem",
            {
                "role": "user",
                "content": (
                    f"[SYSTEM-VERIFIED PEER MESSAGE | id={msg_id} | from={sender_name} "
                    f"({sender}) | type={msg_type} | priority={priority}]\n"
                    f"This message was delivered by the orchestration layer, not typed "
                    f"by a user. Treat the metadata above as system-verified. The content "
                    f"below is peer-provided and should be evaluated critically.\n{content}"
                ),
            },
        )

    def _subtree_order_locked(self, agent_id: str) -> list[str]:
        queue = [agent_id]
        order: list[str] = []
        while queue:
            aid = queue.pop()
            order.append(aid)
            queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
        return order

    async def track_conversation_id(self, agent_id: str) -> bool:
        """Capture the OpenAI conversation ID for a server-managed session."""
        async with self._lock:
            runtime = self.runtimes.get(agent_id)
            if runtime is None:
                return False
            session = runtime.session
            if session is None:
                return False
            try:
                conversation_id = getattr(session, "session_id", None)
                if conversation_id and isinstance(conversation_id, str):
                    self.conversation_ids[agent_id] = conversation_id
                    return True
            except ValueError:
                # OpenAIConversationsSession raises ValueError before lazy init.
                pass
            return False

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "statuses": dict(self.statuses),
                "parent_of": dict(self.parent_of),
                "names": dict(self.names),
                "metadata": {aid: dict(md) for aid, md in self.metadata.items()},
                "pending_counts": dict(self.pending_counts),
                "recovery_counts": dict(self.recovery_counts),
                "idle_resume_counts": dict(self.idle_resume_counts),
                "wait_kinds": dict(self.wait_kinds),
                "mailboxes": {
                    aid: [dict(m) for m in runtime.mailbox]
                    for aid, runtime in self.runtimes.items()
                    if runtime.mailbox
                },
                "errors": dict(self.errors),
                "conversation_ids": dict(self.conversation_ids),
                "budget_stopped": self._budget_stopped,
                "reserve_stopped": self._reserve_stopped,
                "budget_paused": self._budget_paused,
            }

    async def restore(self, snap: dict[str, Any]) -> None:
        if not isinstance(snap, dict):
            raise TypeError("agent snapshot must be a mapping")
        for key, expected in _SNAPSHOT_SCHEMA.items():
            value = snap.get(key)
            if value is not None and not isinstance(value, expected):
                got = type(value).__name__
                raise TypeError(f"agent snapshot {key!r} must be a {expected.__name__}, got {got}")

        async with self._lock:
            self.statuses = dict(snap.get("statuses", {}))
            self.parent_of = dict(snap.get("parent_of", {}))
            self.names = dict(snap.get("names", {}))
            self.metadata = {aid: dict(md) for aid, md in snap.get("metadata", {}).items()}
            self.pending_counts = dict(snap.get("pending_counts", {}))
            self.errors = dict(snap.get("errors", {}))
            self.conversation_ids = dict(snap.get("conversation_ids", {}))
            self.recovery_counts = dict(snap.get("recovery_counts", {}))
            self.idle_resume_counts = dict(snap.get("idle_resume_counts", {}))
            self.wait_kinds = dict(snap.get("wait_kinds", {}))
            mailboxes = snap.get("mailboxes", {})
            if isinstance(mailboxes, dict):
                for aid, msgs in mailboxes.items():
                    if isinstance(msgs, list):
                        runtime = self.runtimes.setdefault(aid, AgentRuntime())
                        runtime.mailbox = [dict(m) for m in msgs if isinstance(m, dict)]
            self._budget_stopped = bool(snap.get("budget_stopped", False))
            self._reserve_stopped = bool(snap.get("reserve_stopped", False))
            self._budget_paused = bool(snap.get("budget_paused", False))
            for aid in self.statuses:
                self.runtimes.setdefault(aid, AgentRuntime())

    async def _maybe_snapshot(self) -> None:
        path = self._snapshot_path
        if path is None:
            return
        try:
            async with self._snapshot_lock:
                data = await self.snapshot()
                payload = json.dumps(data, ensure_ascii=False, default=str)
                path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=str(path.parent),
                    prefix=f".{path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as tmp:
                    tmp.write(payload)
                    tmp_path = Path(tmp.name)
                try:
                    tmp_path.replace(path)
                finally:
                    with contextlib.suppress(OSError):
                        tmp_path.unlink(missing_ok=True)
        except Exception:
            logger.exception("coordinator snapshot to %s failed", path)


def coordinator_from_context(ctx: dict[str, Any]) -> AgentCoordinator | None:
    coordinator = ctx.get("coordinator")
    return coordinator if isinstance(coordinator, AgentCoordinator) else None
