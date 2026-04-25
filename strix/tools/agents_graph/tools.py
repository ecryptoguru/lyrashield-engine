"""Multi-agent graph tools — read/write the :class:`AgentMessageBus`.

- ``view_agent_graph``: render the parent/child tree.
- ``agent_status``: per-agent status + pending message count.
- ``send_message_to_agent``: queue a message in another agent's inbox.
- ``wait_for_message``: pause this agent until a message arrives or
  ``timeout_seconds`` elapses.
- ``create_agent``: spawn a child via
  ``asyncio.create_task(Runner.run(...))``; the task handle is stored
  so a root-level cancel cascades to descendants.
- ``agent_finish``: subagents only — flips ``agent_finish_called`` so
  the ``on_agent_end`` hook records "completed" rather than "crashed",
  and posts a structured completion report to the parent's inbox.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import TYPE_CHECKING, Any, Literal

from agents import RunContextWrapper, Runner
from agents.items import TResponseInputItem

from strix.orchestration.hooks import StrixOrchestrationHooks
from strix.run_config_factory import make_agent_context, make_run_config
from strix.tools._decorator import dump_tool_result, strix_tool


if TYPE_CHECKING:
    from collections.abc import Callable

    from agents import Agent as SDKAgent


logger = logging.getLogger(__name__)


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


@strix_tool(timeout=30)
async def view_agent_graph(ctx: RunContextWrapper) -> str:
    """Print the multi-agent tree — every agent, its parent, its status.

    Use before spawning a new agent (don't duplicate work — check whether
    something specialized for that task already exists) and any time you
    want a snapshot of who's still ``running`` / ``waiting`` /
    ``completed`` / ``crashed`` / ``stopped``. Output is an indented
    bullet list with status in brackets; the agent that called this tool
    is marked ``← you``.
    """
    inner = _ctx(ctx)
    bus = inner.get("bus")
    me = inner.get("agent_id")
    if bus is None:
        return dump_tool_result({"success": False, "error": "Bus not initialized in context."})

    async with bus._lock:
        parent_of = dict(bus.parent_of)
        statuses = dict(bus.statuses)
        names = dict(bus.names)

    lines: list[str] = []

    def render(aid: str, depth: int) -> None:
        status = statuses.get(aid, "?")
        marker = "  ← you" if aid == me else ""
        lines.append(f"{'  ' * depth}- {names.get(aid, aid)} ({aid}) [{status}]{marker}")
        for child, p in parent_of.items():
            if p == aid:
                render(child, depth + 1)

    roots = [aid for aid, parent in parent_of.items() if parent is None]
    for root in roots:
        render(root, 0)

    summary = {
        "total": len(parent_of),
        "running": sum(1 for s in statuses.values() if s == "running"),
        "waiting": sum(1 for s in statuses.values() if s == "waiting"),
        "completed": sum(1 for s in statuses.values() if s == "completed"),
        "crashed": sum(1 for s in statuses.values() if s == "crashed"),
        "stopped": sum(1 for s in statuses.values() if s == "stopped"),
    }
    return dump_tool_result(
        {
            "success": True,
            "graph_structure": "\n".join(lines) or "(no agents)",
            "summary": summary,
        }
    )


@strix_tool(timeout=30)
async def agent_status(ctx: RunContextWrapper, agent_id: str) -> str:
    """Look up one agent's lifecycle state + pending message count.

    Use when you need precise state on a specific agent (e.g., "is the
    XSS specialist still going?") rather than the full tree view.
    Returns ``status`` (``running`` / ``waiting`` / ``completed`` /
    ``crashed`` / ``stopped``), ``parent_id``, and ``pending_messages``.

    Args:
        agent_id: The 8-char id from ``view_agent_graph`` /
            ``create_agent``.
    """
    inner = _ctx(ctx)
    bus = inner.get("bus")
    if bus is None:
        return dump_tool_result({"success": False, "error": "Bus not initialized in context."})

    async with bus._lock:
        if agent_id not in bus.statuses:
            return dump_tool_result(
                {
                    "success": False,
                    "error": f"Unknown agent_id: {agent_id}",
                }
            )
        return dump_tool_result(
            {
                "success": True,
                "agent_id": agent_id,
                "name": bus.names.get(agent_id),
                "status": bus.statuses.get(agent_id),
                "parent_id": bus.parent_of.get(agent_id),
                "pending_messages": len(bus.inboxes.get(agent_id, [])),
            }
        )


@strix_tool(timeout=30)
async def send_message_to_agent(
    ctx: RunContextWrapper,
    target_agent_id: str,
    message: str,
    message_type: Literal["query", "instruction", "information"] = "information",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> str:
    """Send a message to another agent's inbox — sparingly.

    Inter-agent messages are surfaced at the top of the target's next
    LLM turn. Use only when essential:

    - Sharing a discovered finding/credential another agent needs.
    - Asking a specialist a focused question.
    - Coordinating who covers what (avoid overlap).
    - Telling a child to wrap up or change course.

    **Don't** use for routine "hello/status" pings, for context the
    target already has (children inherit parent history), or when
    parent/child completion via ``agent_finish`` already covers the
    flow. Messages to a finalized agent are dropped.

    Args:
        target_agent_id: Recipient's 8-char id.
        message: The full message body. Be specific — include payloads,
            URLs, or what you want them to do, not just headlines.
        message_type: ``query`` (you want a reply), ``instruction``
            (you're directing them), ``information`` (FYI, no reply
            expected). Default ``information``.
        priority: ``low`` / ``normal`` / ``high`` / ``urgent``.
    """
    inner = _ctx(ctx)
    bus = inner.get("bus")
    me = inner.get("agent_id")
    if bus is None or me is None:
        return dump_tool_result({"success": False, "error": "Bus or agent_id missing in context."})

    async with bus._lock:
        if target_agent_id not in bus.statuses:
            return dump_tool_result(
                {
                    "success": False,
                    "error": f"Target agent '{target_agent_id}' not found.",
                }
            )
        target_status = bus.statuses.get(target_agent_id)

    if target_status in ("completed", "crashed", "stopped"):
        return dump_tool_result(
            {
                "success": False,
                "error": f"Target agent '{target_agent_id}' is {target_status}; message dropped.",
            }
        )

    msg_id = f"msg_{uuid.uuid4().hex[:8]}"
    await bus.send(
        target_agent_id,
        {
            "id": msg_id,
            "from": me,
            "content": message,
            "type": message_type,
            "priority": priority,
        },
    )
    return dump_tool_result(
        {
            "success": True,
            "message_id": msg_id,
            "target_agent_id": target_agent_id,
            "delivery_status": "queued",
        }
    )


# Tighter would burn CPU; slacker would feel laggy when a sibling
# delivers a message right after the wait starts.
_WAIT_POLL_SECONDS = 1.0


@strix_tool(timeout=601)
async def wait_for_message(
    ctx: RunContextWrapper,
    reason: str = "Waiting for messages from other agents",
    timeout_seconds: int = 600,
) -> str:
    """Pause this agent until a message lands in its inbox (or timeout).

    Use when you have nothing useful to do until a child/peer responds
    — typically after spawning subagents and you want to wait for
    their completion reports. The agent automatically resumes when any
    message arrives.

    **Critical caveats:**

    - **Never** call this if you finished your own task and have **no**
      child agents running — that's a permanent stall. Call
      ``finish_scan`` (root) or ``agent_finish`` (subagent) instead.
    - If you're waiting on an agent that **isn't your child**, message
      it first asking it to ping you when done — otherwise it has no
      reason to send to your inbox and you'll wait the full timeout.
    - Children update the parent automatically via ``agent_finish``
      → no extra coordination needed.

    Args:
        reason: One-line note shown in graph snapshots while you're
            waiting (helps a human or sibling agent debug who's stuck
            on what).
        timeout_seconds: Hard cap (default 600s). On timeout the tool
            returns and you decide whether to keep working or wait
            again.
    """
    inner = _ctx(ctx)
    bus = inner.get("bus")
    me = inner.get("agent_id")
    if bus is None or me is None:
        return dump_tool_result({"success": False, "error": "Bus or agent_id missing in context."})

    async with bus._lock:
        bus.statuses[me] = "waiting"

    deadline = asyncio.get_event_loop().time() + timeout_seconds
    try:
        while asyncio.get_event_loop().time() < deadline:
            async with bus._lock:
                pending = len(bus.inboxes.get(me, []))
            if pending > 0:
                async with bus._lock:
                    bus.statuses[me] = "running"
                return dump_tool_result(
                    {
                        "success": True,
                        "status": "message_arrived",
                        "pending_messages": pending,
                        "reason": reason,
                    }
                )
            await asyncio.sleep(_WAIT_POLL_SECONDS)
    finally:
        async with bus._lock:
            # Don't clobber a status another writer set (e.g., on_agent_end
            # finalized us as ``stopped`` mid-wait).
            if bus.statuses.get(me) == "waiting":
                bus.statuses[me] = "running"

    return dump_tool_result(
        {
            "success": True,
            "status": "timeout",
            "timeout_seconds": timeout_seconds,
            "reason": reason,
            "note": "No messages within timeout — continue work or call agent_finish.",
        }
    )


@strix_tool(timeout=120)
async def create_agent(
    ctx: RunContextWrapper,
    name: str,
    task: str,
    inherit_context: bool = True,
    skills: list[str] | None = None,
) -> str:
    """Spawn a specialist child agent to run in parallel.

    Decompose complex pentests by handing focused subtasks to dedicated
    children. The child runs asynchronously — the parent continues
    immediately and can ``wait_for_message`` later (or just keep
    working in parallel). When the child calls ``agent_finish``, its
    completion report lands in the parent's inbox.

    **Before spawning, call ``view_agent_graph``** to confirm no
    existing agent already covers this scope — duplicate specialists
    waste turns and create coordination headaches.

    **Specialization principles:**

    - Most agents need at least one ``skill`` to be useful.
    - Aim for **1-3 related skills** per agent. Up to 5 only when the
      task genuinely spans them.
    - One skill = most focused (e.g., XSS-only). Five skills = upper
      bound.
    - Match the ``name`` to the focus (``XSS Specialist``,
      ``SQLi Validator``, ``Auth Specialist``).

    **When to spawn vs do it yourself:**

    - Spawn when the subtask is large, parallelizable, or needs
      different specialization than what you're already doing.
    - Don't spawn for trivial one-shot probes — just run the tool
      yourself.

    Args:
        name: Human-readable child name (used in graph views and
            ``send_message_to_agent`` flows).
        task: Specific objective. Be concrete — what to test, what
            success looks like, any constraints.
        inherit_context: Default ``True``. The child receives the
            parent's input history as background; only set ``False``
            when starting a clean-slate task.
        skills: Comma-separated skill names. Max 5; prefer 1-3.
    """
    inner = _ctx(ctx)
    bus = inner.get("bus")
    parent_id = inner.get("agent_id")
    factory: Callable[..., SDKAgent] | None = inner.get("agent_factory")

    if bus is None or parent_id is None:
        return dump_tool_result({"success": False, "error": "Bus or agent_id missing in context."})
    if factory is None:
        return dump_tool_result(
            {
                "success": False,
                "error": (
                    "No agent_factory in context. "
                    "The root assembly must inject one via make_agent_context."
                ),
            }
        )

    child_id = uuid.uuid4().hex[:8]

    try:
        child_agent = factory(name=name, skills=skills or [])
    except Exception as e:
        logger.exception("agent_factory raised while building child '%s'", name)
        return dump_tool_result(
            {
                "success": False,
                "error": f"agent_factory failed: {e!s}",
            }
        )

    await bus.register(child_id, name, parent_id)

    parent_history = inner.get("parent_input_items") if inherit_context else None
    initial_input: list[TResponseInputItem] = []
    if parent_history:
        initial_input.append(
            {
                "role": "user",
                "content": "[Inherited context from parent — read-only history]",
            }
        )
        initial_input.extend(parent_history)
        initial_input.append(
            {
                "role": "user",
                "content": "[End of inherited context]",
            }
        )
    initial_input.append(
        {
            "role": "user",
            "content": (
                f"You are agent {name} ({child_id}); your parent is {parent_id}. "
                f"Maintain your own identity. Call agent_finish when your task "
                f"is complete."
            ),
        }
    )
    initial_input.append({"role": "user", "content": task})

    child_ctx = make_agent_context(
        bus=bus,
        sandbox_session=inner.get("sandbox_session"),
        sandbox_client=inner.get("sandbox_client"),
        sandbox_token=inner.get("sandbox_token"),
        tool_server_host_port=inner.get("tool_server_host_port"),
        caido_host_port=inner.get("caido_host_port"),
        caido_client=inner.get("caido_client"),
        agent_id=child_id,
        parent_id=parent_id,
        tracer=inner.get("tracer"),
        model=inner.get("model", "anthropic/claude-sonnet-4-6"),
        model_settings=inner.get("model_settings"),
        max_turns=int(inner.get("max_turns", 300)),
        is_whitebox=bool(inner.get("is_whitebox", False)),
        diff_scope=inner.get("diff_scope"),
        run_id=inner.get("run_id"),
        agent_factory=factory,
    )

    child_run_config = make_run_config(
        sandbox_session=inner.get("sandbox_session"),
        sandbox_client=inner.get("sandbox_client"),
        model=inner.get("model", "anthropic/claude-sonnet-4-6"),
        model_settings_override=inner.get("model_settings"),
    )

    task_handle = asyncio.create_task(
        Runner.run(
            child_agent,
            input=initial_input,
            run_config=child_run_config,
            context=child_ctx,
            hooks=StrixOrchestrationHooks(),
            max_turns=int(inner.get("max_turns", 300)),
        ),
        name=f"agent-{name}-{child_id}",
    )
    async with bus._lock:
        bus.tasks[child_id] = task_handle

    return dump_tool_result(
        {
            "success": True,
            "agent_id": child_id,
            "name": name,
            "parent_id": parent_id,
            "message": f"Spawned '{name}' ({child_id}) running in parallel.",
        }
    )


@strix_tool(timeout=30)
async def agent_finish(
    ctx: RunContextWrapper,
    result_summary: str,
    findings: list[str] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> str:
    """Subagent termination — post a completion report to the parent.

    **Subagents only.** Root agents must call ``finish_scan`` instead;
    this tool refuses to run for root agents. Calling this:

    1. Marks the subagent as ``completed``.
    2. Posts a structured completion report to the parent's inbox
       (when ``report_to_parent`` is true).
    3. Stops this subagent's execution.

    **Vulnerability findings must already be filed via
    ``create_vulnerability_report`` before calling this.** The
    ``findings`` field here is for narrative summary only — it does
    not register vulns in the scan report.

    Write the summary as if the parent has no idea what you were
    doing: what did you test, what did you find/confirm/rule out,
    what's still open.

    Args:
        result_summary: What you accomplished and discovered. Concrete
            and specific (URLs, parameters, payloads that worked).
        findings: Optional bullet list of confirmed observations. For
            credit-bearing vulnerabilities, file
            ``create_vulnerability_report`` first; this is for
            narrative.
        success: Whether the assigned subtask was completed
            successfully. Default ``True``.
        report_to_parent: Whether to deliver the completion report to
            the parent's inbox. Default ``True``.
        final_recommendations: Optional next-step suggestions for the
            parent (e.g., "prioritize testing X", "spawn an agent to
            cover Y").
    """
    inner = _ctx(ctx)
    bus = inner.get("bus")
    me = inner.get("agent_id")
    if bus is None or me is None:
        return dump_tool_result({"success": False, "error": "Bus or agent_id missing in context."})

    parent_id = inner.get("parent_id")
    if parent_id is None:
        return dump_tool_result(
            {
                "success": False,
                "agent_completed": False,
                "error": (
                    "agent_finish is for subagents. Root/main agents must call finish_scan instead."
                ),
                "parent_notified": False,
            }
        )

    inner["agent_finish_called"] = True

    parent_notified = False
    if report_to_parent:
        async with bus._lock:
            agent_name = bus.names.get(me, me)
        report = json.dumps(
            {
                "kind": "agent_completion_report",
                "from": agent_name,
                "agent_id": me,
                "success": success,
                "summary": result_summary,
                "findings": list(findings or []),
                "recommendations": list(final_recommendations or []),
            },
            ensure_ascii=False,
        )
        await bus.send(
            parent_id,
            {
                "id": f"report_{uuid.uuid4().hex[:8]}",
                "from": me,
                "content": report,
                "type": "completion",
                "priority": "high",
            },
        )
        parent_notified = True

    return dump_tool_result(
        {
            "success": True,
            "agent_completed": True,
            "parent_notified": parent_notified,
            "agent_id": me,
            "summary": result_summary,
            "findings_count": len(findings or []),
            "has_recommendations": bool(final_recommendations),
        }
    )
