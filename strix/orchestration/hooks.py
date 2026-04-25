"""StrixOrchestrationHooks — RunHooks subclass wiring bus + tracer + warnings.

References:
    - PLAYBOOK.md §2.5
    - AUDIT.md §2.5  (C5 — streaming/hook bridge)
    - AUDIT_R2.md §1.3 (C8 — subagent crash detection)
    - AUDIT_R3.md F2 (context types: AgentHookContext for agent_*,
      RunContextWrapper otherwise; on_tool_end result is str)
    - AUDIT_R3.md C15 (every hook body try/except so a hook bug never tears down the run)
"""

from __future__ import annotations

import logging
from typing import Any

from agents.items import ModelResponse
from agents.lifecycle import RunHooks
from agents.run_context import AgentHookContext, RunContextWrapper


logger = logging.getLogger(__name__)


class StrixOrchestrationHooks(RunHooks[Any]):
    """Lifecycle hooks for Strix multi-agent runs.

    Wires four concerns:

    1. Turn-budget warnings injected into ``input_items`` at 85% and ``N - 3``
       of ``max_turns`` (legacy: ``base_agent.py:186-211``).
    2. LLM usage recording into the bus (replaces legacy ``LLM._total_stats``
       + ``_completed_agent_llm_totals``).
    3. Sandbox readiness: awaits the ``CaidoCapability._healthcheck_task``
       on first agent start so the agent doesn't fire tools before Caido and
       the tool server are ready.
    4. Subagent crash detection (C8): if ``on_agent_end`` fires without
       ``agent_finish_called`` being set in context, posts a synthetic
       ``<agent_crash>`` message to the parent's inbox so the parent learns
       on its next turn instead of polling ``wait_for_message`` forever.
    """

    async def on_llm_start(
        self,
        context: RunContextWrapper[Any],
        agent: Any,
        system_prompt: str | None,
        input_items: list[Any],
    ) -> None:
        try:
            # Type contract guarantees ``input_items`` is list[TResponseInputItem];
            # we trust SDK here. The try/except below catches any surprise.
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            max_turns = int(ctx.get("max_turns", 300))
            cur = int(ctx.get("turn_count", 0))
            if max_turns >= 4 and cur == int(max_turns * 0.85):
                input_items.append(
                    {
                        "role": "user",
                        "content": (
                            "<system_warning>You are at 85% of your iteration "
                            "budget. Begin consolidating findings.</system_warning>"
                        ),
                    }
                )
            elif max_turns >= 4 and cur == max_turns - 3:
                input_items.append(
                    {
                        "role": "user",
                        "content": (
                            "<system_warning>You have 3 iterations left. Your "
                            "next tool call MUST be the finish tool."
                            "</system_warning>"
                        ),
                    }
                )
        except Exception:
            logger.exception("on_llm_start failed")

    async def on_llm_end(
        self,
        context: RunContextWrapper[Any],
        agent: Any,
        response: ModelResponse,
    ) -> None:
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            bus = ctx.get("bus")
            agent_id = ctx.get("agent_id")
            if bus is not None and agent_id is not None:
                await bus.record_usage(agent_id, getattr(response, "usage", None))
            ctx["turn_count"] = int(ctx.get("turn_count", 0)) + 1
        except Exception:
            logger.exception("on_llm_end failed")

    async def on_agent_start(
        self,
        context: AgentHookContext[Any],
        agent: Any,
    ) -> None:
        try:
            cap = next(
                (
                    c
                    for c in (getattr(agent, "capabilities", None) or [])
                    if hasattr(c, "_healthcheck_task")
                ),
                None,
            )
            if cap is not None and getattr(cap, "_healthcheck_task", None) is not None:
                await cap._healthcheck_task
        except Exception:
            logger.exception("on_agent_start failed")

    async def on_agent_end(
        self,
        context: AgentHookContext[Any],
        agent: Any,
        output: Any,
    ) -> None:
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            bus = ctx.get("bus")
            me = ctx.get("agent_id")
            if bus is None or me is None:
                return
            crashed = (output is None) or not ctx.get("agent_finish_called", False)
            parent = bus.parent_of.get(me)
            if crashed and parent is not None:
                await bus.send(
                    parent,
                    {
                        "from": me,
                        "content": (
                            f"<agent_crash agent_id='{me}' "
                            f"name='{bus.names.get(me, me)}'>"
                            "Agent terminated without calling agent_finish. "
                            "Stop waiting on this child."
                            "</agent_crash>"
                        ),
                        "type": "crash",
                    },
                )
            await bus.finalize(me, "crashed" if crashed else "completed")
        except Exception:
            logger.exception("on_agent_end failed")

    async def on_tool_start(
        self,
        context: RunContextWrapper[Any],
        agent: Any,
        tool: Any,
    ) -> None:
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            tracer = ctx.get("tracer")
            if tracer is not None and hasattr(tracer, "log_tool_start"):
                tracer.log_tool_start(ctx.get("agent_id", "?"), tool.name)
        except Exception:
            logger.exception("on_tool_start failed")

    async def on_tool_end(
        self,
        context: RunContextWrapper[Any],
        agent: Any,
        tool: Any,
        result: str,
    ) -> None:
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            if tool.name in ("agent_finish", "finish_scan"):
                ctx["agent_finish_called"] = True
            tracer = ctx.get("tracer")
            if tracer is not None and hasattr(tracer, "log_tool_end"):
                tracer.log_tool_end(ctx.get("agent_id", "?"), tool.name, result)
        except Exception:
            logger.exception("on_tool_end failed")

    async def on_handoff(
        self,
        context: RunContextWrapper[Any],
        from_agent: Any,
        to_agent: Any,
    ) -> None:
        # Strix multi-agent goes through the bus; SDK handoffs are unused.
        pass
