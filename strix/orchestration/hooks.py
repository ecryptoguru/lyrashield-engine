"""``StrixOrchestrationHooks`` — RunHooks wiring bus + tracer + warnings."""

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

    1. Turn-budget warnings injected into ``input_items`` at 85% and
       ``N - 3`` of ``max_turns``.
    2. LLM usage recording into the bus + tracer.
    3. Sandbox readiness: awaits the
       ``CaidoCapability._healthcheck_task`` on first agent start so
       the agent doesn't fire tools before Caido and the tool server
       are ready.
    4. Subagent crash detection: if ``on_agent_end`` fires without
       ``agent_finish_called`` being set, posts a crash message to the
       parent's inbox so the parent learns on its next turn instead of
       waiting forever.
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
                            "[System warning] You are at 85% of your iteration "
                            "budget. Begin consolidating findings."
                        ),
                    }
                )
            elif max_turns >= 4 and cur == max_turns - 3:
                input_items.append(
                    {
                        "role": "user",
                        "content": (
                            "[System warning] You have 3 iterations left. Your "
                            "next tool call MUST be the finish tool."
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
        del agent
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            usage = getattr(response, "usage", None)
            agent_id = ctx.get("agent_id")
            bus = ctx.get("bus")
            if bus is not None and agent_id is not None:
                await bus.record_usage(agent_id, usage)
            tracer = ctx.get("tracer")
            if tracer is not None and usage is not None and hasattr(tracer, "record_llm_usage"):
                cached = 0
                details = getattr(usage, "input_tokens_details", None)
                if details is not None:
                    cached = int(getattr(details, "cached_tokens", 0) or 0)
                tracer.record_llm_usage(
                    agent_id=str(agent_id or "unknown"),
                    input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                    output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                    cached_tokens=cached,
                    cost=0.0,
                    requests=1,
                    bucket="live",
                )
            ctx["turn_count"] = int(ctx.get("turn_count", 0)) + 1
        except Exception:
            logger.exception("on_llm_end failed")

    async def on_agent_start(
        self,
        context: AgentHookContext[Any],
        agent: Any,
    ) -> None:
        # The CaidoCapability is bound to the sandbox session, not the
        # Agent (we use plain ``Agent``, not ``SandboxAgent``). We stash
        # it in the context dict at scan-bring-up time so the hook can
        # await its healthcheck before the first LLM call.
        del agent
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            cap = ctx.get("caido_capability")
            task = getattr(cap, "_healthcheck_task", None)
            if task is not None:
                await task
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
                            f"[Agent crash] {bus.names.get(me, me)} ({me}) "
                            f"terminated without calling agent_finish. "
                            f"Stop waiting on this child."
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
