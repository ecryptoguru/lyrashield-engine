"""``StrixOrchestrationHooks`` — RunHooks wiring bus + tracer + warnings."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from agents.items import ModelResponse
from agents.lifecycle import RunHooks
from agents.run_context import AgentHookContext, RunContextWrapper


logger = logging.getLogger(__name__)


class StrixOrchestrationHooks(RunHooks[Any]):
    """Lifecycle hooks for Strix multi-agent runs.

    Wires three concerns:

    1. Turn-budget warnings injected into ``input_items`` at 85% and
       ``N - 3`` of ``max_turns``.
    2. LLM usage recording into the bus + tracer, plus mirroring the
       bus's agent tree into ``tracer.agents`` for the TUI.
    3. Subagent crash detection: if ``on_agent_end`` fires without
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
        del agent, system_prompt
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            bus = ctx.get("bus")
            agent_id = ctx.get("agent_id")
            if bus is None or agent_id is None:
                return
            stats = bus.stats_live.get(agent_id)
            if stats is None:
                return
            max_turns = int(ctx.get("max_turns", 300))
            cur = int(stats.get("calls", 0))
            if max_turns < 4:
                return
            # Once-flags live alongside ``calls`` on ``bus.stats_live`` so the
            # warnings fire exactly once per agent lifetime — surviving
            # ``run_with_continuation`` cycles, mirroring legacy
            # ``state.max_iterations_warning_sent``.
            if cur >= int(max_turns * 0.85) and not stats.get("warned_85"):
                stats["warned_85"] = True
                input_items.append(
                    {
                        "role": "user",
                        "content": (
                            "[System warning] You are at 85% of your iteration "
                            "budget. Begin consolidating findings."
                        ),
                    },
                )
            if cur >= max_turns - 3 and not stats.get("warned_final"):
                stats["warned_final"] = True
                input_items.append(
                    {
                        "role": "user",
                        "content": (
                            "[System warning] You have 3 iterations left. Your "
                            "next tool call MUST be the finish tool."
                        ),
                    },
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
                    input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                    output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                    cached_tokens=cached,
                )
        except Exception:
            logger.exception("on_llm_end failed")

    async def on_agent_start(
        self,
        context: AgentHookContext[Any],
        agent: Any,
    ) -> None:
        # The TUI reads ``tracer.agents`` to render the agent tree;
        # mirror the bus state into the tracer here so the tree
        # populates as agents come online.
        del agent
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            tracer = ctx.get("tracer")
            bus = ctx.get("bus")
            me = ctx.get("agent_id")
            if tracer is None or bus is None or me is None:
                return
            now = datetime.now(UTC).isoformat()
            tracer.agents.setdefault(
                me,
                {
                    "id": me,
                    "name": bus.names.get(me, me),
                    "parent_id": bus.parent_of.get(me),
                    "status": bus.statuses.get(me, "running"),
                    "created_at": now,
                    "updated_at": now,
                },
            )
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

            # Interactive agents (root and children) stay alive across
            # ``Runner.run`` cycles — ``run_with_continuation`` re-invokes
            # ``Runner.run`` whenever the agent receives a follow-up
            # message, so we just park (status=waiting) instead of
            # finalizing. Crashed runs always finalize so the parent
            # learns to stop waiting.
            stays_alive = bool(ctx.get("interactive", False)) and not crashed

            final_status = "waiting" if stays_alive else ("crashed" if crashed else "completed")

            tracer = ctx.get("tracer")
            if tracer is not None and me in tracer.agents:
                tracer.agents[me]["status"] = final_status
                tracer.agents[me]["updated_at"] = datetime.now(UTC).isoformat()
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

            if stays_alive:
                await bus.park(me)
                # Reset the finish flag so the next cycle can detect its own
                # finish-tool call. The lifetime turn counter and warning
                # flags live on ``bus.stats_live`` and persist across cycles.
                ctx["agent_finish_called"] = False
            else:
                await bus.finalize(me, final_status)
        except Exception:
            logger.exception("on_agent_end failed")

    async def on_tool_start(
        self,
        context: RunContextWrapper[Any],
        agent: Any,
        tool: Any,
    ) -> None:
        del agent
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            tracer = ctx.get("tracer")
            if tracer is not None:
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
        del agent
        try:
            ctx = context.context
            if not isinstance(ctx, dict):
                return
            if tool.name in ("agent_finish", "finish_scan"):
                ctx["agent_finish_called"] = True
            tracer = ctx.get("tracer")
            if tracer is not None:
                tracer.log_tool_end(ctx.get("agent_id", "?"), tool.name, result)
        except Exception:
            logger.exception("on_tool_end failed")
