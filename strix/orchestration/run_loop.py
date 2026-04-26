"""``run_with_continuation`` — interactive-mode demo-loop wrapper around ``Runner.run_streamed``.

Pre-migration ``BaseAgent.agent_loop`` ran forever in interactive mode,
re-entering a "waiting state" after each finish-tool call so the agent
could pick up follow-up messages from its parent (or from the user, in
the root's case). Post-migration this helper restores the legacy
semantics using the SDK's streaming Runner + ``RunResultStreaming.cancel``
so the user can interrupt mid-turn without truncating session state.

Behaviors restored from legacy:

- **Mid-stream interrupt** via ``streamed.cancel(mode="after_turn")``:
  TUI signals through ``bus.request_interrupt``; the SDK saves the
  current turn cleanly before honoring the cancel.
- **LLM failure resume** (legacy ``state.llm_failed``): hard model
  failures after retries exhausted park the agent in ``llm_failed``
  status; only direct user input can resume.
- **Waiting timeout** auto-resume (legacy ``waiting_timeout``):
  interactive subagents auto-resume after 300s with a "Waiting timeout
  reached" message. Interactive root waits forever.
- **Graceful stop** (legacy ``stop_agent``): ``bus.stopping`` set
  causes the outer loop to return instead of awaiting more messages.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from agents import Runner
from agents.exceptions import AgentsException, MaxTurnsExceeded, UserError
from openai import APIError


if TYPE_CHECKING:
    from agents.lifecycle import RunHooks
    from agents.memory import Session
    from agents.result import RunResultBase
    from agents.run_config import RunConfig

    from strix.orchestration.bus import AgentMessageBus


logger = logging.getLogger(__name__)


#: Auto-resume timeout for interactive *subagents* (legacy parity).
#: Interactive root agents wait forever; non-interactive runs don't loop.
_WAITING_TIMEOUT_SUBAGENT = 300.0

_TIMEOUT_RESUME_MESSAGE = "Waiting timeout reached. Resuming execution."


async def run_with_continuation(
    *,
    agent: Any,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    hooks: RunHooks[Any],
    max_turns: int,
    bus: AgentMessageBus,
    agent_id: str,
    interactive: bool,
    session: Session | None = None,
) -> RunResultBase:
    """Run an agent once (non-interactive) or in a continuation loop (interactive)."""
    kwargs: dict[str, Any] = {
        "input": initial_input,
        "run_config": run_config,
        "context": context,
        "hooks": hooks,
        "max_turns": max_turns,
    }
    if session is not None:
        kwargs["session"] = session

    # Interactive subagents auto-resume after a timeout to mirror legacy
    # ``waiting_timeout``. Roots wait forever (legacy ``waiting_timeout=0``).
    waiting_timeout: float | None = None
    if interactive:
        async with bus._lock:
            parent_id = bus.parent_of.get(agent_id)
        if parent_id is not None:
            waiting_timeout = _WAITING_TIMEOUT_SUBAGENT

    result = await _run_streamed(agent, bus, agent_id, **kwargs)

    if not interactive:
        return result

    logger.debug(
        "run_with_continuation: entering interactive outer loop for %s (timeout=%s)",
        agent_id,
        waiting_timeout,
    )
    while True:
        if agent_id in bus.stopping:
            logger.info("run_with_continuation: %s in stopping set, returning", agent_id)
            return result

        try:
            if waiting_timeout is None:
                await bus.wait_for_message(agent_id)
            else:
                await asyncio.wait_for(
                    bus.wait_for_message(agent_id),
                    timeout=waiting_timeout,
                )
        except asyncio.CancelledError:
            logger.info("run_with_continuation: %s cancelled while waiting", agent_id)
            return result
        except TimeoutError:
            logger.info(
                "run_with_continuation: %s waiting timeout, auto-resuming",
                agent_id,
            )
            kwargs["input"] = _TIMEOUT_RESUME_MESSAGE
            result = await _run_streamed(agent, bus, agent_id, **kwargs)
            continue

        pending = await bus.drain(agent_id)
        if not pending:
            continue
        next_input = "\n\n".join(
            str(msg.get("content", "")).strip() for msg in pending if msg.get("content")
        )
        if not next_input:
            continue

        logger.debug(
            "run_with_continuation: %s resuming with %d message(s) (input_len=%d)",
            agent_id,
            len(pending),
            len(next_input),
        )
        kwargs["input"] = next_input
        result = await _run_streamed(agent, bus, agent_id, **kwargs)


async def _run_streamed(
    agent: Any,
    bus: AgentMessageBus,
    agent_id: str,
    **kwargs: Any,
) -> RunResultBase:
    """Drive one ``Runner.run_streamed`` cycle to completion.

    Catches hard model failures (after SDK retries are exhausted) and
    parks the agent in ``llm_failed`` until a user message arrives,
    matching legacy ``state.llm_failed`` semantics. Programmer errors
    (``UserError``), max-turn breaches, and explicit cancellation
    propagate to the caller.
    """
    interactive = bool(kwargs.get("context", {}).get("interactive", False))
    while True:
        streamed = Runner.run_streamed(agent, **kwargs)
        try:
            async with bus.attach_stream(agent_id, streamed):
                async for _event in streamed.stream_events():
                    pass
        except (UserError, MaxTurnsExceeded, asyncio.CancelledError):
            raise
        except (AgentsException, APIError):
            if not interactive:
                raise
            logger.exception(
                "LLM hard failure for agent %s; awaiting user resume",
                agent_id,
            )
            await bus.mark_llm_failed(agent_id)
            await bus.wait_for_user_message(agent_id)
            pending = await bus.drain(agent_id)
            next_input = "\n\n".join(
                str(msg.get("content", "")).strip() for msg in pending if msg.get("content")
            )
            if not next_input:
                continue
            kwargs["input"] = next_input
            continue
        else:
            return streamed
