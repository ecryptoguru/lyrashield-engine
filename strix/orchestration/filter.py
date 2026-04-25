"""inject_messages_filter — SDK call_model_input_filter for the message bus.

This is the integration point that replaces Strix's per-iteration
_check_agent_messages call (legacy: agents/base_agent.py:448-531). The SDK
runs ``call_model_input_filter`` exactly once per turn before the LLM call
(``run_internal/turn_preparation.py:55-80``), and captures the filter's
output in a lambda closure for any subsequent retries
(``run_internal/model_retry.py:34-35``) — so a single drain per turn does
not lose messages on retry.

References:
    - PLAYBOOK.md §2.4
    - AUDIT_R3.md C14 (filter must be defensive — exception → unmodified data)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agents.run_config import CallModelData, ModelInputData


if TYPE_CHECKING:
    from strix.orchestration.bus import AgentMessageBus


logger = logging.getLogger(__name__)


async def inject_messages_filter(data: CallModelData) -> ModelInputData:
    """Drain bus inbox and append messages as user-role items before the LLM call.

    Each drained message is wrapped in an ``<inter_agent_message>`` XML envelope
    that mirrors Strix's legacy format (base_agent.py:491-514) so the system
    prompt's existing rules around inter-agent communication still apply.

    Messages from the literal sender ``"user"`` (a real human via TUI) skip
    the XML wrap and are added as plain user messages.

    C14: any exception inside the filter — including a malformed message dict
    or a bug in ``bus.drain`` — is caught and the original ``data.model_data``
    is returned unmodified. A bug in the filter must never tear down the run.
    """
    try:
        if not isinstance(data.context, dict):
            return data.model_data
        bus: AgentMessageBus | None = data.context.get("bus")
        agent_id: str | None = data.context.get("agent_id")
        if bus is None or agent_id is None:
            return data.model_data
        pending = await bus.drain(agent_id)
        if not pending:
            return data.model_data

        new_input = list(data.model_data.input)
        for msg in pending:
            sender = msg.get("from", "unknown")
            content = msg.get("content", "")
            if sender == "user":
                new_input.append({"role": "user", "content": content})
            else:
                new_input.append(
                    {
                        "role": "user",
                        "content": (
                            f"<inter_agent_message from='{sender}' "
                            f"type='{msg.get('type', 'info')}' "
                            f"priority='{msg.get('priority', 'normal')}'>"
                            f"{content}"
                            f"</inter_agent_message>"
                        ),
                    }
                )
        return ModelInputData(
            input=new_input,
            instructions=data.model_data.instructions,
        )
    except Exception:
        logger.exception(
            "inject_messages_filter failed; proceeding with unmodified input",
        )
        return data.model_data
