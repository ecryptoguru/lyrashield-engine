"""``inject_messages_filter`` — SDK ``call_model_input_filter`` for the bus.

The SDK runs ``call_model_input_filter`` exactly once per turn before
the LLM call and captures the output in a closure for any subsequent
retries — so a single drain per turn doesn't lose messages on retry.
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

    Messages from peer agents are formatted with a labeled header so the
    receiving model can attribute them. Messages from the literal sender
    ``"user"`` (a real human via TUI) are added as plain user messages.

    Any exception inside the filter — malformed message dict, bug in
    ``bus.drain``, etc. — is caught and the original ``data.model_data``
    is returned unmodified. A bug here must never tear down the run.
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
                msg_type = msg.get("type", "info")
                priority = msg.get("priority", "normal")
                header = f"[Message from agent {sender} | type={msg_type} | priority={priority}]"
                new_input.append(
                    {
                        "role": "user",
                        "content": f"{header}\n{content}",
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
