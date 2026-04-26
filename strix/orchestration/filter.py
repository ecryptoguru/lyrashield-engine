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
    from typing import Any

    from strix.orchestration.bus import AgentMessageBus


logger = logging.getLogger(__name__)


async def inject_messages_filter(data: CallModelData) -> ModelInputData:
    """Drain bus inbox and append messages as user-role items before the LLM call.

    Peer-agent messages get a one-line labeled header followed by the
    body. Direct user messages (``from="user"``) are passed plain.

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
                new_input.append(
                    {
                        "role": "user",
                        "content": _format_inter_agent_message(bus, msg),
                    },
                )
        logger.debug(
            "inject_messages_filter: appended %d message(s) to input for %s",
            len(pending),
            agent_id,
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


def _format_inter_agent_message(bus: AgentMessageBus, msg: dict[str, Any]) -> str:
    """Render a peer-agent message as a labeled header + body.

    Format:
        [Message from {name} ({id}) | type={type} | priority={priority}]
        {content}

    Plain text by design — no XML wrapping, no escaping concerns. The
    label line tells the receiver who sent this and why so it doesn't
    confuse a peer message with its own work; the rest of the body is
    delivered as-is.
    """
    sender_id = str(msg.get("from", "unknown"))
    sender_name = bus.names.get(sender_id, sender_id)
    msg_type = msg.get("type", "information")
    priority = msg.get("priority", "normal")
    content = str(msg.get("content", ""))
    return (
        f"[Message from {sender_name} ({sender_id}) "
        f"| type={msg_type} | priority={priority}]\n"
        f"{content}"
    )
