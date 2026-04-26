"""``inject_messages_filter`` — SDK ``call_model_input_filter`` for the bus.

The SDK runs ``call_model_input_filter`` exactly once per turn before
the LLM call and captures the output in a closure for any subsequent
retries — so a single drain per turn doesn't lose messages on retry.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agents.run_config import CallModelData, ModelInputData


if TYPE_CHECKING:
    from typing import Any

    from strix.orchestration.bus import AgentMessageBus


logger = logging.getLogger(__name__)


async def inject_messages_filter(data: CallModelData) -> ModelInputData:
    """Drain bus inbox and append messages as user-role items before the LLM call.

    Peer-agent messages are wrapped in the legacy ``<inter_agent_message>``
    XML envelope (sender / metadata / content / delivery_info) so the
    receiving model gets the same prompt-shape as pre-migration — including
    the explicit "DO NOT echo back" instruction. Direct user messages
    (``from="user"``) are passed plain.

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
    """Render a peer-agent message in the legacy XML envelope.

    The wrapper carries an explicit "do not echo back" instruction that
    the legacy harness used to keep models from quoting the entire
    received message dict in their own next turn.
    """
    sender_id = str(msg.get("from", "unknown"))
    sender_name = bus.names.get(sender_id, sender_id)
    msg_type = msg.get("type", "information")
    priority = msg.get("priority", "normal")
    timestamp = msg.get("timestamp") or datetime.now(UTC).isoformat()
    content = str(msg.get("content", ""))
    return (
        "<inter_agent_message>\n"
        "  <delivery_notice><important>You have received a message from another "
        "agent. Acknowledge and respond to the sender if needed; DO NOT echo "
        "back this entire message block.</important></delivery_notice>\n"
        f"  <sender><agent_name>{sender_name}</agent_name>"
        f"<agent_id>{sender_id}</agent_id></sender>\n"
        f"  <message_metadata><type>{msg_type}</type>"
        f"<priority>{priority}</priority>"
        f"<timestamp>{timestamp}</timestamp></message_metadata>\n"
        f"  <content>{content}</content>\n"
        "  <delivery_info><note>This message was delivered during your task "
        "execution. Please acknowledge and respond if needed.</note>"
        "</delivery_info>\n"
        "</inter_agent_message>"
    )
