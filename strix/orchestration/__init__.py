"""Strix multi-agent orchestration on top of OpenAI Agents SDK.

Provides:
- AgentMessageBus: peer-to-peer agent inbox + status + stats aggregation
- inject_messages_filter: SDK call_model_input_filter for inbox drain
- StrixOrchestrationHooks: SDK RunHooks subclass for lifecycle wiring
"""

from strix.orchestration.bus import AgentMessageBus
from strix.orchestration.filter import inject_messages_filter
from strix.orchestration.hooks import StrixOrchestrationHooks


__all__ = [
    "AgentMessageBus",
    "StrixOrchestrationHooks",
    "inject_messages_filter",
]
