"""``AnthropicCachingLitellmModel`` — inject ``cache_control`` on the system message.

``ModelSettings.extra_body`` lands fields at the request top level,
which Anthropic ignores. Anthropic only honors ``cache_control`` when
it is on the message itself, so we patch the input list before
delegating to the parent.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Any

from agents.agent_output import AgentOutputSchemaBase
from agents.extensions.models.litellm_model import LitellmModel
from agents.handoffs import Handoff
from agents.items import ModelResponse, TResponseInputItem, TResponseStreamEvent
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.tool import Tool


logger = logging.getLogger(__name__)


class AnthropicCachingLitellmModel(LitellmModel):
    """LitellmModel that injects ``cache_control: {"type": "ephemeral"}`` on the
    system message for Anthropic models. Other providers pass through unchanged.

    Detection: case-insensitive substring match on ``"anthropic/"`` or
    ``"claude"`` against the model name.
    """

    def _is_anthropic(self) -> bool:
        m = (self.model or "").lower()
        return "anthropic/" in m or "claude" in m

    def _patch(
        self,
        items: list[TResponseInputItem],
    ) -> list[TResponseInputItem]:
        """Return a copy of ``items`` with cache_control on the system message.

        Returns the input list unchanged for non-Anthropic models. For
        Anthropic, the first ``role: system`` item has its content rewritten
        from a string to a list-of-blocks with ``cache_control`` attached.
        """
        if not self._is_anthropic():
            return items
        out: list[TResponseInputItem] = []
        patched_count = 0
        for item in items:
            if isinstance(item, dict) and item.get("role") == "system":
                content = item.get("content")
                if isinstance(content, str):
                    new_item = {
                        **item,
                        "content": [
                            {
                                "type": "text",
                                "text": content,
                                "cache_control": {"type": "ephemeral"},
                            },
                        ],
                    }
                    out.append(new_item)  # type: ignore[arg-type]
                    patched_count += 1
                    continue
            out.append(item)
        if patched_count:
            logger.debug(
                "Anthropic cache_control injected on %d system message(s) for %s",
                patched_count,
                self.model,
            )
        return out

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        previous_response_id: str | None = None,
        conversation_id: str | None = None,
        prompt: Any | None = None,
    ) -> ModelResponse:
        patched = self._patch(input if isinstance(input, list) else [])
        # If input was a string, patching is a no-op; pass straight through.
        effective: str | list[TResponseInputItem] = patched if isinstance(input, list) else input
        return await super().get_response(
            system_instructions,
            effective,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        previous_response_id: str | None = None,
        conversation_id: str | None = None,
        prompt: Any | None = None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        patched = self._patch(input if isinstance(input, list) else [])
        effective: str | list[TResponseInputItem] = patched if isinstance(input, list) else input
        async for event in super().stream_response(
            system_instructions,
            effective,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        ):
            yield event
