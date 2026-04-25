"""AnthropicCachingLitellmModel — inject cache_control on the system message.

ModelSettings.extra_body lands the field at the request top level, which
Anthropic ignores. Anthropic only honors ``cache_control`` when it is on the
message itself. We patch the input list before delegating to the parent.

References:
    - PLAYBOOK.md §2.1
    - AUDIT.md §2.2 (C2 — original blocker)
    - AUDIT_R3.md F1 (signature: first 7 params positional, then *,)
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from agents.agent_output import AgentOutputSchemaBase
from agents.extensions.models.litellm_model import LitellmModel
from agents.handoffs import Handoff
from agents.items import ModelResponse, TResponseInputItem, TResponseStreamEvent
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.tool import Tool


class AnthropicCachingLitellmModel(LitellmModel):
    """LitellmModel that injects ``cache_control: {"type": "ephemeral"}`` on the
    system message for Anthropic models. Other providers pass through unchanged.

    Detection follows the legacy Strix logic: case-insensitive substring match
    on ``"anthropic/"`` or ``"claude"`` against the model name (llm/llm.py:338-341).

    For Strix proxy routing where the API model is ``openai/<base>`` but the
    underlying provider is still Anthropic (e.g., ``strix/claude-sonnet-4.6``
    resolves to api_model=``openai/claude-sonnet-4.6`` against the Strix
    proxy with a canonical of ``anthropic/claude-sonnet-4-6``), pass
    ``is_anthropic_override=True`` so the wrapper still injects cache_control
    even though the model name doesn't match the heuristic.
    """

    def __init__(
        self,
        model: str,
        *,
        is_anthropic_override: bool | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(model=model, **kwargs)
        self._is_anthropic_override = is_anthropic_override

    def _is_anthropic(self) -> bool:
        if self._is_anthropic_override is not None:
            return self._is_anthropic_override
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
                    continue
            out.append(item)
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
