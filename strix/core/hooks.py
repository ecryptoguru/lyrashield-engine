# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import json
import logging
import math
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse


logger = logging.getLogger(__name__)

MODEL_INPUT_COMPACTION_TRIGGER_TOKENS = 240_000
MODEL_INPUT_COMPACTION_TARGET_TOKENS = 180_000
_COMPACTION_NOTICE = {
    "role": "user",
    "content": (
        "Earlier conversation history was compacted to keep this request below the model's "
        "input-token threshold. Continue from the retained task and recent evidence; re-read "
        "repository files when older detail is needed."
    ),
}
_COMPACTED_ITEM_MAX_BYTES = 64_000


def _compact_item(item: Any) -> dict[str, str]:
    serialized = json.dumps(item, default=str, ensure_ascii=False, separators=(",", ":"))
    encoded = serialized.encode("utf-8")
    if len(encoded) > _COMPACTED_ITEM_MAX_BYTES:
        head_size = (_COMPACTED_ITEM_MAX_BYTES * 2) // 3
        tail_size = _COMPACTED_ITEM_MAX_BYTES - head_size
        head = encoded[:head_size].decode("utf-8", errors="ignore")
        tail = encoded[-tail_size:].decode("utf-8", errors="ignore")
        serialized = f"{head}\n...[older item compacted]...\n{tail}"
    return {
        "role": "user",
        "content": f"Retained content from a compacted history item:\n{serialized}",
    }


def _estimate_input_tokens(
    model: str,
    system_prompt: str | None,
    input_items: list[Any],
    agent: Any,
) -> int:
    """Conservative local estimate; leaves 32k tokens below the 272k price boundary."""
    import litellm  # noqa: PLC0415

    payload = json.dumps(
        {
            "instructions": system_prompt or "",
            "input": input_items,
            "tools": getattr(agent, "tools", []),
            "output_type": str(getattr(agent, "output_type", "")),
        },
        default=str,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    bare_model = model.strip().lower().split("/")[-1]
    try:
        token_count = int(litellm.token_counter(model=bare_model, text=payload))
    except Exception:  # noqa: BLE001
        # UTF-8 bytes are a conservative ceiling for BPE token count.
        token_count = len(payload.encode("utf-8"))
    return token_count + 4_096


def _compact_input_items(
    model: str,
    system_prompt: str | None,
    input_items: list[Any],
    agent: Any,
) -> tuple[int, int]:
    before = _estimate_input_tokens(model, system_prompt, input_items, agent)
    if before < MODEL_INPUT_COMPACTION_TRIGGER_TOKENS or not input_items:
        return before, before

    first = input_items[0]
    if (
        _estimate_input_tokens(model, system_prompt, [first, _COMPACTION_NOTICE], agent)
        > MODEL_INPUT_COMPACTION_TARGET_TOKENS
    ):
        first = _compact_item(first)

    recent: list[Any] = []
    # ponytail: bounded reverse scan; replace with semantic compaction only if
    # losing old tool chatter measurably reduces scan quality.
    for item in reversed(input_items[1:]):
        candidate = [first, _COMPACTION_NOTICE, item, *recent]
        if (
            _estimate_input_tokens(model, system_prompt, candidate, agent)
            <= MODEL_INPUT_COMPACTION_TARGET_TOKENS
        ):
            recent.insert(0, item)
            continue
        if not recent:
            compacted_item = _compact_item(item)
            compacted_candidate = [first, _COMPACTION_NOTICE, compacted_item]
            if (
                _estimate_input_tokens(model, system_prompt, compacted_candidate, agent)
                <= MODEL_INPUT_COMPACTION_TARGET_TOKENS
            ):
                recent.insert(0, compacted_item)
            break

    input_items[:] = [first, _COMPACTION_NOTICE, *recent]
    return before, _estimate_input_tokens(model, system_prompt, input_items, agent)


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage after every model response."""

    def __init__(self, *, model: str, max_budget_usd: float | None = None) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        self._model = model
        self._max_budget_usd = max_budget_usd

    async def on_llm_start(
        self,
        _context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[Any],
    ) -> None:
        before, after = _compact_input_items(self._model, system_prompt, input_items, agent)
        if after < before:
            logger.info(
                "Compacted model input before request: tokens=%s -> %s, items=%s",
                before,
                after,
                len(input_items),
            )

    async def on_llm_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        report_state = get_global_report_state()
        if report_state is None:
            return

        ctx = context.context if isinstance(context.context, dict) else {}
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = ctx.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = agent_name or "unknown"

        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=self._model,
                usage=response.usage,
            )
        except Exception:
            logger.exception("failed to record SDK usage for agent %s", agent_id)

        if self._max_budget_usd is not None:
            cost = report_state.get_total_llm_cost()
            if cost >= self._max_budget_usd:
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
