# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import asyncio
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

# Keep the root session comfortably below a request that could consume most of
# a small protected scan budget. Older evidence remains available in sandbox
# artifacts and can be re-read on demand.
MODEL_INPUT_COMPACTION_TRIGGER_TOKENS = 96_000
MODEL_INPUT_COMPACTION_TARGET_TOKENS = 64_000
_COMPACTION_NOTICE = {
    "role": "user",
    "content": (
        "Earlier conversation history was compacted to keep this request below the model's "
        "input-token threshold. Continue from the retained task and recent evidence; re-read "
        "repository files when older detail is needed."
    ),
}
_COMPACTED_ITEM_MAX_BYTES = 64_000
_GPT56_LONG_CONTEXT_TOKENS = 272_000
_GPT56_RATES = {
    "sol": (6.25, 0.5, 30.0),
    "terra": (3.125, 0.25, 15.0),
    "luna": (1.25, 0.1, 6.0),
}


def _model_rates(model: str) -> tuple[float, float, float]:
    normalized = model.lower()
    for tier, rates in _GPT56_RATES.items():
        if tier in normalized:
            return rates
    raise RuntimeError("Unsupported model for LyraShield budget enforcement")


def _usage_cost_upper_bound(model: str, usage: Any) -> float:
    input_rate, cached_input_rate, output_rate = _model_rates(model)
    entries = list(getattr(usage, "request_usage_entries", None) or [usage])
    total = 0.0
    for entry in entries:
        input_tokens = max(0, int(getattr(entry, "input_tokens", 0) or 0))
        output_tokens = max(0, int(getattr(entry, "output_tokens", 0) or 0))
        input_details = getattr(entry, "input_tokens_details", None)
        if isinstance(input_details, list):
            input_details = input_details[0] if input_details else None
        cached_input_tokens = min(
            input_tokens,
            max(0, int(getattr(input_details, "cached_tokens", 0) or 0)),
        )
        uncached_input_tokens = input_tokens - cached_input_tokens
        multiplier = 2.0 if input_tokens > _GPT56_LONG_CONTEXT_TOKENS else 1.0
        total += (
            uncached_input_tokens * input_rate * multiplier
            + cached_input_tokens * cached_input_rate * multiplier
            + output_tokens * output_rate * (1.5 if multiplier > 1 else 1.0)
        ) / 1_000_000
    return total


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


def _item_type(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("type") or item.get("role") or "").lower()
    return str(getattr(item, "type", "") or getattr(item, "role", "")).lower()


def _history_groups(items: list[Any]) -> list[list[Any]]:
    """Keep tool-call batches and their outputs in the same compaction unit."""
    groups: list[list[Any]] = []
    tool_group: list[Any] | None = None
    for item in items:
        item_type = _item_type(item)
        is_output = item_type == "tool" or item_type.endswith("_output")
        is_call = item_type.endswith("_call") and not is_output
        if is_call:
            if tool_group is None:
                tool_group = []
                groups.append(tool_group)
            tool_group.append(item)
        elif is_output:
            if tool_group is None:
                # A pre-existing orphan cannot be sent as a protocol item. Preserve
                # its readable content as ordinary background instead.
                groups.append([_compact_item(item)])
            else:
                tool_group.append(item)
        else:
            tool_group = None
            groups.append([item])
    return groups


def _estimate_input_tokens(
    model: str,
    system_prompt: str | None,
    input_items: list[Any],
    agent: Any,
) -> int:
    """Conservative local estimate for bounded context and reservations."""
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

    groups = _history_groups(input_items[1:])

    def suffix(start: int) -> list[Any]:
        return [item for group in groups[start:] for item in group]

    # Find the largest complete suffix in O(log n) token estimates. Keeping
    # groups intact prevents orphaned function/tool outputs.
    low, high = 0, len(groups)
    while low < high:
        middle = (low + high) // 2
        candidate = [first, _COMPACTION_NOTICE, *suffix(middle)]
        if (
            _estimate_input_tokens(model, system_prompt, candidate, agent)
            <= MODEL_INPUT_COMPACTION_TARGET_TOKENS
        ):
            high = middle
        else:
            low = middle + 1

    recent = suffix(low)
    if not recent and groups:
        compacted_group = _compact_item(groups[-1])
        if (
            _estimate_input_tokens(
                model,
                system_prompt,
                [first, _COMPACTION_NOTICE, compacted_group],
                agent,
            )
            <= MODEL_INPUT_COMPACTION_TARGET_TOKENS
        ):
            recent = [compacted_group]

    input_items[:] = [first, _COMPACTION_NOTICE, *recent]
    return before, _estimate_input_tokens(model, system_prompt, input_items, agent)


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage after every model response."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        max_output_tokens: int = 8_192,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._max_output_tokens = max_output_tokens
        self._reservation_lock = asyncio.Lock()
        self._reservations: dict[str, float] = {}
        self._committed_cost_floor = 0.0

    @staticmethod
    def _agent_id(context: RunContextWrapper[dict[str, Any]], agent: Agent[dict[str, Any]]) -> str:
        ctx = context.context if isinstance(context.context, dict) else {}
        value = ctx.get("agent_id")
        if isinstance(value, str) and value:
            return value
        name = getattr(agent, "name", None)
        return name if isinstance(name, str) and name else "unknown"

    def _agent_model(self, agent: Agent[dict[str, Any]]) -> str:
        model = getattr(agent, "model", None)
        return model if isinstance(model, str) and model.strip() else self._model

    def _agent_max_output_tokens(self, agent: Agent[dict[str, Any]]) -> int:
        model_settings = getattr(agent, "model_settings", None)
        max_tokens = getattr(model_settings, "max_tokens", None)
        if isinstance(max_tokens, int) and max_tokens > 0:
            return max_tokens
        return self._max_output_tokens

    async def on_llm_start(
        self,
        _context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[Any],
    ) -> None:
        model = self._agent_model(agent)
        before, after = _compact_input_items(model, system_prompt, input_items, agent)
        if after < before:
            logger.info(
                "Compacted model input before request: tokens=%s -> %s, items=%s",
                before,
                after,
                len(input_items),
            )
        if self._max_budget_usd is not None:
            input_rate, _, output_rate = _model_rates(model)
            multiplier = 2.0 if after > _GPT56_LONG_CONTEXT_TOKENS else 1.0
            reservation = (
                after * input_rate * multiplier
                + self._agent_max_output_tokens(agent)
                * output_rate
                * (1.5 if multiplier > 1 else 1.0)
            ) / 1_000_000
            agent_id = self._agent_id(_context, agent)
            async with self._reservation_lock:
                # A repeated start for the same agent means the prior attempt did
                # not complete; providers do not bill a response with no usage.
                self._reservations.pop(agent_id, None)
                report_state = get_global_report_state()
                observed = report_state.get_total_llm_cost() if report_state is not None else 0.0
                committed = max(observed, self._committed_cost_floor)
                reserved = sum(self._reservations.values())
                if committed + reserved + reservation > self._max_budget_usd:
                    raise BudgetExceededError(
                        f"Next bounded GPT-5.6 request would exceed ${self._max_budget_usd:.2f}"
                    )
                self._reservations[agent_id] = reservation

    async def on_llm_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        report_state = get_global_report_state()
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = self._agent_id(context, agent)
        model = self._agent_model(agent)

        if report_state is not None:
            try:
                report_state.record_sdk_usage(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    model=model,
                    usage=response.usage,
                )
            except Exception:
                logger.exception("failed to record SDK usage for agent %s", agent_id)

        async with self._reservation_lock:
            self._reservations.pop(agent_id, None)
            if response.usage is not None:
                self._committed_cost_floor += _usage_cost_upper_bound(model, response.usage)

        if self._max_budget_usd is not None:
            observed = report_state.get_total_llm_cost() if report_state is not None else 0.0
            cost = max(observed, self._committed_cost_floor)
            if cost >= self._max_budget_usd:
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
