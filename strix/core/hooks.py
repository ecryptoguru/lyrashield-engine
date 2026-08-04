# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import math
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from agents.lifecycle import RunHooks

from strix.report.state import get_global_report_state
from strix.tools.output_store import _take_prefix, _take_suffix


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse, TResponseInputItem


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

# System-trusted tag for budget/turn warnings injected into the conversation.
# The system prompt instructs the model to treat messages prefixed with this
# tag as system-verified and to ignore any similar-looking content from
# user or peer messages.
_SYSTEM_NOTICE_TAG = "[SYSTEM-NOTICE]"
_GPT56_RATES = {
    "terra": (2.5, 15.0),
    "luna": (1.0, 6.0),
}

_GPT56_CACHED_RATES = {
    "terra": 0.25,
    "luna": 0.1,
}

# Conservative defaults for models not explicitly priced. We deliberately
# overestimate so budget enforcement errs on the side of protecting the
# cap rather than silently overspending. Rates are dollars per 1M tokens.
_DEFAULT_FALLBACK_INPUT_RATE = 5.0
_DEFAULT_FALLBACK_OUTPUT_RATE = 15.0
_DEFAULT_FALLBACK_CACHE_RATE = 0.5

# Headroom kept between a compaction trigger and the long-context boundary, so a
# request that trips the trigger still has room for its output allowance without
# crossing into 2x input billing.
_LONG_CONTEXT_SAFETY_MARGIN_TOKENS = 32_000
# Ratio between the compaction target and its trigger, preserved from the
# defaults above (64k / 96k) so a custom ceiling compacts equally aggressively.
_COMPACTION_TARGET_RATIO = (
    MODEL_INPUT_COMPACTION_TARGET_TOKENS / MODEL_INPUT_COMPACTION_TRIGGER_TOKENS
)
# A compacted request always retains the first item plus the notice; below this
# a "ceiling" cannot be honored at all, so refuse to shrink past it.
_MIN_COMPACTION_TARGET_TOKENS = 4_000


def resolve_compaction_thresholds(max_input_tokens: int | None) -> tuple[int, int]:
    """Resolve the (trigger, target) token thresholds for input compaction.

    ``max_input_tokens`` is a ceiling that compaction keeps requests under, not a
    hard reject. Unset preserves the module defaults exactly.

    The effective trigger is clamped strictly below the GPT-5.6 long-context
    boundary: compaction exists to keep requests out of 2x input billing, so a
    ceiling above that boundary would defeat the very cost protection this knob is
    meant to provide. Clamping is logged rather than applied silently.
    """
    if max_input_tokens is None:
        return MODEL_INPUT_COMPACTION_TRIGGER_TOKENS, MODEL_INPUT_COMPACTION_TARGET_TOKENS

    ceiling = _GPT56_LONG_CONTEXT_TOKENS - _LONG_CONTEXT_SAFETY_MARGIN_TOKENS
    trigger = max_input_tokens
    if trigger > ceiling:
        logger.warning(
            "LYRASHIELD_MAX_INPUT_TOKENS=%s exceeds the safe long-context ceiling; "
            "clamping to %s to keep requests below the %s-token 2x billing boundary",
            max_input_tokens,
            ceiling,
            _GPT56_LONG_CONTEXT_TOKENS,
        )
        trigger = ceiling

    target = max(int(trigger * _COMPACTION_TARGET_RATIO), _MIN_COMPACTION_TARGET_TOKENS)
    # A pathologically low ceiling must still leave the target below the trigger,
    # otherwise compaction could never report progress.
    target = min(target, trigger)
    return trigger, target


@functools.cache
def _model_rates(model: str) -> tuple[float, float]:
    normalized = model.lower()
    for tier, rates in _GPT56_RATES.items():
        if tier in normalized:
            return rates
    return _fallback_model_rates(model)


@functools.cache
def _cached_input_rate(model: str) -> float:
    normalized = model.lower()
    for tier, rate in _GPT56_CACHED_RATES.items():
        if tier in normalized:
            return rate
    return _fallback_cached_input_rate(model)


@functools.cache
def _fallback_model_rates(model: str) -> tuple[float, float]:
    """Return (input_rate, output_rate) in dollars per 1M tokens.

    Prefer known GPT-5.6 rates (handled by callers); for other models try the
    LiteLLM public cost map. If the model is unknown, use a conservative
    default so budget enforcement does not crash and still overestimates cost.
    """
    cost_info = _lookup_litellm_cost(model)
    if cost_info is not None:
        input_cost = cost_info.get("input_cost_per_token")
        output_cost = cost_info.get("output_cost_per_token")
        if input_cost and output_cost:
            try:
                return float(input_cost) * 1_000_000, float(output_cost) * 1_000_000
            except (TypeError, ValueError):
                pass

    logger.warning("No LiteLLM cost rates for model %s; using conservative fallback rates", model)
    return _DEFAULT_FALLBACK_INPUT_RATE, _DEFAULT_FALLBACK_OUTPUT_RATE


@functools.cache
def _fallback_cached_input_rate(model: str) -> float:
    """Return a cached-input rate in dollars per 1M tokens.

    LiteLLM models often list a cache-read rate; otherwise fall back to a
    fraction of the standard input rate. This is intentionally conservative.
    """
    cost_info = _lookup_litellm_cost(model)
    if cost_info is not None:
        cached_cost = cost_info.get("cache_read_input_token_cost")
        if cached_cost:
            try:
                return float(cached_cost) * 1_000_000
            except (TypeError, ValueError):
                pass

    input_rate, _ = _model_rates(model)
    return max(input_rate * 0.1, _DEFAULT_FALLBACK_CACHE_RATE)


def _lookup_litellm_cost(model: str) -> dict[str, Any] | None:
    """Look up a LiteLLM model_cost entry using common alias normalisations."""
    import litellm  # noqa: PLC0415

    model_cost = cast("dict[str, Any]", getattr(litellm, "model_cost", {}))

    normalized = model.strip().lower()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]

    candidates: list[str] = [normalized, normalized.split("/", 1)[-1]]
    seen: set[str] = set(candidates)
    for name in list(candidates):
        if not name:
            continue
        # litellm sometimes stores keys with dots instead of dashes.
        dotted = name.replace("-", ".")
        dashed = name.replace(".", "-")
        for variant in (dotted, dashed):
            if variant and variant not in seen:
                candidates.append(variant)
                seen.add(variant)

    for name in candidates:
        cost_info = model_cost.get(name)
        if isinstance(cost_info, dict):
            return cast("dict[str, Any]", cost_info)
    return None


def _usage_value(entry: Any, field: str) -> Any:
    """Read a usage counter from either a dict or an object."""
    if isinstance(entry, dict):
        entry = cast("dict[str, Any]", entry)
        return entry.get(field)
    return getattr(entry, field, None)


def _cached_tokens_from_entry(entry: Any) -> int:
    details = _usage_value(entry, "input_tokens_details")
    if not details:
        return 0
    if isinstance(details, dict):
        details = cast("dict[str, Any]", details)
        return max(0, int(details.get("cached_tokens", 0) or 0))
    cached = getattr(details, "cached_tokens", None)
    return max(0, int(cached or 0))


def _usage_cost_upper_bound(model: str, usage: Any) -> float:
    input_rate, output_rate = _model_rates(model)
    cached_rate = _cached_input_rate(model)
    entries = list(getattr(usage, "request_usage_entries", None) or [usage])
    total = 0.0
    for entry in entries:
        input_tokens = max(0, int(_usage_value(entry, "input_tokens") or 0))
        cached_tokens = min(_cached_tokens_from_entry(entry), input_tokens)
        uncached_tokens = input_tokens - cached_tokens
        output_tokens = max(0, int(_usage_value(entry, "output_tokens") or 0))
        multiplier = 2.0 if input_tokens > _GPT56_LONG_CONTEXT_TOKENS else 1.0
        total += (
            uncached_tokens * input_rate * multiplier
            + cached_tokens * cached_rate * multiplier
            + output_tokens * output_rate * (1.5 if multiplier > 1 else 1.0)
        ) / 1_000_000
    return total


def _compact_item(item: Any) -> dict[str, str]:
    serialized = json.dumps(item, default=str, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > _COMPACTED_ITEM_MAX_BYTES:
        head_size = (_COMPACTED_ITEM_MAX_BYTES * 2) // 3
        tail_size = _COMPACTED_ITEM_MAX_BYTES - head_size
        head = _take_prefix(serialized, head_size)
        tail = _take_suffix(serialized, tail_size)
        serialized = f"{head}\n...[older item compacted]...\n{tail}"
    return {
        "role": "user",
        "content": f"Retained content from a compacted history item:\n{serialized}",
    }


def _item_type(item: Any) -> str:
    if isinstance(item, dict):
        item = cast("dict[str, Any]", item)
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
        counter = cast(Callable[..., int], litellm.token_counter)  # noqa: TC006
        token_count = int(counter(model=bare_model, text=payload))
    except Exception:  # noqa: BLE001
        # UTF-8 bytes are a conservative ceiling for BPE token count.
        token_count = len(payload.encode("utf-8"))
    return token_count + 4_096


def _compact_input_items(
    model: str,
    system_prompt: str | None,
    input_items: list[Any],
    agent: Any,
    thresholds: tuple[int, int] | None = None,
) -> tuple[int, int]:
    trigger, target = thresholds or (
        MODEL_INPUT_COMPACTION_TRIGGER_TOKENS,
        MODEL_INPUT_COMPACTION_TARGET_TOKENS,
    )
    before = _estimate_input_tokens(model, system_prompt, input_items, agent)
    if before < trigger or not input_items:
        return before, before

    first = input_items[0]
    if _estimate_input_tokens(model, system_prompt, [first, _COMPACTION_NOTICE], agent) > target:
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
        if _estimate_input_tokens(model, system_prompt, candidate, agent) <= target:
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
            <= target
        ):
            recent = [compacted_group]

    input_items[:] = [first, _COMPACTION_NOTICE, *recent]
    return before, _estimate_input_tokens(model, system_prompt, input_items, agent)


_STAGE_LABELS: tuple[str, ...] = ("NOTICE", "URGENT", "CRITICAL")
_TURN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_ROOT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_SUBAGENT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.75, 0.80, 0.85)
_SUBAGENT_BUDGET_RESERVE = 0.90


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


_active_hooks: ReportUsageHooks | None = None


def set_active_hooks(hooks: ReportUsageHooks | None) -> None:
    """Register the hooks driving the current scan.

    Lets metered call sites outside the agent run loop (deduplication) reserve
    against the same budget. Mirrors the existing global report-state pattern.
    """
    global _active_hooks  # noqa: PLW0603
    _active_hooks = hooks


def get_active_hooks() -> ReportUsageHooks | None:
    return _active_hooks


class SubagentBudgetReservedError(RuntimeError):
    """Raised to stop a single sub-agent once the reserve threshold is crossed."""


class BudgetPausedError(RuntimeError):
    """Raised to park one agent when an interactive scan reaches its budget."""


def recomputed_budget_flags(
    cost: float,
    max_budget_usd: float | None,
    *,
    interactive: bool,
) -> tuple[bool, bool]:
    """Return the (budget_stopped, reserve_stopped) flags a resumed scan should carry."""
    if max_budget_usd is None:
        return False, False
    if interactive:
        return False, False
    budget_stopped = cost >= max_budget_usd
    reserve_stopped = cost >= max_budget_usd * _SUBAGENT_BUDGET_RESERVE
    return budget_stopped, reserve_stopped


def _crossed_stage(fraction: float, bands: tuple[float, ...]) -> int | None:
    crossed: int | None = None
    for index, band in enumerate(bands):
        if fraction >= band:
            crossed = index
    return crossed


_ROOT_DIRECTIVES: tuple[str, ...] = (
    (
        "As the root agent, begin planning your wind-down of the whole scan: avoid "
        "starting large new lines of investigation, and keep your required objectives on "
        "track so you can call finish_scan comfortably before the limit."
    ),
    (
        "As the root agent, prioritize wrapping up the whole scan now: stop opening new "
        "lines of investigation, close out only what is essential, and move toward calling "
        "finish_scan to compile and deliver the final report."
    ),
    (
        "As the root agent, STOP all other work on the whole scan and finish immediately: "
        "secure your findings and call finish_scan now — anything left unfinished when the "
        "limit is hit is discarded."
    ),
)
_SUBAGENT_DIRECTIVES: tuple[str, ...] = (
    (
        "As a sub-agent, begin planning your wind-down: avoid starting large new subtasks, "
        "and if you are close to a confirmed, validated vulnerability, drive it to a result "
        "you can report."
    ),
    (
        "As a sub-agent, prioritize wrapping up your task now: report any confirmed, "
        "validated vulnerability, finish work that is nearly done rather than starting "
        "anything new, and prepare to call agent_finish."
    ),
    (
        "As a sub-agent, STOP all other work and finish immediately: report any confirmed "
        "vulnerability right now and call agent_finish to hand your results back to your "
        "parent before you are cut off."
    ),
)


def _wrapup_directive(context: RunContextWrapper[dict[str, Any]], stage: int) -> str:
    is_root = context.context.get("parent_id") is None
    directives = _ROOT_DIRECTIVES if is_root else _SUBAGENT_DIRECTIVES
    return directives[stage]


def _urgency(stage: int) -> str:
    return _STAGE_LABELS[stage]


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage and warn/stop as turn and cost budgets are consumed."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        max_output_tokens: int = 8_192,
        max_input_tokens: int | None = None,
        max_turns: int | None = None,
        interactive: bool = False,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        if max_turns is not None and max_turns <= 0:
            raise ValueError("max_turns must be a positive integer")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._max_output_tokens = max_output_tokens
        # Resolved once here (including the long-context clamp and its warning)
        # rather than per request, and passed into compaction as a plain tuple so
        # the compaction helper stays free of settings/env coupling.
        self._compaction_thresholds = resolve_compaction_thresholds(max_input_tokens)
        self._reservation_lock = asyncio.Lock()
        self._reservations: dict[str, float] = {}
        self._committed_cost_floor = 0.0
        self._budget_increment = max_budget_usd
        self._max_turns = max_turns
        self._interactive = interactive

    def extend_budget(self) -> None:
        if self._max_budget_usd is None or self._budget_increment is None:
            return
        self._max_budget_usd += self._budget_increment

    async def reserve_out_of_band_request(
        self,
        *,
        key: str,
        model: str,
        input_tokens: int,
        max_output_tokens: int,
    ) -> None:
        """Reserve budget for a metered call that does not flow through these hooks.

        Deduplication queries the model directly rather than through an agent
        run, so `on_llm_start` never sees them. Without this they were only
        recorded after the fact, letting a scan overshoot `max_budget_usd` by
        the cost of every dedupe call in flight.

        Raises `BudgetExceededError` when the request would breach the budget;
        callers must pair this with `release_out_of_band_request`.
        """
        if self._max_budget_usd is None:
            return
        input_rate, output_rate = _model_rates(model)
        multiplier = 2.0 if input_tokens > _GPT56_LONG_CONTEXT_TOKENS else 1.0
        reservation = (
            input_tokens * input_rate * multiplier
            + max_output_tokens * output_rate * (1.5 if multiplier > 1 else 1.0)
        ) / 1_000_000
        async with self._reservation_lock:
            self._reservations.pop(key, None)
            report_state = get_global_report_state()
            observed = report_state.get_total_llm_cost() if report_state is not None else 0.0
            committed = max(observed, self._committed_cost_floor)
            reserved = sum(self._reservations.values())
            if committed + reserved + reservation > self._max_budget_usd:
                raise BudgetExceededError(
                    f"Next bounded request would exceed ${self._max_budget_usd:.2f}"
                )
            self._reservations[key] = reservation

    async def release_out_of_band_request(self, *, key: str, model: str, usage: Any = None) -> None:
        """Drop an out-of-band reservation and commit its observed cost."""
        async with self._reservation_lock:
            self._reservations.pop(key, None)
            if usage is not None:
                self._committed_cost_floor += _usage_cost_upper_bound(model, usage)

    async def reserve_web_search_call(
        self,
        *,
        key: str,
        estimated_cost: float,
    ) -> None:
        """Reserve budget for a Parallel Search web_search call.

        Web search is charged per call, not per token, so this bypasses the
        token-rate math and reserves a fixed cost directly against the scan
        budget. Callers must pair this with ``release_web_search_call``.
        """
        if self._max_budget_usd is None:
            return
        if not math.isfinite(estimated_cost) or estimated_cost < 0:
            estimated_cost = 0.0
        async with self._reservation_lock:
            self._reservations.pop(key, None)
            report_state = get_global_report_state()
            observed = report_state.get_total_llm_cost() if report_state is not None else 0.0
            committed = max(observed, self._committed_cost_floor)
            reserved = sum(self._reservations.values())
            if committed + reserved + estimated_cost > self._max_budget_usd:
                raise BudgetExceededError(
                    f"Next web search would exceed ${self._max_budget_usd:.2f}"
                )
            self._reservations[key] = estimated_cost

    async def release_web_search_call(self, *, key: str, actual_cost: float) -> None:
        """Drop a web search reservation and commit the observed per-call cost."""
        if not math.isfinite(actual_cost) or actual_cost < 0:
            actual_cost = 0.0
        async with self._reservation_lock:
            self._reservations.pop(key, None)
            self._committed_cost_floor += actual_cost

    @property
    def compaction_trigger_tokens(self) -> int:
        """Input-token threshold above which history is compacted (post-clamp)."""
        return self._compaction_thresholds[0]

    @property
    def compaction_target_tokens(self) -> int:
        """Input-token size compaction aims for once triggered (post-clamp)."""
        return self._compaction_thresholds[1]

    def _maybe_warn_turns(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if not self._max_turns:
            return
        usage = getattr(context, "usage", None)
        requests = getattr(usage, "requests", None)
        if not isinstance(requests, int):
            return
        turns_used = requests + 1
        stage = _crossed_stage(turns_used / self._max_turns, _TURN_WARN_BANDS)
        if stage is None:
            return
        remaining = max(self._max_turns - turns_used, 0)
        pct = round(100 * turns_used / self._max_turns)
        content = (
            f"{_SYSTEM_NOTICE_TAG} [{_urgency(stage)}] Turn budget: "
            f"{turns_used}/{self._max_turns} used ({pct}%). "
            f"About {remaining} turn(s) remain before this agent is force-stopped and any "
            f"in-progress work is discarded. {_wrapup_directive(context, stage)}"
        )
        input_items.append({"role": "user", "content": content})

    def _maybe_warn_budget(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._max_budget_usd is None:
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        cost = report_state.get_total_llm_cost()
        is_root = context.context.get("parent_id") is None
        if self._interactive:
            bands = _ROOT_BUDGET_WARN_BANDS
        else:
            bands = _ROOT_BUDGET_WARN_BANDS if is_root else _SUBAGENT_BUDGET_WARN_BANDS
        stage = _crossed_stage(cost / self._max_budget_usd, bands)
        if stage is None:
            return
        pct = round(100 * cost / self._max_budget_usd)
        reserve_pct = round(_SUBAGENT_BUDGET_RESERVE * 100)
        if self._interactive:
            content = (
                f"{_SYSTEM_NOTICE_TAG} [{_urgency(stage)}] Scan cost budget: "
                f"${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached all agents are paused until the user chooses to continue. "
                f"{_wrapup_directive(context, stage)}"
            )
        elif is_root:
            content = (
                f"{_SYSTEM_NOTICE_TAG} [{_urgency(stage)}] Scan cost budget: "
                f"${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached the whole scan is stopped immediately, and sub-agents are stopped at "
                f"{reserve_pct}% to reserve the remainder for your final report. "
                f"{_wrapup_directive(context, stage)}"
            )
        else:
            content = (
                f"{_SYSTEM_NOTICE_TAG} [{_urgency(stage)}] Scan cost budget: "
                f"${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; "
                f"sub-agents are stopped at {reserve_pct}% to leave the remainder for the root "
                f"agent's final report. {_wrapup_directive(context, stage)}"
            )
        input_items.append({"role": "user", "content": content})

    @staticmethod
    def _agent_id(context: RunContextWrapper[dict[str, Any]], agent: Agent[dict[str, Any]]) -> str:
        ctx = context.context
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
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        try:
            self._maybe_warn_turns(context, input_items)
            self._maybe_warn_budget(context, input_items)
        except Exception:
            logger.exception("budget/turn warning injection failed")

        model = self._agent_model(agent)
        before, after = _compact_input_items(
            model,
            system_prompt,
            input_items,
            agent,
            self._compaction_thresholds,
        )
        if after < before:
            logger.info(
                "Compacted model input before request: tokens=%s -> %s, items=%s",
                before,
                after,
                len(input_items),
            )
        if self._max_budget_usd is not None:
            input_rate, output_rate = _model_rates(model)
            multiplier = 2.0 if after > _GPT56_LONG_CONTEXT_TOKENS else 1.0
            reservation = (
                after * input_rate * multiplier
                + self._agent_max_output_tokens(agent)
                * output_rate
                * (1.5 if multiplier > 1 else 1.0)
            ) / 1_000_000
            agent_id = self._agent_id(context, agent)
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
                        f"Next bounded request would exceed ${self._max_budget_usd:.2f}"
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
            self._committed_cost_floor += _usage_cost_upper_bound(model, response.usage)

        if self._max_budget_usd is not None:
            observed = report_state.get_total_llm_cost() if report_state is not None else 0.0
            cost = max(observed, self._committed_cost_floor)
            if cost >= self._max_budget_usd:
                if self._interactive:
                    raise BudgetPausedError(
                        f"Scan budget of ${self._max_budget_usd:.2f} reached "
                        f"(spent ${cost:.4f}); pausing until the user continues"
                    )
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
            is_root = context.context.get("parent_id") is None
            if not self._interactive and not is_root:
                reserve_limit = self._max_budget_usd * _SUBAGENT_BUDGET_RESERVE
                if cost >= reserve_limit:
                    raise SubagentBudgetReservedError(
                        f"Sub-agent budget reserve reached: spent ${cost:.4f} of "
                        f"${self._max_budget_usd:.2f} "
                        f"(>= {round(_SUBAGENT_BUDGET_RESERVE * 100)}% reserve); stopping this "
                        "sub-agent so the root agent can finish the scan."
                    )
