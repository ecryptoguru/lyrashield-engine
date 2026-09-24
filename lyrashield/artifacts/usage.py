# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""SDK-native LLM usage aggregation for scan reports."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, cast

from agents.usage import Usage, deserialize_usage, serialize_usage


logger = logging.getLogger(__name__)


_GPT56_USD_PER_MILLION: dict[str, tuple[float, float, float, float]] = {
    "gpt-5.6-terra": (2.0, 0.2, 2.5, 12.0),
    "gpt-5.6-luna": (0.2, 0.02, 0.25, 1.2),
}
_GPT6_USD_PER_MILLION: dict[str, tuple[float, float, float, float]] = {
    "gpt-6-sol": (2.0, 0.2, 2.5, 10.0),
    "gpt-6-luna": (0.1, 0.01, 0.125, 0.5),
}
_METERED_USD_PER_MILLION = {**_GPT56_USD_PER_MILLION, **_GPT6_USD_PER_MILLION}
_GPT56_LONG_CONTEXT_THRESHOLD_TOKENS = 272_000


def extract_provider_usage(response: Any) -> dict[str, Any] | None:
    """Keep only validated numeric usage from a completed raw Responses result."""
    raw = response.model_dump(exclude_unset=True) if hasattr(response, "model_dump") else response
    if not isinstance(raw, Mapping) or raw.get("status") != "completed":
        return None
    response_id = raw.get("id")
    usage = raw.get("usage")
    if not isinstance(response_id, str) or not response_id or not isinstance(usage, Mapping):
        return None
    details = usage.get("input_tokens_details")
    if not isinstance(details, Mapping):
        return None
    values = (
        usage.get("input_tokens"),
        details.get("cached_tokens"),
        details.get("cache_write_tokens"),
        usage.get("output_tokens"),
    )
    if any(type(value) is not int or value < 0 for value in values):
        return None
    input_tokens, cached_tokens, cache_write_tokens, output_tokens = cast(
        "tuple[int, int, int, int]", values
    )
    if cached_tokens + cache_write_tokens > input_tokens:
        return None
    return {
        "response_id": response_id,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "input_tokens_details": {
            "cached_tokens": cached_tokens,
            "cache_write_tokens": cache_write_tokens,
        },
    }


class LLMUsageLedger:
    """Aggregate SDK ``Usage`` objects and attach best-effort cost estimates."""

    def __init__(self) -> None:
        self._total_usage = Usage()
        self._agent_usage: dict[str, Usage] = {}
        self._agent_metadata: dict[str, dict[str, str]] = {}
        self._request_usage_entries: list[dict[str, Any]] = []
        self._gpt6_accounting_complete = True
        self._gpt6_seen = False
        self._recorded_response_ids: set[str] = set()
        self._total_cost = 0.0
        self._has_cost = False
        # Per-agent cost accumulated at record() time from the model rate card.
        # Token-share pro-rata is only a fallback for cost that cannot be
        # attributed to one agent (e.g. provider-reported callback cost).
        self._agent_costs: dict[str, float] = {}
        # Models for which the LiteLLM success callback already reported an
        # observed cost; record() must not ALSO estimate those tokens.
        self._observed_cost_models: set[str] = set()
        # Response ids already counted via record_observed_cost (callback
        # double-fire protection).
        self._observed_response_ids: set[str] = set()
        # When True, tokens are still tracked but cost stays $0 — the run is on a
        # model subscription, so there is no metered per-token charge to report.
        self.zero_cost = False
        # Ancillary provider charges (web search, etc.) classified by category.
        # These are NOT covered by a model subscription: subscription zero-cost
        # applies only to covered model-token categories, so ancillary charges
        # stay metered and reach the reconciled total.
        self._ancillary_costs: dict[str, float] = {}

    def record(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
        provider_receipt: dict[str, Any] | None = None,
    ) -> bool:
        if usage is None or not _usage_has_activity(usage):
            return False

        is_gpt6 = _normalized_model_key(model) in _GPT6_USD_PER_MILLION
        if is_gpt6:
            self._gpt6_seen = True
            response_id = provider_receipt.get("response_id") if provider_receipt else None
            if isinstance(response_id, str) and response_id in self._recorded_response_ids:
                return False
            complete = (
                provider_receipt is not None
                and usage.requests == 1
                and provider_receipt["input_tokens"] == usage.input_tokens
                and provider_receipt["output_tokens"] == usage.output_tokens
            )
            self._gpt6_accounting_complete = self._gpt6_accounting_complete and complete
            if isinstance(response_id, str):
                self._recorded_response_ids.add(response_id)

        normalized_agent_id = str(agent_id or "unknown")
        self._total_usage.add(usage)
        self._agent_usage.setdefault(normalized_agent_id, Usage()).add(usage)
        if is_gpt6 and provider_receipt is not None and usage.requests == 1:
            self._request_usage_entries.append({**provider_receipt, "model": model})
        elif not is_gpt6:
            self._request_usage_entries.extend(_serialize_request_usage_entries(usage, model=model))

        metadata = self._agent_metadata.setdefault(normalized_agent_id, {})
        if agent_name:
            metadata["agent_name"] = agent_name
        if model:
            metadata["model"] = model

        if not self.zero_cost and _normalized_model_key(model) not in self._observed_cost_models:
            estimated = (
                estimate_gpt56_request_cost_usd(
                    model,
                    input_tokens=provider_receipt["input_tokens"],
                    cached_input_tokens=provider_receipt["input_tokens_details"]["cached_tokens"],
                    cache_write_input_tokens=provider_receipt["input_tokens_details"][
                        "cache_write_tokens"
                    ],
                    output_tokens=provider_receipt["output_tokens"],
                )
                if is_gpt6 and provider_receipt is not None and usage.requests == 1
                else None
                if is_gpt6
                else _estimate_gpt56_cost(usage, model)
            )
            if estimated is None and _gpt56_rate(model) is None and not _is_litellm_routed(model):
                estimated = _estimate_litellm_cost(usage, model)
            if estimated:
                self._total_cost += estimated
                self._agent_costs[normalized_agent_id] = (
                    self._agent_costs.get(normalized_agent_id, 0.0) + estimated
                )
                self._has_cost = True

        return True

    def record_observed_cost(
        self,
        cost: Any,
        *,
        model: str | None = None,
        response_id: str | None = None,
    ) -> None:
        if self.zero_cost or _gpt56_rate(model) is not None:
            return
        if response_id is not None:
            if response_id in self._observed_response_ids:
                return
            self._observed_response_ids.add(response_id)
        try:
            numeric_cost = float(cost)
        except (TypeError, ValueError):
            return
        if numeric_cost > 0:
            self._total_cost += numeric_cost
            self._has_cost = True
            model_key = _normalized_model_key(model)
            if model_key:
                self._observed_cost_models.add(model_key)

    def record_ancillary_cost(self, category: str, cost: Any) -> None:
        """Record a metered ancillary charge (e.g. paid web search).

        Ancillary charges are outside the model-subscription coverage, so
        they are recorded regardless of ``zero_cost`` and included in the
        reconciled total alongside (possibly zero) model-token cost.
        """
        try:
            numeric_cost = float(cost)
        except (TypeError, ValueError):
            return
        if numeric_cost > 0:
            self._ancillary_costs[category] = (
                self._ancillary_costs.get(category, 0.0) + numeric_cost
            )

    @property
    def ancillary_cost_total(self) -> float:
        return _round_cost(sum(self._ancillary_costs.values()))

    @property
    def total_cost(self) -> float:
        return _round_cost(self._total_cost + sum(self._ancillary_costs.values()))

    def to_record(self) -> dict[str, Any]:
        record = serialize_usage(self._total_usage)
        # ``Usage.add`` reconstructs SDK request entries from aggregate detail
        # models, which can drop provider extension fields such as
        # ``cache_write_tokens``. Preserve each original response receipt so
        # the worker can price it exactly when the provider exposed every
        # billable dimension.
        if self._request_usage_entries:
            record["request_usage_entries"] = list(self._request_usage_entries)
        elif self._gpt6_seen or self._total_usage.requests != 1:
            # The SDK may synthesize one request entry from a multi-request
            # aggregate. It has no per-call cache buckets, so it cannot be
            # used for exact pricing.
            record.pop("request_usage_entries", None)
        if self._gpt6_seen:
            gpt6_receipts = sum(
                _normalized_model_key(entry.get("model")) in _GPT6_USD_PER_MILLION
                for entry in self._request_usage_entries
            )
            record["accounting_complete"] = self._gpt6_accounting_complete and (
                gpt6_receipts == self._total_usage.requests
            )
        ancillary_total = sum(self._ancillary_costs.values())
        reconciled = self._total_cost + ancillary_total
        if self._has_cost or self.zero_cost or ancillary_total > 0:
            record["cost"] = _round_cost(reconciled)
        if self.zero_cost:
            record["subscription"] = True
        if ancillary_total > 0:
            # Subscription zero-cost covers model tokens only; ancillary
            # charges stay classified so the total reconciles by category.
            record["ancillary_costs"] = {
                category: _round_cost(amount) for category, amount in self._ancillary_costs.items()
            }
        agents: list[dict[str, Any]] = []

        agent_tokens = {aid: _resolve_total_tokens(u) for aid, u in self._agent_usage.items()}
        # Cost attributed to no single agent (provider callback cost, web search)
        # is shared pro-rata so per-agent costs still sum to the run total.
        priced_total = sum(
            self._agent_costs[aid] for aid in self._agent_usage if aid in self._agent_costs
        )
        residual = max(0.0, self._total_cost - priced_total)
        share_recipients: list[str] = []
        if residual > 0 and self._agent_usage:
            fallback = [aid for aid in self._agent_usage if aid not in self._agent_costs]
            share_recipients = fallback or list(self._agent_usage)
            share_tokens = sum(agent_tokens[aid] for aid in share_recipients)
            if share_tokens > 0:
                residual_shares = {
                    aid: residual * agent_tokens[aid] / share_tokens for aid in share_recipients
                }
            else:
                residual_shares = {
                    aid: residual / len(share_recipients) for aid in share_recipients
                }
        else:
            residual_shares = {}

        all_priced = True
        for agent_id in sorted(self._agent_usage):
            usage = self._agent_usage[agent_id]
            metadata = self._agent_metadata.get(agent_id, {})
            priced = self._agent_costs.get(agent_id)
            shared = residual_shares.get(agent_id, 0.0)
            if priced is not None:
                agent_cost: float | None = priced + shared
                cost_basis = "per_agent_priced" if shared == 0.0 else "pro_rata"
            else:
                agent_cost = shared if self._has_cost else None
                cost_basis = "pro_rata"
            if cost_basis != "per_agent_priced":
                all_priced = False

            agent_record = serialize_usage(usage)
            agent_record.update(
                {
                    "agent_id": agent_id,
                    "agent_name": metadata.get("agent_name") or agent_id,
                    "model": metadata.get("model"),
                }
            )
            if agent_cost is not None:
                agent_record["cost"] = _round_cost(agent_cost)
                agent_record["cost_basis"] = cost_basis
            agents.append(agent_record)

        record["agents"] = agents
        if (self._has_cost or self.zero_cost) and agents:
            record["cost_basis"] = "per_agent_priced" if all_priced else "pro_rata"
        return record

    def hydrate(self, raw_usage: Any) -> None:
        self._total_usage = Usage()
        self._agent_usage.clear()
        self._agent_metadata.clear()
        self._request_usage_entries.clear()
        self._gpt6_accounting_complete = True
        self._gpt6_seen = False
        self._recorded_response_ids.clear()
        self._total_cost = 0.0
        self._has_cost = False
        self._agent_costs.clear()
        self._observed_cost_models.clear()
        self._observed_response_ids.clear()
        self._ancillary_costs.clear()

        if not isinstance(raw_usage, dict):
            return
        raw_usage = cast("dict[str, Any]", raw_usage)

        raw_ancillary = raw_usage.get("ancillary_costs")
        if isinstance(raw_ancillary, dict):
            for category, amount in raw_ancillary.items():
                if isinstance(category, str):
                    self.record_ancillary_cost(category, amount)

        try:
            self._total_usage = deserialize_usage(raw_usage)
        except Exception:
            logger.exception("Failed to hydrate aggregate llm_usage from run.json")
            self._total_usage = Usage()

        if "cost" in raw_usage:
            # Persisted cost is the reconciled total (model + ancillary);
            # keep the model-token portion here so categories don't
            # double-count after resume.
            persisted_total = _float_or_zero(raw_usage.get("cost"))
            self._total_cost = max(0.0, persisted_total - sum(self._ancillary_costs.values()))
            self._has_cost = True
        self._request_usage_entries = _hydrate_request_usage_entries(
            raw_usage.get("request_usage_entries")
        )
        self._recorded_response_ids = {
            entry["response_id"]
            for entry in self._request_usage_entries
            if isinstance(entry.get("response_id"), str)
        }
        self._gpt6_seen = (
            any(
                _normalized_model_key(entry.get("model")) in _GPT6_USD_PER_MILLION
                for entry in self._request_usage_entries
            )
            or "accounting_complete" in raw_usage
        )
        self._gpt6_accounting_complete = raw_usage.get("accounting_complete") is True

        raw_agents = raw_usage.get("agents")
        if isinstance(raw_agents, list):
            for raw in raw_agents:
                if not isinstance(raw, dict):
                    continue
                raw_agent = cast("dict[str, Any]", raw)
                agent_id = str(raw_agent.get("agent_id") or "").strip()
                if not agent_id:
                    continue
                try:
                    self._agent_usage[agent_id] = deserialize_usage(raw_agent)
                except Exception:
                    logger.exception("Failed to hydrate llm_usage for agent %s", agent_id)
                    self._agent_usage[agent_id] = Usage()

                metadata: dict[str, str] = {}
                agent_name = raw_agent.get("agent_name")
                model = raw_agent.get("model")
                if isinstance(agent_name, str) and agent_name:
                    metadata["agent_name"] = agent_name
                if isinstance(model, str) and model:
                    metadata["model"] = model
                self._agent_metadata[agent_id] = metadata

                # Restore per-agent priced costs so a resumed run keeps exact
                # attribution instead of falling back to token-share pro-rata.
                if raw_agent.get("cost_basis") == "per_agent_priced":
                    cost = raw_agent.get("cost")
                    if isinstance(cost, int | float) and cost > 0:
                        self._agent_costs[agent_id] = float(cost)


def _normalized_model_key(model: str | None) -> str | None:
    if not model:
        return None
    return model.strip().lower().split("/")[-1] or None


def _resolve_total_tokens(usage: Usage) -> int:
    total = max(0, int(usage.total_tokens or 0))
    if total > 0:
        return total
    prompt = _int_or_zero(getattr(usage, "input_tokens", 0))
    completion = _int_or_zero(getattr(usage, "output_tokens", 0))
    return prompt + completion


def _is_litellm_routed(model: str | None) -> bool:
    if not model:
        return False
    name = model.strip().lower()
    if "/" not in name:
        return False
    return not name.startswith("openai/")


def _gpt56_rate(model: str | None) -> tuple[float, float, float, float] | None:
    if not model:
        return None
    return _METERED_USD_PER_MILLION.get(model.strip().lower().split("/")[-1])


def gpt56_usd_per_million(model: str | None) -> tuple[float, float, float, float] | None:
    """Read-only LyraShield model rate lookup shared with offline evaluators.

    Returns ``(uncached input, cached read, cache write, output)`` USD per
    million tokens using the ledger's model normalization (lowercase,
    stripped, last path segment). ``None`` for models outside the GPT-5.6
    rate card, including historical GPT-5.6 receipts.
    """
    return _gpt56_rate(model)


def estimate_gpt56_request_cost_usd(
    model: str | None,
    *,
    input_tokens: float,
    cached_input_tokens: float,
    cache_write_input_tokens: float,
    output_tokens: float,
) -> float | None:
    """Price one validated request using the versioned LyraShield rate card."""
    rate = _gpt56_rate(model)
    if rate is None:
        return None
    input_multiplier = 2.0 if input_tokens > _GPT56_LONG_CONTEXT_THRESHOLD_TOKENS else 1.0
    output_multiplier = 1.5 if input_multiplier > 1.0 else 1.0
    uncached_input_tokens = input_tokens - cached_input_tokens - cache_write_input_tokens
    return (
        uncached_input_tokens * rate[0] * input_multiplier
        + cached_input_tokens * rate[1] * input_multiplier
        + cache_write_input_tokens * rate[2] * input_multiplier
        + output_tokens * rate[3] * output_multiplier
    ) / 1_000_000


def _estimate_gpt56_cost(usage: Usage, model: str | None) -> float | None:
    entries: list[Any] = list(usage.request_usage_entries or [])
    if not entries and usage.requests == 1:
        entries = [usage]
    if not entries:
        return None
    total = 0.0
    for entry in entries:
        input_tokens = _int_or_zero(getattr(entry, "input_tokens", 0))
        output_tokens = _int_or_zero(getattr(entry, "output_tokens", 0))
        if input_tokens + output_tokens <= 0:
            continue
        details = _details_to_dict(getattr(entry, "input_tokens_details", None))
        if _normalized_model_key(model) in _GPT6_USD_PER_MILLION and (
            "cached_tokens" not in details or "cache_write_tokens" not in details
        ):
            return None
        cached = min(_int_or_zero(details.get("cached_tokens")), input_tokens)
        cache_write = min(_int_or_zero(details.get("cache_write_tokens")), input_tokens - cached)
        cost = estimate_gpt56_request_cost_usd(
            model,
            input_tokens=input_tokens,
            cached_input_tokens=cached,
            cache_write_input_tokens=cache_write,
            output_tokens=output_tokens,
        )
        if cost is None:
            return None
        total += cost
    return _round_cost(total)


def _usage_has_activity(usage: Usage) -> bool:
    return bool(
        usage.requests
        or usage.input_tokens
        or usage.output_tokens
        or usage.total_tokens
        or usage.request_usage_entries
    )


def _estimate_litellm_cost(usage: Usage, model: str | None) -> float | None:
    litellm_model = _litellm_model_name(model)
    if not litellm_model:
        return None

    entries = list(usage.request_usage_entries or [])
    if not entries:
        return _estimate_litellm_entry_cost(usage, litellm_model)

    total = 0.0
    estimated_any = False
    for entry in entries:
        cost = _estimate_litellm_entry_cost(entry, litellm_model)
        if cost is None:
            continue
        total += cost
        estimated_any = True

    return total if estimated_any else None


def _estimate_litellm_entry_cost(entry: Any, model: str) -> float | None:
    prompt_tokens = _int_or_zero(getattr(entry, "input_tokens", 0))
    completion_tokens = _int_or_zero(getattr(entry, "output_tokens", 0))
    total_tokens = _int_or_zero(getattr(entry, "total_tokens", 0))
    if total_tokens <= 0:
        total_tokens = prompt_tokens + completion_tokens
    if total_tokens <= 0:
        return None

    usage_payload: dict[str, Any] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }
    prompt_details = _details_to_dict(getattr(entry, "input_tokens_details", None))
    completion_details = _details_to_dict(getattr(entry, "output_tokens_details", None))
    if prompt_details:
        usage_payload["prompt_tokens_details"] = prompt_details
    if completion_details:
        usage_payload["completion_tokens_details"] = completion_details

    from litellm import completion_cost

    candidates = [model]
    if "/" in model:
        candidates.append(model.split("/", 1)[-1])

    cost: Any = None
    for candidate in candidates:
        try:
            cost = completion_cost(
                completion_response={"model": candidate, "usage": usage_payload},
                model=model,
            )
            break
        except Exception:  # nosec B112  # noqa: BLE001, S112
            continue

    if cost is None:
        logger.debug("LiteLLM cost estimate unavailable for model %s", model)
        return None

    return cost if isinstance(cost, int | float) and cost >= 0 else None


def _litellm_model_name(model: str | None) -> str | None:
    if not model:
        return None
    normalized = model.strip()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if normalized.startswith(prefix):
            normalized = normalized.removeprefix(prefix)
            break
    return normalized or None


def _details_to_dict(details: Any) -> dict[str, Any]:
    if details is None:
        return {}
    if isinstance(details, list):
        for item in details:
            result = _details_to_dict(item)
            if result:
                return result
        return {}
    if hasattr(details, "model_dump"):
        return _details_to_dict(details.model_dump())
    if not isinstance(details, dict):
        return {}
    return {str(k): v for k, v in details.items() if v is not None}


def _serialize_request_usage_entries(
    usage: Usage,
    *,
    model: str | None = None,
) -> list[dict[str, Any]]:
    entries: list[Any] = list(usage.request_usage_entries or [])
    # An aggregate covering more than one request is not a billable receipt:
    # its cache buckets may differ per call. Keep it out of the exact-pricing
    # path until the provider supplies the individual records.
    if not entries and usage.requests == 1 and _usage_has_activity(usage):
        entries = [usage]
    serialized = [_serialize_request_usage_entry(entry) for entry in entries]
    if model:
        for entry in serialized:
            entry["model"] = model
    return serialized


def _serialize_request_usage_entry(
    entry: Any, *, preserve_zero_write: bool = False
) -> dict[str, Any]:
    input_tokens = _int_or_zero(getattr(entry, "input_tokens", 0))
    output_tokens = _int_or_zero(getattr(entry, "output_tokens", 0))
    total_tokens = _int_or_zero(getattr(entry, "total_tokens", 0))
    input_details = _details_to_dict(getattr(entry, "input_tokens_details", None))
    details: dict[str, int] = {
        "cached_tokens": _int_or_zero(input_details.get("cached_tokens")),
    }
    cache_write_tokens = input_details.get("cache_write_tokens")
    if isinstance(cache_write_tokens, int) and (cache_write_tokens > 0 or preserve_zero_write):
        details["cache_write_tokens"] = cache_write_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens or input_tokens + output_tokens,
        "input_tokens_details": details,
    }


def _hydrate_request_usage_entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    entries: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        entry = cast("dict[str, Any]", entry)
        serialized = _serialize_request_usage_entry(
            _UsageEntryAdapter(entry), preserve_zero_write=bool(entry.get("response_id"))
        )
        model = entry.get("model")
        if isinstance(model, str) and model:
            serialized["model"] = model
        response_id = entry.get("response_id")
        if isinstance(response_id, str) and response_id:
            serialized["response_id"] = response_id
        entries.append(serialized)
    return entries


class _UsageEntryAdapter:
    """Adapter for preserving bounded serialized receipts during resume."""

    def __init__(self, entry: dict[str, Any]) -> None:
        self.input_tokens = entry.get("input_tokens")
        self.output_tokens = entry.get("output_tokens")
        self.total_tokens = entry.get("total_tokens")
        self.input_tokens_details = entry.get("input_tokens_details")


def _int_or_zero(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _float_or_zero(value: Any) -> float:
    try:
        result = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return result if result >= 0 else 0.0


def _round_cost(cost: float) -> float:
    return round(max(0.0, cost), 10)
