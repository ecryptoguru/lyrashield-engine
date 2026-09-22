"""Exact cache-economics evaluator for serialized ``run.json`` records.

Read-only analysis: no provider or network calls, no mutation of the input
record, and no logging of run content. Provider receipts in
``llm_usage.request_usage_entries`` are the accounting authority; entries are
validated before pricing and inconsistent receipts are flagged with bounded
error codes instead of being silently coerced or clamped. All scenario
outputs are hypothetical repricings of recorded buckets, never measured
savings, and are never summed together.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lyrashield.artifacts.usage import (
    _GPT56_LONG_CONTEXT_THRESHOLD_TOKENS,
    gpt56_usd_per_million,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True)
class CacheEconomicsReport:
    """Allowlisted, immutable summary of billed cache economics."""

    requests: int
    input_tokens: int
    cached_input_tokens: int
    cache_write_input_tokens: int
    uncached_input_tokens: int
    output_tokens: int
    estimated_cost_usd: float | None
    complete: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return the fixed allowlist of report fields."""
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "cache_write_input_tokens": self.cache_write_input_tokens,
            "uncached_input_tokens": self.uncached_input_tokens,
            "output_tokens": self.output_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "complete": self.complete,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class _PricedEntry:
    """One validated request receipt paired with its rate-card row."""

    rate: tuple[float, float, float, float]
    input_tokens: int
    cached_tokens: int
    cache_write_tokens: int
    uncached_tokens: int
    output_tokens: int


def analyze_cache_economics(run_record: Mapping[str, Any]) -> CacheEconomicsReport:
    """Summarize billed cache economics from a parsed ``run.json`` mapping."""
    report, _ = _evaluate(run_record)
    return report


def _evaluate(
    run_record: Mapping[str, Any],
) -> tuple[CacheEconomicsReport, tuple[_PricedEntry, ...]]:
    errors: list[str] = []
    usage = run_record.get("llm_usage") if isinstance(run_record, Mapping) else None
    if not isinstance(usage, Mapping):
        report = CacheEconomicsReport(
            requests=0,
            input_tokens=0,
            cached_input_tokens=0,
            cache_write_input_tokens=0,
            uncached_input_tokens=0,
            output_tokens=0,
            estimated_cost_usd=None,
            complete=False,
            errors=("llm_usage_missing",),
        )
        return report, ()

    declared_requests = _declared_requests(usage, errors)
    raw_entries = usage.get("request_usage_entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        errors.append("request_usage_entries_missing")
        report = CacheEconomicsReport(
            requests=declared_requests or 0,
            input_tokens=0,
            cached_input_tokens=0,
            cache_write_input_tokens=0,
            uncached_input_tokens=0,
            output_tokens=0,
            estimated_cost_usd=None,
            complete=False,
            errors=tuple(errors),
        )
        return report, ()

    priced: list[_PricedEntry] = []
    for index, raw in enumerate(raw_entries):
        result = _parse_entry(index, raw)
        if isinstance(result, _PricedEntry):
            priced.append(result)
        else:
            errors.append(result)

    requests = declared_requests if declared_requests is not None else len(raw_entries)
    report = CacheEconomicsReport(
        requests=requests,
        input_tokens=sum(entry.input_tokens for entry in priced),
        cached_input_tokens=sum(entry.cached_tokens for entry in priced),
        cache_write_input_tokens=sum(entry.cache_write_tokens for entry in priced),
        uncached_input_tokens=sum(entry.uncached_tokens for entry in priced),
        output_tokens=sum(entry.output_tokens for entry in priced),
        estimated_cost_usd=(
            round(sum(_entry_cost(entry) for entry in priced), 6) if priced else None
        ),
        complete=not errors,
        errors=tuple(errors),
    )
    return report, tuple(priced)


def _declared_requests(usage: Mapping[Any, Any], errors: list[str]) -> int | None:
    value = usage.get("requests")
    if value is None:
        return None
    parsed = _counter(value)
    if parsed is not None:
        return parsed
    errors.append("requests_invalid")
    return None


def _parse_entry(index: int, raw: Any) -> _PricedEntry | str:
    """Return a validated receipt, or a bounded ``entry[i]:code`` error."""
    prefix = f"entry[{index}]"
    if not isinstance(raw, Mapping):
        return f"{prefix}:not_a_mapping"
    model = raw.get("model")
    if not isinstance(model, str) or not model.strip():
        return f"{prefix}:model_missing"
    rate = gpt56_usd_per_million(model)
    if rate is None:
        return f"{prefix}:model_unpriced"
    input_tokens = _counter(raw.get("input_tokens"))
    output_tokens = _counter(raw.get("output_tokens"))
    if input_tokens is None or output_tokens is None:
        return f"{prefix}:counter_invalid"
    details = raw.get("input_tokens_details")
    if not isinstance(details, Mapping):
        return f"{prefix}:input_details_missing"
    cached_tokens = _counter(details.get("cached_tokens"))
    # The ledger omits ``cache_write_tokens`` from a receipt when it is zero,
    # so absence means zero rather than a missing dimension.
    cache_write_tokens = _counter(details.get("cache_write_tokens", 0))
    if cached_tokens is None or cache_write_tokens is None:
        return f"{prefix}:counter_invalid"
    if cached_tokens + cache_write_tokens > input_tokens:
        return f"{prefix}:cache_exceeds_input"
    return _PricedEntry(
        rate=rate,
        input_tokens=input_tokens,
        cached_tokens=cached_tokens,
        cache_write_tokens=cache_write_tokens,
        uncached_tokens=input_tokens - cached_tokens - cache_write_tokens,
        output_tokens=output_tokens,
    )


def _counter(value: Any) -> int | None:
    """Return ``value`` when it is a non-negative integer counter."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _entry_multipliers(input_tokens: int) -> tuple[float, float]:
    if input_tokens > _GPT56_LONG_CONTEXT_THRESHOLD_TOKENS:
        return 2.0, 1.5
    return 1.0, 1.0


def _price(
    rate: tuple[float, float, float, float],
    uncached: float,
    cached: float,
    cache_write: float,
    output: float,
    input_multiplier: float,
    output_multiplier: float,
) -> float:
    return (
        uncached * rate[0] * input_multiplier
        + cached * rate[1] * input_multiplier
        + cache_write * rate[2] * input_multiplier
        + output * rate[3] * output_multiplier
    ) / 1_000_000


def _entry_cost(entry: _PricedEntry) -> float:
    input_multiplier, output_multiplier = _entry_multipliers(entry.input_tokens)
    return _price(
        entry.rate,
        entry.uncached_tokens,
        entry.cached_tokens,
        entry.cache_write_tokens,
        entry.output_tokens,
        input_multiplier,
        output_multiplier,
    )


def _input_reduction_cost(entries: tuple[_PricedEntry, ...], fraction: float) -> float:
    keep = 1.0 - fraction
    total = 0.0
    for entry in entries:
        input_multiplier, output_multiplier = _entry_multipliers(entry.input_tokens)
        total += _price(
            entry.rate,
            entry.uncached_tokens * keep,
            entry.cached_tokens * keep,
            entry.cache_write_tokens * keep,
            entry.output_tokens,
            input_multiplier,
            output_multiplier,
        )
    return total


def _cache_conversion_cost(entries: tuple[_PricedEntry, ...], fraction: float) -> float:
    total = 0.0
    for entry in entries:
        input_multiplier, output_multiplier = _entry_multipliers(entry.input_tokens)
        converted = fraction * (entry.uncached_tokens + entry.cache_write_tokens)
        total += _price(
            entry.rate,
            entry.uncached_tokens * (1.0 - fraction),
            entry.cached_tokens + converted,
            entry.cache_write_tokens * (1.0 - fraction),
            entry.output_tokens,
            input_multiplier,
            output_multiplier,
        )
    return total


def _scenario_payload(name: str, fraction: float, baseline: float, cost: float) -> dict[str, Any]:
    return {
        "name": name,
        "kind": "hypothetical",
        "fraction": fraction,
        "estimated_cost_usd": round(cost, 6),
        "estimated_savings_usd": round(baseline - cost, 6),
    }


def _fraction(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return parsed


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only CLI; exit 0 only for a complete report."""
    parser = argparse.ArgumentParser(
        prog="python -m lyrashield.evals.cache_economics",
        description="Read-only cache-economics analysis for a serialized run.json.",
    )
    parser.add_argument("run_json", type=Path, help="Path to a serialized run.json file.")
    parser.add_argument(
        "--input-reduction",
        type=_fraction,
        default=None,
        metavar="FRACTION",
        help="Hypothetical: remove FRACTION of every input bucket per model.",
    )
    parser.add_argument(
        "--cache-conversion",
        type=_fraction,
        default=None,
        metavar="FRACTION",
        help="Hypothetical: reprice FRACTION of uncached and cache-write buckets as reads.",
    )
    args = parser.parse_args(argv)

    try:
        run_record: Any = json.loads(args.run_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(  # noqa: T201
            json.dumps(
                {"complete": False, "errors": ["run_json_unreadable"], "scenarios": []},
                sort_keys=True,
            )
        )
        return 2
    if not isinstance(run_record, Mapping):
        run_record = {}

    report, entries = _evaluate(run_record)
    payload = report.to_dict()
    scenarios: list[dict[str, Any]] = []
    if report.complete:
        baseline = sum(_entry_cost(entry) for entry in entries)
        if args.input_reduction is not None:
            cost = _input_reduction_cost(entries, args.input_reduction)
            scenarios.append(
                _scenario_payload("input_reduction", args.input_reduction, baseline, cost)
            )
        if args.cache_conversion is not None:
            cost = _cache_conversion_cost(entries, args.cache_conversion)
            scenarios.append(
                _scenario_payload("cache_conversion", args.cache_conversion, baseline, cost)
            )
    payload["scenarios"] = scenarios

    print(json.dumps(payload, indent=2, sort_keys=True))  # noqa: T201
    return 0 if report.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
