# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Pin the exact GPT-6 rate values so a future transposition is caught.

The canonical rate card lives in :mod:`lyrashield.artifacts.usage` and is the
single source of truth for both reservation and final scan billing. A silent
swap of two digits would misbill every scan and still pass CI unless these
values are asserted here.
"""

from __future__ import annotations

from lyrashield.artifacts.usage import _METERED_USD_PER_MILLION
from lyrashield.lifecycle.hooks import _METERED_USD_PER_MILLION as _HOOKS_CARD


def test_sol_rates() -> None:
    """Sol: input $2.00, cached $0.20, cache-write $2.50, output $10.00 per 1M."""
    assert _METERED_USD_PER_MILLION["gpt-6-sol"] == (2.0, 0.2, 2.5, 10.0)


def test_luna_rates() -> None:
    """Luna: input $0.10, cached $0.01, cache-write $0.125, output $0.50 per 1M."""
    assert _METERED_USD_PER_MILLION["gpt-6-luna"] == (0.1, 0.01, 0.125, 0.5)


def test_rate_table_has_exactly_two_tiers() -> None:
    """The rate table must contain exactly sol and luna — no more, no less."""
    assert set(_METERED_USD_PER_MILLION.keys()) == {"gpt-6-sol", "gpt-6-luna"}


def test_hooks_reservations_use_the_canonical_card() -> None:
    """Reservation math must consume the same card as final pricing (I8)."""
    assert _HOOKS_CARD is _METERED_USD_PER_MILLION


def test_long_context_threshold_is_272k() -> None:
    """E5: the long-context threshold must be exactly 272,000 tokens in both
    usage.py and hooks.py (single source of truth)."""
    from lyrashield.artifacts.usage import _LONG_CONTEXT_THRESHOLD_TOKENS  # noqa: PLC0415
    from lyrashield.lifecycle.hooks import _LONG_CONTEXT_TOKENS  # noqa: PLC0415

    assert _LONG_CONTEXT_THRESHOLD_TOKENS == 272_000
    assert _LONG_CONTEXT_TOKENS == _LONG_CONTEXT_THRESHOLD_TOKENS


def test_long_context_multiplier_is_2x_input_1_5x_output() -> None:
    """E5: above 272k input tokens, the multiplier must be exactly 2.0 for
    input and 1.5 for output in both usage.py and hooks.py."""
    from agents.usage import Usage  # noqa: PLC0415

    from lyrashield.artifacts.usage import (  # noqa: PLC0415
        _estimate_metered_cost,
    )

    # Just above threshold: 272,001 input tokens, 0 cached, 0 cache_write.
    usage = Usage(
        requests=1,
        input_tokens=272_001,
        output_tokens=1_000,
        total_tokens=273_001,
    )
    usage.input_tokens_details = {"cached_tokens": 0, "cache_write_tokens": 0}  # type: ignore[assignment]

    cost = _estimate_metered_cost(usage, "openai/gpt-6-sol") or 0.0
    # Expected: 272_001 * 2.0 * 2.0 / 1M + 1_000 * 10.0 * 1.5 / 1M
    expected = (
        272_001 * 2.0 * 2.0 / 1_000_000  # input * rate * multiplier
        + 1_000 * 10.0 * 1.5 / 1_000_000  # output * rate * output_multiplier
    )
    assert abs(cost - expected) < 1e-9, f"cost={cost}, expected={expected}"


def test_below_threshold_multiplier_is_1x() -> None:
    """E5: below 272k input tokens, the multiplier must be exactly 1.0."""
    from agents.usage import Usage  # noqa: PLC0415

    from lyrashield.artifacts.usage import _estimate_metered_cost  # noqa: PLC0415

    usage = Usage(
        requests=1,
        input_tokens=271_999,
        output_tokens=1_000,
        total_tokens=272_999,
    )
    usage.input_tokens_details = {"cached_tokens": 0, "cache_write_tokens": 0}  # type: ignore[assignment]

    cost = _estimate_metered_cost(usage, "openai/gpt-6-sol") or 0.0
    expected = (
        271_999 * 2.0 * 1.0 / 1_000_000  # input * rate * 1.0
        + 1_000 * 10.0 * 1.0 / 1_000_000  # output * rate * 1.0
    )
    assert abs(cost - expected) < 1e-9, f"cost={cost}, expected={expected}"
