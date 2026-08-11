# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Pin the exact Azure GPT-5.6 rate values so a future transposition is caught.

The rate table in :mod:`lyrashield.lifecycle.hooks` is the single source of truth for
scan billing.  A silent swap of two digits would misbill every scan and still
pass CI unless these values are asserted here.
"""

from __future__ import annotations

from lyrashield.lifecycle.hooks import _GPT56_CACHED_RATES, _GPT56_RATES


def test_terra_rates() -> None:
    """Terra: input $2.00, output $12.00 per 1M tokens."""
    input_rate, output_rate = _GPT56_RATES["terra"]
    assert input_rate == 2.0
    assert output_rate == 12.0


def test_luna_rates() -> None:
    """Luna: input $0.20, output $1.20 per 1M tokens."""
    input_rate, output_rate = _GPT56_RATES["luna"]
    assert input_rate == 0.2
    assert output_rate == 1.2


def test_terra_cached_input_rate() -> None:
    """Terra cached input: $0.20 per 1M tokens."""
    assert _GPT56_CACHED_RATES["terra"] == 0.2


def test_luna_cached_input_rate() -> None:
    """Luna cached input: $0.02 per 1M tokens."""
    assert _GPT56_CACHED_RATES["luna"] == 0.02


def test_rate_table_has_exactly_two_tiers() -> None:
    """The rate table must contain exactly terra and luna — no more, no less."""
    assert set(_GPT56_RATES.keys()) == {"terra", "luna"}
    assert set(_GPT56_CACHED_RATES.keys()) == {"terra", "luna"}
