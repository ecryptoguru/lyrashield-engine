# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Pin the exact Azure GPT-5.6 rate values so a future transposition is caught.

The canonical rate card lives in :mod:`lyrashield.artifacts.usage` and is the
single source of truth for both reservation and final scan billing. A silent
swap of two digits would misbill every scan and still pass CI unless these
values are asserted here.
"""

from __future__ import annotations

from lyrashield.artifacts.usage import _GPT56_USD_PER_MILLION
from lyrashield.lifecycle.hooks import _GPT56_USD_PER_MILLION as _HOOKS_CARD


def test_terra_rates() -> None:
    """Terra: input $2.00, cached $0.20, cache-write $2.50, output $12.00 per 1M."""
    assert _GPT56_USD_PER_MILLION["gpt-5.6-terra"] == (2.0, 0.2, 2.5, 12.0)


def test_luna_rates() -> None:
    """Luna: input $0.20, cached $0.02, cache-write $0.25, output $1.20 per 1M."""
    assert _GPT56_USD_PER_MILLION["gpt-5.6-luna"] == (0.2, 0.02, 0.25, 1.2)


def test_rate_table_has_exactly_two_tiers() -> None:
    """The rate table must contain exactly terra and luna — no more, no less."""
    assert set(_GPT56_USD_PER_MILLION.keys()) == {"gpt-5.6-terra", "gpt-5.6-luna"}


def test_hooks_reservations_use_the_canonical_card() -> None:
    """Reservation math must consume the same card as final pricing (I8)."""
    assert _HOOKS_CARD is _GPT56_USD_PER_MILLION
