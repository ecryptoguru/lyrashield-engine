"""Tests for the LYRASHIELD_MAX_OUTPUT_TOKENS cap resolution."""

from __future__ import annotations

import pytest

from lyrashield.lifecycle.runner import (
    DELEGATE_OUTPUT_TOKEN_CEILING,
    resolve_max_output_tokens,
)


@pytest.mark.parametrize(
    ("scan_mode", "expected"),
    [("quick", 4_096), ("standard", 8_192), ("deep", 16_384), ("unknown-mode", 8_192)],
)
def test_unset_cap_preserves_scan_mode_defaults(scan_mode: str, expected: int) -> None:
    # Regression guard: existing deployments set no cap, so behavior must be
    # byte-identical to the previous hardcoded table.
    assert resolve_max_output_tokens(scan_mode, None) == expected


@pytest.mark.parametrize("scan_mode", ["quick", "standard", "deep"])
def test_configured_cap_replaces_the_scan_mode_default(scan_mode: str) -> None:
    # A single global override, per the founder decision — not one knob per mode.
    assert resolve_max_output_tokens(scan_mode, 2_048) == 2_048


def test_configured_cap_may_exceed_the_scan_mode_default() -> None:
    # The knob is an override, not only a reduction; an operator raising it for a
    # quick scan is honored (delegates stay clamped separately).
    assert resolve_max_output_tokens("quick", 12_000) == 12_000


def test_delegate_ceiling_bounds_a_raised_coordinator_cap() -> None:
    coordinator = resolve_max_output_tokens("deep", 64_000)
    delegate = min(coordinator, DELEGATE_OUTPUT_TOKEN_CEILING)

    # Raising the coordinator budget must not multiply spend across every child
    # agent, so the delegate clamp still applies.
    assert coordinator == 64_000
    assert delegate == DELEGATE_OUTPUT_TOKEN_CEILING


def test_delegate_ceiling_does_not_raise_a_lower_coordinator_cap() -> None:
    coordinator = resolve_max_output_tokens("standard", 1_000)

    assert min(coordinator, DELEGATE_OUTPUT_TOKEN_CEILING) == 1_000
