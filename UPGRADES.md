# LyraShield patch ledger

This fork stays deliberately thin. Keep these compatibility patches while
syncing upstream:

- `lyrashield_adapter`: compatibility adapter for LyraShield invocation.
- Telemetry defaults: LyraShield-safe telemetry behavior by default.
- Pydantic compatibility: fixes required by the supported runtime.
- Pre-Docker validation: validate inputs before container setup.
- Per-instance binds: avoid shared mutable configuration between scans.
- Worker output compatibility: preserve the worker's expected result format.

## Current upstream base

`7b639505fecf20a2d9e356f96bd91470aa828182`

Run `scripts/check-upstream.sh` before updating this ledger. It reports whether
upstream has advanced and rejects rewritten upstream history for manual review.
