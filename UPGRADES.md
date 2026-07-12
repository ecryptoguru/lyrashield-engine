# LyraShield patch ledger

This fork stays deliberately thin. Keep these compatibility patches while
syncing upstream:

- `lyrashield_adapter`: compatibility adapter for LyraShield invocation.
- Telemetry defaults: LyraShield-safe telemetry behavior by default.
- Pydantic compatibility: fixes required by the supported runtime.
- Pre-Docker validation: validate inputs before container setup.
- Per-instance binds: avoid shared mutable configuration between scans.
- Worker output compatibility: preserve the worker's expected result format.
- Apache attribution banners: retain the one-line LyraShield modification notice
  in every fork-modified `strix/` source file.

## Current upstream base

`7b639505fecf20a2d9e356f96bd91470aa828182`

Run `scripts/check-upstream.sh` before updating this ledger. It reports whether
upstream has advanced and rejects rewritten upstream history for manual review.

## Automated review path

`.github/workflows/upstream-sync.yml` checks upstream every Monday at 03:23
UTC and can also be started manually. When the recorded base is an ancestor and
upstream has advanced, it rebases into an `automation/upstream-<short-sha>`
branch, locks and verifies the thin fork, then opens a review PR. It never
auto-merges, force-pushes, or attempts to resolve rebase conflicts. Rewritten
upstream history exits with status 20 before any rebase. The workflow requires
a LyraShield-controlled writable `origin`; this local fork currently has only
the read/write `upstream` remote, so it has not been dispatched or published.
