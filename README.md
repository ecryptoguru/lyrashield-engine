# LyraShield Engine

LyraShield Engine is the AI scan engine used by LyraShield. This repository is
a deliberately thin compatibility fork: product-facing behavior lives in
`lyrashield_adapter/`, which maps LyraShield environment variables and invokes
the otherwise upstream-compatible engine.

> **Attribution:** LyraShield Engine is a modified derivative of
> [Strix](https://github.com/usestrix/strix), used under the Apache-2.0 license.
> See [NOTICE](NOTICE).

## Run locally

Requirements: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/), Docker,
and an API key for your configured model provider.

```bash
uv sync --frozen
uv run lyrashield --help
uv run lyrashield --target https://example.com
```

Production invocation must use the `lyrashield` entry point. It applies the
product compatibility aliases and forces upstream telemetry off.

## Verify the fork

Run the full repository gate before opening or reviewing a change:

```bash
bash scripts/verify-thin-fork.sh
```

The gate installs the locked environment and runs lint, formatting, tests,
strict type checking, and security checks.

## Sync upstream

The upstream commit is pinned in `.lyrashield-upstream-base`. To check whether
Strix has advanced:

```bash
bash scripts/check-upstream.sh
```

The weekly `.github/workflows/upstream-sync.yml` workflow rebases the thin fork
onto a verified upstream commit, updates the pin and lockfile, runs the full
gate, and opens a review PR. It never auto-merges. Keep fork-specific changes
in `lyrashield_adapter/`, repository configuration, workflows, and root docs
where possible. Record unavoidable changes under `strix/` in [UPGRADES.md](UPGRADES.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
