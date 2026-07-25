# LyraShield ownership and upstream-import ledger

LyraShield Engine is a controlled derivative over a pinned Strix substrate. It
is not a thin wrapper: the adapter is the public entry point, while significant
model, lifecycle, budget, result, and worker-contract behavior is intentionally
owned within modified upstream modules. Preserve this reviewed boundary while
syncing releases.

## LyraShield-owned contract

- GPT-5.6 Sol, Terra, and Luna acceptance; OpenAI/Azure-compatible credential
  routing; no Perplexity, Parallel, or non-OpenAI model path.
- Context compaction, bounded output and agent count, and concurrent
  pre-request spend reservations.
- Non-interactive lifecycle, cancellation, cleanup, target-safe errors, and
  forced telemetry-off production behavior.
- Deterministic finding identities, structured control/evidence metadata, and
  the bounded `run.json` / `vulnerabilities.json` worker protocol.

## Compatibility patches retained across imports

- `lyrashield_adapter`: compatibility adapter for LyraShield invocation.
- Telemetry defaults: LyraShield-safe telemetry behavior by default.
- Pydantic compatibility: fixes required by the supported runtime.
- Pre-Docker validation: validate inputs before container setup.
- Per-instance binds: avoid shared mutable configuration between scans.
- Worker output compatibility: preserve the worker's expected result format and
  coordinate schema evolution with the application repository.
- Apache attribution banners: retain the one-line LyraShield modification notice
  in every fork-modified `strix/` source file.
- Upstream formatter compatibility: retain Ruff's mechanical formatting in
  `strix/tools/reporting/tool.py` and `tests/test_runner_root_prompt.py` until
  upstream contains the same formatting.
- Upstream strict-typing compatibility: retain the local-variable narrowing in
  `strix/skills/__init__.py` and dependency ecosystem normalization in
  `strix/tools/reporting/tool.py` until upstream contains equivalent fixes.

## Current upstream base

`7d5a67d234bd3faef34d22be8c6f5a9607de41a3`

This will be updated to the new upstream commit after the manual merge is
complete.

## LyraShield PR #20 (2026-07-25)

Merged from branch `codex/engine-v5`. This change set refined the GPT-5.6 cost accounting and telemetry plumbing while keeping the execution boundary intact:

- `strix/core/hooks.py`: `_model_rates` now returns a 2-tuple (input, output) matching the GPT-5.6 Terra/Luna rate card; `_usage_cost_upper_bound` handles provider-reported cache-read tokens and extracts `input_tokens`/`output_tokens` from both dict and object usage entries via `_usage_value`.
- `strix/interface/main.py`: telemetry start arguments are passed as explicit keyword arguments to `posthog.start` and `scarf.start` instead of an untyped kwargs dict.
- `tests/conftest.py`: a pytest fixture clears LLM-related environment variables before each test to isolate unit tests from leaked Azure endpoints.
- `Makefile`: the `type-check` and `security` targets now match `scripts/verify-thin-fork.sh` (mypy excludes `strix/interface/tui`, bandit covers `strix` and `lyrashield_adapter`).

The existing worker artifact contract and `run.json`/`vulnerabilities.json` schema did not change.

## Independence decision

Continue maintaining the controlled derivative while the reviewed upstream
substrate remains useful. Reconsider a fully independent engine only if
upstream repeatedly blocks required behavior, release imports become more
expensive than ownership, or a LyraShield evaluation corpus demonstrates a
substrate-imposed quality ceiling. Test-count and packaging gates are not that
evaluation evidence.
