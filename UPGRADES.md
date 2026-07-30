# LyraShield ownership and upstream-import ledger

LyraShield Engine is a controlled derivative over a pinned Strix substrate. It
is not a thin wrapper: the adapter is the public entry point, while significant
model, lifecycle, budget, result, and worker-contract behavior is intentionally
owned within modified upstream modules. Preserve this reviewed boundary while
syncing releases.

## LyraShield-owned contract

- GPT-5.6 Terra and Luna acceptance (Sol retired in PR #22); OpenAI/Azure
  API-key credential routing; no Perplexity, Parallel, non-OpenAI, or
  ChatGPT-subscription model path at the product boundary.
- Context compaction, bounded output and agent count, and concurrent
  pre-request spend reservations.
- Non-interactive lifecycle, cancellation, cleanup, target-safe errors, and
  forced telemetry-off production behavior.
- Deterministic finding identities, structured control/evidence metadata, and
  the bounded `run.json` / `vulnerabilities.json` worker protocol.

## Compatibility patches retained across imports

- `lyrashield_adapter`: compatibility adapter for LyraShield invocation. It
  forces telemetry off, disables the upstream update check, and rejects
  `chatgpt/` subscription-backed models (which bypass the Terra/Luna gate and
  zero out metered cost accounting). It also sets
  `LYRASHIELD_PRODUCT_BOUNDARY`, which `validate_environment` uses to re-check
  the resolved model after `--config` is applied; the bare upstream `strix` CLI
  does not set it and keeps upstream subscription support.
- Out-of-band budget reservations: metered calls made outside the agent run
  loop (report deduplication) reserve against `max_budget_usd` through
  `ReportUsageHooks.reserve_out_of_band_request`, registered per scan via
  `set_active_hooks`. Upstream has no budget enforcement, so this has no
  upstream equivalent to reconcile with.
- Bounded dedupe payload: `strix/report/dedupe.py` caps the serialized
  existing-report list. Upstream compares against every prior report.
- Telemetry defaults: LyraShield-safe telemetry behavior by default.
- Self-update disabled: `--update` and the startup update notice are disabled
  in `strix/interface/main.py` — upstream self-update fetches usestrix/strix
  artifacts, which would replace the controlled derivative.
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

`8157ccba276c8fdd5eaa07a1a9d8d686315f6bd1` (fully current with upstream `main`
as of 2026-07-26)

Imported on 2026-07-26 as a tree delta (`git diff 08126eb..upstream/main`
applied with `git apply --3way`) rather than a merge: this fork's history is a
squashed sync with no shared merge base, so `git merge` reports spurious
add/add conflicts on files both sides created independently. The delta applied
cleanly across all 15 files with no conflicts against LyraShield-owned code.

Contents: the root-agent rename to "Strix" (`f23fadf`) plus five report
fence-handling fixes (`31c18f8`, `97ed7e7`, `2124348`, `95d2e5f`, `8157ccb`)
that move `parse_fenced_code` / `safe_fence` / `guess_language_name` into
`strix/report/writer.py`. That file is LyraShield-modified, so re-verify those
helpers on the next import.

Prior base was `08126eb`, incorporated by the 2026-07-25 manual merge
(`418c0e3`), which also removed the automated upstream-sync workflow and
scripts (`.github/workflows/upstream-sync.yml`,
`scripts/sync-upstream-release.sh`, `scripts/check-upstream.sh`); release
imports are now manual, reviewed merges.

## LyraShield PR #20 (2026-07-25)

Merged from branch `codex/engine-v5`. This change set refined the GPT-5.6 cost accounting and telemetry plumbing while keeping the execution boundary intact:

- `strix/core/hooks.py`: `_model_rates` now returns a 2-tuple (input, output) matching the GPT-5.6 Terra/Luna rate card; `_usage_cost_upper_bound` handles provider-reported cache-read tokens and extracts `input_tokens`/`output_tokens` from both dict and object usage entries via `_usage_value`.
- `strix/interface/main.py`: telemetry start arguments are passed as explicit keyword arguments to `posthog.start` and `scarf.start` instead of an untyped kwargs dict.
- `tests/conftest.py`: a pytest fixture clears LLM-related environment variables before each test to isolate unit tests from leaked Azure endpoints.
- `Makefile`: the `type-check` and `security` targets now match `scripts/verify-thin-fork.sh` (mypy excludes `strix/interface/tui`, bandit covers `strix` and `lyrashield_adapter`).

The existing worker artifact contract and `run.json`/`vulnerabilities.json` schema did not change.

## LyraShield PR #22 (2026-07-25)

Enforced token caps and made the compaction ceiling configurable. Sol model was retired; only GPT-5.6 Terra and Luna remain at the product boundary.

## LyraShield PR #26 (2026-07-26)

Synced upstream through `8157ccb` (root-agent rename to "Strix" plus five report fence-handling fixes) as a tree delta rather than a merge. Added dedupe spend reservation so out-of-band report deduplication calls reserve against `max_budget_usd`.

## LyraShield PR #33 (2026-07-26)

Hardened Azure GPT-5.6 execution and provider gates. Azure AI Foundry endpoints are normalized to their `/openai/v1/` base; deployment names must identify GPT-5.6 Terra or Luna.

## LyraShield PR #35 (2026-07-27)

Cost and cache optimization review fixes: corrected cache-read accounting, removed broken `prompt_cache_options` to restore implicit prompt caching, and aligned cost reconciliation paths.

## LyraShield PR #36 (2026-07-27)

Called session close synchronously to prevent async cleanup races during non-interactive execution.

## LyraShield PR #39 (2026-07-28)

Resolved all outstanding lint, type, and viewer extra issues. Moved `reportlab`/`pypdf` to an optional viewer extra (PR #28) so the core install remains lean.

## LyraShield PR #40 (2026-07-29)

Hardened `run.json` with `phase`, `seq`, and `turn_count` progress fields. The worker schema accepts these via `engineRunRecordSchema` for progress tracking without claiming streamed phase completion.

## Independence decision

Continue maintaining the controlled derivative while the reviewed upstream
substrate remains useful. Reconsider a fully independent engine only if
upstream repeatedly blocks required behavior, release imports become more
expensive than ownership, or a LyraShield evaluation corpus demonstrates a
substrate-imposed quality ceiling. Test-count and packaging gates are not that
evaluation evidence.
