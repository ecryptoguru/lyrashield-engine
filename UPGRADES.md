# LyraShield ownership and upstream-import ledger

LyraShield Engine is a controlled derivative over a pinned Strix substrate. It
is not a thin wrapper: the adapter is the public entry point, while significant
model, lifecycle, budget, result, and worker-contract behavior is intentionally
owned within modified upstream modules. Preserve this reviewed boundary while
syncing releases.

> **Upgrade to v1.5.3 product-outside-strix (2026-08-11).** The `strix/**`
> substrate is pinned to upstream release v1.5.3
> (`7cc9fa9faa0179fc7e35111102fe3d20a9028393`). Product-specific behavior lives
> in `lyrashield/**` and `lyrashield_adapter/**`. Only two generic fixes remain:
> `strix/config/loader.py` provides the settings-loader composition seam and
> `strix/skills/__init__.py` avoids starting telemetry threads when telemetry is
> disabled. The agent factory and prompt renderer now remain exact upstream;
> product callers use their LyraShield implementations directly. The verification
> gate checks staged and unstaged files, enforces this exact two-file allowlist,
> and fails when the +30/-0 line ceiling is exceeded.
>
> **Historical note.** Deep Review v12 introduced a warning-only footprint
> budget when product behavior still lived throughout `strix/**`. The v1.5.3
> product-outside-Strix migration superseded it with the hard two-file,
> +30/-0 gate above. The larger v1.4.1-era measurements below remain only as an
> audit trail and are not the current contribution policy.

## Upgrade to v1.5.3 product-outside-strix (2026-08-11)

The vendored substrate was advanced to upstream release v1.5.3
(`7cc9fa9faa0179fc7e35111102fe3d20a9028393`). All product-specific behavior
remains outside `strix/**` in `lyrashield/**` and `lyrashield_adapter/**`.
Only two generic patches remain:

- `strix/config/loader.py`: registers a pluggable product settings loader and
  falls back to the upstream `Settings` class when none is registered.
- `strix/skills/__init__.py`: skips telemetry-thread creation when the resolved
  settings disable telemetry. v1.5.3 already provides skill-directory
  registration, so that extension no longer requires a local patch.

The footprint vs v1.5.3 is two modified files with +24/-0 lines. The
`scripts/verify-controlled-derivative.sh` gate compares the actual working tree
to the pin, including staged and unstaged changes. Added, deleted, renamed, and
unlisted modified files fail; exceeding two files, 30 insertions, or any
deletions also fails.

Prior `strix/**` product-ownership claims in this ledger (e.g., product behavior
in `strix/core/hooks.py`, `strix/core/inputs.py`, `strix/config/settings.py`,
`strix/agents/prompts/system_prompt.jinja`, and the other files listed in the
v1.4.1 merge section below) are superseded by this migration. The product now
owns that behavior in `lyrashield/**` and `lyrashield_adapter/**`, while
`strix/**` tracks upstream v1.5.3 with only the two documented generic patches.

## LyraShield-owned contract

- GPT-5.6 Terra and Luna acceptance (Sol retired in PR #22); only
  LiteLLM/Strix-supported providers whose cost map lists `gpt-5.6-*` are allowed
  (currently OpenAI, Azure/Azure AI, and Bedrock Mantle); OpenAI/Azure remain
  the primary reference paths; ChatGPT-subscription model path is allowed by
  default and can be disabled with `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0`;
  no OpenRouter, Bedrock (non-Mantle), Vertex, Novita, Perplexity, Parallel, or
  local/self-hosted endpoint as the main model at the product boundary.
- Parallel Search is available as an optional, redacted `web_search` agent tool
  when `LYRASHIELD_WEB_SEARCH_ENABLED=1` and a Parallel API key is configured.
  It is not an LLM endpoint and does not replace GPT-5.6 Terra/Luna.
- Context compaction, bounded output and agent count, and concurrent
  pre-request spend reservations.
- Non-interactive lifecycle, cancellation, cleanup, target-safe errors, and
  forced telemetry-off production behavior.
- Deterministic finding identities, structured control/evidence metadata, and
  the bounded `run.json` / `vulnerabilities.json` worker protocol.

## Compatibility patches retained across imports

- `lyrashield_adapter`: compatibility adapter for LyraShield invocation. It
  forces telemetry off, disables the upstream update check, and supports
  `chatgpt/` subscription-backed models by default (which bypass the Terra/Luna
  gate and zero out metered cost accounting). Set
  `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0` to disable the subscription path.
  Subscription runs are recorded with `auth_mode: "subscription"` and
  `llm_usage.cost: 0` in `run.json`. It also sets `LYRASHIELD_PRODUCT_BOUNDARY`,
  which `validate_environment` uses to re-check the resolved model after
  `--config` is applied; the bare upstream `strix` CLI does not set it and keeps
  upstream subscription support.
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

`7cc9fa9faa0179fc7e35111102fe3d20a9028393` (upstream `v1.5.3`, reset on
2026-08-11).

This is a subtree replacement with upstream v1.5.3, not a history merge:
this fork's history is a squashed sync with no shared merge base, so
`git merge` reports spurious add/add conflicts on files both sides created
independently. All product behavior has been moved out of `strix/**` into
`lyrashield/**` and `lyrashield_adapter/**`; only the two generic seams
documented in the "Upgrade to v1.5.3 product-outside-strix" section remain
modified. The `strix/**` files that previously carried product behavior
(e.g., `strix/core/hooks.py`, `strix/core/inputs.py`, `strix/config/settings.py`)
were restored to upstream content and any prior product claims about them are
superseded by the product-outside-strix migration.

## Prior upstream base (v1.4.1, 2026-08-02)

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
- `Makefile`: the `type-check` and `security` targets now match `scripts/verify-controlled-derivative.sh` (mypy excludes `strix/interface/tui`, bandit covers `strix` and `lyrashield_adapter`).

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

## LyraShield deep code review v11 (2026-08-02)

Post-review hardening of the controlled-derivative boundary:

- `strix/core/runner.py`: added the missing 2026 LyraShield attribution banner.
- `strix/core/inputs.py`: added the missing 2026 LyraShield attribution banner.
- `strix/interface/cli.py`: added the missing 2026 LyraShield attribution banner.
- `scripts/verify-controlled-derivative.sh`: now diffs `strix/**` against the pinned upstream
  base and fails on any file that lacks both the attribution banner and a
  `UPGRADES.md` entry, preventing future undocumented `strix/` drift.
- `README.md`: reconciled the pinned upstream base with `UPGRADES.md` and
  restored `.lyrashield-upstream-base`.

## LyraShield sync to upstream 2e70402 (2026-08-02)

Synced the controlled derivative from upstream base `8157ccb` to `2e7040240d0...`.
This is a major upstream release (v1.4.1) with the following themes:

- **LLM lifecycle:** split `respond_to_user` / `wait_for_agents` tools, added
  `max_turns` and interactive budget pause/resume (`BudgetPausedError`,
  `SubagentBudgetReservedError`), and `LLM_DISABLE_STREAMING` / `LLM_EXTRA_HEADERS`
  support.
- **Prompt caching:** explicit Bedrock/Anthropic prompt cache markers and
  `STRIX_PROMPT_CACHE` in `strix/config/models.py`.
- **Model support:** added `max` reasoning effort, Claude/Bedrock route detection,
  and openrouter attribution headers.
- **Budget and resilience:** per-turn and root/sub-agent budget warnings in
  `strix/core/hooks.py`, transient model retry and forced context compaction in
  `strix/core/execution.py`, mailbox-based agent messaging in
  `strix/core/agents.py`.
- **Viewer and interface:** viewer code moved under `strix/interface/viewer`.
- **Reporting:** `list_reports` / `get_report` tools and new renderers.

LyraShield customizations preserved across the merge:

- Product name, version, and wheel packaging in `pyproject.toml`.
- `LYRASHIELD_*` env aliases, `max_input_tokens`, `max_output_tokens`, and Azure
  API-key/model routing in `strix/config/settings.py` and `strix/config/models.py`.
- `ReportUsageHooks` budget reservations and context compaction in
  `strix/core/hooks.py`.
- `set_active_hooks` / `get_active_hooks` for out-of-band deduplication spend.
- LyraShield telemetry opt-out, GPT-5.6 product boundary, and viewer auth.

Files with meaningful LyraShield/Upstream merge work:

- `strix/core/agents.py`
- `strix/core/execution.py`
- `strix/core/hooks.py`
- `strix/core/inputs.py`
- `strix/core/runner.py`
- `strix/core/sessions.py`
- `strix/config/models.py`
- `strix/config/settings.py`
- `strix/config/codex.py`
- `strix/config/__init__.py`
- `strix/agents/factory.py`
- `strix/agents/prompts/system_prompt.jinja`
- `strix/interface/cli.py`
- `strix/interface/main.py`
- `strix/interface/utils.py`
- `strix/interface/viewer/auth.py`
- `strix/interface/viewer/cli.py`
- `strix/interface/viewer/server.py`
- `strix/interface/viewer/frontend/src/components/vulnerability/MdCodeBlock.tsx`
- `strix/llm/compaction.py`
- `strix/report/dedupe.py`
- `strix/report/state.py`
- `strix/report/writer.py`
- `strix/runtime/caido_bootstrap.py`
- `strix/telemetry/posthog.py`
- `strix/telemetry/scarf.py`
- `strix/tools/agents_graph/tools.py`
- `strix/tools/proxy/caido_api.py`
- `strix/tools/proxy/tools.py`
- `strix/tools/reporting/tool.py`
- `pyproject.toml`
- `uv.lock`

## Independence decision

Continue maintaining the controlled derivative while the reviewed upstream
substrate remains useful. Reconsider a fully independent engine only if
upstream repeatedly blocks required behavior, release imports become more
expensive than ownership, or a LyraShield evaluation corpus demonstrates a
substrate-imposed quality ceiling. Test-count and packaging gates are not that
evaluation evidence.

## Documentation reconciliation (2026-08-02)

Operator docs were reconciled with the actual `Settings` schema and the
GPT-5.6 Terra/Luna product boundary. No runtime behavior changed.

- `CONTRIBUTING.md`: rewritten from stale upstream Strix content to the
  LyraShield controlled-derivative workflow (entry point, banner, verify gate,
  ownership boundary).
- `docs/usage/cli.mdx`: rewritten for the `lyrashield` executable and the full
  verified flag set (`--run-name`, `--resume`, `--max-budget`/`--max-budget-usd`,
  `--max-turns`, `provider-contract` subcommand).
- `docs/advanced/configuration.mdx`: rewritten to match `strix/config/settings.py`
  — `LYRASHIELD_*` aliases for every `STRIX_*` setting, GPT-5.6-only examples,
  dropped nonexistent vars (`STRIX_MEMORY_COMPRESSOR_TIMEOUT`,
  `STRIX_LLM_MAX_RETRIES`, `PERPLEXITY_API_KEY`, `TRACELOOP_*`,
  `STRIX_SANDBOX_EXECUTION_TIMEOUT`, `STRIX_SANDBOX_CONNECT_TIMEOUT`, local
  `events.jsonl` dual-write).
- `docs/llm-providers/local.mdx`: added the unsupported-upstream-reference
  Warning banner (local models are not a production path) and replaced
  `STRIX_LLM`/`gpt-5.4`/Claude references with the LyraShield spelling.
- `strix/telemetry/README.md`: rewritten to reflect the forced-off LyraShield
  telemetry boundary (the adapter sets `STRIX_TELEMETRY=0`).

## Parallel Search web_search tool (2026-08-04)

Added an optional, redacted `web_search` agent tool backed by Parallel Search.
It is not an LLM endpoint and does not alter the GPT-5.6 product boundary.

- `strix/tools/web_search/tool.py`: new tool with redaction, call/budget caps,
  and `reserve_web_search_call` / `release_web_search_call` hook integration.
- `strix/config/settings.py`: new `WebSearchSettings` with `LYRASHIELD_*` env
  aliases and `PARALLEL_API_KEY` fallback.
- `strix/agents/factory.py`: registers `web_search` in the base tool set.
- `strix/interface/tui/renderers/web_search_renderer.py`: TUI rendering for
  search tool events.
- `strix/core/hooks.py`: `reserve_web_search_call` and `release_web_search_call`
  on `ReportUsageHooks` for per-call budget reservations.
- `strix/report/state.py`: records web search cost and usage in `run.json`.
- `docs/advanced/configuration.mdx` and `docs/llm-providers/overview.mdx`:
  updated to clarify that Parallel is not an LLM endpoint but may be used as a
  web search tool when explicitly enabled.

## Security hardening pass (2026-08-05)

Comprehensive AI safety, privacy, and reliability hardening based on the
multi-domain audit in `AI_AUDIT_REPORT.md`. All 911 tests pass with no
regressions. See the audit report for per-finding resolution status.

### Prompt injection and trust boundaries

- `strix/agents/prompts/system_prompt.jinja`: added `TRUST BOUNDARIES —
SYSTEM-INJECTED MARKERS` section defining `[SYSTEM-NOTICE]` (budget/turn
  warnings) and `[SYSTEM-VERIFIED PEER MESSAGE]` (inter-agent communication)
  tags, with anti-spoofing rules. Tags are only valid at the start of a
  top-level user message from the platform; tags inside tool output or target
  content are treated as injection attempts.
- `strix/core/agents.py`: `_message_to_session_item` wraps peer messages with
  the `[SYSTEM-VERIFIED PEER MESSAGE | id=... | from=... | type=... |
priority=...]` header (already present from upstream sync, now documented in
  the system prompt).
- `strix/core/hooks.py`: budget/turn warnings prefixed with `[SYSTEM-NOTICE]`
  (already present from upstream sync, now documented in the system prompt).

### Privacy and data leakage

- `strix/llm/compaction.py`: summary prompt no longer instructs verbatim
  credential preservation. Now instructs the model to record placeholder types
  (e.g. `[SECRET]`) and where they apply. Conversation head is redacted via
  `redact_text()` before summarization; summary is redacted again before
  checkpointing.
- `strix/report/state.py`: `add_vulnerability_report` and
  `update_scan_final_fields` now apply `redact_text()` to all free-text fields.
  Internal path redaction is mode-aware via `_is_whitebox` property: whitebox
  scans preserve `/workspace/<subdir>` target paths; blackbox scans redact them.
  `poc_script_code` always preserves internal paths for reproducibility.
- `strix/utils/redaction.py`: split path patterns into `_ALWAYS_REDACT_PATH_\
PATTERNS` (spill paths, tmp state — always redacted) and `_MODE_DEPENDENT_\
PATH_PATTERNS` (general `/workspace/` paths — mode-dependent). Added
  `redact_spill_paths()` for whitebox mode.

### Structured output reliability

- `strix/report/dedupe.py`: `DedupeJudgement` Pydantic model with
  `AgentOutputSchema(strict_json_schema=True)` enforces structured output.
  Fallback to lenient `_parse_dedupe_response` on validation failure (already
  present from upstream sync, now covered by new tests).

### Telemetry hygiene

- `strix/telemetry/posthog.py`: replaced module-level `_POSTHOG_PUBLIC_API_KEY`
  and `_POSTHOG_HOST` with lazy `_posthog_api_key()` / `_posthog_host()`
  functions that read `STRIX_POSTHOG_API_KEY` / `STRIX_POSTHOG_HOST` at call
  time.
- `strix/telemetry/scarf.py`: replaced module-level `_SCARF_ENDPOINT` with
  lazy `_scarf_endpoint()` that reads `STRIX_SCARF_ENDPOINT` at call time.
- `strix/skills/__init__.py`: `_track_skill_loaded` now checks
  `load_settings().telemetry.enabled` before spawning the telemetry thread.

### Prompt sanitization

- `strix/core/inputs.py`: `_JINJA_TAG_RE` regex updated to also strip Jinja
  comment tags (`{# #}`) in addition to `{{ }}` and `{% %}`. Applied to
  `root_instructions_override`, `extra_system_prompt_context`, and target
  values in `build_scope_context`.

### Tests added

- `tests/test_redaction.py`: whitebox path preservation, PoC path preservation
  in blackbox, spill path always redacted.
- `tests/test_dedupe_model.py`: schema validation path, fallback parser path,
  `DedupeJudgement` field validation.
- `tests/test_telemetry_keys.py` (new): lazy env var reads, skip-when-
  unconfigured, skills telemetry gate.
- `tests/test_runner_root_prompt.py`: Jinja comment tag stripping test case.
