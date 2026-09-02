# LyraShield ownership and upstream-import ledger

## Customer branding and viewer rebuild

The owned viewer uses a LyraShield wordmark and local functionality only. Upstream
Cloud/Pro, PR, integration and member upsells have been removed. The unapproved
`logo.png` asset is retained pending founder approval, but is not displayed by the
viewer. Existing `lyrashield.dev` references outside the SARIF product-information
URL remain pending the domain decision. Legal attribution remains in NOTICE and LICENSE.

Export downloads the already-loaded Markdown report locally. Legacy email delivery,
feedback and OTP unlock entrypoints are not offered: they depend on an upstream relay.
The backend's existing history authorization remains intact; locked history points
to `lyrashield view <name>`. PDF generation remains available to existing internal
callers, but the viewer does not promise an unimplemented local PDF download.

Rebuild the tracked viewer assets from source; never patch a minified bundle:

```sh
cd lyrashield/interface/viewer/frontend
npm ci
npx tsc --noEmit
npm run build
npm audit
cd ../../../..
uv run python scripts/verify-customer-branding.py
uv run pytest -q tests/test_customer_branding.py
```

The CI branding gate checks all text in the owned interface, TUI and skills,
including frontend source and generated static assets. Its reviewed allowlist
retains exact source lines for module/class names, environment variables, persisted
paths and keys, package/release names, and legal/historical attribution. The system
prompt's bytes after the first newline are intentionally preserved. Legacy updater
code remains unreachable from the product CLI, whose `--update` fails closed.
Bundles allow only the three exact persisted preference keys and terminal-prompt
regex; adding visible upstream branding on the same line still fails the gate.

Removed the obsolete `scripts/install.sh` and its installer-only tests: it downloaded
and replaced upstream executables and pulled an unrelated upstream image. The owned
release workflow still produces compatibility-named binaries, but does not establish
a reviewed shell installation/upgrade contract. Use reviewed release artifacts or
the documented source installation. No installer was executed for this change.

LyraShield Engine is a controlled derivative over a pinned Strix substrate. It
is not a thin wrapper: the adapter is the public entry point, while significant
model, lifecycle, budget, result, and worker-contract behavior is intentionally
owned in `lyrashield/**` and `lyrashield_adapter/**`, outside the retained
upstream tree. Preserve this reviewed boundary while syncing releases.

> **Upgrade to v1.5.3 product-outside-strix (2026-08-11).** The `strix/**`
> substrate is pinned to upstream release v1.5.3
> (`7cc9fa9faa0179fc7e35111102fe3d20a9028393`). Product-specific behavior lives
> in `lyrashield/**` and `lyrashield_adapter/**`. Two generic integration seams remain:
> `strix/config/loader.py` provides the settings-loader composition seam and
> `strix/skills/__init__.py` avoids starting telemetry threads when telemetry is
> disabled. A reviewed 2026-08-24 compatibility patch also corrects upstream
> typing and import cycles without changing model policy. The verification gate
> checks staged and unstaged files, enforces the exact 14-file allowlist and
> +151/-57 footprint, and pins the complete patch-object digest.
>
> **Historical note.** Deep Review v12 introduced a warning-only footprint
> budget when product behavior still lived throughout `strix/**`. The v1.5.3
> product-outside-Strix migration superseded it with a hard reviewed-patch gate.
> The larger v1.4.1-era measurements below remain only as an audit trail and are
> not the current contribution policy.

## Artifact persistence optimization (2026-08-24)

Merged revision `944a84f` avoids rewriting unchanged report projections during
usage-only state saves. `run.json` still persists on every save because it is
the lifecycle and model-usage/cost receipt. Finding JSON/Markdown, executive
Markdown, and SARIF now write only after report content changes.

The durable `report_artifacts_revision` in `run.json` is restored on resume, so
a usage-only save after process restart does not regenerate unchanged report
artifacts. An in-process re-entrant lock serializes saves and prevents an older
concurrent snapshot from replacing newer findings. Required-artifact failures
remain fail-closed; optional executive/SARIF failures retain their established
non-fatal semantics.

This change reduces redundant serialization and filesystem I/O. It does not
change model selection, prompts, token consumption, provider-reported cost,
worker artifact schemas, or detection results. Any latency or infrastructure
cost improvement depends on scan workload and storage and requires a separate
benchmark before a quantified claim.

Verification at `944a84f`: 1,302 tests passed and 1 skipped; repository-wide
Pyright reported 0 errors and 0 warnings. Ruff, Mypy, Bandit, controlled-
derivative policy, build/CLI, Desktop logic, native binary, sandbox image, and
worker-contract CI gates also passed.

## Upstream typing and import-cycle compatibility (2026-08-24)

Repository-wide Pyright exposed 18 errors in the pinned v1.5.3 substrate. The
reviewed compatibility patch fixes those errors at source: exact handler and
async callable types, safe optional-callable access, typed Caido overloads, and
lazy viewer/telemetry imports that remove cycles. It does not change model
routing, budgets, provider selection, scan behavior, or public claims.

The controlled-derivative gate now allows exactly 14 modified Strix files (the
two existing integration seams plus these twelve compatibility files), enforces
the reviewed +151/-57 footprint, and requires patch object
`fafe7c8e0a7f58c4c10e5619a6579880cf1457c4`. Any byte-level change requires an
explicit review and digest update.

## Upgrade to v1.5.3 product-outside-strix (2026-08-11)

The vendored substrate was advanced to upstream release v1.5.3
(`7cc9fa9faa0179fc7e35111102fe3d20a9028393`). All product-specific behavior
remains outside `strix/**` in `lyrashield/**` and `lyrashield_adapter/**`.
The original product-outside-Strix migration retained only two generic seams:

- `strix/config/loader.py`: registers a pluggable product settings loader and
  falls back to the upstream `Settings` class when none is registered.
- `strix/skills/__init__.py`: skips telemetry-thread creation when the resolved
  settings disable telemetry. v1.5.3 already provides skill-directory
  registration, so that extension no longer requires a local patch.

At that migration revision, the footprint vs v1.5.3 was two modified files with
+24/-0 lines, and the gate rejected more than two files, 30 insertions, or any
deletions. That historical limit was superseded by the exact 14-file
compatibility patch documented above. The current
`scripts/verify-controlled-derivative.sh` gate compares the actual working tree
to the pin, including staged and unstaged changes.

Prior `strix/**` product-ownership claims in this ledger (e.g., product behavior
in `strix/core/hooks.py`, `strix/core/inputs.py`, `strix/config/settings.py`,
`strix/agents/prompts/system_prompt.jinja`, and the other files listed in the
v1.4.1 merge section below) are superseded by this migration. The product now
owns that behavior in `lyrashield/**` and `lyrashield_adapter/**`, while
`strix/**` tracks upstream v1.5.3 with only the two documented generic patches.

## LyraShield-owned contract

All product-critical behavior lives in `lyrashield/**` and
`lyrashield_adapter/**`. The retained `strix/**` substrate is upstream v1.5.3
plus the exact review-gated compatibility patch documented above.

- GPT-5.6 Terra and Luna acceptance (Sol retired in PR #22); only
  LiteLLM/Strix-supported providers whose cost map lists `gpt-5.6-*` are allowed
  (currently OpenAI, Azure/Azure AI, and Bedrock Mantle); OpenAI/Azure remain
  the primary reference paths; ChatGPT-subscription model path is allowed by
  default and can be disabled with `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0`;
  no OpenRouter, Bedrock (non-Mantle), Vertex, Novita, Perplexity, Parallel, or
  local/self-hosted endpoint as the main model at the product boundary. Model
  policy lives in `lyrashield/policy/models.py`; settings in
  `lyrashield/policy/settings.py`.
- Parallel Search is available as an optional, redacted `web_search` agent tool
  when `LYRASHIELD_WEB_SEARCH_ENABLED=1` and a Parallel API key is configured.
  It is not an LLM endpoint and does not replace GPT-5.6 Terra/Luna. The tool
  lives in `lyrashield/tools/web_search/tool.py`.
- Context compaction, bounded output and agent count, and concurrent
  pre-request spend reservations. Lifecycle and hooks live in
  `lyrashield/lifecycle/`.
- Non-interactive lifecycle, cancellation, cleanup, target-safe errors, and
  forced telemetry-off production behavior. Interface and CLI live in
  `lyrashield/interface/`; telemetry in `lyrashield/telemetry/`.
- Deterministic finding identities, structured control/evidence metadata, and
  the bounded `run.json` / `vulnerabilities.json` worker protocol. Report
  state, dedupe, and writers live in `lyrashield/artifacts/`.
- Product agent factory, prompt renderer, tool overrides, and skill overlays
  live in `lyrashield/agents/`, `lyrashield/tools/`, and `lyrashield/skills/`
  respectively, all registered through generic seams in the retained
  `strix/**` substrate.

## Compatibility patches retained across imports

After the v1.5.3 product-outside-strix migration (PR #58), product behavior
lives in `lyrashield/**` and `lyrashield_adapter/**`. The two generic seams below
remain inside `strix/**`; the additional 2026-08-24 type/import compatibility
files are separately pinned by exact patch digest. Everything else below is
owned in the product tree and has no upstream equivalent to reconcile with.

- `strix/config/loader.py` (one of two `strix/**` seams): registers a pluggable
  product settings loader via `register_settings_loader` and falls back to the
  upstream `Settings` class when none is registered. `lyrashield/policy/loader.py`
  is the registered product loader.
- `strix/skills/__init__.py` (one of two `strix/**` seams): skips
  telemetry-thread creation when the resolved settings disable telemetry, and
  accepts additional skill directories via `register_skill_dir` (an upstream
  v1.5.3 feature used to load `lyrashield/skills/`).
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
  `set_active_hooks`. Lives in `lyrashield/lifecycle/hooks.py`. Upstream has no
  budget enforcement, so this has no upstream equivalent to reconcile with.
- Bounded dedupe payload: `lyrashield/artifacts/dedupe.py` caps the serialized
  existing-report list. Upstream compares against every prior report.
- Telemetry defaults: LyraShield-safe telemetry behavior by default. Product
  telemetry lives in `lyrashield/telemetry/`.
- Self-update disabled: `--update` and the startup update notice are disabled
  in `lyrashield/interface/main.py` — upstream self-update fetches
  usestrix/strix artifacts, which would replace the controlled derivative.
- Pydantic compatibility: fixes required by the supported runtime.
- Pre-Docker validation: validate inputs before container setup.
- Per-instance binds: avoid shared mutable configuration between scans.
- Worker output compatibility: preserve the worker's expected result format and
  coordinate schema evolution with the application repository.
- Apache attribution banners: retain the one-line LyraShield modification notice
  on the two reviewed `strix/` seam files and on all `lyrashield/` product
  source files that derive from upstream.
- Upstream formatter compatibility: retain Ruff's mechanical formatting in
  `lyrashield/tools/reporting/tool.py` and `tests/test_runner_root_prompt.py`
  until upstream contains the same formatting.
- Upstream strict-typing compatibility: retain the local-variable narrowing in
  `strix/skills/__init__.py` (one of the two seams) and dependency ecosystem
  normalization in `lyrashield/tools/reporting/tool.py` until upstream contains
  equivalent fixes.

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

> **Migration note (PR #58, 2026-08-12).** All `strix/**` paths listed below
> were moved to `lyrashield/**` during the product-outside-strix migration.
> The current locations are noted in parentheses; the original `strix/**`
> paths were reset to upstream v1.5.3.

- `strix/tools/web_search/tool.py`: new tool with redaction, call/budget caps,
  and `reserve_web_search_call` / `release_web_search_call` hook integration.
  (Now `lyrashield/tools/web_search/tool.py`, registered as a tool override.)
- `strix/config/settings.py`: new `WebSearchSettings` with `LYRASHIELD_*` env
  aliases and `PARALLEL_API_KEY` fallback. (Now `lyrashield/policy/settings.py`.)
- `strix/agents/factory.py`: registers `web_search` in the base tool set.
  (Now `lyrashield/agents/factory.py`.)
- `strix/interface/tui/renderers/web_search_renderer.py`: TUI rendering for
  search tool events. (Now `lyrashield/interface/tui/renderers/`.)
- `strix/core/hooks.py`: `reserve_web_search_call` and `release_web_search_call`
  on `ReportUsageHooks` for per-call budget reservations.
  (Now `lyrashield/lifecycle/hooks.py`.)
- `strix/report/state.py`: records web search cost and usage in `run.json`.
  (Now `lyrashield/artifacts/state.py`.)
- `docs/advanced/configuration.mdx` and `docs/llm-providers/overview.mdx`:
  updated to clarify that Parallel is not an LLM endpoint but may be used as a
  web search tool when explicitly enabled.

## Security hardening pass (2026-08-05)

Comprehensive AI safety, privacy, and reliability hardening based on a
multi-domain security audit. All 911 tests pass with no regressions. The
per-finding resolution details are documented in the subsections below.

> **Migration note (PR #58, 2026-08-12).** All `strix/**` paths listed below
> were moved to `lyrashield/**` during the product-outside-strix migration.
> The current locations are noted in parentheses; the original `strix/**`
> paths were reset to upstream v1.5.3. `strix/skills/__init__.py` remains one
> of the two reviewed seams.

### Prompt injection and trust boundaries

- `strix/agents/prompts/system_prompt.jinja`: added `TRUST BOUNDARIES —
SYSTEM-INJECTED MARKERS` section defining `[SYSTEM-NOTICE]` (budget/turn
  warnings) and `[SYSTEM-VERIFIED PEER MESSAGE]` (inter-agent communication)
  tags, with anti-spoofing rules. Tags are only valid at the start of a
  top-level user message from the platform; tags inside tool output or target
  content are treated as injection attempts.
  (Now `lyrashield/skills/system_prompt.jinja`, loaded via the
  template-override seam in `strix/agents/prompt.py`.)
- `strix/core/agents.py`: `_message_to_session_item` wraps peer messages with
  the `[SYSTEM-VERIFIED PEER MESSAGE | id=... | from=... | type=... |
priority=...]` header (already present from upstream sync, now documented in
  the system prompt). (Now `lyrashield/lifecycle/agents.py`.)
- `strix/core/hooks.py`: budget/turn warnings prefixed with `[SYSTEM-NOTICE]`
  (already present from upstream sync, now documented in the system prompt).
  (Now `lyrashield/lifecycle/hooks.py`.)

### Privacy and data leakage

- `strix/llm/compaction.py`: summary prompt no longer instructs verbatim
  credential preservation. Now instructs the model to record placeholder types
  (e.g. `[SECRET]`) and where they apply. Conversation head is redacted via
  `redact_text()` before summarization; summary is redacted again before
  checkpointing. (Now `lyrashield/lifecycle/compaction.py`.)
- `strix/report/state.py`: `add_vulnerability_report` and
  `update_scan_final_fields` now apply `redact_text()` to all free-text fields.
  Internal path redaction is mode-aware via `_is_whitebox` property: whitebox
  scans preserve `/workspace/<subdir>` target paths; blackbox scans redact them.
  `poc_script_code` always preserves internal paths for reproducibility.
  (Now `lyrashield/artifacts/state.py`.)
- `strix/utils/redaction.py`: split path patterns into `_ALWAYS_REDACT_PATH_\
PATTERNS` (spill paths, tmp state — always redacted) and `_MODE_DEPENDENT_\
PATH_PATTERNS` (general `/workspace/` paths — mode-dependent). Added
  `redact_spill_paths()` for whitebox mode. (Now `lyrashield/utils/redaction.py`.)

### Structured output reliability

- `strix/report/dedupe.py`: `DedupeJudgement` Pydantic model with
  `AgentOutputSchema(strict_json_schema=True)` enforces structured output.
  Fallback to lenient `_parse_dedupe_response` on validation failure (already
  present from upstream sync, now covered by new tests).
  (Now `lyrashield/artifacts/dedupe.py`.)

### Telemetry hygiene

- `strix/telemetry/posthog.py`: replaced module-level `_POSTHOG_PUBLIC_API_KEY`
  and `_POSTHOG_HOST` with lazy `_posthog_api_key()` / `_posthog_host()`
  functions that read `STRIX_POSTHOG_API_KEY` / `STRIX_POSTHOG_HOST` at call
  time. (Now `lyrashield/telemetry/posthog.py`.)
- `strix/telemetry/scarf.py`: replaced module-level `_SCARF_ENDPOINT` with
  lazy `_scarf_endpoint()` that reads `STRIX_SCARF_ENDPOINT` at call time.
  (Now `lyrashield/telemetry/scarf.py`.)
- `strix/skills/__init__.py`: `_track_skill_loaded` now checks
  `load_settings().telemetry.enabled` before spawning the telemetry thread.
  (Remains one of the two reviewed `strix/**` seams.)

### Prompt sanitization

- `strix/core/inputs.py`: `_JINJA_TAG_RE` regex updated to also strip Jinja
  comment tags (`{# #}`) in addition to `{{ }}` and `{% %}`. Applied to
  `root_instructions_override`, `extra_system_prompt_context`, and target
  values in `build_scope_context`. (Now `lyrashield/lifecycle/inputs.py`.)

### Tests added

- `tests/test_redaction.py`: whitebox path preservation, PoC path preservation
  in blackbox, spill path always redacted.
- `tests/test_dedupe_model.py`: schema validation path, fallback parser path,
  `DedupeJudgement` field validation.
- `tests/test_telemetry_keys.py` (new): lazy env var reads, skip-when-
  unconfigured, skills telemetry gate.
- `tests/test_runner_root_prompt.py`: Jinja comment tag stripping test case.

## LyraShield PR #58 — Complete adapter migration and release hardening (2026-08-12)

The largest single change in the ledger. All product-specific behavior was
moved out of `strix/**` into `lyrashield/**` and `lyrashield_adapter/**`, and
the retained `strix/**` substrate was reset to exact upstream v1.5.3
(`7cc9fa9faa0179fc7e35111102fe3d20a9028393`). Only two generic, reviewed seams
remain modified inside `strix/**`; everything else is owned in the product tree.

### Generic seams in `strix/**` (the only two modified files)

- `strix/config/loader.py`: `register_settings_loader` composition seam.
  `lyrashield/policy/loader.py` is the registered product loader.
- `strix/skills/__init__.py`: telemetry-thread gate + `register_skill_dir`
  extension (an upstream v1.5.3 feature used to load `lyrashield/skills/`).

Additional generic seams in `strix/**` that remain exact upstream (no local
patch, but provide the registration hooks the product uses):

- `strix/agents/factory.py`: `register_tool_override` and
  `register_model_policy` seams so product tools and model policy can replace
  upstream base behavior without modifying the base toolset.
- `strix/agents/prompt.py`: Jinja `FileSystemLoader` searches registered skill
  directories before the built-in `strix/agents/prompts/` path, allowing
  product templates to override built-in ones.

### Product modules created in `lyrashield/**`

- `lyrashield/policy/`: `settings.py`, `models.py`, `codex.py`, `loader.py`,
  `provider_contract.py` — GPT-5.6 model acceptance, reasoning policy,
  `LYRASHIELD_*` env aliases, subscription gating, and provider-contract
  probing.
- `lyrashield/lifecycle/`: `agents.py`, `execution.py`, `hooks.py`,
  `inputs.py`, `runner.py`, `sessions.py`, `compaction.py` — non-interactive
  lifecycle, budget hooks, context compaction, prompt sanitization, and
  cancellation.
- `lyrashield/runtime/`: `caido_bootstrap.py`, `docker_client.py`,
  `session_manager.py`, `local_dir_staging.py`, `backends.py` — sandbox
  session and staging mechanics.
- `lyrashield/agents/`: `factory.py`, `prompt.py` — product agent builder,
  programmatic tool calling, output-store binding, redaction, and the product
  system-prompt renderer.
- `lyrashield/interface/`: `main.py`, `cli.py`, `auth_cli.py`,
  `provider_contract_cli.py`, `update_check.py`, `utils.py`, `tui/`,
  `viewer/`, `assets/` — product CLI, TUI, viewer SPA, and auth flows.
- `lyrashield/artifacts/`: `dedupe.py`, `state.py`, `writer.py`, `sarif.py`,
  `usage.py` — report state, dedupe, SARIF, and writer with redaction.
- `lyrashield/telemetry/`: `posthog.py`, `scarf.py`, `_common.py`,
  `logging.py` — lazy-key telemetry with forced-off defaults.
- `lyrashield/utils/`: `redaction.py` — mode-aware path and secret redaction.
- `lyrashield/tools/`: `web_search/`, `proxy/`, `reporting/`, `respond/`,
  `todo/`, `agents_graph/`, `finish/`, `notes/`, `thinking/`, `load_skill/`,
  `output_store.py` — all product tool overrides registered via
  `register_tool_override`.
- `lyrashield/skills/`: `system_prompt.jinja`, `coordination/`, `custom/`,
  `scan_modes/`, `technologies/`, `tooling/`, `vulnerabilities/` — product
  skill overlays and the product system-prompt template, registered via
  `register_skill_dir`.

### Tool overrides registered from `lyrashield_adapter/cli.py`

The adapter registers the following tool overrides before delegating to the
upstream `main()`:

- `agent_finish`, `create_agent`, `send_message_to_agent`, `stop_agent`,
  `view_agent_graph`, `wait_for_agents` (agents_graph)
- `web_search` (Parallel Search)
- `respond_to_user`
- `list_requests`, `view_request`, `repeat_request`, `list_sitemap`,
  `view_sitemap_entry`, `scope_rules` (Caido proxy)
- `create_vulnerability_report`, `create_dependency_report`, `list_reports`,
  `get_report` (reporting)
- `create_todo`, `list_todos`, `update_todo`, `mark_todo_done`,
  `mark_todo_pending`, `delete_todo` (todo)

It also registers the product model policy via `register_model_policy` and the
product skill directory via `register_skill_dir`.

### Verification

- `bash scripts/verify-controlled-derivative.sh`: 968 passed, 1 skipped;
  lint/format/mypy/Bandit pass; `strix/**` footprint is exactly two files,
  +24/-0 lines.
- `bash scripts/verify-worker-contract.sh`: 68 passed.
- `uv build` succeeds; wheel contains `lyrashield/**` product modules and
  `strix/**` v1.5.3 substrate.

### Files reset to upstream v1.5.3

All `strix/**` paths that previously carried product behavior were restored to
upstream content, including but not limited to: `strix/core/agents.py`,
`strix/core/execution.py`, `strix/core/hooks.py`, `strix/core/inputs.py`,
`strix/core/runner.py`, `strix/core/sessions.py`, `strix/config/settings.py`,
`strix/config/models.py`, `strix/config/codex.py`, `strix/agents/factory.py`,
`strix/agents/prompts/system_prompt.jinja`, `strix/interface/main.py`,
`strix/interface/cli.py`, `strix/llm/compaction.py`, `strix/report/dedupe.py`,
`strix/report/state.py`, `strix/report/writer.py`, `strix/telemetry/posthog.py`,
`strix/telemetry/scarf.py`, `strix/tools/web_search/`,
`strix/tools/proxy/tools.py`, `strix/tools/proxy/caido_api.py`,
`strix/tools/reporting/tool.py`, `strix/tools/todo/tools.py`,
`strix/tools/respond/tool.py`, `strix/tools/agents_graph/tools.py`,
`strix/utils/redaction.py`. Prior product-ownership claims about these paths
in this ledger are superseded by this migration.

## LyraShield PR #59 — fix(release): harden sandbox supply chain and docs (2026-08-12)

Restructured the sandbox publication workflow to smoke-test the exact candidate
digest before promoting it, and reconciled operator docs with the
product-outside-strix boundary.

### Sandbox supply-chain hardening

- `.github/workflows/publish-sandbox.yml`: replaced the two-stage
  build-smoke-then-publish flow with a single publish job that (1) builds and
  pushes an unqualified `candidate-<sha>` image with provenance and SBOM, (2)
  smokes the exact candidate digest on both `linux/amd64` and `linux/arm64`
  (non-root, no Docker socket, `cap_net_raw` on nmap, Caido GraphQL startup),
  and (3) promotes only the smoke-qualified digest to the release and SHA tags
  via `docker buildx imagetools create`. The release unit is the digest, never
  a mutable tag.
- `containers/npm-tools/package.json` and `package-lock.json`: removed the
  stale npm lockfile that was not used by the sandbox build.
- `.dockerignore`: tightened to exclude additional dev artifacts.
- `tests/test_sandbox_dockerfile.py` and
  `tests/test_sandbox_release_workflow.py`: added coverage for the new
  candidate-digest-then-promote flow.

### Documentation updates

- `CONTRIBUTING.md`: updated from v1.4.1 references to v1.5.3; replaced the
  warning-only footprint budget description with the hard two-file, +30/-0
  gate; added a Dependency updates section; noted that skills now live in
  `lyrashield/skills/` with `strix/skills/` as inherited substrate; added
  worker-promotion boundary note.
- `README.md`: updated upstream base reference to v1.5.3.
- `UPGRADES.md`: replaced the Deep Review v12 footprint-budget blockquote with
  a historical note clarifying the v1.5.3 hard gate supersedes it; fixed
  markdown table separator and indentation formatting flagged by markdownlint.
- `docs/advanced/configuration.mdx`: expanded to match the full `Settings`
  schema, added ChatGPT subscription route documentation, clarified cache key
  scoping and usage artifacts, and added sandbox digest verification and
  worker-promotion-boundary notes.
- `docs/tools/sandbox.mdx`: added worker-promotion-boundary note.
- `docs/usage/scan-modes.mdx`: updated for current scan-mode behavior.
- `lyrashield/skills/custom/source_aware_sast.md` and
  `lyrashield/skills/system_prompt.jinja`: minor product wording adjustments.

## LyraShield PR #60 — docs: clarify ChatGPT subscription support (2026-08-12)

Docs-only change. Reconciled the public docs with the adapter's actual
subscription support, which was enabled in PR #58 but still described as
"rejected" in several pages.

- `docs/index.mdx`: replaced "ChatGPT subscription-backed models are rejected"
  with "supported through the authenticated `chatgpt/<model>` route."
- `docs/llm-providers/overview.mdx`: added a ChatGPT subscription row to the
  route table and updated the unsupported-providers sentence to scope the
  rejection to subscription routes outside `chatgpt/*`.
- `docs/llm-providers/openai.mdx`: clarified that subscription models use the
  separately authenticated `chatgpt/<model>` route, not the API-credential
  route.
- `docs/usage/cli.mdx`: updated the `auth` subcommand description from
  "retained only for upstream compatibility" to the actual ChatGPT
  subscription sign-in flow.
- `docs/usage/instructions.mdx`: updated the instruction constraint from
  "enable ChatGPT subscription models" to "change the configured ChatGPT
  subscription policy."
## LyraShield PR — fix(sandbox): default-on resource caps + authorized-target egress scope (2026-08-16)

Sandbox isolation posture change (founder-pinned values).

- **Resource caps are now default-on**, mirroring the log-limit pattern: `mem_limit=2g`, `shm_size=512m` (Chromium/headless tools OOM on docker's 64m `/dev/shm` default), `cpus=2`, `pids_limit=512`. Previously these were opt-in and unset meant docker's unbounded default — a fork bomb or memory hog inside an autonomous agent's container could exhaust the host and take down co-located scans. Each `STRIX_SANDBOX_*` knob still overrides the default; the explicit opt-out tokens `0`/`off`/`none`/`unlimited` restore docker's unbounded default for that knob; an unparseable value falls back to the pinned default, never to unbounded. The effective resolved cap set is logged at container create (`sandbox caps: …`) so "was this scan bounded?" is answerable from logs.
- **Authorized-target egress scope**: at sandbox bring-up the engine now derives the scan's authorized network hosts from `targets_info` (URL + IP targets), creates a default `authorized-targets` Caido scope from them before the agent starts (recorded on the run record as `proxy_default_scope`), and registers the hosts with the replay egress guard. The replay path blocks RFC1918/loopback space by default — reachable only toward an authorized target or when `STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS=1` is explicitly set. Cloud-metadata and link-local blocks remain unconditional. Repositories and local source trees are not network destinations and produce no egress hosts.
- Docs: `docs/tools/sandbox.mdx` and `docs/advanced/configuration.mdx` document the new cap table, default-on posture, and escape hatches.

## LyraShield PR — chore(deps): move openai-agents to a released range and litellm to a compatible release pin (2026-08-16)

Dependency-policy change (ENG finding: the structural pins blocked Dependabot
and `uv` from picking up security fixes).

- `openai-agents` was pinned to git SHA `f663a06`. That SHA was a PRE-RELEASE
  commit of the 0.19 line — its package metadata still reported 0.18.3, but the
  PyPI 0.18.3 wheel lacks `ProgrammaticToolCallingTool`, which the engine
  imports. It is now `>=0.19.0,<0.20` resolved from PyPI (currently 0.19.4,
  hash-pinned in uv.lock), so patch releases in the 0.19 line flow through a
  lock refresh without re-deriving a SHA pin. The 0.x SDK reserves minor
  versions for breaking changes, hence the `<0.20` ceiling.
- `litellm==1.90.1` (exact pin) is now `~=1.90` (>=1.90, <2.0). Resolution is
  unchanged today (still 1.90.1) but 1.x security releases can flow through
  `uv lock` refreshes.
- Historical reason for the original SHA pin: the engine depends on
  SDK-internal seams (Docker sandbox create-container signature, usage
  serialization shapes) that moved between releases; the pin froze them while
  the controlled-derivative work stabilized. `assert_sdk_docker_compatibility`
  still fails fast at scan time if the private hook changes.
- Re-review cadence: re-run the full engine gate (`scripts/verify-controlled-derivative.sh`)
  and a live Standard/Luna scan against an approved target whenever a
  `uv lock` refresh moves either dependency, and before any ceiling lift
  (`openai-agents>=0.20` or `litellm>=2`, or the openai `<2.49` cap — the
  last is tracked by Dependabot PR #73 and needs a manual LLM-path regression
  first).
## LyraShield PR — test: pin the agent SDK seams in a contract test (2026-08-16)

`tests/test_sdk_seam_contract.py` turns the dependency-range policy above into
a CI-enforced contract:

- Every `agents.*` symbol the product imports is inventoried **dynamically from
  the source tree** (AST walk over `lyrashield/**` + `lyrashield_adapter/**`)
  and asserted to exist on the pinned SDK — new imports are covered
  automatically, and a lock refresh that drops a symbol fails here with the
  exact missing names instead of at scan time.
- The private Docker adapter seam (`DockerSandboxClient._create_container`
  signature) is pinned alongside the runtime `assert_sdk_docker_compatibility`
  check the worker depends on.
- The usage-serialization round-trip the billing ledger relies on
  (`serialize_usage`/`deserialize_usage`) is pinned explicitly.

This complements — not replaces — the re-review cadence above: the full gate
plus a live Standard/Luna scan remain required before promoting a worker image
on a moved SDK.
