# Upstream Sync Plan: 8157ccb → 2e70402

## Goal

Bring the LyraShield fork current with `usestrix/strix` main from the pinned upstream base `8157ccba276c8fdd5eaa07a1a9d8d686315f6bd1` to target `2e7040240d201f433d0fe42f922dbfbe953c6c8b`, while preserving all LyraShield customizations (cost/model/budget/dedupe/viewer/telemetry boundaries).

## Current State

- **Base:** `8157ccba276c8fdd5eaa07a1a9d8d686315f6bd1`
- **Target:** `2e7040240d201f433d0fe42f922dbfbe953c6c8b`
- **Gap:** 46 commits, 160 files, 7,814 insertions / 656 deletions
- **Tree-delta dry-run:** `git apply --3way --check` succeeds but reports **39 conflicted files** that will need manual resolution.
- **Blocked on:** PR #42 (`sync/v11-hardening-2026-08-02`) must merge first so `main` is clean and the sync can start from a fresh `main`.

## Upstream Update Details

### Commit Range

```
8157ccb..2e70402
```

### Files Most at Risk (LyraShield-Modified)

| File | Change Size | LyraShield Customization to Protect |
|---|---|---|
| `strix/core/execution.py` | 625 lines | agent loop, provider refusals, retry/budget pause, mid-stream errors |
| `strix/core/hooks.py` | 205 lines | `max_input_tokens`, `max_output_tokens`, `max_budget_usd`, `_model_rates` |
| `strix/config/models.py` | 281 lines | GPT-5.6 list, `is_gpt56_model`, `LYRASHIELD_*` aliases |
| `strix/core/agents.py` | 245 lines | parent/child agent lifecycle, budget pause/continue, stall recovery |
| `strix/core/runner.py` | 47 lines | runner lifecycle, budget teardown, `LYRASHIELD_PRODUCT_BOUNDARY` |
| `strix/core/inputs.py` | 53 lines | input token / budget capping |
| `strix/interface/main.py` | 70 lines | `--update` disabled, telemetry off, viewer settings |
| `strix/interface/cli.py` | 2 lines | attribution banner, entry point |
| `strix/report/dedupe.py` | 11 lines | deterministic `_dynamic_identity` pre-check |
| `strix/report/writer.py` | 6 lines | fenced-code helpers (flagged for re-verification on every import) |
| `strix/report/state.py` | 74 lines | usage ledger, reservation state |
| `pyproject.toml` | 15 lines | ruff ignores, optional deps, version |
| `uv.lock` | 2 lines | lock file — regenerate after apply if corrupted |

### 39 Conflicted Files

```
CONTRIBUTING.md
docs/advanced/configuration.mdx
docs/llm-providers/local.mdx
docs/usage/cli.mdx
pyproject.toml
strix/agents/factory.py
strix/agents/prompts/system_prompt.jinja
strix/config/__init__.py
strix/config/codex.py
strix/config/models.py
strix/config/settings.py
strix/core/agents.py
strix/core/execution.py
strix/core/hooks.py
strix/core/inputs.py
strix/core/runner.py
strix/core/sessions.py
strix/interface/cli.py
strix/interface/main.py
strix/interface/utils.py
strix/interface/viewer/auth.py
strix/interface/viewer/server.py
strix/report/dedupe.py
strix/report/state.py
strix/report/writer.py
strix/telemetry/posthog.py
strix/telemetry/scarf.py
strix/tools/agents_graph/tools.py
strix/tools/reporting/tool.py
tests/test_agent_tool_registration.py
tests/test_config_loader.py
tests/test_execution.py
tests/test_fenced_code.py
tests/test_hooks.py
tests/test_inputs.py
tests/test_runner_rate_limit.py
tests/test_runner_root_prompt.py
tests/test_viewer.py
uv.lock
```

### New Upstream Capabilities

| Area | Commits |
|---|---|
| **LLM / Providers** | `feat(config): accept STRIX_REASONING_EFFORT=max`; `feat(llm): enable Bedrock/Anthropic prompt caching for Claude models`; `feat(llm): custom request headers via LLM_EXTRA_HEADERS`; `feat(llm): opt-in LLM_DISABLE_STREAMING for non-streaming OpenAI-compatible endpoints`; `fix(llm): surface structured provider refusals`; `fix(llm): avoid auth during ChatGPT lookup` |
| **Runtime / Execution** | `fix: pre-v1-style lifecycle resilience`; `fix(core): stop interactive runs stalling on a missing tool call`; `fix(core): tell the parent when an interactive subagent parks`; `fix(core): persist the tool-call recovery counter across resumes`; `fix(tools): split wait_for_message into respond_to_user + wait_for_agents`; `fix(tools): halve the wait_for_message ceiling to 300s`; `fix(runtime): retry transient mid-stream provider errors`; `fix(runtime): wake parent when child hits a terminal state`; `feat(runtime): graduated wrap-up warnings, budget reserve, and interactive budget pause/continue`; `fix(runtime): label docker sandbox containers with the run id for teardown` |
| **Context / Tool Output** | `feat(context): bound per-tool output before it enters agent history`; `fix(context): clamp shell output cap`; `fix(context): bound native filesystem tool output in Responses mode`; `fix(context): reserve notice budget`; `fix(context): reject tool-output byte ceilings below the notice size`; `feat(context): model-aware conversation compaction for long scans`; `feat(context): spill oversized tool output into the sandbox workspace`; new `strix/llm/compaction.py` and `strix/llm/context_budget.py` |
| **Tools / Respond** | `refactor(tools): split wait_for_message into respond_to_user + wait_for_agents`; new `strix/tools/output_store.py`; `strix/tools/reporting/tool.py` and `strix/tools/respond/tool.py` changes; `strix/tools/notes/tools.py` updates; `strix/tools/agents_graph/tools.py` updates |
| **Reporting** | `feat(reporting): add read-only list_reports + get_report tools`; `strix/report/state.py` reservation changes; `strix/report/writer.py` fence helper updates |
| **Viewer / CLI** | `refactor: move strix/viewer under strix/interface`; `fix: restore viewer-auth.json path`; `fix: viewer session cookie scoped to bound port`; `fix viewer tool call collisions across agents`; `fix(cli): align View label spacing`; `fix(cli): don't dump raw warm-up traceback`; `docs(prompts): text-only turns no longer end an autonomous run`; `docs(prompt): teach agents to recognize Caido proxy error pages` |
| **Build / Release** | `Add Linux ARM64 standalone release support`; `fix(tls): replace raw urllib with requests for external HTTPS calls`; release `v1.4.0` and `v1.4.1` |
| **Tests** | New tests: `test_compaction`, `test_context_budget`, `test_disable_streaming`, `test_e2e_budget_lifecycle`, `test_execution_transient_retry`, `test_list_reports`, `test_llm_extra_headers`, `test_output_store`, `test_respond_to_user`, plus updates to `test_execution`, `test_hooks`, `test_inputs`, `test_viewer` |
| **Docs** | `docs(skills)`, `docs(llm-providers)`, `docs(usage/cli)`, `docs(prompts)`, `docs/advanced/configuration` updates |

### New Upstream Files to Watch

- `strix/llm/compaction.py`
- `strix/llm/context_budget.py`
- `strix/tools/output_store.py`
- `tests/test_compaction.py`
- `tests/test_context_budget.py`
- `tests/test_disable_streaming.py`
- `tests/test_e2e_budget_lifecycle.py`
- `tests/test_execution_transient_retry.py`
- `tests/test_list_reports.py`
- `tests/test_llm_extra_headers.py`
- `tests/test_output_store.py`
- `tests/test_respond_to_user.py`

## Sync Tasks

- [ ] **1. Merge PR #42 first** → Verify `main` is at the v11 hardening commit and `origin/main` is updated.
- [ ] **2. Create sync branch** → `git checkout main && git pull origin main --ff-only && git checkout -b sync/upstream-2e70402-2026-08-02`
- [ ] **3. Generate and preview tree delta** → `git diff --find-renames --find-copies -p 8157ccb..2e70402 > /tmp/strix.patch && git apply --stat /tmp/strix.patch`
- [ ] **4. Apply delta with `--3way`** → Let it create conflict markers; do not use `-X ours/theirs`.
- [ ] **5. Resolve 39 conflicted files** → Prefer LyraShield customizations unless the upstream change is a clear bug fix. Follow the risk table above.
- [ ] **6. Restore cost/model/budget/dedupe knobs** → Verify `zero_cost`, `max_budget_usd`, `_dynamic_identity`, GPT-5.6 validation, `LYRASHIELD_*` aliases.
- [ ] **7. Add attribution banners to all LyraShield-modified `strix/` files** → Or reference them in `UPGRADES.md` so `verify-controlled-derivative.sh` passes.
- [ ] **8. Update `UPGRADES.md`** → Add a `## Current upstream base` section for `2e70402` and a new LyraShield section describing the sync-specific changes.
- [ ] **9. Update `.lyrashield-upstream-base`** → Only after the sync is verified locally.
- [ ] **10. Regenerate `uv.lock` if needed** → Delete and run `uv lock` if the lock file was corrupted by the apply.
- [ ] **11. Run full verification** → `bash scripts/verify-controlled-derivative.sh`, `bash scripts/build.sh`, `bash scripts/verify-worker-contract.sh .ci/lyrashield-ai`.
- [ ] **12. Push and open PR** → `gh pr create --base main --title "sync: upstream strix 2e70402" --body "Tree-delta sync from 8157ccb to 2e70402."`
- [ ] **13. Merge** → Wait for `verify` CI green, then `gh pr merge --rebase` (or the method the repo allows) and reset local `main` to `origin/main`.

## Done When

- [ ] `git log --oneline 8157ccb..2e70402` changes are present in `strix/` and other tracked paths.
- [ ] `bash scripts/verify-controlled-derivative.sh` passes locally.
- [ ] `bash scripts/build.sh` and worker contract pass locally.
- [ ] `verify-controlled-derivative.sh` attribution check passes for every `strix/` delta.
- [ ] `UPGRADES.md` and `.lyrashield-upstream-base` are updated.
- [ ] PR is merged and `origin/main` is at the sync commit.
