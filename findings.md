# Findings & Decisions: Strix Overlay Migration

## Requirements

- Primary goal: make future upstream Strix updates easy to integrate.
- Preserve all current LyraShield behavior and public contracts.
- Move product behavior out of core Strix files.
- Keep security, privacy, budgets, error recovery, UX, packaging, and worker behavior intact.
- Produce an implementation path another coding agent can execute without relying on chat context.

## Current Repository Evidence

- Repository: `/Users/defiankit/Desktop/lyrashield-engine`.
- Branch: `codex/strix-overlay-migration` (created from `main`).
- Engine `HEAD`: `63800d5e66a8b6cc0c767a02c10cf9faabd9d553`; `origin/main` matches.
- Pinned upstream base: `2e7040240d201f433d0fe42f922dbfbe953c6c8b` (10-char prefix in `.lyrashield-upstream-base` resolves unambiguously).
- Latest stable upstream tag: `v1.5.2` at `597aae67159636ee794a02a3cc1694138d619c44`.
- `upstream/main`: `ae07af61597041951d2116f108fb72bae4967caf` (`v1.5.2-2-gae07af6`).
- Refreshed counts (base → `v1.5.2`): 46 upstream commits, 141 `strix/**` paths changed upstream.
- Refreshed counts (base → `HEAD`): the fork differs in 68 `strix/**` files, +5,486/-1,297 lines.
- Refreshed overlap: 36 of the 68 fork-changed `strix/**` paths were also changed in `v1.5.2` (recomputed after the fetch).
- 32 fork-changed paths are not changed in `v1.5.2`; these are the cleanest early-move candidates because there is no overlapping upstream diff to reconcile.
- The footprint budget still warns rather than fails and permits up to 80 files, +8,000/-2,000 lines. This is a visibility guard, not the target zero-diff invariant.

## Existing Useful Extension Seams

- `strix.agents.factory.register_agent_tools()` registers tools for root and child scan agents.
- `strix.skills.register_skill_dir()` supports external skill additions and overrides.
- `strix.runtime.backends.register_backend()` supports external runtime backends.
- The runner accepts root instruction overrides and extra system prompt context.
- These make skills, Parallel web search, and custom runtime behavior strong early migration candidates.

## Current Hard Blockers

- `lyrashield_adapter/cli.py` imports fork-only `PRODUCT_BOUNDARY_ENV_VAR` and `is_chatgpt_subscription_allowed` from `strix.config.settings`; it is not currently portable to clean upstream Strix.
- The adapter also calls fork-only GPT-5.6 helpers in `strix.config.models`.
- `strix/core/runner.py` directly constructs `StrixProvider` and `ReportUsageHooks`.
- `strix/interface/cli.py` directly constructs `ReportState`.
- The interactive TUI directly constructs `ReportState`.
- Lifecycle recovery, content-filter/delegate behavior, budget hooks, run-record metadata, and redaction are interleaved with Strix implementation.
- Copying these modules or monkeypatching them would preserve internal coupling and would not achieve the update-ease goal.

## Product Contract Surface

The production worker invokes the `lyrashield` executable with:

- `--non-interactive`
- `--run-name`
- `--target`
- `--scan-mode`
- optional `--instruction`
- optional `--max-budget-usd`

The worker consumes `run.json` and `vulnerabilities.json`. Relevant `run.json` fields include:

- `schema_version`
- `run_id`, `run_name`, timestamps, and status
- `phase`, `seq`, and `turn_count`
- target and usage data
- engine/model/reasoning/token/agent metadata
- prompt bundle hash
- `terminal_reason`: completed, content-filter-stopped, engine-stopped, budget-exceeded, cancelled, or timed-out

The worker treats partial findings and terminal reasons as security-sensitive product truth. Preserve the distinction between completed, partial, stopped, and failed runs.

## Functional Disposition

| Area | Intended disposition |
|---|---|
| CLI branding/version/bootstrap | `lyrashield_adapter` |
| Environment translation and early side-effect policy | `lyrashield_adapter` |
| GPT-5.6/provider/product policy | `lyrashield/policy` |
| Provider-contract command | LyraShield command module |
| Parallel web search | `lyrashield/tools`, registered through upstream seam |
| Skill overrides/additions | `lyrashield/skills`, registered through upstream seam |
| Runtime/backend integration | `lyrashield/runtime`, registered through upstream seam |
| Budgets and out-of-band reservations | LyraShield hooks injected by neutral factory seam |
| Content-filter/delegate recovery | LyraShield lifecycle policy injected by neutral seam |
| `run.json` and finding artifacts | `lyrashield/artifacts` through report-state/serializer seam |
| Generic bug/security fixes | Independent upstream-compatible commits/PRs |
| Product docs, packaging, CI | Fork layer outside `strix/**` |

## File-by-File Migration Matrix

The complete matrix is in `MIGRATION_MATRIX.md`. It assigns every changed `strix/` file one of: `move to lyrashield_adapter`, `move to lyrashield/policy`, `move to lyrashield/tools`, `move to lyrashield/skills`, `move to lyrashield/runtime`, `move to lyrashield/lifecycle`, `move to lyrashield/artifacts`, `upstream as generic fix`, `delete`, or `retain as generic seam`. The largest drifts are `strix/core/hooks.py`, `strix/tools/web_search/tool.py`, `strix/core/runner.py`, `strix/interface/main.py`, `strix/report/dedupe.py`, `strix/config/settings.py`, `strix/config/models.py`, and `strix/report/state.py`.

## Risks

1. **False zero-diff:** monkeypatching or copying the runner moves lines but not coupling.
2. **Import-order privacy failure:** telemetry policy must apply before side-effectful imports.
3. **Config override bypass:** model validation must run after config files are applied, not just against initial environment values.
4. **Artifact drift:** worker parsing may continue while silently dropping new/omitted fields; compare semantic fixtures.
5. **Interactive regression:** non-interactive worker tests do not prove TUI/viewer compatibility.
6. **Packaging regression:** source tests do not prove PyInstaller/resource discovery.
7. **Detection regression:** unit tests and readiness checks do not prove real scan quality or lifecycle behavior.
8. **Upstream churn:** re-fetch before implementation; the audited v1.5.2 state may no longer be current.
9. **Stale docs:** README, CONTRIBUTING, and UPGRADES currently contain inconsistent historical upstream-base descriptions.
10. **Security simplification:** redaction, budgets, partial-result truth, and safe failure behavior may not be dropped for architectural cleanliness.

## Verification Evidence from Planning Audit

- `bash scripts/verify-controlled-derivative.sh` passed.
- Ruff lint and formatting passed.
- Pytest: 953 passed, 1 skipped.
- Mypy: no issues in 80 source files.
- Bandit completed without a failing finding; informational warnings were printed for existing `nosec` comments.
- `bash scripts/verify-worker-contract.sh /Users/defiankit/Desktop/lyrashieldai` passed.
- Worker contract tests: 2 files, 68 tests passed.
- Both engine and sibling app worktrees were clean after these checks.
- Native binary, Docker, and live paid-model scans were not rerun during the planning audit.

## Technical Decisions

| Decision | Rationale |
|---|---|
| First milestone is byte-identical upstream `strix/**` | It directly removes overlap conflicts while preserving the option to improve dependency packaging later. |
| Dependency vs vendored source remains an evidence-gated choice | PyInstaller, skills, viewer assets, and Docker packaging must be proven. |
| Generic hooks default to unchanged Strix behavior | Makes upstream acceptance and safe rebasing more likely. |
| Product tests target LyraShield public contracts | Tests tied to private Strix functions would preserve the coupling being removed. |
| Migration proceeds vertically in green PRs | Each behavior can be compared and rolled back independently. |

## Resources

- `/Users/defiankit/Desktop/lyrashield-engine/lyrashield_adapter/cli.py`
- `/Users/defiankit/Desktop/lyrashield-engine/lyrashield/README.md`
- `/Users/defiankit/Desktop/lyrashield-engine/UPGRADES.md`
- `/Users/defiankit/Desktop/lyrashield-engine/LYRASHIELD_DIFF_REPORT.md`
- `/Users/defiankit/Desktop/lyrashield-engine/scripts/verify-controlled-derivative.sh`
- `/Users/defiankit/Desktop/lyrashield-engine/scripts/verify-worker-contract.sh`
- `/Users/defiankit/Desktop/lyrashieldai/apps/worker/src/engine/command-builder.ts`
- `/Users/defiankit/Desktop/lyrashieldai/apps/worker/src/engine/engine-output-schema.ts`
- `/Users/defiankit/Desktop/lyrashieldai/apps/worker/src/engine/output-parser.ts`

## Source-Consumption Decision (Phase 1)

- **Preferred option (exact Strix dependency) was tested in a throwaway worktree** (`/tmp/strix-dep-spike`, branch `spike/dependency-test`) by removing `strix` from the wheel packages and adding `strix-agent @ git+https://github.com/usestrix/strix.git@v1.5.2`.
- **Result:** `uv sync` failed with an unsatisfiable `openai-agents[litellm]>=0.19.0,<0.20` constraint. The fork pins `openai-agents` to a direct git commit (`f663a06aea...`), while `strix-agent` expects a PyPI release in a range that the current `uv` resolution cannot satisfy together with that direct reference.
- **Additional findings:** upstream `strix-agent` v1.5.2 does not declare a direct `textual` dependency even though its `strix/interface/tui/app.py` uses Textual; the fork already carries `textual>=6.0.0` because it owns the TUI path.
- **Decision:** the **vendored/subtree** end state is the safer, evidence-backed choice. `strix/**` will be reset to byte-identical to the pinned upstream release (`v1.5.2` at `597aae67159636ee794a02a3cc1694138d619c44` or a later chosen SHA), and LyraShield behavior will live outside it. The dependency option is not viable without either forking the upstream `pyproject.toml` constraints or giving up the `openai-agents` git pin, both of which introduce packaging and runtime risks that exceed the benefit.
- **TUI variant:** keep the fork's Python Textual TUI. Move `strix/interface/tui/app.py`, `strix/interface/assets/tui_styles.tcss`, `strix/interface/tui/renderers/*.py`, and related Python TUI helpers to `lyrashield/interface/tui/`; accept the upstream v1.5.2 Go TUI sidecar (`strix/interface/tui/cmd/strix-tui/`, `strix/interface/tui/backend/`, `strix/interface/tui/internal/`, `go.mod`, `go.sum`) inside `strix/**`.

## Issues Encountered

| Issue | Resolution |
|---|---|
| No existing planning files were present | Created a fresh repository-root planning set for this migration. |
| `UPGRADES.md` claims a stale `Current upstream base` of `8157ccba...` (2026-07-26) while `.lyrashield-upstream-base` is `2e7040240d...` | Documented in `findings.md`; reconciliation deferred until the final architecture/pin is chosen (Phase 8). |
| `upstream-sync-2e70402.md` and `LYRASHIELD_DIFF_REPORT.md` contain superseded fork HEADs | Treat as historical artifacts; the definitive current baseline is now this Phase 0 refresh. |
| Exact `strix-agent` dependency resolution failed in the worktree | Documented above; vendored source chosen. |

