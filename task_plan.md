# Task Plan: Make Strix Upstream Updates Routine

## Goal

Move LyraShield-owned behavior out of `strix/**` so the retained Strix tree is byte-for-byte identical to a pinned stable upstream release (or consumed as an exact dependency), while preserving CLI, worker artifact, security, packaging, Docker, and scan behavior.

## Next Step

Implement the first vertical slice: move the LyraShield-specific skill markdown overlays to `lyrashield/skills/` and register the directory from the adapter.

## Current Phase

Phase 4 — in progress (skills overlay complete; tools/runtime next).

## Non-Negotiable Outcomes

- `strix/**` has no LyraShield product logic.
- Preferred end state: `git diff <pinned-upstream-sha> -- strix/` is empty.
- If upstream cannot accept every required seam, retain only a measured micro-fork: at most 5 upstream files and 200 changed lines, with every patch generic, documented, tested, and eligible for upstream submission.
- Do not use monkeypatching, `sys.modules` manipulation, import hooks, or copied Strix runner/CLI modules to create the appearance of separation.
- `lyrashield_adapter` remains a thin bootstrap/CLI compatibility layer. Product implementation belongs under `lyrashield/`.
- Preserve telemetry-off, self-update-off, GPT-5.6 policy, spend limits, redaction, prompt-safety, partial-result salvage, deterministic artifacts, and worker compatibility.
- Preserve user-visible interactive behavior, non-interactive behavior, binary startup, viewer behavior, and Docker worker execution.
- Generic bug/security fixes belong upstream; do not hide them in a LyraShield-named adapter.
- Never weaken validation, authorization, redaction, budget enforcement, or error handling to achieve a zero-diff metric.

## Scope

### In scope

- `/Users/defiankit/Desktop/lyrashield-engine`
- Read-only contract discovery and required compatibility updates in `/Users/defiankit/Desktop/lyrashieldai/apps/worker`
- Upstream Strix stable tag/commit selection and compatibility analysis
- LyraShield CLI/bootstrap, policy, tools, skills, runtime registration, model policy, lifecycle policy, reporting, artifacts, packaging, Docker, and verification
- Neutral Strix extension seams, preferably contributed upstream

### Out of scope unless separately approved

- New scan features or detection rules unrelated to the migration
- Product UX redesign
- Changing public worker artifact semantics
- Changing supported providers or pricing policy
- Broad formatting/refactoring of upstream source
- Force-pushing, merging to `main`, publishing packages, deploying, or opening upstream PRs

## Target Shape

```text
lyrashield-engine/
├── lyrashield_adapter/
│   └── cli.py                  # bootstrap, env translation, CLI compatibility
├── lyrashield/
│   ├── policy/                 # model/provider/product rules
│   ├── tools/                  # Parallel web search and LyraShield tools
│   ├── skills/                 # overlays/additions registered with Strix
│   ├── runtime/                # backend/bootstrap registration
│   ├── lifecycle/              # error, fallback, budget policy
│   └── artifacts/              # run.json, redaction, worker contract
├── tests/                      # product and cross-repo contract tests
└── strix/                      # exact pinned upstream tree, or absent if dependency-backed
```

Do not create every directory preemptively. Create a module only when a migrated behavior needs it.

## Branch and Change Strategy

1. Start from a clean worktree. Preserve all unrelated user changes.
2. Fetch `origin` and `upstream`; choose the latest stable Strix tag after checking release notes and current code. The last audited state was upstream `v1.5.2` plus two commits at `ae07af61597041951d2116f108fb72bae4967caf`.
3. Create a `codex/` migration branch. Do not modify `main` directly.
4. Keep every intermediate PR deployable and green.
5. Prefer this PR sequence:
   - PR A: baseline contracts, migration inventory, and hard drift accounting; no runtime behavior change.
   - PR B: existing extension seams — env/bootstrap, skills, tools, runtime backend.
   - PR C: model/provider/product policy extraction.
   - PR D: generic lifecycle/reporting extension seams plus LyraShield implementations.
   - PR E: remove remaining `strix/**` patches; reset to exact upstream tree or dependency.
   - PR F: packaging, Docker, docs, and final upgrade simulation.
6. Do not merge a later PR while an earlier one is not green. Do not combine unrelated cleanup.

## Phases

### Phase 0: Establish the reproducible baseline

- [x] Run `git status --short --branch`; stop if unrelated changes overlap the migration.
- [x] Run `git remote -v`, fetch `origin` and `upstream`, and record exact SHAs/tags.
- [x] Record `.lyrashield-upstream-base`, `HEAD`, `origin/main`, latest stable upstream tag, and `upstream/main`.
- [x] Run and capture `git diff --shortstat <pinned-base> HEAD -- strix/`.
- [x] Generate a file-by-file migration matrix for every changed `strix/**` path with exactly one disposition:
  - delete because current upstream already contains equivalent behavior;
  - move to `lyrashield_adapter`;
  - move to `lyrashield/`;
  - submit as a generic upstream fix;
  - temporarily retain as a minimal generic seam.
- [x] Reconcile the stale upstream-base claims in `README.md`, `CONTRIBUTING.md`, and `UPGRADES.md`, but defer edits until the final architecture is known.
- [x] Capture current CLI help/version output and wheel contents as golden compatibility evidence.
- [x] Capture representative `run.json` and `vulnerabilities.json` fixtures for completed, partial, content-filter-stopped, engine-stopped, budget-stopped, cancelled, and timed-out runs. Sanitize all fixtures.
- [x] Run the current baseline gates and log results in `progress.md`.
- **Exit gate:** inventory covers every changed upstream file; baseline is reproducible; no runtime code changed.
- **Status:** complete

### Phase 1: Decide source consumption without risking packaging

- [x] In a temporary worktree, test exact upstream Strix as a pinned dependency or isolated upstream source tree.
- [x] Verify Python imports, packaged skills/templates, viewer static assets, optional viewer dependencies, and version metadata.
- [x] Verify PyInstaller can discover required modules/resources without broad hidden-import collection.
- [x] Verify the sandbox Docker build can obtain required Strix resources without copying LyraShield secrets or the entire development tree.
- [x] Choose one end state:
  - preferred: exact Strix tag/SHA dependency locked by `uv.lock`;
  - fallback: vendored/subtree `strix/**` that is byte-identical to the pinned upstream tree.
- [x] Record the choice and evidence in `findings.md` before restructuring files.
- **Exit gate:** source-consumption choice is proven by a package/binary spike, not selected on aesthetics.
- **Status:** complete

### Phase 2: Strengthen compatibility tests before extraction

- [ ] Convert current behavior into product-facing tests that import or invoke LyraShield public interfaces, not private Strix implementation details.
- [ ] Cover all environment translations and precedence, including empty high-priority aliases.
- [ ] Cover telemetry and update-check disabling before any Strix import that could create side effects.
- [ ] Cover GPT-5.6 Terra/Luna acceptance, unsupported provider rejection, subscription policy, config-file overrides, reasoning, token ceilings, and prompt-cache settings.
- [ ] Cover CLI flags required by the worker: `--non-interactive`, `--run-name`, `--target`, `--scan-mode`, `--instruction`, and `--max-budget-usd`.
- [ ] Cover worker artifact schema/version, terminal reasons, partial-result preservation, usage fields, deterministic IDs, and bounded/redacted text.
- [ ] Cover interactive/TUI and viewer entrypoints at least with construction and smoke tests.
- [ ] Keep existing upstream tests intact; do not rewrite them as LyraShield tests.
- **Exit gate:** deleting any product-critical behavior causes a focused LyraShield contract test to fail.
- **Status:** pending

### Phase 3: Move bootstrap, environment, update, and telemetry policy

- [ ] Make `lyrashield_adapter` independent of fork-only symbols currently imported from `strix.config.settings` and `strix.config.models`.
- [ ] Move `LYRASHIELD_* -> STRIX_*` translation into the adapter using the smallest maintainable mapping strategy. Do not require LyraShield aliases inside upstream settings models.
- [ ] Apply telemetry-off and update-check-off before importing Strix runtime modules.
- [ ] Keep `--version` fast and independent of heavy Strix imports.
- [ ] Preserve caller environment precedence over `.env`; continue removing stale empty generic LLM variables that shadow provider-specific values.
- [ ] Decide how to handle upstream `--update`: remove it from the LyraShield parser or reject it in the adapter with the current clear error.
- [ ] Prove that importing alternate LyraShield entrypoints cannot accidentally enable telemetry.
- **Exit gate:** environment/update/telemetry product tests pass with an unmodified upstream settings module.
- **Status:** pending

### Phase 4: Move skills, tools, and runtime integrations through existing seams

- [x] Move LyraShield skill additions/overrides from `strix/skills/**` to a LyraShield resource directory.
- [x] Register the directory with `register_skill_dir()` before agents are built.
- [ ] Move Parallel web search into `lyrashield/tools/` and register it with `register_agent_tools()`.
- [ ] Preserve web-search enablement, API-key handling, URL/secret redaction, call caps, spend reservations, timeout behavior, and result bounds.
- [ ] Preserve renderer UX. If Strix lacks a renderer registry, propose the smallest generic renderer-registration seam upstream; do not silently degrade to unreadable generic output.
- [ ] Move custom runtime/backend behavior through `register_backend()` where possible.
- [ ] Separate generic Caido/sandbox correctness fixes from LyraShield policy; upstream the generic fixes.
- [ ] Ensure repeat imports do not double-register tools, skills, or backends.
- **Exit gate:** changed skill/tool/runtime files under `strix/**` are removed or reduced to an accepted generic seam, with behavior-equivalent tests.
- **Status:** in progress

### Phase 5: Extract model and provider policy

- [ ] Move GPT-5.6 model-name/provider acceptance rules into `lyrashield/policy/`.
- [ ] Move LyraShield-only provider-contract diagnostics and CLI command outside `strix/**`.
- [ ] Preserve validation both before delegation and after config-file overrides are resolved.
- [ ] Prefer upstream/LiteLLM provider metadata when reliable; keep LyraShield-owned dated rate overrides only where product budget safety requires them.
- [ ] Preserve maximum input/output token policy, delegate token ceilings, prompt-cache behavior, extra headers, streaming controls, and supported reasoning levels.
- [ ] Identify generic Strix model/provider fixes and submit them independently rather than duplicating them in product policy.
- [ ] If post-config validation cannot be injected, design a neutral validator callback/default-no-op seam and add upstream-compatible tests.
- **Exit gate:** `strix/config/**` matches upstream while every LyraShield provider-policy test passes.
- **Status:** pending

### Phase 6: Add the minimum neutral lifecycle/reporting seams

- [ ] Re-read `task_plan.md` and the migration matrix before designing any new interface.
- [ ] Confirm no newer upstream API already solves each need.
- [ ] Add only the seams proven necessary by failing product contracts, likely:
  - report-state factory for non-interactive CLI and TUI;
  - usage-hooks factory for the runner;
  - model/provider policy or run-config factory;
  - lifecycle/error policy for content-filter/delegate fallback;
  - artifact transformation/serialization hook.
- [ ] Each upstream seam must preserve current Strix behavior by default and include an upstream-style test with no LyraShield names.
- [ ] Keep hook interfaces narrow and typed; avoid a single unstructured plugin object or global monkeypatch registry.
- [ ] Prefer parameters/factories at composition roots over callbacks scattered through hot loops.
- [ ] Prepare generic commits suitable for upstream PRs. Do not mix LyraShield implementation into those commits.
- [ ] If upstream rejects a seam, document the rejection and keep the smallest patch in the micro-fork allowance.
- **Exit gate:** LyraShield can inject required behavior without copying or monkeypatching runner, CLI, TUI, hooks, or report-state modules.
- **Status:** pending

### Phase 7: Move lifecycle, budgets, reporting, artifacts, and privacy

- [ ] Implement LyraShield usage hooks outside `strix/**`, preserving concurrent pre-request reservations, out-of-band dedupe/search reservations, rate-limit behavior, cache-aware upper bounds, and budget extensions.
- [ ] Implement LyraShield lifecycle policy outside `strix/**`, preserving transient retry, content-filter detection, delegate fallback, descendant cancellation, session cleanup, and partial-finding salvage.
- [ ] Implement LyraShield report state/artifact policy outside `strix/**`.
- [ ] Preserve `schema_version`, `phase`, `seq`, `turn_count`, engine/model metadata, prompt-bundle hash, usage accounting, terminal reasons, and atomic writes.
- [ ] Preserve mode-aware redaction: spill/tmp paths always redacted; whitebox target paths preserved where required; secrets and sensitive evidence redacted; PoC reproducibility handled by the existing policy.
- [ ] Preserve bounded dedupe input, structured judgement parsing, and safe fallback behavior.
- [ ] Upstream generic prompt-injection, compaction-secret, telemetry-key, session, and reporting correctness fixes.
- [ ] Confirm that every removed `strix/**` call site is replaced through a public seam, not import-order luck.
- **Exit gate:** core/runtime/report/telemetry diffs are zero except approved micro-fork seams; product lifecycle and artifact tests pass.
- **Status:** pending

### Phase 8: Reset Strix to an exact upstream release

- [ ] Re-fetch upstream and confirm the selected stable SHA has not moved.
- [ ] Remove obsolete local Strix patches only after their replacement tests pass.
- [ ] Make `strix/**` byte-identical to the selected upstream tree, or remove it if dependency consumption was proven.
- [ ] Run `git diff --exit-code <pinned-upstream-sha> -- strix/`.
- [ ] Replace the warning-only footprint budget with a hard invariant:
  - zero changed files for the clean-overlay target; or
  - an explicit allowlist and strict line/file cap for a temporary micro-fork.
- [ ] Ensure CI fetches the exact upstream commit/tag and fails when the pin, lockfile, source tree, or patch allowlist disagree.
- [ ] Update `.lyrashield-upstream-base`, `UPGRADES.md`, `NOTICE`, README, contributing guidance, and package metadata consistently.
- [ ] Remove obsolete banners and stale migration documentation only from files that are no longer modified.
- **Exit gate:** automated source-integrity check proves the Strix substrate matches its pin.
- **Status:** pending

### Phase 9: Full verification and upgrade simulation

- [ ] Run `bash scripts/verify-controlled-derivative.sh` or its renamed zero-diff successor.
- [ ] Run `bash scripts/verify-worker-contract.sh /Users/defiankit/Desktop/lyrashieldai`.
- [ ] Run focused adapter/policy/tool/lifecycle/artifact tests independently.
- [ ] Run `uv build` and inspect wheel/sdist contents for required resources and absence of tests, secrets, caches, and frontend source.
- [ ] Run `bash scripts/build.sh`; invoke the produced binary with `--version` and `--help` under timeouts.
- [ ] Verify auth/provider-contract/viewer subcommands and interactive construction.
- [ ] Build the worker and sandbox Docker images without cache; inspect build context and image contents for `.env*` or credentials.
- [ ] Run a local Docker worker smoke that creates the expected sandbox and artifacts.
- [ ] Run controlled authorized scans for quick, standard, and deep paths. Exercise Terra and Luna where credentials/cost approval permit.
- [ ] Exercise content-filter, transient failure, delegate failure, budget stop, cancellation, and timeout paths with deterministic fakes where live triggering is impractical.
- [ ] Compare artifact schemas, terminal classification, finding persistence, and billing usage with baseline fixtures.
- [ ] Simulate the actual future workflow by advancing to the next upstream stable tag/SHA in a throwaway branch and running all gates.
- **Exit gate:** the version bump requires only pin/lock updates plus intentional compatibility adjustments outside `strix/**`.
- **Status:** pending

### Phase 10: Review and delivery

- [ ] Review the final diff for accidental upstream modifications, copied implementation, hidden monkeypatches, and weakened security controls.
- [ ] Report separately: source tests, worker contracts, package/binary proof, Docker proof, controlled-scan proof, CI state, merge state, and deployment state.
- [ ] Document any remaining micro-fork seam, its upstream PR/status, and its removal condition.
- [ ] Obtain user approval before merge, publish, deployment, or consequential upstream submissions.
- [ ] Merge only after actual CI is green and required review is complete.
- **Exit gate:** handoff contains exact commits/PRs, tests, unresolved risks, and the next upstream-update procedure.
- **Status:** pending

## Required Verification Commands

Re-check command names after scripts are changed; do not blindly preserve obsolete names.

```bash
git status --short --branch
git fetch --prune origin
git fetch --prune upstream
git diff --exit-code "$(cat .lyrashield-upstream-base)" -- strix/
bash scripts/verify-controlled-derivative.sh
bash scripts/verify-worker-contract.sh /Users/defiankit/Desktop/lyrashieldai
uv run lyrashield --version
uv run lyrashield --help
uv build
bash scripts/build.sh
```

For Docker and live scans, use the repository's current documented commands after inspecting them. Never infer that a green source gate proves binary, Docker, worker, or live scan behavior.

## Definition of Done

- [ ] Exact Strix source integrity is machine-enforced.
- [ ] Product behavior is outside `strix/**`.
- [ ] No monkeypatch/copy-based pseudo-adapter exists.
- [ ] All current LyraShield contracts are preserved or intentionally versioned with coordinated worker changes.
- [ ] Full source, worker, package, binary, Docker, and controlled-scan gates pass.
- [ ] A real upstream-version bump has been rehearsed successfully.
- [ ] Documentation contains one consistent pin, architecture description, and update procedure.
- [ ] The worktree is clean and unrelated user changes remain untouched.

## Decisions Made

| Decision | Rationale |
| --- | --- |
| Optimize for an immutable upstream tree, not merely fewer banners | Future update cost depends on eliminating overlapping edits, not renaming their location. |
| Keep bootstrap separate from product implementation | A one-file adapter containing lifecycle, reporting, tools, and policy would become another fork-shaped maintenance problem. |
| Upstream generic fixes | Generic correctness and security patches should disappear from the local delta once released upstream. |
| Add seams only after a failing contract proves the need | Avoid speculative plugin architecture and keep the patch surface minimal. |
| Prove dependency packaging before deleting vendored source | Skills, viewer assets, PyInstaller, and Docker resources make package consumption a verification question. |
| Use multiple green PRs | A single migration would make regressions and rollback boundaries difficult to isolate. |

## Errors Encountered

| Error | Attempt | Resolution |
| --- | ---: | --- |
| None during plan creation | 1 | N/A |

## Agent Handoff Rules

- Read `task_plan.md`, `findings.md`, and `progress.md` before acting.
- Update all three files after every phase.
- Keep exactly one phase `in_progress` at a time.
- Record every failed command and do not repeat an unchanged failing approach.
- Re-fetch upstream before making current-state claims.
- Preserve unrelated worktree changes and branches.
- Do not merge, publish, deploy, force-push, or open consequential upstream PRs without user approval.

