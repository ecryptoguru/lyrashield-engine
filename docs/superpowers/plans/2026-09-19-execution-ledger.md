# Execution Ledger — Production Engine/App Handoff

Plan: `docs/superpowers/plans/2026-09-19-production-engine-app-handoff.md`
Executor: Devin orchestrator + delegated subagents (delegation authorized by user 2026-09-19)
Started: 2026-09-19

## Baseline SHAs (post `git fetch --all --tags`)

| Ref | Value | Plan expectation | Delta |
|---|---|---|---|
| Engine `origin/main` | `353abde0c8c7488ce5937f15a6d32d7b5e1146d5` | `353abde0` | match |
| Engine checkout (main repo) | `93efe66c141d566392b2e8f079e52cd17f661625` on `fix/pyproject-sdist-desktop-exclude` | `93efe66c` | match; clean except untracked `docs/superpowers/` |
| App `origin/main` | `5944f6c5bbd9aa954e91a2dd05d5e29027dacb11` | `137c337b` | **MOVED +8** — PR #733 `codex/review-scan-polling` (scan detail refresh coordination, desktop test fix, e2e handoff docs). Possible minor overlap with Task 9 scan-detail UI. |
| App root checkout | `1b2863d0f75e6c1c2893cbe1f9c1cc5807bc434a` on `chore/tailwind4-rename-and-gitignore` | same | match; 52 commits behind refreshed main; not the baseline |
| Strix `v1.6.2` tag commit | `ff5c8cc8e46d8e60c2bc2439f7bcb07c05ca3db2` | same | match |
| Strix `v1.5.3` tag commit | `7cc9fa9faa0179fc7e35111102fe3d20a9028393` | same | match |
| Strix `upstream/main` | `355a8bb43743ce769e5ff3f72461c07127f3c45c` | same | match |
| Upstream gap | 86 non-merge commits `v1.5.3..v1.6.2`; 100 `v1.5.3..upstream/main` | same | verified |
| Controlled derivative | digest `fafe7c8e0a7f58c4c10e5619a6579880cf1457c4` | same | re-verified by baseline gate (pending) |

All app baselines use refreshed `5944f6c5`, not the reviewed `137c337b`. Plan statements about app code must be re-verified against `5944f6c5` (8 commits ahead).

## Worktree map (fresh, from fetched `origin/main`; pre-existing worktrees untouched)

| Task | Repo | Path | Branch |
|---|---|---|---|
| baseline | engine | `~/.codex/worktrees/baseline-engine` | detached `353abde0` |
| baseline | app | `lyrashield-ai/.worktrees/baseline-app` | detached `5944f6c5` |
| 1 | engine | `~/.codex/worktrees/task-01-anyio` | `codex/task-01-anyio-patch` |
| 2 | engine | `~/.codex/worktrees/task-02-target-inference` | `codex/task-02-target-inference` |
| 2 | app | `lyrashield-ai/.worktrees/task-02-target-type` | `codex/task-02-target-type` |
| 3 | engine | `~/.codex/worktrees/task-03-session-cleanup` | `codex/task-03-session-cleanup` |
| 4 | engine | `~/.codex/worktrees/task-04-docs` | `codex/task-04-docs` |
| 4 | app | `lyrashield-ai/.worktrees/task-04-profiles` | `codex/task-04-profiles-desktop` |
| 5 | app | `lyrashield-ai/.worktrees/task-05-exec-plan` | `codex/task-05-exec-plan` |
| 6 | engine | `~/.codex/worktrees/task-06-review-changes` | `codex/task-06-review-changes` |
| 6 | app | `lyrashield-ai/.worktrees/task-06-review-changes` | `codex/task-06-review-changes` |
| 7 | engine | `~/.codex/worktrees/task-07-strix-162` | `codex/task-07-strix-162` |
| 8 | engine | `~/.codex/worktrees/task-08-evidence` | `codex/task-08-evidence` |
| 8 | app | `lyrashield-ai/.worktrees/task-08-evidence` | `codex/task-08-evidence` |
| 9 | app | `lyrashield-ai/.worktrees/task-09-ux` | `codex/task-09-ux-attachments` |
| 10 | app | `lyrashield-ai/.worktrees/task-10-clients` | `codex/task-10-clients` |
| 11 | app | `lyrashield-ai/.worktrees/task-11-auth-beta` | `codex/task-11-auth-beta` |
| 12 | engine | `~/.codex/worktrees/task-12-connectors` | `codex/task-12-connectors` |
| 12 | app | `lyrashield-ai/.worktrees/task-12-connectors` | `codex/task-12-connectors` |
| 13 | app | `lyrashield-ai/.worktrees/task-13-release` | `codex/task-13-release` |

Engine worktrees live under `~/.codex/worktrees/` (established engine convention); app worktrees under repo `.worktrees/` (established app convention, gitignored).

## Baseline gate results (before any code change)

| Gate | Scope | Result |
|---|---|---|
| `scripts/verify-controlled-derivative.sh` | engine @ `353abde0` | PASS — 1374 passed, 1 skipped; footprint 14 files +151/−57; ruff/format/mypy (152 files)/bandit clean; `anyio==4.14.1` confirmed in frozen env (advisory-affected) |
| `pnpm install --frozen-lockfile` | app @ `5944f6c5` | PASS — lockfile passes supply-chain policy; 1326 pkgs |
| Focused vitest (14 files) | app @ `5944f6c5` | PASS — 422/422 tests, matches review evidence; run.json major-version tripwire already present in output-parser |

## Tracking issues

- Engine: https://github.com/ecryptoguru/lyrashield-engine/issues/143
- App: https://github.com/ecryptoguru/lyrashield-ai/issues/735

## Requirement tracking

Statuses: NOT_STARTED / IN_PROGRESS / CODE_VERIFIED / RELEASE_VERIFIED / BLOCKED

| Task | Status | Branch | Commit | Tests | PR | Notes |
|---|---|---|---|---|---|---|
| 0 baseline+ledger | IN_PROGRESS | — | — | — | — | this file |
| 1 AnyIO patch | CODE_VERIFIED | `codex/task-01-anyio-patch` | `ba1b0d1f`→`684b1b54` | audit clean; 1376 tests; full gate pass | [#144](https://github.com/ecryptoguru/lyrashield-engine/pull/144) | +Kali InRelease digest refresh; re-audit at release |
| 2 target inference no-network | CODE_VERIFIED | `codex/task-02-target-inference` + `codex/task-02-target-type` | `29d1b2d9`→`e21354f2` + `a88a39da` | 133+91 engine tests; 30 vitest + 88 cargo | [#146](https://github.com/ecryptoguru/lyrashield-engine/pull/146) + [#737](https://github.com/ecryptoguru/lyrashield-ai/pull/737) | **merge order:** app PR blocked until engine pin ≥ `--target-type` commit (T13 bridge); +anyio cherry-pick + digest |
| 3 sandbox startup cleanup | CODE_VERIFIED | `codex/task-03-session-cleanup` | `7640240c`→`4c944d19` | 52+52 tests; ruff/mypy clean | [#147](https://github.com/ecryptoguru/lyrashield-engine/pull/147) | +branding allowlist realign (re-indented STRIX_ lines), +anyio, +digest; agent debris cleaned (dup test + sync marker) |
| 4 profiles/Desktop contracts | CODE_VERIFIED | `codex/task-04-docs` + `codex/task-04-profiles-desktop` | `6100a6fd`→`73622d8d` + `c2cd6d6d`→`4581fac6` | 34 vitest + 91 cargo pass; tsc/eslint clean | [#736](https://github.com/ecryptoguru/lyrashield-ai/pull/736) + [#145](https://github.com/ecryptoguru/lyrashield-engine/pull/145) | +docs line reflow (STRIX_APP_URL allowlist), +ScanScreen undefined guard, +anyio, +digest; rendered Desktop check deferred to T13 |
| 5 execution-plan snapshot | CODE_VERIFIED | `codex/task-05-exec-plan` | `d2fb1808`→`fb0697dc` | 561 vitest; migration drift-free on local dev DB | [#738](https://github.com/ecryptoguru/lyrashield-ai/pull/738) | +prettier pass (12 files); flag `LYRASHIELD_SCAN_PLAN_REQUIRED` off; AUTH_ASSESSMENT → 400 until T11 |
| 6 Review Changes workflow | CODE_VERIFIED | `codex/task-06-review-changes` ×2 | engine `46780b77`→`6ce548f3` + app `e8b810fb`→`a2838742` | 59+320 tests | [#148](https://github.com/ecryptoguru/lyrashield-engine/pull/148) + [#739](https://github.com/ecryptoguru/lyrashield-ai/pull/739) | stacked on #146/#738; needs engine pin ≥ 46780b77; +fail-closed no-repo-scopes guard (agent leftover), +anyio, +digest, +prettier (15 files) |
| 7 upstream v1.6.2 import | CODE_VERIFIED | `codex/task-07-strix-162` | `56ef2765`→`f807dab4` | 2236 tests; gate+rehearsal green; digest `30b8c59d` recomputed | [#149](https://github.com/ecryptoguru/lyrashield-engine/pull/149) | dispositions: 56 adopt/9 port/18 exclude/3 equivalent; +anyio, +digest |
| 8 evidence through boundaries | CODE_VERIFIED | `codex/task-08-evidence` ×2 | app `b67b4c1a`→`85abec07` + engine `25364663`→`dfe72ab6` | 922 app + 18 new engine (2253 total) | [#740](https://github.com/ecryptoguru/lyrashield-ai/pull/740) + [#150](https://github.com/ecryptoguru/lyrashield-engine/pull/150) | writer flag `LYRASHIELD_RUN_RECORD_V1_1` off; readers first; +anyio, +digest, +prettier (27 files) |
| 9 attachments + scan UX | CODE_VERIFIED | `codex/task-09-attachments` + `codex/task-09-ux-attachments` | engine `29e219de` + app `5c1aa8a3` | 48 engine (1550 total) + 614 app tests | [#151](https://github.com/ecryptoguru/lyrashield-engine/pull/151) + [#741](https://github.com/ecryptoguru/lyrashield-ai/pull/741) | migration 20260920000000_scan_attachments; read-only mount + injection-denial proven |
| 10 API/SDK/CLI/MCP/Desktop parity | CODE_VERIFIED | `codex/task-10-clients` | `d5c6b8aa` + `929cdcf1` (+merge `0c26ed2a`) | 101 cargo + 340+ vitest | [#742](https://github.com/ecryptoguru/lyrashield-ai/pull/742) | fixture scan-workflows.json parity contract; Action recorded-scan inputs; Desktop cloud-submit keychain-gated |
| 11 authenticated staging beta | CODE_VERIFIED | `codex/task-11-auth-beta` | `0c48800e` | ~1200 tests; negative matrix green | [#743](https://github.com/ecryptoguru/lyrashield-ai/pull/743) | flag `LYRASHIELD_AUTH_ASSESSMENT_ENABLED` off + allowlist; live run BLOCKED pending auth |
| 12 outbound connectors + quality | CODE_VERIFIED | `codex/task-12-connectors` ×2 | app `7378260d` + engine `86ee99eb` | 567 app + 33 engine (2289 total) | [#744](https://github.com/ecryptoguru/lyrashield-ai/pull/744) + [#152](https://github.com/ecryptoguru/lyrashield-engine/pull/152) | connectors bridge ready; no auto-invocation until plan field exists |
| 13 release proof | PARTIAL — integration verified, release gates blocked | `codex/task-13-release` + `codex/integration-release-candidate` | `80a383e8`+`fa616c96`+relay fix; engine `89d8458a` | engine 2482 pass/4 skip; app 264 cross-suite pass | — | merge order validated; 2 merge bugs fixed (attachments_dir outside ownership scope + stranded-bundle transfer; dropped `}` in relay-grant); PR merges, pin bump, deploys, paid scans need founder auth |

## CI remediation — 2026-09-20

- `Build and smoke-test sandbox image` failed on ALL engine PRs (and would fail on main): Kali rotated the `kali-last-snapshot` InRelease on 2026-09-18, invalidating `KALI_APT_INRELEASE_SHA256=6e298f…`. Verified the new InRelease's PGP signature (Kali Archive Automatic Signing Key 2025, `827C8569…C8D5E4C5`, keyring fetched via HTTPS from archive.kali.org) and bumped the pin to `1aa2f15a…` on every task branch. **This pin will rot on every Kali snapshot rotation — consider a dated `snapshot.kali.org` suite or a scheduled digest-refresh job.**
- `Audit locked Python dependencies` failed on every engine branch predating #144 — cherry-picked `ba1b0d1f` onto all six.
- Branding gate failures: #147's refactor re-indented two allowlisted `STRIX_*` compatibility lines (allowlist match is exact-line) → allowlist realigned; #145 rewrapped a doc paragraph, splitting an allowlisted line → reflowed to keep the allowlisted line verbatim.
- App `Lint, Typecheck, Test & Build` failures: #736 real TS error (`selectedDepth` possibly undefined) fixed with render guard; #738/#739/#740 were unformatted touched files → `prettier --write` + targeted vitest re-verified.
- Recovered uncommitted agent leftovers: task-06 engine had a real fail-closed fix (`diff_head` pinned + zero repo scopes no longer degrades to full scan) → committed as `6ce548f3`; task-03's leftover was pure debris (duplicate test, `sync-marker` comment) → discarded after verifying HEAD identical.
- Prior-session agents for Task 9 (engine `cf7f1552`, app `edab5112`) and Task 10 died mid-work — uncommitted drafts retained in their worktrees, no commits pushed.

## CI remediation — round 2 (2026-09-20)

- Engine #151: branch predated the round-1 fixes — cherry-picked the AnyIO audit patch (`45f8edeb`) and Kali InRelease refresh (`e21354f2`) onto `codex/task-09-attachments` → `74329bfe`.
- Engine #152: `ruff format --check` flagged `lyrashield/artifacts/quality.py` + `lyrashield/runtime/capabilities.py` → formatted, `2de9d054`.
- App #741/#742/#743/#744 `Lint, Typecheck, Test & Build`: unformatted touched files (branches sat on pre-prettier bases) → `prettier --write` on each (39/33/58/62 files).
- App eslint `--max-warnings 0`: new fixture-driven parity tests read `scan-workflows.json` via non-literal paths → file-level `security/detect-non-literal-fs-filename` disable (repo convention) on `packages/sdk`, `packages/types`, `packages/cli` parity tests across #742/#743/#744.
- App #744 diff-gate: Slack OAuth test fixtures (`"xox-secret"`, `"xoxb-abc"`) matched the `(token)=[\"']…{8,}` secret shape → shortened below the 8-char threshold (`def223bb`).
- App #741 real test failures (3): (a) `scan-detail-client.tsx` JSX text contained banned "the run" phrasing across a line break → copy rewritten without the noun; (b) task-9 reordered `SCAN_PRESET_ORDER` breaking onboarding's canonical option order → order restored (Standard default still enforced via `isDefault`), agent-pinned expectations updated; (c) findings route test mock lacked `prisma.evidence.findFirst`/`readEncryptedArtifact` → mock extended (`e581c0de`).
- `e2e/browser/polling-harness.tsx` fixture missing now-required `executionPlan` key → `executionPlan: null` added on #741/#743/#744 and task-13.
- Fixes propagated: merges `eae48eb6` (task-11), `27f87483` (task-12), `c952330f` (task-13); engine integration `51a181d7`.

## CI remediation — round 3 (2026-09-20)

- #741 `e2e/browser/desktop.spec.ts`-adjacent fixes verified locally (57 focused tests); residual unformatted edit → prettier, `52420180`. One `Setup pnpm` infra flake rerun → green.
- #742 `desktop.spec.ts` "listener registration finishes before replay" was timing-racy: asserted `get_scan_events` absent from call log (depended on mock delay vs poll). Replaced with an ordering invariant — each invoke records `resolvedListeners`; test now polls for the replay call then asserts `resolvedListeners >= 1` (`44c25485`, `b6bdfc46`).
- All fixes merged into task-11/task-12/task-13 (`0e78aa7b`, `6767f64b`, `fe2afc2f`, `de6993e9`, `f215e644`, `89cded96`).
- Integrated app branch re-verified post-merge: 374 tests across the 10 cross-cutting suites pass.

**Final CI state 2026-09-20**: all 18 PRs green — engine #144–152 (audit + image build + verify), app #736–744 (lint/typecheck/test/build, diff-gate, SCA, pinned-engine contract, Desktop cargo/Vite, GitHub Action). No PR is merged; all remain review candidates.

## Live/production gates — NOT authorized by this session

Production dispatch, paid scans, feature admission, real credentials, migrations against live DBs, and any destructive operation remain blocked pending founder authorization. Agents must stop at code/test/PR level.
