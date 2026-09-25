# Engine Integrity and Local UX Implementation Plan

This plan records the reviewed implementation sequence and the remaining release gates. Its checkboxes describe acceptance criteria; the execution record below distinguishes completed code work from evidence still needed.

**Goal:** Fix every confirmed issue in the [2026-09-25 review](2026-09-25-deep-code-review.md), improve Local TUI and viewer integrity, and establish honest production gates.

**Architecture:** Keep product changes under `lyrashield/**`; reuse the CLI, canonical `run.json` and `vulnerabilities.json`, existing SQLite store, and stdlib process primitives. The owned viewer stays under `lyrashield/interface/viewer/**`. Preserve the upstream patch digest and worker contract. Ship independent, reviewable changes with a focused regression and full gate before release.

**Tech Stack:** Python 3.12+, `uv`, pytest, Textual, SQLite, Pydantic settings, React 19, TypeScript, Vite, GitHub Actions.

## Global constraints

- Use only GPT-6 Sol/Luna routes already admitted by product policy. Keep telemetry off, budget reservations fail-closed, sandbox egress scoped, and incomplete scans inconclusive.
- Do not edit `strix/**` unless the controlled-derivative allowlist and digest are deliberately reviewed and updated.
- Never put real tokens in tests, logs or artifacts. Test with synthetic credentials and local subprocesses.
- An artifact contract change must pass `scripts/verify-worker-contract.sh` against the pinned app consumer. Keep `.lyrashield-worker-pin` and the app's `ENGINE_REVISION` mutually reconciled.
- Run `bash scripts/verify-controlled-derivative.sh`, `git diff --check`, Python package build, owned viewer typecheck/build, and exact-head CI before release.
- A green code gate is not provider, deployment, quality, payment or signed-release proof.

## Ownership map

| Area | Source | Regression surface |
|---|---|---|
| OAuth file safety | `lyrashield/policy/codex.py` | `tests/test_codex_auth.py` |
| Encrypted local store and migration | `lyrashield/tui/results_store.py` | `tests/tui/test_results_store.py` |
| Provider setup and routing | `lyrashield/tui/byok_config.py`, `lyrashield/tui/app.py`, `lyrashield/tui/scan_flow.py` | `tests/tui/test_byok_config.py`, `tests/tui/test_scan_flow.py`, new `tests/tui/test_app.py` |
| CLI process, artifact import and exports | `lyrashield/tui/scan_flow.py` | `tests/tui/test_scan_flow.py` |
| Viewer API and state | `lyrashield/interface/viewer/transcript.py`, `lyrashield/interface/viewer/frontend/src/data/serverSource.ts`, `.../src/App.tsx` | `tests/test_viewer.py`, new frontend tests |
| Build and docs | `Makefile`, `.github/workflows/ci.yml`, frontend `package.json`, `CONTRIBUTING.md`, `docs/contributing.mdx`, `lyrashield/README.md` | local build and CI |

---

### Task 1: Protect OAuth token writes (R13)

**Files:** Modify `lyrashield/policy/codex.py`; test `tests/test_codex_auth.py`.

- [ ] Add a synthetic-file test: under umask `022`, a saved auth record remains readable by the app, the temporary and final file modes are owner-only, and a symlink planted at the old predictable `.json.tmp` path cannot alter its target.
- [ ] Confirm the existing implementation fails that regression.
- [ ] Replace `Path.write_text()` plus late chmod with a unique same-directory `tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=AUTH_PATH.parent, delete=False)`, `flush` and `os.fsync`, then `Path.replace()`. Use `try/finally` to unlink a leftover temporary file. Check final mode before success; never log content.
- [ ] Run `uv run pytest -q tests/test_codex_auth.py` and commit this security change alone.

### Task 2: Fail closed when the local encryption key is unavailable (R1)

**Files:** Modify `lyrashield/tui/results_store.py`, `lyrashield/tui/byok_config.py`; test `tests/tui/test_results_store.py` and `tests/tui/test_byok_config.py`.

- [ ] Write tests for these exact observable cases: keychain read error; key absent and write failure; existing ciphertext with missing key; valid legacy ciphertext. Assert writes fail before DB commit and reads raise a dedicated store/key error, not `{}`.
- [ ] Split keychain get into an operation that distinguishes backend failure from an absent item. Cache the verified DEK per store instance or pass it explicitly through encryption helpers; never create a key during decryption. Confirm a newly generated key can be read back before use.
- [ ] Make `save_config()` inspect every keyring write result and raise on failure. Change the TUI success notice to require successful persistence.
- [ ] Run focused tests, `uv run mypy strix lyrashield_adapter lyrashield`, and commit.

### Task 3: Migrate finding identity safely (R10)

**Files:** Modify `lyrashield/tui/results_store.py`; test `tests/tui/test_results_store.py`.

- [ ] Build a legacy-schema DB fixture with two runs and a valid Fernet ciphertext. Assert it can be upgraded without losing encrypted payloads. Save `vuln-0001` for both runs and assert both remain visible; saving it again for one run must update only that run.
- [ ] In one transaction create `findings_new` with `PRIMARY KEY (run_id, finding_id)`, copy old rows without decrypt/re-encrypt, drop the old table, rename, recreate `idx_findings_run`, set `PRAGMA user_version`, and commit. Preserve rollback on failures and idempotence on reopen.
- [ ] Add `PRAGMA foreign_keys=ON` only after checking existing behaviors and migration order; otherwise leave deletion as explicit existing code. Do not introduce an untested cascade.
- [ ] Run focused tests and commit before enabling automatic import.

### Task 4: Bind selected provider to the subprocess (R2)

**Files:** Modify `lyrashield/tui/scan_flow.py`, if needed `lyrashield/tui/byok_config.py`; test `tests/tui/test_scan_flow.py`.

- [ ] Test Azure selection with inherited `STRIX_LLM`, `LLM_API_KEY`, `LLM_API_BASE`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and delegate/dedupe vars. After adapter preparation, `LlmSettings` must resolve the selected model, endpoint and key. Test ChatGPT selection with inherited metered Azure variables; no unrelated runtime variable should be removed.
- [ ] Define one canonical connection-variable set in `build_env()`. Remove conflicting inherited routing/connection aliases, then set provider-selected `STRIX_LLM` or `LYRASHIELD_LLM`, `LLM_API_KEY`, `LLM_API_BASE`, and version as one unit. Handle delegate/dedupe routes explicitly rather than preserving stale alternate-provider credentials.
- [ ] Run focused tests and `uv run lyrashield --help`; commit.

### Task 5: Own the scan child and prevent duplicate starts (R5)

**Files:** Modify `lyrashield/tui/scan_flow.py`, `lyrashield/tui/app.py`; test `tests/tui/test_scan_flow.py`, new `tests/tui/test_app.py`.

- [ ] Add a real local child test that prints a ready marker and sleeps. Cancel `run_scan()`: child must be interrupted, reaped and absent. Test callback error cleanup. In Textual `run_test()`, two Run actions must create only one child.
- [ ] Wrap reader tasks and `proc.wait()` in `try/finally`. On cancellation or callback failure, send a graceful interrupt to the owned child, wait a bounded interval, then terminate/kill and reap if needed. Cancel/await reader tasks without masking the original exception. Preserve receipt if graceful exit succeeds.
- [ ] Keep one active scan task in the app; disable Run while active, add Cancel and lifecycle shutdown handling, then restore controls on completion/failure.
- [ ] Run focused tests and commit. Do not claim sandbox cleanup for a forced child kill.

### Task 6: Bind run ID, receipt and canonical findings (R3, R6)

**Files:** Modify `lyrashield/tui/scan_flow.py`, `lyrashield/tui/app.py`; test `tests/tui/test_scan_flow.py`, `tests/tui/test_app.py`.

- [ ] Write a fake local CLI executable that emits `run.json`, `vulnerabilities.json`, SARIF and a Markdown report into its supplied `--run-name`. Run through the TUI `run_scan()` path: one finding must appear in the store and both exports; run ID and artifacts must match. Also test valid zero findings, absent/corrupt files, completed exit `2`, partial exit `2`, and no-change exit `0`.
- [ ] Generate the run ID before argv, pass `--run-name`, capture a stable launch cwd, and resolve `run_dir_for(run_id, cwd=launch_cwd)`. Load and validate canonical artifacts using existing sanitizer/contract rules. Import findings into the migrated store transactionally. Prefer copying the engine's canonical SARIF/report artifacts to rendering reduced substitutes; report why export is unavailable when absent.
- [ ] Derive Local status from the persisted receipt (`status`, `terminal_reason`, `receipt_persisted`) plus exit code. Keep partial and missing receipt states visible and inconclusive.
- [ ] Run focused tests, full Python gate, and commit. If any worker-facing schema changes, run pinned consumer contract before merge.

### Task 7: Deliver real-time progress without unbounded logs (R7)

**Files:** Modify `lyrashield/tui/scan_flow.py`; test `tests/tui/test_scan_flow.py`.

- [ ] Run a fake CLI that prints `ready`, sleeps 0.5 seconds and prints `done`. Assert the first callback arrives while child is alive and receives a smaller elapsed time than the final callback. Emit a large line and assert retained diagnostic text is bounded.
- [ ] Emit events from the two existing concurrent readers. Preserve concurrent pipe drainage; cap retained byte/line tails for persisted diagnostics. Keep callback failures routed through Task 5 cleanup.
- [ ] Run focused tests and commit.

### Task 8: Complete the Local setup and validation flow (R8, R9)

**Files:** Modify `lyrashield/tui/app.py`, `lyrashield/tui/byok_config.py`; test `tests/tui/test_app.py`, `tests/tui/test_byok_config.py`.

- [ ] In headless Textual tests, fresh Save must not claim ready when credentials are missing; authenticated ChatGPT or valid Azure input must reach configured state. For budget `abc`, `0`, `-1`, `nan` and `inf`, assert an inline error, preserved form state and zero subprocess starts.
- [ ] Reuse `validate_chatgpt_credential()` and the existing engine auth CLI; expose a concise login instruction/button. Add Azure endpoint, deployment and password-masked key inputs, with a keychain save result. Run blocking Doctor/auth operations in a worker/thread.
- [ ] Apply the CLI's positive finite budget rule locally; focus the invalid input. Gate Run on a configured provider and show the reason.
- [ ] Run focused tests and a 80×24 plus 120×45 Textual UI smoke; commit.

### Task 9: Gate the owned viewer source (R11)

**Files:** Modify `Makefile`, `.github/workflows/ci.yml`, `lyrashield/interface/viewer/frontend/package.json`; rebuild only `lyrashield/interface/viewer/static/**` if source changes later.

- [ ] Change `make viewer` to the owned frontend path. Add `typecheck: tsc --noEmit` to package scripts. CI must run `npm ci`, `npm run typecheck`, `npm run build`, then `git diff --exit-code -- lyrashield/interface/viewer/static` and reject untracked generated files. Keep `strix/**` untouched.
- [ ] Run the same commands in a temporary copy first, then on the branch; inspect static diff. The build from current source should be byte-stable.
- [ ] Run Python gate and commit this independently testable DX improvement.

### Task 10: Make viewer data errors visible and retriable (R4)

**Files:** Modify `lyrashield/interface/viewer/transcript.py`, frontend `src/data/serverSource.ts`, `src/App.tsx`; add a minimal frontend behavior test harness using the existing frontend dependency stack and Python viewer tests.

- [ ] Reproduce the review's fixture: a completed run contains one finding but `/api/vulnerabilities` fails. Assert the UI does not say “No findings”; it shows an alert and Retry. Then restore the endpoint and assert the finding appears. Test transient final-settlement failure and prior-good-data retention during live polling.
- [ ] Define a typed load state for critical findings data; let critical fetch errors propagate, preserve the last good array, and retry final fetch before setting `finishedRef`. On the server, only missing startup artifact may be an empty projection; corrupt terminal artifact must signal failure.
- [ ] Run frontend typecheck/build/tests, Python viewer tests and actual browser checks at desktop/mobile widths; rebuild tracked owned static assets and commit.

### Task 11: Align contributor docs (R12)

**Files:** Modify `docs/contributing.mdx`, `CONTRIBUTING.md`, `lyrashield/README.md`, `lyrashield/tui/byok_config.py` comments if needed.

- [ ] Replace stale upstream base, footprint and gate claims with current executable values from `.lyrashield-upstream-base`, `scripts/verify-controlled-derivative.sh`, `pyproject.toml` and `.github/workflows/ci.yml`.
- [ ] Describe OAuth JSON-store permissions and local results keychain accurately; document TUI setup/partial result behavior after Tasks 2–10 land.
- [ ] Run `rg` for obsolete `v1.5.3`, `+151/-57`, “exactly pinned” and inaccurate keychain text; commit the docs correction.

### Task 12: Measure and address transcript growth (O1)

**Files:** Only if the baseline warrants change: `lyrashield/interface/tui/history.py`, `lyrashield/interface/viewer/transcript.py`, viewer `src/data/serverSource.ts`, `src/App.tsx`; tests `tests/test_viewer.py` and frontend.

- [ ] Benchmark 1k and 10k-message runs on the same host, five reads each, capturing median server time, JSON bytes, and browser interaction time. Record both cold and warm results in the PR.
- [ ] First try visibility-aware polling and conditional responses on an authenticated, run-scoped revision. Do not use only the SQLite main-file mtime; WAL commits must invalidate it. Keep a bounded latest-events projection and full history available on demand if needed.
- [ ] Repeat the exact benchmark; keep the change only if response bytes/time improve outside noise and all transcript/security tests pass. Otherwise record the failed experiment and revert.

### Task 13: Measure viewer code loading (O2)

**Files:** Only if measured: viewer `src/App.tsx`, `src/components/live/AgentGraph.tsx` and test/build files.

- [ ] Capture initial gzip bytes, network waterfall and time to usable overview on desktop/mobile. The baseline bundle is 286.97 kB gzip.
- [ ] Test one lazy route/surface split around the Agents graph with an accessible Suspense loading state and error recovery. No new dependency.
- [ ] Rebuild and compare initial bytes and user-visible times on the same device/conditions. Keep only a measured, regression-free improvement.

### Task 14: Final integration and readiness evidence

- [ ] Run `bash scripts/verify-controlled-derivative.sh`, `git diff --check`, `uv build`, CLI help/version smoke, frontend `npm ci && npm run typecheck && npm run build`, and static consistency.
- [ ] Run pinned worker-consumer tests from `scripts/verify-worker-contract.sh` using an exact clean checkout and the reviewed `.lyrashield-worker-pin`; inspect both pins before any release.
- [ ] Build and smoke the sandbox image with Docker, including network admission and relay probes. Build native binary only when the platform/toolchain is available.
- [ ] Recheck branch HEAD, CI run SHA, review state, package artifact hashes and complete tests after the last code change.
- [ ] For production-readiness claims, verify promoted worker digest/revision, actual VM/container traffic and health, `/api/ready/scans`, provider entitlement with authorized live requests, and versioned evaluation corpus. Record unavailable gates as unproven; never infer them from local or CI success.

## Self-review mapping

R1=2; R2=4; R3=6; R4=10; R5=5; R6=6; R7=7; R8=8; R9=8; R10=3; R11=9; R12=11; R13=1. O1=12; O2=13. The harmless duplicate assignment in `lyrashield/artifacts/state.py:1655-1662` can be deleted in a focused artifact touch; no standalone refactor is needed.

## Execution record (2026-09-25)

| Work | State | Evidence / remaining condition |
|---|---|---|
| R1–R3, R5–R10, R12–R13 | Implemented locally | Focused TUI/OAuth/viewer tests, real child cancellation, headless TUI and browser failure probe. Full controlled-derivative gate passed before the final local-store hardening; rerun on final tree. |
| R4 and R11 | Implemented locally | Owned viewer typecheck/build and responsive browser failure state passed. Static asset consistency must pass on committed tree and exact-head CI. |
| O1 transcript polling | Partially optimized | Hidden tabs poll every 5 seconds and failed critical fetches back off to 5 seconds. Full transcript still scales linearly with history; do not claim 10k-message payload reduction without a measured incremental protocol. |
| O2 initial viewer bundle | Measured improvement | Lazy agent graph reduced initial JavaScript from 286.97 to about 209.3 kB gzip (about 27%). Graph loads with an accessible status message. |
| Worker consumer contract | Passed locally | Exact pinned consumer `c372685bde37a566ac75a7ac204239b4547930ad`, 398 tests passed. The app's deployment `ENGINE_REVISION` points at a different released engine revision and must be deliberately reconciled for any new promotion. |
| Package, CI, Docker, deployment and provider proof | In progress / separate gates | Wheel and sdist build and CLI smoke passed. Exact-head CI, sandbox image, live provider entitlement, deployed digest/traffic, and quality evaluation remain independent evidence requirements. |
