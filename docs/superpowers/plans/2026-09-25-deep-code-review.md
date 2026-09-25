# LyraShield Engine deep code review

Reviewed 2026-09-25 against `55eb4a30cd5202cd4c29db46db60d9a2b415f935`, matching freshly fetched `origin/main`. The working tree was clean. Both remotes were fetched. Review branch: `codex/deep-review-plan-2026-09-25`.

## Verdict

The established engine gates pass, but they do not establish a seamless Local TUI or viewer experience. This review found **13 actionable issues: five P1, seven P2, and one P3**, plus two measured optimization candidates and one optional cleanup. Prioritize credential/data integrity and honest results before performance changes.

This is a targeted deep review of important flows, not a claim that every line or every possible defect was examined. No application code was changed, scans against external targets were not launched, and no production deployment or provider configuration was changed.

Implementation sequence, regression examples, acceptance criteria, and release gates are in [the remediation plan](2026-09-25-engine-improvements-plan.md).

## Review coverage

| Area | Work performed | Limits |
|---|---|---|
| Adapter and model policy | Traced environment aliases, provider selection, resolved settings, subscription configuration | No live model call or provider entitlement test |
| Agent lifecycle and budget | Inspected runner setup/fallback/finalization, concurrent reservations and usage hooks; ran lifecycle, deadline, budget and accounting tests | No paid evaluation or scan-quality comparison |
| Sandbox and source staging | Inspected session ownership, startup cleanup, capability admission and staging paths; ran existing tests | No fresh full sandbox image build; see Docker note below |
| Artifacts and evidence | Inspected required receipt writes, revision dedupe, reporting projections and worker exit mapping; ran artifact/contract tests | Pinned application-consumer suite not rerun locally |
| Local TUI | Traced setup, subprocess, progress, persistence, findings and export; ran synthetic process probes and Textual headless interaction | No real credentials or target scans |
| Results viewer | Inspected data fetch, terminal polling, server reads/auth and transcript projection; reproduced a failure in the actual bundled browser UI | Responsive/mobile and complete accessibility audit remain execution gates |
| DX and delivery | Inspected Makefile, Python/frontend config, CI, controlled-derivative rules and contributor docs; built Python packages and isolated frontend | No native binary/signing build locally |

## Findings

### R1 — P1: Reject encrypted writes when the key cannot be safely retained

**Location:** `lyrashield/tui/results_store.py:68-75,93-112,258-273`; `lyrashield/tui/byok_config.py:177-199`.

`keyring_get()` returns `None` for both a missing key and a backend failure. `_get_or_create_dek()` generates a new key and ignores `keyring_set()` returning `False`. Each subsequent encrypt/decrypt can therefore use another key. Reads swallow the decryption failure and return an empty payload. A transient read error followed by a successful write can also replace an existing DEK, making older records unreadable.

**Reproduced:** mocked keychain read unavailable/write failed, then saved and immediately loaded a synthetic run: save succeeded; payload read back as `{}`. No real keychain was touched.

**Fix:** distinguish absent, unavailable and invalid keys; require confirmed key persistence before committing ciphertext; never generate a key while reading existing ciphertext; surface an unavailable/corrupt state instead of an empty result. Apply the same fail-closed persistence result to BYOK save notifications. Preserve existing Fernet ciphertext compatibility.

### R2 — P1: Bind the chosen BYOK provider to its actual endpoint and credentials

**Location:** `lyrashield/tui/scan_flow.py:86-90`; `lyrashield/tui/byok_config.py:76-87`; `lyrashield/policy/settings.py:17-20,95-123`; `lyrashield_adapter/cli.py:101-120`.

`build_env()` copies the entire parent environment and overlays only provider-specific variables. Existing generic variables have higher alias priority. Existing `STRIX_LLM` also outranks the selected `LYRASHIELD_LLM`. The UI can consequently name one provider while the subprocess uses another model, endpoint or key.

**Reproduced:** selecting synthetic Azure configuration resolved `azure/gpt-6-luna` with `https://stale.example` and the inherited key. This tested actual adapter preparation and `LlmSettings`, without a network call.

**Fix:** normalize the TUI-selected connection as a coherent set; clear conflicting model/connection aliases and set the canonical engine variables explicitly. Preserve unrelated runtime/network settings. Handle delegate and dedupe overrides deliberately; do not silently send credentials to inherited endpoints. Test combinations of generic, upstream and product aliases.

### R3 — P1: Connect local scans to their actual artifacts before enabling export

**Location:** `lyrashield/tui/scan_flow.py:120-122,163-172,214-226,229-295`.

The generated local ID is allocated after argv is built and is not passed to the engine unless the caller supplied a run name. `ScanResult.run_dir` is never populated. `_parse_sarif_findings()` always returns `[]`. The standard Local TUI flow therefore cannot ingest findings, and its exports serialize an empty store even when the engine produced findings.

**Reproduced:** returned local ID had no bound run directory; the ingestion function returned no findings with synthetic findings supplied. Export tests pass because they seed the store manually rather than exercising scan-to-export.

**Fix:** allocate one run ID before argv, pass `--run-name`, resolve the existing `run_dir_for()` path from a fixed launch cwd, validate the terminal receipt, and import the canonical findings JSON. Reuse/copy canonical SARIF and Markdown where available. Distinguish missing/unreadable artifacts from a valid empty array, and block misleading exports. Complete R10 before ingesting repeated engine finding IDs.

### R4 — P1: Never present a failed findings read as a clean result

**Location:** `lyrashield/interface/viewer/frontend/src/data/serverSource.ts:97-104`; `lyrashield/interface/viewer/frontend/src/App.tsx:107-125,275-280,500`; `lyrashield/interface/viewer/transcript.py:85-106`.

Both initial/final fetch and live polling replace findings request failures with an empty array. The backend also normalizes unreadable findings JSON into an empty list. A finished run then stops polling, so the false empty result can persist for the session. Live failures erase previously loaded findings; top-level error rendering is hidden after a run has loaded.

**Browser reproduction:** a synthetic completed run contained a high-severity finding; its findings endpoint was made to raise an I/O error. The shipped viewer rendered `Complete` and `No findings in this run.` with no visible error.

**Fix:** track loading/loaded/stale/error separately from the findings array; preserve last-known good data; expose an accessible error and retry; only declare a valid empty result after successfully reading a valid artifact. Set final-settlement state after successful data loading, and retry transient final-load failures. Treat an absent artifact during initial startup separately from corrupt/missing terminal evidence.

### R5 — P1: Give Local TUI scans explicit process ownership

**Location:** `lyrashield/tui/scan_flow.py:125-150`; `lyrashield/tui/app.py:204-214`; no matching task shutdown/cancellation handler exists.

`run_scan()` does not terminate or reap its child when canceled or when pipe/callback processing fails. The app also allows repeated Run actions and overwrites `_scan_task`, leaving earlier tasks active. This can continue consuming provider budget after the UI loses ownership.

**Reproduced:** canceling a synthetic scan task left the real child process alive; the probe terminated/reaped that child afterward. Two Run actions in a Textual headless test started two concurrent tasks.

**Fix:** allow one active scan per app instance, provide Cancel, stop owned children on quit, and place pipe tasks/process cleanup in `finally`. Give the CLI a bounded graceful interruption interval to persist partial receipts and clean its sandbox, then escalate only for the owned process if necessary. Forced termination must never be labeled confirmed sandbox cleanup.

### R6 — P2: Derive scan status from the receipt rather than `returncode == 0`

**Location:** `lyrashield/tui/scan_flow.py:192`; `lyrashield/tui/app.py:231-233`; authoritative producer `lyrashield/interface/main.py:1689-1709`.

Exit `2` can mean completed with findings, or a partial scan with findings. The TUI stores all nonzero exits as failed and colors all returned outcomes green. A zero exit can also be a no-change result rather than a new completed scan.

**Reproduced:** persisting a synthetic exit-2 result stored status `failed`. The producer's completed-with-findings path returns `2`.

**Fix:** preserve `run.json` status and terminal reason, use exit code as corroboration/fallback, and distinguish completed, partial, budget stopped, rate limited, interrupted, no-change and failed. Never translate all exit-2 outcomes into completed.

### R7 — P2: Stream progress while the process runs and bound output retention

**Location:** `lyrashield/tui/scan_flow.py:93-104,139-160`.

The pipes are drained concurrently, but callbacks run only after both pipes reach EOF. Every event gets the final elapsed time, and stdout events are replayed before stderr regardless of observed arrival order. Both full text and a full line list are retained per stream.

**Reproduced:** a child flushed `ready` and stayed alive; after 300 ms, zero progress callbacks had fired. Callbacks appeared only after exit.

**Fix:** emit callbacks from the concurrent readers, timestamp receipt time, keep bounded diagnostic tails, and tolerate oversized/unbroken output without abandoning the process. A simple line/chunk reader is sufficient; no event broker is required.

### R8 — P2: Make BYOK setup complete or clearly guide the missing steps

**Location:** `lyrashield/tui/app.py:116-126,169-180`; `lyrashield/tui/byok_config.py:96-106,145-162,243-258`.

The setup form only selects a provider. It has no Azure endpoint/deployment/key fields and does not enable or guide ChatGPT authentication. Clicking Save on fresh configuration reports success while `chatgpt.enabled` stays false and `to_env()` returns `{}`. Pre-existing shell configuration can mask this gap.

**Reproduced:** fresh app, Save BYOK setup: `configured_after_save=false`, environment `{}`, success notice shown.

**Fix:** reuse the existing auth-status/login path for ChatGPT, add the missing Azure inputs with a password field and local validation, and gate Run on configuration readiness. Credential checks and Doctor must run off the UI event loop. Distinguish saved configuration from successfully authenticated/verified configuration.

### R9 — P2: Validate budget input without throwing from the event handler

**Location:** `lyrashield/tui/app.py:209-214`; existing CLI policy `lyrashield/interface/main.py:590-599`.

The optional text field is converted with an unguarded `float()`. Invalid text raises before `_scan_async()`'s error handler exists. Negative, zero, NaN and infinity also reach later layers instead of receiving useful inline validation.

**Reproduced:** headless UI with budget `abc` raised `ValueError` from `_run_scan()`.

**Fix:** accept blank or finite positive values, keep the form usable, focus the invalid field, and show actionable copy without starting a subprocess. Keep the CLI's independent boundary validation.

### R10 — P2: Scope stored finding identity to its run

**Location:** `lyrashield/tui/results_store.py:132-139,206-221`; engine allocator `lyrashield/artifacts/state.py:759`.

The local DB uses `finding_id` alone as its primary key and upserts with `INSERT OR REPLACE`. Engine IDs such as `vuln-0001` restart for every run. Saving that ID for a second run removes the first run's finding.

**Reproduced:** two runs each saved `vuln-0001`; first run then had zero findings, second had one. This is currently latent in the normal TUI scan path because R3 prevents ingestion; it must be fixed before enabling ingestion.

**Fix:** use `(run_id, finding_id)` as the database identity with a transactional, versioned migration. Preserve existing payload ciphertext and ensure re-import updates only the same run. Test rollback on migration failure with a real legacy-schema database.

### R11 — P2: Build and gate the owned viewer source

**Location:** `Makefile:80-83`; `lyrashield/interface/viewer/frontend/package.json:6-10`; `.github/workflows/ci.yml`.

`make viewer` builds `strix/interface/viewer/frontend`, although the product serves `lyrashield/interface/viewer/static`. This leaves product UI changes unbuilt and can modify the tightly controlled upstream substrate. CI installs Node but does not type-check/build the owned viewer or verify source/static consistency. The package build command is only `vite build`; Vite's transpilation does not replace a TypeScript check. [Vite documentation](https://vite.dev/guide/features.html#typescript).

**Verified:** an isolated install, `tsc --noEmit`, and owned viewer build passed. Generated filenames matched committed assets. The issue is the documented command and missing regression gate, not a current TypeScript error or observed stale bundle.

**Fix:** point Makefile at the owned source; add a typecheck script; run locked frontend install, typecheck and build in CI; fail on changes or unexpected additions to owned static assets; assert no substrate modifications. Introduce the focused frontend error-path tests required by R4.

### R12 — P3: Make contributor and credential documentation match executable behavior

**Location:** `docs/contributing.mdx:15`; `CONTRIBUTING.md` dependency guidance; `lyrashield/README.md` policy description; `lyrashield/tui/byok_config.py:7-10` and `lyrashield/tui/app.py:16-17` credential comments.

The MDX contributor guide still names Strix v1.5.3, obsolete patch bounds, and claims the local script runs package, native-binary, sandbox and consumer-contract gates. Current source uses v1.6.2 and separates those gates. LiteLLM is described as exactly pinned while `pyproject.toml` uses `~=1.90` (the lock still pins the installed version). Subscription-policy and keychain claims also conflict with current code: OAuth is stored in a permission-restricted JSON file, not the local TUI keychain.

**Fix:** synchronize documentation with the root contributor guide, lock/config and auth implementation. Correct scope and gate claims rather than silently broadening functionality or changing auth storage architecture.

### R13 — P2: Create OAuth credential temporary files with restrictive permissions

**Location:** `lyrashield/policy/codex.py:79-87`.

`_write_store()` writes credentials to a predictable `.json.tmp` path before applying mode `0600`, and suppresses chmod errors. Under umask `022`, the temporary file starts as `0644`. Where parent directories are searchable by another local account, tokens are readable during the write window. A crash before chmod can leave that temporary file behind. This is a conditional local exposure, not proof that credentials were accessed.

**Reproduced:** synthetic credentials in an isolated directory, with permissions observed immediately before chmod: `0644` for the temporary file, then `0600` for the replaced final file. No real auth store was read or changed.

**Fix:** use a securely created, unique same-directory temporary file, write and close it, then atomically replace the auth record; clean it on failure. Permission restrictions must hold before the first credential byte is written. Python's `mkstemp` creates owner-only files and avoids the predictable-name creation race. [Python documentation](https://docs.python.org/3/library/tempfile.html#tempfile.mkstemp).

## Measured optimization candidates

### O1 — Repeated full transcript rebuild and transfer

`App.tsx` schedules another poll after 500 ms. Every `/api/transcript` request creates a new `TuiLiveView`; `load_session_history()` fetches all SQLite messages, then parses/projects/serializes the full history.

Synthetic local benchmark, one agent, 500-character message bodies, median of five reads including JSON serialization:

| History | JSON response | Median projection + serialization |
|---|---:|---:|
| 1,000 messages | 707,089 bytes | 7.09 ms |
| 10,000 messages | 7,079,090 bytes | 68.99 ms |

These are local synthetic costs, not production latency or browser rendering measurements. Payload growth is proven. Polls do not overlap within one effect, so do not claim an unbounded concurrent-request loop.

Start with server-side conditional responses keyed to committed history changes, client last-good retention, and visibility-aware polling. Preserve WAL freshness and per-run authorization. Add incremental cursors only if measured growing-history work still warrants them. Do not cache solely on the main SQLite file mtime: WAL writes may not alter it.

### O2 — Large eagerly loaded viewer bundle

The isolated production build produced **922.59 kB JavaScript / 286.97 kB gzip**, and 68.28 kB CSS / 12.74 kB gzip. Vite emitted the large-chunk warning. `App.tsx` eagerly imports the graph and detail surfaces; graph code imports React Flow and Dagre.

Measure initial interactive time and tab-open latency before changing boundaries. A small `React.lazy`/`Suspense` split around the Agents surface is the first experiment. Keep accessible loading/error handling, and retain only a measured improvement. The bundle size alone does not prove a poor real-user experience.

### C1 — Optional cleanup

`lyrashield/artifacts/state.py:1655-1662` repeats the identical persisted-report-revision assignment block twice. Remove the second block when touching that area; existing artifact revision tests should remain unchanged. No behavior defect or measurable speed benefit is claimed.

## Verification evidence

| Gate | Result |
|---|---|
| Fresh Git refs | HEAD and origin/main both `55eb4a30cd5202cd4c29db46db60d9a2b415f935` |
| Initial full pytest | 2,595 passed, 5 skipped, 67.75 s |
| Authoritative controlled-derivative script | Passed; 16 substrate files, +149/-258; expected digest accepted |
| Script's full pytest with Pydantic warning-as-error | 2,595 passed, 5 skipped, 63.74 s |
| Ruff | Lint passed; 383 files already formatted |
| mypy | Passed across 194 source files; configured TUI/viewer exclusions still apply |
| Bandit | Exit 0; existing nosec/comment warnings, no failing findings |
| Python packaging | sdist and wheel built successfully into `/tmp/lyrashield-engine-review-dist` |
| CLI | `lyrashield 1.2.1`; help smoke passed |
| Owned viewer | Locked install in a temporary copy; `tsc --noEmit` and Vite build passed; install audit reported zero vulnerabilities |
| Targeted fault probes | Keychain loss, environment override, findings stub, exit mapping, absent progress, surviving canceled child, duplicate starts, invalid budget, setup gap, cross-run ID collision and token temp permissions reproduced |
| Browser | Shipped bundle displayed false empty findings for an injected HTTP failure |
| Existing GitHub CI | [Engine CI run 36134956047](https://github.com/ecryptoguru/lyrashield-engine/actions/runs/36134956047), success on the exact reviewed SHA |

The authoritative run skipped three Linux-specific subprocess security tests, the no-viewer-extra variant, and the real Docker network admission test. A later targeted rerun passed 18 tests with four skips, including a successful real Docker admission test when the daemon became available. This does not constitute a fresh build/smoke of the full engine sandbox image.

Not performed here: live GPT-6 provider requests, fresh Python advisory audit, pinned app consumer tests, full sandbox/native release builds, signed release verification, mobile-browser matrix, production promotion, scan recall/precision evaluation, or live production smoke. Existing CI success is reported separately from local evidence.

## Implementation safeguards

- Keep fixes within owned modules; preserve the `strix/**` patch allowlist/digest.
- Keep model acceptance, telemetry-off defaults, budget reservation logic, sandbox egress and receipt semantics intact.
- Preserve partial/inconclusive outcomes; unknown results must never become clean or verified.
- Use synthetic credentials and local child processes for regressions. No paid model calls are necessary for the fixes above.
- Keep database migration, provider normalization, scan orchestration, viewer integrity and performance experiments in separate reviewable commits.
- Verify the pinned application contract before any worker-facing artifact change. Do not advance either repository pin merely to bypass a mismatch.
- Treat CI, packaging, deployed runtime and provider/quality evidence as separate gates. No review can guarantee zero regressions.
