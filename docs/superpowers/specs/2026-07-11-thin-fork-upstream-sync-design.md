# LyraShield Engine Thin-Fork and Upstream-Sync Design

> **Historical record:** This design captures the July 11 decision point and is superseded by the controlled-derivative boundary in the root `README.md` and `UPGRADES.md`. Keep it for implementation provenance, not current provider, executable, or ownership guidance.

**Date:** 2026-07-11

**Status:** Approved for implementation planning

**Scope:** `/Users/defiankit/Desktop/lyrashield-engine` and its integration boundary with `/Users/defiankit/Desktop/lyrashieldai/apps/worker`

## 1. Context

LyraShield Engine is currently a source fork of `usestrix/strix`. The fork has two committed changes on top of its former upstream baseline (`f342808`) plus a verified set of uncommitted compatibility and quality fixes. The fetched upstream head used for this design is `7b63950`.

The committed product rebrand renamed the internal Python package and touched 184 files. Most of those changes are mechanical rather than product differentiation. Upstream has since force-updated `main`; compared with the former baseline, its current tree contains changes across 45 files, including provider fixes, SARIF support, safer report writes, runtime cleanup, cost tracking, target lists, and additional security skills.

This creates two risks:

1. Internal renaming turns routine upstream upgrades into broad conflict-resolution exercises.
2. Blind automatic merging is unsafe because upstream has demonstrated that it may rewrite branch history and because the engine executes security-sensitive scanning workloads.

The LyraSec worker only needs a stable product-facing contract: an executable, environment variables, predictable output discovery, exit semantics, and safe Docker behavior. It does not require the engine's internal Python modules to use LyraShield names.

## 2. Decision

Maintain LyraShield Engine as a **thin compatibility fork** of Strix.

- Preserve upstream's internal `strix` package, imports, and implementation structure.
- Expose LyraShield branding and compatibility only at the process boundary.
- Carry the smallest possible patch set needed for privacy, platform integration, security, and deterministic operation.
- Automate upstream detection and pull-request creation, but never automatically merge upstream code.
- Defer new engine features until the updated baseline passes all offline gates and one controlled end-to-end scan.

This keeps upstream upgrades practical without surrendering the stable LyraSec integration contract.

## 3. Alternatives Considered

### 3.1 Continue the fully branded source fork

This preserves LyraShield naming throughout the codebase but causes nearly every upstream Python change to conflict with package and import renames. It provides little user-visible value because engine internals are not a public product surface.

**Decision:** Rejected.

### 3.2 Build an independent engine

This allows unrestricted differentiation but transfers responsibility for the full agent runtime, reporting stack, sandbox integration, provider compatibility, and vulnerability skill library to LyraShield.

**Decision:** Rejected for the current product stage. Reconsider only when core engine behavior becomes a deliberate competitive differentiator.

### 3.3 Depend only on the published `strix-agent` package

A small wrapper around a pinned package release would be the lowest-maintenance option. It would also limit the ability to carry urgent security fixes, validate unreleased upstream fixes, or adapt source-level Docker behavior.

**Decision:** Not selected now. Reconsider if the local patch set reaches zero and upstream releases become sufficiently frequent and reproducible.

## 4. Target Architecture

```text
LyraSec worker
    |
    | stable process contract
    v
LyraShield compatibility adapter
    - `lyrashield` CLI entry point
    - LYRASHIELD_* to STRIX_* environment translation
    - telemetry disabled by default
    - LyraShield version surface
    - documented output and exit contract
    |
    v
Upstream Strix internals
    - `strix` Python package
    - upstream runtime and skills
    - upstream report formats
    - upstream sandbox integration
```

The adapter must remain small and explicit. It must not monkey-patch upstream internals or duplicate its CLI parser.

## 5. Compatibility Contract

### 5.1 Executable

The worker continues to invoke `lyrashield`. The upstream `strix` executable may remain available for diagnostics, but the product integration must not depend on it.

The adapter delegates normal execution to `strix.interface.main:main`. It may intercept `--version` so the installed product reports the LyraShield Engine distribution and version rather than exposing the upstream distribution name.

### 5.2 Environment variables

Before importing or invoking the upstream CLI, the adapter translates the following variables when the corresponding `STRIX_*` variable is not already set:

| Product variable | Upstream variable |
|---|---|
| `LYRASHIELD_LLM` | `STRIX_LLM` |
| `LYRASHIELD_IMAGE` | `STRIX_IMAGE` |
| `LYRASHIELD_RUNTIME_BACKEND` | `STRIX_RUNTIME_BACKEND` |
| `LYRASHIELD_MAX_LOCAL_COPY_MB` | `STRIX_MAX_LOCAL_COPY_MB` |
| `LYRASHIELD_REASONING_EFFORT` | `STRIX_REASONING_EFFORT` |
| `LYRASHIELD_TELEMETRY` | `STRIX_TELEMETRY` |

Explicit upstream variables take precedence so diagnostics and direct upstream testing remain possible.

If neither telemetry variable is set, the adapter sets `STRIX_TELEMETRY=0`. LyraShield must not send third-party telemetry by default.

Provider variables such as `LLM_API_KEY`, `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY` retain their existing upstream names. The worker must continue to pass only its reviewed provider-variable allowlist and approved prefixes; compatibility work must not broaden that credential boundary.

### 5.3 Output discovery

The LyraSec worker may retain its outer workspace path `lyrashield_runs/<scan-id>`. Inside that workspace, current upstream writes scan results below `strix_runs/<generated-run-name>`.

During migration, output discovery must support both nested directory names:

1. `strix_runs` for the thin fork and current upstream.
2. `lyrashield_runs` for compatibility with existing fork output.

If both exist, the worker selects the newest valid run directory containing expected output artifacts. Failure to find outputs remains a logged, non-crashing parse condition and is interpreted together with the process exit code.

### 5.4 Exit semantics

The worker owns the product lifecycle mapping and must test it independently of upstream's prose or UI:

- `0`: engine completed without the upstream findings exit condition.
- `2`: engine completed and produced findings; the scan is not treated as a worker failure.
- negative/signal-derived codes: cancellation or timeout according to worker state.
- other non-zero codes: engine failure unless a future, explicitly tested contract says otherwise.

The migration must verify current upstream behavior before changing this mapping.

### 5.5 Sandbox image

Until LyraShield publishes and maintains its own sandbox image, the adapter and worker use the verified upstream sandbox image. Production configuration should pin the image to an immutable digest after the image has been pulled and smoke-tested.

A LyraShield-named image must not be configured merely for branding if no maintained image exists at that reference.

## 6. Migration Strategy

The existing dirty worktree contains verified user work and must not be reset or overwritten.

1. Create a recovery reference containing the current committed fork and the verified working-tree changes.
2. Create the thin-fork implementation in a separate worktree based on the freshly fetched `upstream/main`.
3. Keep upstream files and the internal package unchanged.
4. Add the compatibility adapter and its focused tests.
5. Compare each current local fix against upstream and carry it only if upstream still lacks the fix.
6. Update the LyraSec worker's output discovery and Docker integration.
7. Run the complete verification ladder.
8. Replace the active fork branch only after the thin fork passes all gates.

The old fully renamed fork remains recoverable until a controlled end-to-end scan succeeds.

## 7. Upstream Update Automation

### 7.1 Repository prerequisite

The engine repository currently has only an `upstream` remote. A writable `origin` repository is required before hosted automation can create branches and pull requests.

### 7.2 Trigger

Run weekly and allow manual dispatch. Daily updates would add review noise without materially improving a pinned production engine.

### 7.3 Workflow

1. Fetch `upstream/main` and tags.
2. Read the last accepted upstream commit from a tracked baseline file or equivalent workflow state.
3. Verify that the recorded commit is an ancestor of current `upstream/main`.
4. If ancestry fails, stop without merging and produce a clear failed check requiring manual reconciliation.
5. If upstream advanced normally, create or refresh a dedicated update branch.
6. Apply the small LyraShield patch series on top of the new upstream commit.
7. Refresh the lockfile using the repository's pinned package manager.
8. Run every required quality gate.
9. Open or update a pull request describing the old and new upstream commits and notable upstream changes.

The workflow must not auto-merge, force-update the protected product branch, or resolve conflicts heuristically.

## 8. Verification Gates

An upstream update is eligible for human review only after passing:

### Engine checks

- `uv sync --frozen`
- Ruff lint
- Ruff format check
- pytest, including deprecations treated as errors where currently enforced
- headless mypy for the verified non-TUI source set
- Bandit
- CLI alias and version tests
- environment translation and precedence tests
- telemetry-default test
- upstream output fixture parsing
- exit-code contract test

Full TUI mypy and repo-wide Pyright remain documented upstream-quality debt unless the migration changes their baseline. They must not silently regress beyond the recorded count.

### Docker checks

- build the worker image using the thin-fork engine context
- verify `lyrashield --version`
- verify the engine can reach the Docker daemon required for its sandbox
- confirm the configured sandbox image resolves
- run a no-credential validation path and confirm it fails before pulling or starting unnecessary runtime resources

### LyraSec checks

- worker lint, typecheck, and targeted engine tests
- output discovery for both directory layouts
- successful interpretation of exit `0`
- findings interpretation for exit `2`
- failure interpretation for other non-zero exits
- cancellation and timeout behavior
- full application verification before merging a production engine update

## 9. Error Handling and Recovery

- A rewritten upstream history blocks automation; it never triggers a giant merge.
- A conflict blocks the update PR and names the LyraShield patch that no longer applies.
- A failed test leaves the current production engine pinned and unchanged.
- A missing or invalid sandbox image fails during preflight/smoke verification, not during a user scan where practical.
- A parser compatibility failure retains raw stdout, stderr, and artifact metadata without logging credentials.
- Rollback means restoring the prior accepted engine commit and rebuilding the worker image; database rollback is not involved.

## 10. Feature Policy

New work follows this order:

1. Confirm the capability is not already present in current upstream.
2. Prefer implementing product-specific behavior in the LyraSec worker or compatibility adapter.
3. Contribute generic engine improvements upstream where feasible.
4. Carry a core fork patch only for an essential LyraSec requirement, urgent security control, or accepted upstream gap.

Each carried patch must have a focused test and a short patch-ledger entry explaining why it cannot live outside the upstream core.

The first development priority is therefore **upgrade and compatibility**, not additional features. Feature work starts after the new baseline passes one controlled scan and the existing upgrade roadmap is reconciled with capabilities already delivered upstream.

## 11. Success Criteria

The migration is complete when:

- the active engine branch is based on current upstream with no internal package rename;
- LyraSec still invokes `lyrashield` and accepts existing product environment variables;
- third-party telemetry is off by default;
- the worker discovers and persists upstream scan outputs correctly;
- exit, cancellation, timeout, and failure semantics pass contract tests;
- offline engine, worker, application, and Docker gates pass;
- one controlled end-to-end scan completes and its findings reach the LyraSec UI;
- the previous fork remains recoverable;
- a weekly update workflow can open tested PRs once a writable `origin` exists.

## 12. Non-Goals

- Rebranding every upstream source file or internal module.
- Automatically merging security-sensitive upstream changes.
- Fixing all upstream TUI typing debt during this migration.
- Building a custom sandbox image before there is a functional or security reason.
- Adding speculative engine features before the upgraded baseline is proven.
