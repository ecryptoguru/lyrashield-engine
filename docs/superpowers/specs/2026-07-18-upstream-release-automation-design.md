# Upstream Strix Release Automation Design

> **Historical design record:** Current upstream-import behavior is documented in the root `UPGRADES.md`. This document does not override the current controlled-derivative ownership boundary or supported execution contract.

## Goal

Automatically detect and reconcile immutable Strix releases into the LyraShield
Engine thin fork, prove compatibility, and open a reviewable GitHub pull request.
Merging remains approval-gated because engine changes can alter findings, cost,
evidence, or sandbox behavior.

## Decisions

- Track stable GitHub release tags, not the mutable `upstream/main` branch.
- Import upstream tree changes rather than rebasing commit history.
- Preserve LyraShield behavior at the adapter and documented patch boundaries.
- Open a ready-for-review PR after every successful reconciliation.
- Enable GitHub auto-merge on that PR, but require one human approval and all
  required checks before GitHub may merge it.
- Never resolve conflicts, approve a PR, deploy, or weaken a failing gate
  automatically.

## Non-goals

- Unattended engine merges or deployments.
- Automatically importing prereleases or arbitrary upstream commits.
- Reimplementing Strix features in the fork.
- Adding new LyraShield application features in this phase.
- Eliminating the fork before the required upstream extension hooks exist.

## State

The repository keeps two small pieces of synchronization state:

- `.lyrashield-upstream-base`: the exact upstream commit whose tree is currently
  incorporated.
- `.lyrashield-upstream-release`: the stable release tag associated with the
  current LyraShield version, initially `v1.1.0`.

`UPGRADES.md` remains the human-readable patch ledger and records the same base
commit and release tag. A sync PR must update all three together.

## Detection

The existing `Upstream Engine Sync` workflow changes from a weekly ancestry
check to a daily stable-release check, while retaining manual dispatch.

1. Query the latest non-draft, non-prerelease GitHub release from
   `usestrix/strix`.
2. Reject malformed tags; accepted tags match `v<major>.<minor>.<patch>`.
3. Fetch the tag and peel annotated tags to an exact commit SHA.
4. Compare the semantic version with `.lyrashield-upstream-release`.
5. Exit successfully when no newer stable release exists.

The scheduled workflow accepts no caller-controlled repository or ref. Manual
dispatch may optionally select a stable release tag from `usestrix/strix`, but
never an arbitrary repository or raw ref.

## Reconciliation

A small shell script owns the deterministic reconciliation so it can be tested
locally and called by GitHub Actions.

1. Require a clean checkout of `main` and validate both state files.
2. Create `automation/upstream-<version>-<sha12>` from current `main`.
3. Generate the binary tree delta between the recorded upstream base and the
   selected release commit.
4. Apply that delta to the fork with Git's three-way application support.
5. If any conflict remains, abort without committing or pushing.
6. Set the package version to `<upstream-version>.post1`, preserving the
   `lyrashield-engine` package name and adapter entry point.
7. Update the base SHA, release tag, and patch ledger.
8. Regenerate `uv.lock`.

This works when upstream rewrites history because it compares file trees rather
than requiring the old base to be an ancestor of the new release.

## LyraShield Boundaries

The reconciliation must retain and test:

- `lyrashield_adapter` invocation and environment aliases.
- Forced-off upstream telemetry.
- LyraShield package identity and version output.
- Validation before Docker setup.
- Per-instance bind mounts and worker-compatible result artifacts.
- Docker networking, resource/log limits, and host reachability.
- PyInstaller adapter entry point and honest release smoke failures.
- Apache attribution for fork-modified upstream source files.

`UPGRADES.md` is the canonical list. Adding a new fork patch requires updating
that ledger and adding one focused regression test.

## Verification

The write-enabled sync job only reconciles, locks, commits, and opens the PR. It
does not execute candidate upstream code. The separate `Engine CI / verify`
pull-request job has read-only repository permissions and disabled persisted
checkout credentials. It must pass before auto-merge:

1. `scripts/verify-thin-fork.sh` for Ruff lint/format, the full pytest suite,
   strict mypy, and Bandit.
2. `uv build` and wheel inspection for package identity, adapter contents, and
   the sole `lyrashield` console entry point.
3. Source CLI checks for `--version` and `--help`.
4. Native release build and smoke checks on the supported release runner.
5. Docker image build and runtime smoke for the unprivileged user, workdir,
   Caido readiness, expected tools, proxy/CA setup, and absent Docker socket.
6. Worker contract checks against public repository
   `ecryptoguru/lyrashield-ai`:
   - run its existing command-builder and output-parser tests;
   - assert the candidate CLI still exposes `--non-interactive`, `--target`,
     `--scan-mode`, `--instruction`, and `--max-budget-usd`;
   - validate representative `run.json` and `vulnerabilities.json` artifacts
     with the application's bounded parser contract.

The Docker smoke runs the real entrypoint and verifies Caido readiness,
unprivileged execution, the `/workspace` workdir, proxy/CA setup, expected
tools, and the absence of a Docker socket. A failure in any required check
blocks auto-merge.

## Pull Request and Approval

On successful reconciliation, the workflow commits the reconciled tree, pushes
the automation branch, and opens one ready-for-review PR. The body includes:

- previous and new release tags and commit SHAs;
- upstream release notes link;
- changed paths and any LyraShield patch-boundary overlap;
- the package, CLI, native, Docker, and worker-contract checks that GitHub will
  require before merge;
- an explicit statement that no deployment occurred.

The workflow then requests review from `@ecryptoguru` and enables GitHub
auto-merge. Repository rules require one approval and all required checks, so
approval is visible in GitHub's **Pull requests** and **Notifications** views.
After approval, GitHub merges automatically when the remaining checks are
green.

Repeated runs find the existing automation branch/PR and update it rather than
creating duplicates. Merged or superseded automation branches are deleted.

## Conflict and Failure Handling

When tree application conflicts, the workflow:

1. records the conflicting paths and upstream release metadata;
2. uploads the generated upstream delta and conflict report as run artifacts;
3. creates or updates one GitHub issue labelled `upstream-sync`;
4. exits non-zero without pushing a partial branch.

Transient registry or package-download failures may be retried once by the
individual build step. Code, test, schema, or contract failures are never
retried as if they were infrastructure failures.

## Security

- Pin third-party GitHub Actions to full commit SHAs.
- Use the built-in token with only `contents`, `pull-requests`, and `issues`
  permissions required by the job.
- Never execute candidate upstream code in the write-enabled synchronization
  job. Candidate code runs only in the read-only required PR check with
  persisted checkout credentials disabled.
- Keep workflow changes themselves subject to repository review rules.
- Do not expose application, model-provider, deployment, or production secrets
  to the synchronization job.

## Rollout

1. Add the release-state file and reconciliation script with synthetic Git
   tests covering linear history, rewritten history, no-op, malformed tag, and
   conflict failure.
2. Replace the ancestry-based workflow with release detection and source gates.
3. Add native, Docker, and public app-contract jobs.
4. Configure the `main` ruleset for required checks and one approval.
5. Run a manual no-op against `v1.1.0`, then test the full path using a local
   synthetic newer tag before enabling the daily schedule.

## Later Exit From the Fork

The long-term simplification is to contribute the required Docker, artifact,
and adapter hooks upstream. Once LyraShield can consume an immutable Strix
package/container without patching upstream files, replace tree reconciliation
with an ordinary pinned dependency update. That migration is intentionally
separate from this automation.
