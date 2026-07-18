# Upstream Release Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reliably import stable Strix releases into LyraShield Engine through a tested review PR that auto-merges only after one owner approval and all required checks pass.

**Architecture:** Record both the last imported release tag and exact upstream base SHA. A deterministic sync script applies the upstream tree delta between that base and a selected immutable release tag, so upstream branch rewrites do not break future imports. GitHub Actions detects releases daily, runs engine/package/Docker/worker-contract gates, opens a ready PR, enables auto-merge, and raises a single actionable issue when reconciliation conflicts.

**Tech Stack:** Bash, Git, Python 3.12/pytest, uv, GitHub Actions and GitHub CLI, Docker, pnpm/Vitest.

## Global Constraints

- Track stable semantic-version tags matching `vMAJOR.MINOR.PATCH`; ignore prereleases and moving branch heads.
- Keep `.lyrashield-upstream-base` as the exact imported commit and add `.lyrashield-upstream-release` as the imported release tag.
- Never force-push `main`, never auto-resolve merge conflicts, and never auto-deploy.
- Keep LyraShield-specific patches adapter-shaped and preserve every item in `UPGRADES.md`.
- Require one owner approval and the `Engine CI / verify` status before GitHub auto-merges a sync PR.
- Test the public worker contract from `ecryptoguru/lyrashield-ai` without requiring repository secrets.
- Keep the developer checkout on the single local branch `main`.

---

## File Structure

- `.lyrashield-upstream-release`: source-of-truth stable Strix release tag currently imported.
- `scripts/sync-upstream-release.sh`: validate a selected release and apply its tree delta to the current checkout.
- `scripts/verify-worker-contract.sh`: verify required CLI flags and run the app worker's focused command/output contract tests.
- `tests/test_upstream_release_sync.py`: isolated temporary-Git-repository coverage for no-op, forward, rewritten-history, and conflict behavior.
- `tests/test_worker_contract.py`: focused tests for the worker-contract verifier's flag and test-path behavior.
- `.github/workflows/ci.yml`: the one stable required PR check, including source, package, Docker, and worker contract proof.
- `.github/workflows/upstream-sync.yml`: daily/manual release detection, reconciliation branch, ready PR, auto-merge, and conflict issue orchestration.
- `UPGRADES.md`: operator contract, release/base state, approval location, and recovery instructions.

### Task 1: Release-aware tree-delta synchronizer

**Files:**
- Create: `.lyrashield-upstream-release`
- Create: `scripts/sync-upstream-release.sh`
- Create: `tests/test_upstream_release_sync.py`
- Modify: `tests/test_upstream_sync.py`

**Interfaces:**
- Consumes: `scripts/sync-upstream-release.sh <vMAJOR.MINOR.PATCH>`, `UPSTREAM_REMOTE`, `GITHUB_OUTPUT`, `SYNC_REPORT_DIR`.
- Produces: GitHub outputs `needs_sync`, `base_sha`, `release_sha`, `release_tag`; exit `0` for success/no-op, `2` for invalid configuration, and `20` for reconciliation conflicts.

- [ ] **Step 1: Write failing integration tests**

Create temporary upstream/fork repositories and assert:

```python
def test_same_release_is_a_noop(tmp_path: Path) -> None:
    upstream, fork = make_release_repositories(tmp_path)
    result = run_sync(fork, "v1.1.0")
    assert result.returncode == 0
    assert "needs_sync=false" in read_outputs(fork)

def test_release_delta_survives_rewritten_main(tmp_path: Path) -> None:
    upstream, fork = make_release_repositories(tmp_path)
    release_sha = publish_release(upstream, "v1.1.1", rewritten_main=True)
    result = run_sync(fork, "v1.1.1")
    assert result.returncode == 0
    assert (fork / "upstream.txt").read_text() == "v1.1.1\n"
    assert (fork / ".lyrashield-upstream-base").read_text().strip() == release_sha
    assert (fork / ".lyrashield-upstream-release").read_text().strip() == "v1.1.1"

def test_conflicting_release_writes_report_and_exits_20(tmp_path: Path) -> None:
    _, fork = make_conflicting_release_repositories(tmp_path)
    result = run_sync(fork, "v1.1.1")
    assert result.returncode == 20
    assert "conflict.txt" in (fork / "report" / "conflicts.txt").read_text()
```

- [ ] **Step 2: Run tests and confirm the script is missing**

Run: `uv run pytest tests/test_upstream_release_sync.py -q`

Expected: FAIL because `scripts/sync-upstream-release.sh` and `.lyrashield-upstream-release` do not exist.

- [ ] **Step 3: Implement the synchronizer**

The script must validate the tag, fetch it explicitly, peel it to a commit, compare numeric semver tuples, and apply the delta:

```bash
git fetch --no-tags "$remote" "refs/tags/$release_tag:refs/tags/$release_tag"
release_sha="$(git rev-parse "${release_tag}^{commit}")"
git diff --binary "$base_sha" "$release_sha" > "$report_dir/upstream.patch"
if ! git apply --3way --index "$report_dir/upstream.patch"; then
  git diff --name-only --diff-filter=U > "$report_dir/conflicts.txt"
  exit 20
fi
printf '%s\n' "$release_sha" > .lyrashield-upstream-base
printf '%s\n' "$release_tag" > .lyrashield-upstream-release
```

Use Python's standard library to compare the two three-integer version tuples and update `project.version` from `X.Y.Z.postN` to `<release-without-v>.post1`. Refuse a dirty index before applying, and emit all four outputs on both no-op and successful paths.

- [ ] **Step 4: Retire ancestry-only assertions and run focused tests**

Keep `scripts/check-upstream.sh` as a diagnostic for upstream `main`, but change `tests/test_upstream_sync.py` to describe it as informational rather than the automation engine. Run:

`uv run pytest tests/test_upstream_sync.py tests/test_upstream_release_sync.py -q`

Expected: all focused tests PASS, including rewritten-history reconciliation and conflict reporting.

- [ ] **Step 5: Commit the tested synchronizer**

```bash
git add .lyrashield-upstream-release scripts/sync-upstream-release.sh tests/test_upstream_release_sync.py tests/test_upstream_sync.py
git commit -m "feat: sync immutable upstream releases"
```

### Task 2: Public app worker contract verifier

**Files:**
- Create: `scripts/verify-worker-contract.sh`
- Create: `tests/test_worker_contract.py`

**Interfaces:**
- Consumes: first argument is an existing `lyrashield-ai` checkout; `LYRASHIELD_BIN` optionally selects the CLI command.
- Produces: exit `0` only when the CLI exposes required non-interactive flags and the worker command-builder/output-parser tests pass.

- [ ] **Step 1: Write failing behavior tests**

```python
def test_rejects_help_without_required_flag(tmp_path: Path) -> None:
    app = make_fake_app(tmp_path)
    result = run_contract(app, help_text="--target --scan-mode")
    assert result.returncode != 0
    assert "--non-interactive" in result.stderr

def test_runs_focused_worker_tests(tmp_path: Path) -> None:
    app = make_fake_app(tmp_path)
    result = run_contract(app, help_text=required_help_text())
    assert result.returncode == 0
    assert "command-builder.test.ts" in (app / "pnpm.args").read_text()
    assert "output-parser.test.ts" in (app / "pnpm.args").read_text()
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/test_worker_contract.py -q`

Expected: FAIL because `scripts/verify-worker-contract.sh` does not exist.

- [ ] **Step 3: Implement exact contract checks**

```bash
help="$($lyrashield_bin --help)"
for flag in --non-interactive --target --scan-mode --instruction --max-budget-usd; do
  grep -Fq -- "$flag" <<<"$help" || { echo "Missing CLI flag: $flag" >&2; exit 1; }
done
cd "$app_checkout"
corepack enable
pnpm install --frozen-lockfile
pnpm exec vitest run \
  apps/worker/src/engine/command-builder.test.ts \
  apps/worker/src/engine/output-parser.test.ts
```

Validate the checkout path and `package.json` before invoking pnpm.

- [ ] **Step 4: Run focused and live-local contract tests**

Run:

```bash
uv run pytest tests/test_worker_contract.py -q
LYRASHIELD_BIN="uv run lyrashield" scripts/verify-worker-contract.sh /Users/defiankit/Desktop/lyrashieldai
```

Expected: pytest PASS; both public worker test files PASS against the local engine CLI contract.

- [ ] **Step 5: Commit the contract verifier**

```bash
git add scripts/verify-worker-contract.sh tests/test_worker_contract.py
git commit -m "test: verify public worker engine contract"
```

### Task 3: Required pull-request CI gate

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: pull requests, pushes to `main`, and manual dispatches.
- Produces: stable check context `Engine CI / verify`.

- [ ] **Step 1: Add a failing workflow contract test**

Extend `tests/test_upstream_release_sync.py` with YAML-text assertions that require `pull_request`, `workflow_dispatch`, job id `verify`, pinned actions, `scripts/verify-thin-fork.sh`, `uv build`, `scripts/build.sh`, a Docker build/smoke, and `scripts/verify-worker-contract.sh`.

- [ ] **Step 2: Run the workflow contract test**

Run: `uv run pytest tests/test_upstream_release_sync.py -q`

Expected: FAIL because `.github/workflows/ci.yml` is missing.

- [ ] **Step 3: Create the `Engine CI` workflow**

Create one Ubuntu `verify` job with a 45-minute timeout. Pin checkout, setup-python, setup-uv, and upload-artifact actions by full commit SHA. Its ordered commands are:

```bash
scripts/verify-thin-fork.sh
uv build
uv run lyrashield --version
bash scripts/build.sh
docker build -t lyrashield-engine:ci .
docker run --rm lyrashield-engine:ci --version
git clone --depth 1 https://github.com/ecryptoguru/lyrashield-ai.git "$RUNNER_TEMP/lyrashield-ai"
LYRASHIELD_BIN="uv run lyrashield" scripts/verify-worker-contract.sh "$RUNNER_TEMP/lyrashield-ai"
```

Upload `dist/` on failure for diagnosis, and set `permissions: contents: read`.

- [ ] **Step 4: Validate syntax and run the local equivalent**

Run:

```bash
uv run pytest tests/test_upstream_release_sync.py -q
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml", aliases: true)'
scripts/verify-thin-fork.sh
uv build
```

Expected: tests PASS, YAML parses, source gate PASS, wheel and sdist are produced.

- [ ] **Step 5: Commit the required CI gate**

```bash
git add .github/workflows/ci.yml tests/test_upstream_release_sync.py
git commit -m "ci: add engine release assurance gate"
```

### Task 4: Daily ready-PR automation with conflict escalation

**Files:**
- Modify: `.github/workflows/upstream-sync.yml`
- Modify: `tests/test_upstream_release_sync.py`

**Interfaces:**
- Consumes: latest stable release from `usestrix/strix`, or manual `release_tag` input.
- Produces: `automation/upstream-<tag>-<short-sha>` PR, requested review from `ecryptoguru`, enabled squash auto-merge, or labeled issue `upstream-sync` with uploaded conflict evidence.

- [ ] **Step 1: Write failing orchestration assertions**

Assert the workflow contains daily cron `23 3 * * *`, manual `release_tag`, `issues: write`, release API lookup, the sync script, full pre-PR verification, ready PR creation, `--add-reviewer ecryptoguru`, `gh pr merge --auto --squash`, artifact upload on conflict, and issue deduplication by release tag.

- [ ] **Step 2: Run the failing workflow tests**

Run: `uv run pytest tests/test_upstream_release_sync.py -q`

Expected: FAIL against the weekly ancestry/rebase workflow.

- [ ] **Step 3: Replace the workflow orchestration**

Use `gh api repos/usestrix/strix/releases/latest --jq .tag_name` unless manual input is non-empty. Create the branch from current `main`, call the synchronizer, and stop cleanly on `needs_sync=false`. On success run `uv lock`, the source gate, build/package/Docker smoke, and the public worker contract before committing and pushing.

Use this idempotency rule:

```bash
if gh pr list --state open --head "$branch" --json number --jq 'length > 0' | grep -qx true; then
  echo "An open PR already owns $branch"
  exit 0
fi
```

Create a ready PR, request `ecryptoguru`, and call `gh pr merge --auto --squash "$pr_url"`. On exit `20`, upload the report and create or comment on one open issue titled `Upstream sync blocked: <tag>`.

- [ ] **Step 4: Validate the workflow and no-op path**

Run:

```bash
uv run pytest tests/test_upstream_release_sync.py -q
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/upstream-sync.yml", aliases: true)'
scripts/sync-upstream-release.sh v1.1.0
git status --short
```

Expected: tests PASS, YAML parses, `needs_sync=false`, and no tracked files change.

- [ ] **Step 5: Commit the automation**

```bash
git add .github/workflows/upstream-sync.yml tests/test_upstream_release_sync.py
git commit -m "ci: automate reviewed upstream release imports"
```

### Task 5: Operator documentation, live GitHub policy, and end-to-end proof

**Files:**
- Modify: `UPGRADES.md`
- Modify: `docs/superpowers/specs/2026-07-18-upstream-release-automation-design.md` only if implementation details differ from the approved design.

**Interfaces:**
- Consumes: committed workflows on `origin/main`.
- Produces: documented approval UX, repository auto-merge setting, protected `main`, and a green manual no-op automation run.

- [ ] **Step 1: Update the operator contract**

Document:

- Current release `v1.1.0` and base `7d5a67d234bd3faef34d22be8c6f5a9607de41a3`.
- Approval appears in the sync PR's right-side Reviewers panel and Files changed review flow.
- GitHub merges automatically after `ecryptoguru` approves and `Engine CI / verify` is green.
- Conflicts create/update one issue and attach patch/conflict artifacts; maintainers fix through the PR, never directly in the scheduled job.
- The workflow never deploys the app or engine.

- [ ] **Step 2: Run the complete local release gate**

Run:

```bash
scripts/verify-thin-fork.sh
uv build
uv run lyrashield --version
bash scripts/build.sh
docker build -t lyrashield-engine:upstream-automation .
docker run --rm lyrashield-engine:upstream-automation --version
LYRASHIELD_BIN="uv run lyrashield" scripts/verify-worker-contract.sh /Users/defiankit/Desktop/lyrashieldai
```

Expected: all source, packaging, native binary, Docker, CLI, and worker-contract checks PASS.

- [ ] **Step 3: Commit documentation and push `main`**

```bash
git add UPGRADES.md docs/superpowers/plans/2026-07-18-upstream-release-automation.md
git commit -m "docs: explain upstream release approvals"
git push origin main
```

- [ ] **Step 4: Prove the new CI on GitHub before protection**

```bash
gh workflow run ci.yml --ref main
gh run watch "$(gh run list --workflow ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh workflow run upstream-sync.yml --ref main -f release_tag=v1.1.0
gh run watch "$(gh run list --workflow upstream-sync.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: `Engine CI / verify` is green; the sync workflow is green and creates no PR for the already-imported release.

- [ ] **Step 5: Enable repository auto-merge and protect `main`**

```bash
gh api --method PATCH repos/ecryptoguru/lyrashield-engine \
  -f allow_auto_merge=true -f delete_branch_on_merge=true
gh api --method PUT repos/ecryptoguru/lyrashield-engine/branches/main/protection \
  -f required_status_checks[strict]=true \
  -f 'required_status_checks[contexts][]=Engine CI / verify' \
  -f enforce_admins=true \
  -f required_pull_request_reviews[dismiss_stale_reviews]=true \
  -F required_pull_request_reviews[required_approving_review_count]=1 \
  -f restrictions=
```

If the API rejects form encoding, send the same policy as a JSON body with `required_status_checks`, `enforce_admins`, `required_pull_request_reviews`, and `restrictions: null`. Do not enable protection until the live CI context exists.

- [ ] **Step 6: Audit the final repository state**

Run:

```bash
git status --short --branch
git branch --format='%(refname:short)'
git ls-remote --heads origin
gh api repos/ecryptoguru/lyrashield-engine/branches/main/protection
gh api repos/ecryptoguru/lyrashield-engine --jq '{allow_auto_merge,delete_branch_on_merge,default_branch}'
gh pr list --state open
```

Expected: local checkout is clean on the only local branch `main`; the GitHub policy requires one approval plus `Engine CI / verify`; no unnecessary open sync PR or automation branch exists for `v1.1.0`.
