# LyraShield Engine Thin-Fork and Upstream-Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Rebuild LyraShield Engine on current Strix upstream while preserving LyraShield's stable process contract and adding review-gated upstream update automation.

**Architecture:** Preserve the upstream `strix` package unchanged. Add a small `lyrashield_adapter` package that exposes the `lyrashield` command, maps product environment variables to upstream names, and disables third-party telemetry by default. The LyraSec worker stays product-facing and supports both upstream and legacy output layouts.

**Tech Stack:** Python 3.12+, uv, Hatchling, pytest, Ruff, mypy, Bandit, Bash, GitHub Actions, TypeScript, Vitest, Docker Compose.

## Global Constraints

- Preserve the existing rebranded fork and its verified dirty work. Never reset, overwrite, or delete it.
- Work in a separate worktree based on `upstream/main` commit `7b63950` or its verified successor.
- Keep upstream's internal package, imports, and source paths as `strix`.
- Keep the executable and product configuration variables as `lyrashield` and `LYRASHIELD_*`.
- Explicit `STRIX_*` values override mapped `LYRASHIELD_*` values.
- When neither telemetry variable is supplied, the adapter sets `STRIX_TELEMETRY=0`.
- Add no dependencies for adapter, automation, or test helpers.
- Automation must never auto-merge, force-push, or resolve conflicts heuristically.
- If recorded upstream is not an ancestor of current upstream, exit before rebase/PR creation.
- Do not broaden the worker's existing provider credential allowlist/prefixes.
- Do not claim to fix full-TUI mypy or repo-wide Pyright debt.
- Never run a paid or destructive scan until authorization, credentials, and sandbox provenance are confirmed.

---

## File Structure

| Repository | File | Responsibility |
|---|---|---|
| Engine | `.lyrashield-upstream-base` | Accepted upstream commit. |
| Engine | `pyproject.toml` | Product distribution and CLI entry point. |
| Engine | `lyrashield_adapter/cli.py` | Env mapping, version output, upstream delegation. |
| Engine | `tests/test_lyrashield_adapter.py` | Adapter contract tests. |
| Engine | `tests/test_hardening.py` | Startup and Docker-state regressions. |
| Engine | `strix/config/loader.py` | Pydantic 2.11-safe settings persistence. |
| Engine | `strix/interface/main.py` | Validate before Docker/image pull. |
| Engine | `strix/runtime/docker_client.py` | Non-shared bind mount state. |
| Engine | `scripts/verify-thin-fork.sh` | Local/CI engine gate. |
| Engine | `scripts/check-upstream.sh` | Read-only ancestry check. |
| Engine | `tests/test_upstream_sync.py` | Sync behavior tests using local Git repos. |
| Engine | `.github/workflows/upstream-sync.yml` | Weekly/manual PR-only update. |
| App | `apps/worker/src/engine/runner.ts` | Find either nested engine output layout. |
| App | `apps/worker/src/engine/runner.test.ts` | Output-layout tests plus existing exit tests. |
| App | `docker-compose.yml`, `.env.example` | Real sandbox default and product settings. |
| App | deployment docs plus `AGENTS.md`, `codebase.md`, `PRD.md`, `NEXT-STEPS.md` | Truthful deployment and handoff state. |

## Task 1: Archive the Existing Fork and Create the Thin-Fork Worktree

**Files:**
- Create: branch `codex/engine-rebrand-archive`
- Create: `/Users/defiankit/Desktop/lyrashield-engine-thin-fork`
- Copy: `docs/superpowers/` from the approved design branch

**Interfaces:**
- Consumes: current rebrand, known dirty files, and design commit `4d89727`.
- Produces: a restorable archive and a clean implementation branch based on upstream.

- [ ] **Step 1: Verify only the known dirty files will be archived**

```bash
cd /Users/defiankit/Desktop/lyrashield-engine
git status --porcelain | awk '{print $2}' | sort > /tmp/lyrashield-engine-dirty-files.txt
diff -u <(printf '%s\n' \
  .dockerignore \
  UPGRADES.md \
  lyrashield/config/loader.py \
  lyrashield/core/hooks.py \
  lyrashield/core/runner.py \
  lyrashield/interface/main.py \
  lyrashield/interface/utils.py \
  lyrashield/runtime/docker_client.py \
  pyproject.toml \
  tests/test_main.py \
  uv.lock | sort) /tmp/lyrashield-engine-dirty-files.txt
```

Expected: no diff. Stop if an unknown file appears; do not stage it.

- [ ] **Step 2: Create the recovery commit**

```bash
git switch -c codex/engine-rebrand-archive
git add .dockerignore UPGRADES.md lyrashield/config/loader.py lyrashield/core/hooks.py \
  lyrashield/core/runner.py lyrashield/interface/main.py lyrashield/interface/utils.py \
  lyrashield/runtime/docker_client.py pyproject.toml tests/test_main.py uv.lock
git commit -m "chore: archive rebranded engine baseline"
git status --short
```

Expected: clean tree. Do not push the archive before new implementation verification.

- [ ] **Step 3: Create and seed the isolated implementation worktree**

```bash
git fetch upstream --prune --tags
git worktree add /Users/defiankit/Desktop/lyrashield-engine-thin-fork \
  -b codex/engine-thin-fork upstream/main
cd /Users/defiankit/Desktop/lyrashield-engine-thin-fork
git restore --source=codex/engine-upstream-sync-design -- docs/superpowers
git add docs/superpowers
git commit -m "docs: carry approved thin-fork design and plan"
printf '%s\n' "$(git rev-parse upstream/main)" > .lyrashield-upstream-base
git add .lyrashield-upstream-base
git commit -m "chore: record LyraShield upstream baseline"
```

Expected: `git merge-base --is-ancestor "$(cat .lyrashield-upstream-base)" upstream/main` exits `0`.

- [ ] **Step 4: Verify isolation**

```bash
git -C /Users/defiankit/Desktop/lyrashield-engine log -1 --oneline codex/engine-rebrand-archive
git -C /Users/defiankit/Desktop/lyrashield-engine-thin-fork status --short --branch
git -C /Users/defiankit/Desktop/lyrashield-engine-thin-fork diff --exit-code upstream/main -- strix
```

Expected: recovery branch exists, worktree is clean, and no upstream source differs yet.

- [ ] **Step 5: Commit**

The recovery and baseline commits above deliberately remain separate from functional work.

## Task 2: Add Adapter and Missing Hardening

**Files:**
- Create: `lyrashield_adapter/__init__.py`
- Create: `lyrashield_adapter/cli.py`
- Create: `tests/test_lyrashield_adapter.py`
- Create: `tests/test_hardening.py`
- Modify: `pyproject.toml`, `uv.lock`
- Modify: `strix/config/loader.py`, `strix/interface/main.py`, `strix/runtime/docker_client.py`

**Interfaces:**
- Consumes: `strix.interface.main:main`, upstream `STRIX_*` settings, and the worker's `lyrashield` executable contract.
- Produces: `prepare_environment(environ: MutableMapping[str, str] | None = None) -> MutableMapping[str, str]`, `get_version() -> str`, and `main() -> None`.

- [ ] **Step 1: Write failing tests**

Create `tests/test_lyrashield_adapter.py`:

```python
from __future__ import annotations

from collections.abc import MutableMapping

import pytest

from lyrashield_adapter import cli


@pytest.mark.parametrize(
    ("product", "upstream"),
    [
        ("LYRASHIELD_LLM", "STRIX_LLM"),
        ("LYRASHIELD_IMAGE", "STRIX_IMAGE"),
        ("LYRASHIELD_RUNTIME_BACKEND", "STRIX_RUNTIME_BACKEND"),
        ("LYRASHIELD_MAX_LOCAL_COPY_MB", "STRIX_MAX_LOCAL_COPY_MB"),
        ("LYRASHIELD_REASONING_EFFORT", "STRIX_REASONING_EFFORT"),
        ("LYRASHIELD_TELEMETRY", "STRIX_TELEMETRY"),
    ],
)
def test_prepare_environment_maps_product_variable(product: str, upstream: str) -> None:
    env: MutableMapping[str, str] = {product: "product-value"}
    cli.prepare_environment(env)
    assert env[upstream] == "product-value"


def test_prepare_environment_keeps_explicit_upstream_value() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "product-model",
        "STRIX_LLM": "operator-model",
    }
    cli.prepare_environment(env)
    assert env["STRIX_LLM"] == "operator-model"


def test_prepare_environment_disables_telemetry_by_default() -> None:
    env: MutableMapping[str, str] = {}
    cli.prepare_environment(env)
    assert env["STRIX_TELEMETRY"] == "0"


def test_main_prints_product_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "get_version", lambda: "1.0.4.post1")
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--version"])
    cli.main()
    assert capsys.readouterr().out == "lyrashield 1.0.4.post1\n"


def test_main_delegates_non_version_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_upstream_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(cli, "_run_upstream", fake_upstream_main)
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--non-interactive"])
    cli.main()
    assert called is True
```

Create `tests/test_hardening.py`:

```python
from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from strix.runtime.docker_client import StrixDockerSandboxClient


main_module = import_module("strix.interface.main")


def test_main_validates_configuration_before_docker_setup() -> None:
    args = SimpleNamespace(config=None)

    with (
        patch.object(main_module, "configure_dependency_logging"),
        patch.object(main_module, "parse_arguments", return_value=args),
        patch.object(main_module, "validate_environment", side_effect=RuntimeError("missing key")),
        patch.object(main_module, "check_docker_installed") as check_docker,
        patch.object(main_module, "pull_docker_image") as pull_image,
        pytest.raises(RuntimeError, match="missing key"),
    ):
        main_module.main()

    check_docker.assert_not_called()
    pull_image.assert_not_called()


def test_docker_client_has_no_shared_bind_mount_default() -> None:
    assert "strix_bind_mounts" not in StrixDockerSandboxClient.__dict__
```

- [ ] **Step 2: Verify tests fail on raw upstream**

```bash
uv sync --frozen
uv run pytest tests/test_lyrashield_adapter.py tests/test_hardening.py -v
```

Expected: adapter collection fails; upstream startup order and class default tests fail.

- [ ] **Step 3: Implement adapter and metadata**

Create empty `lyrashield_adapter/__init__.py` and `lyrashield_adapter/cli.py`:

```python
"""Product boundary for the upstream Strix CLI."""

from __future__ import annotations

import os
import sys
from collections.abc import MutableMapping
from importlib.metadata import PackageNotFoundError, version


ENV_ALIASES = {
    "LYRASHIELD_LLM": "STRIX_LLM",
    "LYRASHIELD_IMAGE": "STRIX_IMAGE",
    "LYRASHIELD_RUNTIME_BACKEND": "STRIX_RUNTIME_BACKEND",
    "LYRASHIELD_MAX_LOCAL_COPY_MB": "STRIX_MAX_LOCAL_COPY_MB",
    "LYRASHIELD_REASONING_EFFORT": "STRIX_REASONING_EFFORT",
    "LYRASHIELD_TELEMETRY": "STRIX_TELEMETRY",
}


def prepare_environment(
    environ: MutableMapping[str, str] | None = None,
) -> MutableMapping[str, str]:
    env = environ if environ is not None else os.environ
    for product_name, upstream_name in ENV_ALIASES.items():
        if upstream_name not in env and product_name in env:
            env[upstream_name] = env[product_name]
    env.setdefault("STRIX_TELEMETRY", "0")
    return env


def get_version() -> str:
    try:
        return version("lyrashield-engine")
    except PackageNotFoundError:
        return "unknown"


def _run_upstream() -> None:
    from strix.interface.main import main as upstream_main

    upstream_main()


def main() -> None:
    prepare_environment()
    if sys.argv[1:] in (["--version"], ["-v"]):
        print(f"lyrashield {get_version()}")
        return
    _run_upstream()
```

Set `project.name = "lyrashield-engine"`, `project.version = "1.0.4.post1"`, and:

```toml
[project.scripts]
lyrashield = "lyrashield_adapter.cli:main"
strix = "strix.interface.main:main"

[tool.hatch.build.targets.wheel]
packages = ["strix", "lyrashield_adapter"]
```

Keep upstream dependency versions. Run `uv lock`.

- [ ] **Step 4: Implement exactly the missing safeguards**

In `strix/config/loader.py` use:

```python
for sub_name in type(s).model_fields:
```

In `strix/interface/main.py`, preserve config override but run:

```python
if args.config:
    apply_config_override(validate_config_file(args.config))

validate_environment()
check_docker_installed()
pull_docker_image()
```

In `strix/runtime/docker_client.py`, replace the class list with:

```python
strix_bind_mounts: list[dict[str, Any]]
```

Keep `strix/runtime/backends.py` per-instance assignment. Do not remove current upstream `RequestException` teardown handling.

- [ ] **Step 5: Run the targeted test cycle**

```bash
uv lock
uv sync --frozen
uv run pytest tests/test_lyrashield_adapter.py tests/test_hardening.py tests/test_config_loader.py \
  -W error::pydantic.PydanticDeprecatedSince211 -v
uv run lyrashield --version
uv run strix --version
```

Expected: tests pass; `lyrashield` reports product version; upstream diagnostic command remains available.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock lyrashield_adapter tests/test_lyrashield_adapter.py \
  tests/test_hardening.py strix/config/loader.py strix/interface/main.py \
  strix/runtime/docker_client.py
git commit -m "feat: add LyraShield engine compatibility adapter"
```

## Task 3: Support Upstream Output and Sandbox Contract in LyraSec

**Files:**
- Modify: `/Users/defiankit/Desktop/lyrashieldai/apps/worker/src/engine/runner.ts`
- Modify: `/Users/defiankit/Desktop/lyrashieldai/apps/worker/src/engine/runner.test.ts`
- Modify: `/Users/defiankit/Desktop/lyrashieldai/docker-compose.yml`
- Modify: `/Users/defiankit/Desktop/lyrashieldai/.env.example`
- Modify: local and production deployment docs

**Interfaces:**
- Consumes: outer `lyrashield_runs/<scan-id>` plus nested `strix_runs/<run-name>` or legacy `lyrashield_runs/<run-name>`.
- Produces: `findRunOutputDir(workDir: string): Promise<string | null>` selecting newest valid output containing `run.json` or `vulnerabilities.json`.

- [ ] **Step 1: Write failing output-layout tests**

Replace the import of `interpretExitCode` with the following complete test fixture; retain the existing exit-code assertions below it:

```ts
import { afterEach, describe, expect, it, vi } from "vitest"
import { mkdtemp, mkdir, rm, utimes, writeFile } from "fs/promises"
import { tmpdir } from "os"
import { join } from "path"

import { findRunOutputDir, interpretExitCode } from "./runner"

const cleanupPaths: string[] = []

afterEach(async () => {
  await Promise.all(
    cleanupPaths.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  )
})

async function createRun(
  workDir: string,
  layout: "strix_runs" | "lyrashield_runs",
  name: string,
  artifact: "run.json" | "vulnerabilities.json",
  mtime: Date,
): Promise<string> {
  const runDir = join(workDir, layout, name)
  await mkdir(runDir, { recursive: true })
  await writeFile(join(runDir, artifact), "{}", "utf8")
  await utimes(runDir, mtime, mtime)
  return runDir
}

it("finds an upstream Strix output directory", async () => {
  const workDir = await mkdtemp(join(tmpdir(), "lyrashield-engine-"))
  cleanupPaths.push(workDir)
  const expected = await createRun(
    workDir, "strix_runs", "upstream", "run.json", new Date(1_000),
  )
  await expect(findRunOutputDir(workDir)).resolves.toBe(expected)
})

it("selects the newest valid output across both layouts", async () => {
  const workDir = await mkdtemp(join(tmpdir(), "lyrashield-engine-"))
  cleanupPaths.push(workDir)
  await createRun(workDir, "lyrashield_runs", "legacy", "run.json", new Date(1_000))
  const expected = await createRun(
    workDir, "strix_runs", "current", "vulnerabilities.json", new Date(2_000),
  )
  await expect(findRunOutputDir(workDir)).resolves.toBe(expected)
})

it("ignores directories without expected output artifacts", async () => {
  const workDir = await mkdtemp(join(tmpdir(), "lyrashield-engine-"))
  cleanupPaths.push(workDir)
  await mkdir(join(workDir, "strix_runs", "empty"), { recursive: true })
  await expect(findRunOutputDir(workDir)).resolves.toBeNull()
})
```

- [ ] **Step 2: Verify failure**

```bash
cd /Users/defiankit/Desktop/lyrashieldai
pnpm --filter @lyrashield/worker test -- runner.test.ts
```

Expected: `findRunOutputDir` is private and only looks in legacy layout.

- [ ] **Step 3: Implement artifact-aware dual-layout discovery**

Replace the private function with:

```ts
const ENGINE_RUN_LAYOUTS = ["strix_runs", "lyrashield_runs"] as const
const ENGINE_OUTPUT_ARTIFACTS = ["run.json", "vulnerabilities.json"] as const

async function hasEngineOutputArtifact(runDir: string): Promise<boolean> {
  for (const artifact of ENGINE_OUTPUT_ARTIFACTS) {
    try {
      await stat(join(runDir, artifact))
      return true
    } catch {
      // Try the next expected artifact.
    }
  }
  return false
}

export async function findRunOutputDir(workDir: string): Promise<string | null> {
  let newest: { path: string; mtimeMs: number } | null = null

  for (const layout of ENGINE_RUN_LAYOUTS) {
    const runsDir = join(workDir, layout)
    try {
      for (const entry of await readdir(runsDir)) {
        const entryPath = join(runsDir, entry)
        try {
          const entryStat = await stat(entryPath)
          if (!entryStat.isDirectory() || !(await hasEngineOutputArtifact(entryPath))) continue
          if (!newest || entryStat.mtimeMs > newest.mtimeMs) {
            newest = { path: entryPath, mtimeMs: entryStat.mtimeMs }
          }
        } catch {
          // A disappearing/unreadable run must not fail the worker.
        }
      }
    } catch {
      logger.debug("Engine run layout not found", { runsDir })
    }
  }

  return newest?.path ?? null
}
```

Keep the outer workspace product-branded; do not rename `lyrashield_runs/<scan-id>`.

- [ ] **Step 4: Use a real sandbox reference and document it**

First verify the upstream image:

```bash
docker pull ghcr.io/usestrix/strix-sandbox:1.0.0
docker image inspect ghcr.io/usestrix/strix-sandbox:1.0.0 --format '{{index .RepoDigests 0}}'
```

Then set Compose default to:

```yaml
LYRASHIELD_IMAGE: "${LYRASHIELD_IMAGE:-ghcr.io/usestrix/strix-sandbox:1.0.0}"
```

Set `.env.example` to:

```dotenv
# Production: pin an inspected digest, never a mutable tag.
LYRASHIELD_IMAGE="ghcr.io/usestrix/strix-sandbox@sha256:REPLACE_WITH_VERIFIED_DIGEST"
LYRASHIELD_TELEMETRY="0"
```

Deployment docs must say local development uses the upstream tag and production uses the inspected digest. A LyraShield-named image is allowed only after it is published, signed, and maintained by LyraShield.

- [ ] **Step 5: Verify and commit app changes**

```bash
pnpm --filter @lyrashield/worker test -- runner.test.ts
pnpm --filter @lyrashield/worker lint
pnpm --filter @lyrashield/worker typecheck
docker compose config >/tmp/lyrashield-compose.rendered.yml
rg -n "LYRASHIELD_IMAGE|strix-sandbox" /tmp/lyrashield-compose.rendered.yml
git add apps/worker/src/engine/runner.ts apps/worker/src/engine/runner.test.ts \
  docker-compose.yml .env.example docs/deployment/LOCAL_SETUP.md \
  docs/deployment/PRODUCTION_DEPLOYMENT.md
git commit -m "fix(worker): support upstream engine contract"
```

Expected: dual-layout tests and app static checks pass; Compose defaults to upstream image unless overridden.

## Task 4: Add Reproducible Upstream-Sync Gates

**Files:**
- Create: `scripts/verify-thin-fork.sh`
- Create: `scripts/check-upstream.sh`
- Create: `tests/test_upstream_sync.py`
- Modify: `UPGRADES.md`

**Interfaces:**
- Consumes: `.lyrashield-upstream-base`, remote `upstream`, and local Git.
- Produces: output keys `base_sha`, `upstream_sha`, `needs_sync`; exit `20` when upstream history was rewritten.

- [ ] **Step 1: Write failing sync tests**

Create `tests/test_upstream_sync.py` exactly as follows. It uses only local Git repositories and does not access the network:

```python
from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-upstream.sh"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, text=True, capture_output=True
    ).stdout.strip()


def commit(repo: Path, message: str, contents: str) -> str:
    (repo / "marker.txt").write_text(contents, encoding="utf-8")
    git(repo, "add", "marker.txt")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def make_repositories(tmp_path: Path) -> tuple[Path, Path, str]:
    upstream = tmp_path / "upstream"
    fork = tmp_path / "fork"
    upstream.mkdir()
    git(upstream, "init", "-b", "main")
    git(upstream, "config", "user.email", "test@example.com")
    git(upstream, "config", "user.name", "Test")
    base = commit(upstream, "base", "base")
    git(tmp_path, "clone", str(upstream), str(fork))
    git(fork, "config", "user.email", "test@example.com")
    git(fork, "config", "user.name", "Test")
    git(fork, "remote", "rename", "origin", "upstream")
    (fork / ".lyrashield-upstream-base").write_text(f"{base}\n", encoding="utf-8")
    return upstream, fork, base


def run_check(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT)],
        cwd=repo,
        text=True,
        capture_output=True,
        env={**os.environ, "GITHUB_OUTPUT": str(repo / "outputs.txt")},
    )


def read_outputs(repo: Path) -> str:
    return (repo / "outputs.txt").read_text(encoding="utf-8")


def test_check_upstream_reports_no_change(tmp_path: Path) -> None:
    _, fork, _ = make_repositories(tmp_path)
    result = run_check(fork)
    assert result.returncode == 0
    assert "needs_sync=false" in read_outputs(fork)


def test_check_upstream_reports_fast_forward_update(tmp_path: Path) -> None:
    upstream, fork, _ = make_repositories(tmp_path)
    commit(upstream, "advance", "next")
    result = run_check(fork)
    assert result.returncode == 0
    assert "needs_sync=true" in read_outputs(fork)


def test_check_upstream_rejects_rewritten_history(tmp_path: Path) -> None:
    upstream, fork, _ = make_repositories(tmp_path)
    git(upstream, "checkout", "--orphan", "rewritten")
    git(upstream, "rm", "-rf", ".")
    commit(upstream, "replacement", "replacement")
    git(upstream, "branch", "-f", "main", "HEAD")
    result = run_check(fork)
    assert result.returncode == 20
    assert "not an ancestor" in result.stderr
```

- [ ] **Step 2: Verify tests fail before implementation**

```bash
uv run pytest tests/test_upstream_sync.py -v
```

Expected: missing/non-executable check script.

- [ ] **Step 3: Implement the two scripts**

Create `scripts/verify-thin-fork.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest -W error::pydantic.PydanticDeprecatedSince211
uv run mypy --exclude 'strix/interface/tui' strix lyrashield_adapter
uv run bandit -r strix lyrashield_adapter -q
```

Create executable `scripts/check-upstream.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

base_file=".lyrashield-upstream-base"
remote="${UPSTREAM_REMOTE:-upstream}"
output_file="${GITHUB_OUTPUT:-/dev/stdout}"

if [[ ! -s "$base_file" ]]; then
  echo "Missing $base_file" >&2
  exit 2
fi
if ! git remote get-url "$remote" >/dev/null 2>&1; then
  echo "Missing Git remote: $remote" >&2
  exit 2
fi

base_sha="$(tr -d '[:space:]' < "$base_file")"
git fetch "$remote" main --tags >&2
upstream_sha="$(git rev-parse "$remote/main")"

if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
  echo "Recorded upstream base does not name a commit: $base_sha" >&2
  exit 2
fi
if ! git merge-base --is-ancestor "$base_sha" "$upstream_sha"; then
  echo "Recorded upstream base $base_sha is not an ancestor of $upstream_sha; manual reconciliation is required" >&2
  exit 20
fi

{
  printf 'base_sha=%s\n' "$base_sha"
  printf 'upstream_sha=%s\n' "$upstream_sha"
  if [[ "$base_sha" == "$upstream_sha" ]]; then
    printf 'needs_sync=false\n'
  else
    printf 'needs_sync=true\n'
  fi
} >> "$output_file"
```

Rewrite `UPGRADES.md` as a short patch ledger: adapter, telemetry default, Pydantic fix, pre-Docker validation, per-instance binds, worker output compatibility, and current base. Remove the mass-rebrand sync instructions.

- [ ] **Step 4: Run engine gates and commit**

```bash
chmod +x scripts/verify-thin-fork.sh scripts/check-upstream.sh
uv run pytest tests/test_upstream_sync.py -v
scripts/check-upstream.sh
scripts/verify-thin-fork.sh
git add .lyrashield-upstream-base UPGRADES.md scripts tests/test_upstream_sync.py
git commit -m "chore: add engine upstream verification gates"
```

Expected: local check emits `needs_sync=false`; all offline engine checks pass.

## Task 5: Add Weekly PR-Only Automation and Complete Docker Release Gate

**Files:**
- Create: `.github/workflows/upstream-sync.yml`
- Modify: `UPGRADES.md`
- Modify: app `AGENTS.md`, `codebase.md`, `PRD.md`, `NEXT-STEPS.md`

**Interfaces:**
- Consumes: writable `origin`, baseline file, Task 4 scripts, and thin-fork source path.
- Produces: `automation/upstream-<short-sha>` PRs; verified Docker integration; truthful handoff docs.

- [ ] **Step 1: Confirm origin precondition**

```bash
cd /Users/defiankit/Desktop/lyrashield-engine-thin-fork
git remote -v
git remote get-url origin
```

Expected: a writable LyraShield-controlled origin. If absent, commit automation but do not create/publish a remote without explicit owner direction.

- [ ] **Step 2: Add the GitHub workflow**

Create `.github/workflows/upstream-sync.yml`:

```yaml
name: Upstream Engine Sync

on:
  schedule:
    - cron: "23 3 * * 1"
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

concurrency:
  group: upstream-engine-sync
  cancel-in-progress: false

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@v5
      - name: Configure upstream
        run: |
          git remote add upstream https://github.com/usestrix/strix.git 2>/dev/null || true
          git remote set-url upstream https://github.com/usestrix/strix.git
      - id: upstream
        name: Check ancestry
        run: scripts/check-upstream.sh
      - name: Rebase, verify, and open PR
        if: steps.upstream.outputs.needs_sync == 'true'
        env:
          BASE_SHA: ${{ steps.upstream.outputs.base_sha }}
          UPSTREAM_SHA: ${{ steps.upstream.outputs.upstream_sha }}
          GH_TOKEN: ${{ github.token }}
        run: |
          branch="automation/upstream-${UPSTREAM_SHA:0:12}"
          git switch -c "$branch"
          git rebase --onto "$UPSTREAM_SHA" "$BASE_SHA"
          printf '%s\n' "$UPSTREAM_SHA" > .lyrashield-upstream-base
          uv lock
          scripts/verify-thin-fork.sh
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add -A
          git commit -m "sync: rebase engine on upstream ${UPSTREAM_SHA:0:12}"
          git push --set-upstream origin "$branch"
          gh pr create \
            --title "sync: upstream Strix ${UPSTREAM_SHA:0:12}" \
            --body "Automated compatibility rebase. Review engine gates and LyraSec integration before merging." \
            --base "$GITHUB_REF_NAME" \
            --head "$branch"
```

No auto-merge, merge queue, force push, or conflict resolver may be added.

- [ ] **Step 3: Validate the safe no-change path**

```bash
scripts/check-upstream.sh
git diff --check
```

Expected: exit `0` and `needs_sync=false`; a rewritten upstream exits `20` before rebase.

- [ ] **Step 4: Commit automation**

```bash
git add .github/workflows/upstream-sync.yml UPGRADES.md
git commit -m "ci: add review-gated upstream engine sync"
```

- [ ] **Step 5: Build and smoke-test the worker with the thin fork**

```bash
cd /Users/defiankit/Desktop/lyrashieldai
LYRASHIELD_ENGINE_SOURCE=/Users/defiankit/Desktop/lyrashield-engine-thin-fork docker compose build worker
LYRASHIELD_ENGINE_SOURCE=/Users/defiankit/Desktop/lyrashield-engine-thin-fork \
  docker compose run --rm --no-deps worker lyrashield --version
```

Expected: image builds and prints branded version.

- [ ] **Step 6: Prove missing model config fails before runtime pull**

```bash
set +e
LYRASHIELD_ENGINE_SOURCE=/Users/defiankit/Desktop/lyrashield-engine-thin-fork \
  docker compose run --rm --no-deps -e LYRASHIELD_LLM= worker \
  lyrashield --non-interactive --target https://example.invalid > /tmp/lyrashield-no-model.log 2>&1
status=$?
set -e
test "$status" -ne 0
rg -n "LYRASHIELD_LLM|STRIX_LLM" /tmp/lyrashield-no-model.log
! rg -n "Pulling Docker image|Downloading" /tmp/lyrashield-no-model.log
```

Expected: configuration guidance, non-zero status, no image pull.

- [ ] **Step 7: Run the app ladder and controlled authorized scan**

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
git diff --check
test -n "${LYRASHIELD_LLM:-}" || test -n "$(rg -N '^LYRASHIELD_LLM=.+$' .env 2>/dev/null || true)"
test -n "${LLM_API_KEY:-}" || test -n "$(rg -N '^LLM_API_KEY=.+$' .env 2>/dev/null || true)"
```

Expected: all static gates pass. If both config checks pass, run one SAFE scan only against an explicitly authorized target and verify lifecycle, persisted findings, and rendered scan detail. If either fails, do not substitute a public/paid target: record `LLM configuration absent` as the only remaining controlled-scan blocker.

- [ ] **Step 8: Update SSOT and commit**

Update application `AGENTS.md`, `codebase.md`, `PRD.md`, and `NEXT-STEPS.md` with baseline SHA, adapter contract, `strix_runs` support, sandbox evidence, test counts, origin status, and scan result/blocker.

```bash
git add AGENTS.md codebase.md PRD.md NEXT-STEPS.md
git commit -m "docs: record thin engine fork verification"
```

## Final Acceptance Checklist

- [ ] Archive branch preserves the fully rebranded baseline.
- [ ] Thin fork uses recorded upstream and unchanged `strix` internals.
- [ ] `lyrashield --version` works via uv and worker Docker image.
- [ ] Product variables map, upstream variables win, telemetry defaults off.
- [ ] Configuration fails before Docker setup/pull.
- [ ] Worker reads both layouts and keeps `0`/`2`/error lifecycle behavior.
- [ ] Development image is verified; production docs require digest pinning.
- [ ] Frozen sync, Ruff, pytest, headless mypy, Bandit, app lint/type/test/build, and Docker smoke pass.
- [ ] Sync workflow creates reviewed PRs only and rejects rewritten upstream history.
- [ ] Handoff docs record the verified truth and any credential/origin blocker.
