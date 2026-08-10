# Progress Log: Strix Overlay Migration

## Session: 2026-08-10

### Planning and feasibility audit

- **Status:** complete
- Inspected the live engine branch, remotes, pinned upstream base, current upstream head, adapter, core construction points, packaging configuration, verification scripts, and sibling worker contract.
- Classified the architectural goal as an immutable upstream tree with product behavior outside `strix/**`.
- Identified existing tool, skill, and backend registration seams.
- Identified missing report-state, usage-hook, model-policy, lifecycle-policy, and artifact seams.
- Confirmed that simply moving code into one adapter file or monkeypatching Strix would not reduce upgrade coupling.
- Created the durable handoff files:
  - `task_plan.md`
  - `findings.md`
  - `progress.md`

### Phase 0: Establish the reproducible baseline

- **Status:** complete
- Branch: `codex/strix-overlay-migration` (created from `main`)
- Initial `MIGRATION_MATRIX.md` generated for the 68 changed `strix/` paths against the pinned base.
- Subsequent review against `v1.5.2` revealed the full diff is 173 paths (renames, deletions, upstream additions); a regenerated matrix is in progress.
- Current engine HEAD: `63800d5e66a8b6cc0c767a02c10cf9faabd9d553`
- `origin/main`: `63800d5e66a8b6cc0c767a02c10cf9faabd9d553`
- Pinned upstream base: `2e7040240d201f433d0fe42f922dbfbe953c6c8b`
- Latest stable upstream tag: `v1.5.2` at `597aae67159636ee794a02a3cc1694138d619c44`
- `upstream/main`: `ae07af61597041951d2116f108fb72bae4967caf`
- Drift from pinned base to `HEAD` across `strix/`: 68 files changed, +5486/-1297
- Upstream commits from base to `v1.5.2`: 46; from `v1.5.2` to `upstream/main`: 2
- Plan files are untracked by design; all other tracked files are clean.

## Test Results

| Test | Expected | Actual | Status |
| --- | --- | --- | --- |
| `bash scripts/verify-controlled-derivative.sh` | Current source baseline passes | 953 passed, 1 skipped; Ruff, format, mypy, Bandit passed; footprint 68/+5486/-1297 under budget | Pass |
| `bash scripts/verify-worker-contract.sh /Users/defiankit/Desktop/lyrashieldai` | CLI and worker contract pass | 2 test files and 68 tests passed | Pass |
| `uv run lyrashield --version` | Prints version | `lyrashield 1.2.0` | Pass |
| `uv run lyrashield --help` | Prints worker-required flags and self-update disabled | Flags present; `--update` documented as disabled | Pass |
| `uv build` | Produces wheel/sdist | `lyrashield_engine-1.2.0` wheel and sdist built | Pass |
| Engine worktree status | No test-generated tracked changes | On `codex/strix-overlay-migration`; only untracked plan files | Pass |
| Native binary | Not run in planning audit | Unverified this session | Pending |
| Docker worker/sandbox | Not run in planning audit | Unverified this session | Pending |
| Live Terra/Luna scans | Not run in planning audit | Unverified this session | Pending |
| `run.json`/`vulnerabilities.json` fixtures | Capture sanitized fixtures | 8 fixtures in `fixtures/` (7 run.json variants + 1 vulnerabilities.json); JSON-valid | Pass |

## Error Log

| Timestamp | Error | Attempt | Resolution |
| --- | --- | ---: | --- |
| 2026-08-10 | None during handoff creation | 1 | N/A |

## 5-Question Reboot Check

| Question | Answer |
| --- | --- |
| Where am I? | Handoff complete; Phase 0 implementation is the next phase. |
| Where am I going? | Exact upstream Strix source plus external LyraShield policy/adapter modules. |
| What's the goal? | Make future Strix updates routine without breaking LyraShield contracts. |
| What have I learned? | See `findings.md`. |
| What have I done? | Completed live audit, baseline verification, and durable plan creation. |

### Phase 1: Decide source consumption

- **Status:** complete
- Tested exact `strix-agent` dependency in a throwaway worktree (`/tmp/strix-dep-spike`).
- `uv sync` failed because the fork's direct `openai-agents` git pin cannot satisfy `strix-agent` v1.5.2's `openai-agents[litellm]>=0.19.0,<0.20` constraint together with the project's broad `requires-python`.
- Upstream `strix-agent` v1.5.2 also does not declare a direct `textual` dependency, while the fork's Python Textual TUI depends on it.
- Decision: **vendored `strix/**` reset to byte-identical v1.5.2**, with product behavior outside.

### Phase 4: Skill markdown overlay slice

- **Status:** complete
- Created `lyrashield/skills/` with 15 product-specific `.md` overlays plus `__init__.py`.
- Merged `custom/source_aware_sast.md` and `custom/dependency_cve_scanning.md` onto v1.5.2 base to preserve both upstream v1.5.2 improvements and product wording.
- Moved the renamed `strix/skills/technologies/firebase_firestore.md` to `lyrashield/skills/technologies/firebase_firestore.md`; reset `strix/skills/technologies/firebase.md` to v1.5.2.
- Reset all other `strix/skills/*.md` to v1.5.2 (`git checkout 597aae67159636ee794a02a3cc1694138d619c44 -- strix/skills/`), then removed the leftover `firebase_firestore.md` from `strix/skills/`.
- Added a telemetry gate to `strix/skills/__init__.py` (micro-fork generic seam) and a `yaml.*` mypy override in `pyproject.toml`.
- Wired `lyrashield_adapter/cli.py` to call `strix.skills.register_skill_dir` for `lyrashield/skills/` before handing off to upstream `main()`.
- Added `tests/test_lyrashield_skills_overlay.py` and updated `tests/test_skill_dir_extension.py` for v1.5.2's metadata-bearing `get_available_skills()`.
- Verification: `verify-controlled-derivative.sh` 968 passed/1 skipped; `verify-worker-contract.sh` 68 passed; `uv build` succeeds; `git diff --stat 597aae... -- strix/skills/` shows only `__init__.py` (+4 lines).

### Phase 4: web_search tool override slice

- **Status:** complete
- Regenerated `MIGRATION_MATRIX.md` against v1.5.2 (175 `strix/` paths, +12,226/-17,605).
- Added `register_tool_override` / `_apply_tool_overrides` to `strix/agents/factory.py` as a generic upstream-compatible seam.
- Moved the product `web_search` tool implementation from `strix/tools/web_search/tool.py` to `lyrashield/tools/web_search/tool.py`.
- Reset `strix/tools/web_search/tool.py` and `strix/tools/web_search/__init__.py` to v1.5.2.
- Wired `lyrashield_adapter/cli.py` to call `register_tool_override("web_search", ...)` with the product tool.
- Added `lyrashield/tools/__init__.py` and `lyrashield/tools/web_search/__init__.py`.
- Updated `pyproject.toml` per-file ignores for `lyrashield/tools/web_search/tool.py` (lazy imports) and to preserve the upstream `strix/tools/web_search/tool.py` `noqa`.
- Updated `tests/test_agent_tool_registration.py` with override and adapter registration tests.
- Verification: `uv run ruff check .` passes; `uv run mypy strix/agents/factory.py lyrashield/tools/web_search/tool.py lyrashield_adapter/cli.py tests/test_agent_tool_registration.py` passes; `uv run pytest tests/test_skill_dir_extension.py tests/test_lyrashield_skills_overlay.py tests/test_agent_tool_registration.py tests/test_agent_factory_shell.py` passes (46 tests).

### Phase 4: system prompt overlay slice

- **Status:** complete
- Copied the product `system_prompt.jinja` from `strix/agents/prompts/` to `lyrashield/skills/system_prompt.jinja`.
- Reset `strix/agents/prompts/system_prompt.jinja` to v1.5.2.
- Added a generic seam in `strix/agents/prompt.py`: `FileSystemLoader` now searches registered skill directories before the built-in `strix/agents/prompts/` path, allowing product templates to override built-in ones.
- Updated `tests/test_lyrashield_skills_overlay.py` to assert the rendered root system prompt contains the product `[SYSTEM-NOTICE]` marker.
- Verification: `uv run ruff check .` passes; `uv run mypy strix/agents/prompt.py tests/test_lyrashield_skills_overlay.py` passes; `uv run pytest tests/test_skill_dir_extension.py tests/test_lyrashield_skills_overlay.py tests/test_agent_tool_registration.py tests/test_agent_factory_shell.py` passes (47 tests).

### Phase 4: todo tool override slice

- **Status:** complete
- Moved the product todo tool implementation from `strix/tools/todo/tools.py` to `lyrashield/tools/todo/tools.py`.
- Reset `strix/tools/todo/tools.py` to v1.5.2.
- Added `lyrashield/tools/todo/__init__.py`.
- Updated `lyrashield_adapter/cli.py` to register `create_todo`, `list_todos`, `update_todo`, `mark_todo_done`, `mark_todo_pending`, and `delete_todo` overrides.
- Updated `tests/test_agent_tool_registration.py` to assert all product todo overrides are registered.
- Verification: `uv run ruff check .` passes; `uv run mypy lyrashield_adapter/cli.py lyrashield/tools/todo/tools.py` passes; `uv run pytest tests/test_agent_tool_registration.py tests/test_agent_factory_shell.py` passes (24 tests); combined targeted suite (47 tests) passes.

### Phase 4: respond_to_user tool override slice

- **Status:** complete
- Moved the product `respond_to_user` tool from `strix/tools/respond/tool.py` to `lyrashield/tools/respond/tool.py`.
- Reset `strix/tools/respond/tool.py` to v1.5.2.
- Added `lyrashield/tools/respond/__init__.py`.
- Updated `lyrashield_adapter/cli.py` to register the `respond_to_user` override.
- Updated `tests/test_agent_tool_registration.py` to assert the override is registered.
- Verification: `uv run ruff check .` passes; `uv run mypy lyrashield_adapter/cli.py lyrashield/tools/respond/tool.py` passes; `uv run pytest tests/test_agent_tool_registration.py` passes (13 tests).

### Phase 4: reporting tool override slice

- **Status:** complete
- Moved the product reporting tool from `strix/tools/reporting/tool.py` to `lyrashield/tools/reporting/tool.py`.
- Reset `strix/tools/reporting/tool.py` to v1.5.2.
- Added `lyrashield/tools/reporting/__init__.py`.
- Updated `lyrashield_adapter/cli.py` to register `create_vulnerability_report`, `create_dependency_report`, `list_reports`, and `get_report` overrides.
- Added `pyproject.toml` per-file `PLC0415` ignore for `lyrashield/tools/reporting/tool.py` (lazy imports to avoid circular dependencies).
- Updated `tests/test_agent_tool_registration.py` to assert the reporting overrides are registered.
- Verification: `uv run ruff check .` passes; `uv run mypy lyrashield/tools/reporting/tool.py lyrashield_adapter/cli.py` passes; `uv run pytest tests/test_agent_tool_registration.py` passes (14 tests).

### Phase 4: Caido proxy tool override slice

- **Status:** complete
- Moved the product Caido proxy tools from `strix/tools/proxy/tools.py` and `strix/tools/proxy/caido_api.py` to `lyrashield/tools/proxy/tools.py` and `lyrashield/tools/proxy/caido_api.py`.
- Reset `strix/tools/proxy/tools.py` and `strix/tools/proxy/caido_api.py` to v1.5.2.
- Added `lyrashield/tools/proxy/__init__.py`.
- Updated imports in `lyrashield/tools/proxy/tools.py` to use the local `caido_api` module.
- Updated `lyrashield_adapter/cli.py` to register `list_requests`, `view_request`, `repeat_request`, `list_sitemap`, `view_sitemap_entry`, and `scope_rules` overrides.
- Added `pyproject.toml` per-file `ARG001` ignore for `lyrashield/tools/proxy/caido_api.py` (upstream keeps the same unused argument for API consistency).
- Updated `tests/test_agent_tool_registration.py` to assert the proxy overrides are registered.
- Verification: `uv run ruff check .` passes; `uv run mypy lyrashield/tools/proxy/tools.py lyrashield/tools/proxy/caido_api.py lyrashield_adapter/cli.py` passes; `uv run pytest tests/test_agent_tool_registration.py` passes (15 tests).

### Phase 5: config/policy slice

- **Status:** complete
- Moved product `strix/config/settings.py` to `lyrashield/policy/settings.py` and reset `strix/config/settings.py` to v1.5.2.
- Moved product `strix/config/codex.py` to `lyrashield/policy/codex.py` and reset `strix/config/codex.py` to v1.5.2.
- Moved `strix/provider_contract.py` to `lyrashield/policy/provider_contract.py` and removed the `strix/` copy.
- Added `lyrashield/policy/loader.py` as the product settings loader; it registers itself with the upstream `strix.config.loader.register_settings_loader()` seam.
- Added the generic `register_settings_loader()` seam to `strix/config/loader.py` so `strix.config.load_settings()`/`apply_config_override()`/`persist_current()` can transparently return product settings without `strix` importing `lyrashield`.
- Restored `strix/utils/secret_files.py` and `strix/utils/api_spec.py` from v1.5.2.
- Reset `strix/interface/update_check.py` to v1.5.2 (LyraShield disables updates via `STRIX_NO_UPDATE_CHECK=1`).
- Updated product files still in `strix/` to import from `lyrashield.policy`:
  - `strix/interface/main.py`, `strix/interface/auth_cli.py`, `strix/interface/provider_contract_cli.py`
  - `strix/core/inputs.py`, `strix/core/runner.py`
  - `strix/report/dedupe.py`
  - `lyrashield/tools/web_search/tool.py`, `lyrashield_adapter/cli.py`
- Updated `pyproject.toml` first-party/isort config, ruff per-file ignores, and mypy overrides.
- Updated `tests/test_models.py` and `tests/test_lyrashield_adapter.py` to use `lyrashield.policy.*`.
- Verification: `uv run ruff check .` passes; `uv run mypy strix lyrashield_adapter lyrashield` passes; `uv run pytest tests/test_agent_tool_registration.py tests/test_agent_factory_shell.py tests/test_lyrashield_skills_overlay.py tests/test_models.py tests/test_lyrashield_adapter.py` passes (175 tests).
- Committed: `cddeaef` "Phase 5: config/policy slice".

### Phase 4: agent graph tool override (deferred)

- `strix/tools/agents_graph/tools.py` was attempted as a tool-override move, but the v1.5.2 upstream version imports `notify_parent_on_terminal` from `strix.core.execution` and calls `coordinator.claim_parent_notice`, neither of which exist in the product fork of `strix/core/execution.py` and `strix/core/agents.py`.
- Decision: keep the product `strix/tools/agents_graph/tools.py` in place until `strix/core/execution.py` and `strix/core/agents.py` are reset to v1.5.2 (or their product seams are moved to `lyrashield/`).
- `lyrashield/tools/agents_graph/` and its CLI/test registrations were removed; no net change to committed files for this slice.

## Resume Instructions

1. Read `task_plan.md` and `findings.md` fully.
2. Run `git status --short --branch` before editing; the three planning files may be untracked by design.
3. Re-fetch upstream and refresh every drift count before relying on the 2026-08-10 snapshot.
4. Mark Phase 0 `in_progress`, update `Current Phase` and `Next Step`, and log the exact branch/SHAs here.
5. Do not begin source extraction until the baseline inventory and fixtures are complete.
