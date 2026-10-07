# Engine core fixes: version lookup, tool pins, proven-dead members

## Summary

The engine looked up the distribution `strix-agent` for its own version. No
build of this project installs that name: `pyproject.toml:2` declares
`lyrashield-engine`. The three wrong call sites therefore always raised
`PackageNotFoundError`, which silently omitted the SARIF `tool.driver.version`
field, showed `dev` in the interactive TUI header and reported `unknown` to
telemetry. One shared helper now resolves the real distribution name with an
explicit fallback, and the three call sites use it.

The pre-commit hook revisions are aligned to the versions `uv.lock` and CI
already resolve, so a local hook can no longer pass lint or formatting the
locked gate rejects. The bandit severity setting in `pyproject.toml` was inert,
and the fix states and enforces the floor the gate actually applies instead of
the medium floor the config only appeared to set.

Seven unreferenced members and files are deleted, each with whole-repo `git
grep` proof. The image-pull deadline test gets a bounded daemon wait and CI
caches the Chromium download.

## Per-change safety proof

Every deletion below was checked with `git grep` across the whole repo
(`lyrashield`, `lyrashield_adapter`, `strix`, `tests`, `scripts`, `docs`,
`pyproject.toml`, `strix.spec`, `.github`, `Makefile`, `UPGRADES.md`,
`README.md`, `CONTRIBUTING.md`, all `*.mdx`).

### 1. `lyrashield/artifacts/usage.py` — `ancillary_cost_total` property

```
$ git grep -n -w ancillary_cost_total
lyrashield/artifacts/usage.py:229:    def ancillary_cost_total(self) -> float:
```

One hit, the definition itself. `total_cost` at `:234` computes the same sum
inline and is unaffected. `_round_cost` and `_ancillary_costs` remain used by
`total_cost`, `to_record` and `reset`, so no supporting symbol was orphaned.

### 2. `lyrashield/artifacts/state.py` — `set_sandbox_cleanup_status`

```
$ git grep -n -w set_sandbox_cleanup_status
lyrashield/artifacts/state.py:630:    def set_sandbox_cleanup_status(self, sandbox_removed: bool) -> None:
```

One hit, the definition itself. The method's own docstring calls it a
backward-compatible wrapper and no caller exists. The real method
`set_cleanup_outcome` keeps its callers (`interface/cli.py:311`,
`lifecycle/finalize.py:126`, plus tests), and `CLEANUP_REMOVED` and
`CLEANUP_FAILED` remain used inside `set_cleanup_outcome` itself.

### 3. `lyrashield/lifecycle/agents.py` — `wait_kind_of`

```
$ git grep -n -w wait_kind_of
lyrashield/lifecycle/agents.py:285:    async def wait_kind_of(self, agent_id: str) -> WaitKind | None:
strix/core/agents.py:214:    async def wait_kind_of(self, agent_id: str) -> WaitKind | None:
```

The only other hit is the upstream substrate twin, which is a controlled
derivative boundary and was not touched. No `lyrashield/`, test or script
caller exists. The `wait_kinds` dict and `WaitKind` type stay in use by
`park_waiting`, snapshot and restore.

### 4. `lyrashield/interface/utils.py` — `process_pull_line` shim

```
$ git grep -n 'process_pull_line' -- lyrashield tests scripts docs pyproject.toml strix.spec .github Makefile
lyrashield/interface/image_pull.py:169: ... process_pull_line(payload, layers_info, status, last_update)
lyrashield/interface/image_pull.py:320: ... process_pull_line(line, layers_info, status, last_update)
lyrashield/interface/image_pull.py:358: def process_pull_line(
lyrashield/interface/main.py:42:    process_pull_line,  # noqa: F401
lyrashield/interface/utils.py:586: def process_pull_line(
lyrashield/interface/utils.py:589:     from lyrashield.interface.image_pull import process_pull_line as _process_pull_line
lyrashield/interface/utils.py:591:     return _process_pull_line(line, layers_info, status, last_update)
tests/test_image_digest.py:13:    process_pull_line,
tests/test_image_digest.py:79:     update = process_pull_line(...)
tests/test_main_helper_exports.py:21:        ("process_pull_line", "image_pull", "process_pull_line"),
```

The only removed hits are the three `utils.py` lines. The test imports come
from `lyrashield.interface.main`, which re-exports the real
`image_pull.process_pull_line` at `main.py:42`. `tests/test_main_helper_exports.py:21`
asserts that `main` re-exports the `image_pull` implementation and still passes.
The other stub in the same file, `update_layer_status`, is a different function
and was left alone.

### 5. `scripts/docker.sh`

```
$ git grep -n -F 'docker.sh'
(no output)
```

Zero references anywhere in the repo. The script also builds `strix-sandbox`,
a different image name from the product one. The remaining 11 files in
`scripts/` are referenced by CI, the Makefile, tests or docs.

### 6. `.trivyignore.yaml` — root `Dockerfile` path

```
$ ls Dockerfile
ls: cannot access 'Dockerfile': No such file or directory
```

Only `containers/Dockerfile` exists. The `AVD-DS-0002` rule and its
`containers/Dockerfile` path are unchanged, so the reviewed trust-boundary
decision still applies to the real file.

### 7. `strix.spec` — `tenacity` hidden import

```
$ git grep -n -i 'tenacity' -- strix.spec pyproject.toml lyrashield strix
strix.spec:99:    # Tenacity retry
strix.spec:100:    'tenacity',
$ grep -n '^name = "tenacity"' uv.lock
(no hit)
$ ls .venv/lib/python3.14/site-packages/ | grep -i tenacity
(not installed)
$ git grep -n 'import tenacity\|from tenacity'
(no importer)
```

`tenacity` is absent from `pyproject.toml`, absent from `uv.lock`, not
installed, and imported nowhere. `containers/python-requirements.txt` pins it
for the sandbox image, which is a separate environment from the frozen engine
binary and is untouched. `strix.spec` is at the repo root, outside `strix/**`.

## Tests added

All new tests were made to fail locally before their fix and pass after.

| Test | Failed before with |
| --- | --- |
| `tests/test_engine_version.py::test_sarif_write_path_emits_tool_driver_version` | `KeyError: 'version'` — `_write_report_projections` resolved the wrong distribution, so `sarif.py:262` omitted `driver.version` |
| `tests/test_engine_version.py::test_sarif_write_path_still_omits_version_when_metadata_is_absent` | passed only after the fallback existed; drives the real projection chain with metadata unavailable |
| `tests/test_engine_version.py::test_engine_version_falls_back_when_distribution_is_missing` | `PackageNotFoundError` escaped the old call sites |
| `tests/test_engine_version.py::test_engine_version_survives_a_broken_metadata_backend` | a frozen loader raises something other than `PackageNotFoundError` |
| `tests/test_quality_environments.py::test_precommit_hooks_use_the_locked_tool_versions` | `AssertionError: 'v0.11.13' == 'v0.15.20'` |
| `tests/test_quality_environments.py::test_bandit_severity_floor_is_enforced_by_the_invocation` | `AssertionError: 'severity' in {... 'severity': 'medium'}` |
| `tests/test_release_build.py::test_binary_does_not_request_missing_hidden_imports` | `AssertionError` — `'tenacity'` present in the spec |
| `tests/test_release_build.py::test_every_spec_hidden_import_is_a_declared_or_installed_distribution` | `AssertionError: ... ['tenacity']` |

The SARIF regression is the one that matters. `tests/test_sarif.py:60` passes
`tool_version` explicitly, so it could never catch a broken lookup. The new test
drives `ReportState._write_report_projections`, the production call chain that
resolves the version itself, and reads the written `findings.sarif`.

Existing behaviour is unchanged for the four lookups that were already correct
(`interface/arg_parser.py:40`, `lifecycle/runner.py:129`,
`tools/proxy/caido_api.py:678`, `lyrashield_adapter/cli.py:158`). They were not
edited.

## Bandit: how the intent was verified and why medium was rejected

The config key was inert. Verified with the installed bandit 1.9.4:

```
$ uv run python -c "from bandit.core.config import BanditConfig; c=BanditConfig('pyproject.toml'); print(repr(c.get_option('severity')))"
'medium'

$ uv run bandit -c pyproject.toml -f json /tmp/bandittest/mix.py | python -c "import json,sys; print(sorted({(r['test_id'], r['issue_severity']) for r in json.load(sys.stdin)['results']}))"
[('B311', 'LOW'), ('B602', 'LOW')]

$ uv run bandit -c pyproject.toml -ll -f json /tmp/bandittest/mix.py | python -c "import json,sys; print(sorted({(r['test_id'], r['issue_severity']) for r in json.load(sys.stdin)['results']}))"
[]
```

Bandit parses the key and never applies it as a filter. Only the `-l/--level`
CLI flag filters. The fixture is a temporary file outside the repo, and the
whole-repo run is unaffected:

```
$ uv run bandit -r strix lyrashield_adapter lyrashield -q -c pyproject.toml -f json   # default
0 findings
$ uv run bandit -r strix lyrashield_adapter lyrashield -q -c pyproject.toml -l -f json
0 findings
```

Enforcing medium would weaken the gate, which the brief forbids. The LOW rules
enabled by the current skip list are `B311`, `B403`, `B405`, `B406`, `B407`,
`B408`, `B409`. Their ruff equivalents `S403` and `S405`-`S409` are
**preview-only** in the locked ruff 0.15.20 and this repo does not enable
preview:

```
$ uv run ruff rule S403 | head -4
# suspicious-pickle-import (S403)
Derived from the **flake8-bandit** linter.
This rule is in preview and is not stable. The `--preview` flag is required for use.

$ grep -n 'preview' pyproject.toml
(no setting)
```

So a medium floor would drop seven rules and leave six of them with no
replacement check at all. The applied fix states the real floor and enforces it:

- `pyproject.toml`: the inert `severity = "medium"` key is removed, replaced by
  a comment recording the verified behaviour and why medium is rejected.
- `Makefile` `security`, `.pre-commit-config.yaml` and
  `scripts/verify-controlled-derivative.sh`: `-l` added.

No severity threshold was lowered, no rule was skipped and no suppression was
added. `-l` is behaviourally identical to bandit's default: no rule in bandit
1.9.4 carries `UNDEFINED` severity, so the default `UNDEFINED` floor and the
`LOW` floor select the same rules. `-l` makes the floor explicit rather than
changing it.

## Gates run

| Command | Result |
| --- | --- |
| `uv sync --frozen` | ok |
| `uv run ruff check .` | All checks passed |
| `uv run ruff format --check .` | 448 files already formatted |
| `uv run mypy strix lyrashield_adapter lyrashield` | Success: no issues found in 251 source files |
| `uv run bandit -r strix lyrashield_adapter lyrashield -q -c pyproject.toml -l` | exit 0 |
| `uv run pytest tests/` (all 152 test modules plus `tests/tui` and `tests/upstream`, run in chunks) | 3088 passed, 5 skipped, 2 failed — both environmental, see below |
| `scripts/verify-controlled-derivative.sh` footprint and digest steps | `4 files changed, 22 insertions(+), 201 deletions(-)`; patch digest `3629e8f382fdd8eccf78553b102a25e99c73454c` matches |
| `python scripts/verify-customer-branding.py` | Customer branding gate passed |
| `uv run pre-commit validate-config .pre-commit-config.yaml` | ok |
| `python3 scripts/report_twin_drift.py` | runs clean |

Two failures, both pre-existing and environmental, neither touched by this
change:

1. `tests/test_quality_environments.py::test_precommit_and_make_run_the_same_type_check`
   — `make` is not installed in this sandbox.
2. `tests/test_local_sources.py::test_clone_repository_checks_out_a_full_commit_sha_detached`
   — this sandbox's git cannot resolve the detached test SHA.

The brief lists both as environmental. The three historical pytest failures
remain unreproduced and were not "fixed".

## PROTECTED

- **Pins**: no pin bumped. `ENGINE_REVISION`, the engine
  `.lyrashield-worker-pin` and every dependency cap (openai, litellm,
  openai-agents, cryptography) are untouched. `uv.lock` is unchanged.
- **strix footprint**: `git diff --shortstat "$(cat .lyrashield-upstream-base)" -- strix/`
  returns `4 files changed, 22 insertions(+), 201 deletions(-)`, unchanged. The
  reviewed patch digest `3629e8f382fdd8eccf78553b102a25e99c73454c` matches. No
  file under `strix/**` was edited. `strix.spec` is at the repo root, outside
  `strix/**`.
- **Controlled-derivative boundary**: AST-identical upstream twins were left
  alone. `strix/core/agents.py:214 wait_kind_of` is the upstream twin of the
  member removed on the product side; the upstream file was not touched. Nothing
  from the E2/E3 candidate lists beyond the seven proven-dead items was deleted.
- **Ruff**: 0.15.20 is what the lock already had. No upgrade, no new
  suppression, no per-file ignore added. `ruff 0.16.6` (engine PR #139) stays
  open and held.
- **Customer branding gate**: `scripts/customer-branding-allowlist.json` loses
  four entries that named the removed `strix-agent` lookups. Leaving them would
  have exempted the exact lines this change removes. The gate passes, and the
  remaining inherited-identifier exemptions are unchanged.
- **Viewer, Windows, image and controlled-derivative coverage**: the CI change
  adds a cache step only. Every step name, `if` condition and required check is
  unchanged, and the cache key falls back to a per-OS restore key so a miss
  still downloads.

## Not done

- **No broad flaky-test rewrite.** The image-pull test keeps its intent; only
  the daemon-reach wait is bounded and documented.
- **No enforcement of a medium bandit floor.** Verified to weaken the gate, so
  it was rejected rather than applied. Details above.
- **`email_validator` in `strix.spec`** is also absent from `uv.lock` and the
  installed environment, like `tenacity`. It is a pre-existing pydantic optional
  extra, outside the reviewed deletion set, so it was recorded in the new test's
  `known_absent` set rather than removed. Flagging it for a separate decision.
- **A real PyInstaller frozen build could not run** in this sandbox: PyInstaller
  requires `objdump` from `binutils`, which is not installable here. The
  available substitute was run instead: parsing `strix.spec` and resolving all
  115 `hiddenimports` entries with `importlib.util.find_spec` under
  `uv run --frozen --extra viewer` leaves only `email_validator` unresolved and
  no `tenacity`. The frozen-build check therefore remains an operator step.
- **The full `verify-controlled-derivative.sh` did not run to completion** as one
  command: its pytest stage exceeds the 120-second sandbox command cap. Its
  footprint and digest invariants were run directly and pass, and its full pytest
  stage was run in chunks with the same suite and `-W error::pydantic.PydanticDeprecatedSince211`
  semantics; the bandit, ruff, mypy and format stages it wraps were each run
  individually and pass.
- **Local TUI members** (`_encrypt`, `profile_for`, `update_run_status`,
  `iter_runs`, `KEYCHAIN_CHATGPT_TOKEN`) were not deleted. They are in the E2/E3
  candidate list but not in this workstream's approved deletion set.

## Rollback

Code only, forward-only for any schema. Revert this PR.

Generated with Claude Code
