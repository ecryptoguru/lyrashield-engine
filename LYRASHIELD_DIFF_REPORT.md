# LyraShield Engine Product-Boundary Diff Report

- **Fork HEAD:** `b59a7c31`
- **Pinned upstream base:** `2e7040240d`
- **Latest upstream:** `a51ca18`
- **Scope:** 59 product-boundary files

## Major themes

1. Product entry point
2. GPT-5.6 gating
3. Web search
4. Redaction/privacy
5. AI audit trust boundaries
6. Cost/budget
7. Telemetry
8. Worker artifact contract
9. Deduplication

## Stats

- **Base diff:** 7,168 insertions, 1,363 deletions over base
- **Upstream drift:** 10 files
- **Net vs latest upstream:** 40 files


# LyraShield Entry Points and Product Boundary — Diff Summary

Base: `2e7040240d` → HEAD: `b59a7c31e07e4c5dd8a9cd61043ee34677afa460`

## 1. New `lyrashield/` package (policy placeholders)

### `lyrashield/README.md` (new, lines 1–9)
- Adds package README stating the package is the intended home for product-critical policy (GPT-5.6 gating, environment aliases, telemetry/update defaults, worker artifact contract). Notes that `strix/` still contains the stable implementation while the package is intentionally minimal.

### `lyrashield/__init__.py` (new, lines 1–6)
- Adds module docstring for the `lyrashield` package; references `UPGRADES.md` for the ownership boundary and migration plan.

## 2. `lyrashield_adapter/cli.py` (new, lines 1–186)

Whole file is the product entry-point adapter that wraps the upstream `strix` CLI.

- **Attribution / entry point role**  
  Docstring labels this as the "Product boundary for the upstream Strix CLI".

- **Constants / env-var aliases (lines 34–92)**
  - `_SUBSCRIPTION_PREFIX = "chatgpt/"`
  - `ENV_ALIASES` derived at import time by `_build_env_aliases()` walking `strix.config.settings.Settings` and picking `AliasChoices` that include a `LYRASHIELD_*` variant.
  - `_STALE_EMPTY_ENV_VARS = ("LLM_API_KEY", "LLM_API_BASE", "LLM_API_VERSION")`
  - `_MODEL_ENV_VARS_UPSTREAM = ("STRIX_LLM", "STRIX_DELEGATE_LLM", "STRIX_DEDUPE_MODEL")`
  - `_MODEL_ENV_VARS_PRODUCT` and `_MODEL_ENV_VARS` union upstream + product-specific aliases.

- **`prepare_environment(env)` (lines 97–122)**
  - Pops stale empty generic LLM env vars before pydantic alias resolution.
  - Copies `LYRASHIELD_*` values to their upstream `STRIX_*` counterparts when the upstream var is unset.
  - Sets `STRIX_TELEMETRY = "0"`.
  - Sets `STRIX_NO_UPDATE_CHECK = "1"`.
  - Sets `LYRASHIELD_PRODUCT_BOUNDARY = "1"`.
  - Calls `_reject_subscription_models(env)` and `_reject_unsupported_gpt56_providers(env)`.

- **`_reject_subscription_models(env)` (lines 119–137)**
  - Iterates `_MODEL_ENV_VARS` and `raise SystemExit` if a value starts with `chatgpt/`, unless `is_chatgpt_subscription_allowed(env)` returns `True`.

- **`_reject_unsupported_gpt56_providers(env)` (lines 139–164)**
  - Lazily imports `is_gpt56_model` and `is_gpt56_supported_provider` from `strix.config.models`.
  - Raises `SystemExit` if any configured model is a GPT-5.6 model but the provider is not supported.

- **`get_version()` / `main()` (lines 167–191)**
  - `get_version()` uses `importlib.metadata.version("lyrashield-engine")`.
  - `main()` handles `--version` / `-v` and prints `lyrashield {version}`.
  - Optionally loads `.env` with `override=False`.
  - Calls `prepare_environment()` then lazily imports and runs `strix.interface.main.main`.

## 3. `pyproject.toml`

- **Project identity (lines 1–13)**
  - `name` changed from `strix-agent` to `lyrashield-engine`.
  - `version` changed to `1.2.0`.
  - `description` changed to "LyraShield AI scan engine, based on Strix".
  - Adds `maintainers = [{ name = "LyraShield" }]`.

- **Dependencies (lines 38–53)**
  - `openai-agents[litellm]` pinned to a direct git reference (`git+https://github.com/openai/openai-agents-python.git@f663a06aea...`).
  - `openai` version bumped to `>=2.48.0,<2.49`.
  - `reportlab>=4.0` and `pypdf>=5.0` removed from base deps.

- **Optional dependencies (lines 55–61)**
  - New `viewer` extra with `reportlab>=4.0` and `pypdf>=5.0`, noted as lazy-loaded by the local viewer only.

- **Console script (lines 63–64)**
  - `strix = "strix.interface.main:main"` replaced by `lyrashield = "lyrashield_adapter.cli:main"`.

- **Build configuration (lines 85–93)**
  - `packages = ["strix", "lyrashield_adapter", "lyrashield"]`.
  - `[tool.hatch.metadata] allow-direct-references = true`.

- **Type checking (lines 92–161)**
  - Mypy `exclude` adds `strix/interface/tui` and `tests`.
  - `warn_redundant_casts = false` and `disable_error_code = ["redundant-cast"]`.
  - Pygments added to untyped-module overrides.
  - Pyright `typeCheckingMode` changed from `strict` to `basic`; comment explains mypy is the required gate.

- **Ruff lint (lines 214–322)**
  - New ignores: `PLR0917`, `PLR0911`.
  - `BLE001` added to per-file ignores for `auth_cli.py`, `update_check.py`, `session_manager.py`.
  - `PLC0415` for `viewer/transcript.py`, `runtime/session_manager.py`.
  - `PLR0912` for `core/execution.py`.
  - `strix/tools/web_search/tool.py` gets `PLC0415`.
  - `strix/interface/main.py` override unchanged.

## 4. `strix/interface/main.py`

### Attribution and imports (line 2, lines 7–64)
- Adds banner `# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)`.
- Adds `re`, `tempfile`, `Any`, `cast`.
- Imports `ImageNotFound` from `docker.errors`.
- Imports `Settings`, `is_chatgpt_subscription_allowed`, `is_lyrashield_product` from `strix.config.settings`.
- Imports `is_gpt56_supported_provider` from `strix.config.models`.
- Removes `persist_current` and removes `update_check` imports (`is_binary_install`, `notify_update`, `prompt_update_if_available`, `self_update`, `start_background_check`); adds `validate_run_name` from `utils`.

### New subscription re-check (lines 92–118)
- Adds `_reject_resolved_subscription_models(settings, console)`.
- Rejects `chatgpt/` models after `--config` is applied, with an opt-out only for `STRIX_LLM` when `settings.product.allow_chatgpt_subscription` is set; delegate/dedupe still rejected.

### `validate_environment()` gate (lines 121–278)
- Calls `_reject_resolved_subscription_models(settings, console)` at the start.
- Rejects ChatGPT-subscription `STRIX_LLM` unless `allow_chatgpt_subscription` is set; error text points to `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=1`.
- Adds a hard provider gate for main, delegate, and dedupe models using `is_gpt56_supported_provider()`; error banner states "LyraShield scans require a GPT-5.6 Terra or Luna deployment from a supported provider".
- Missing-variable messaging now uses `STRIX_LLM or LYRASHIELD_LLM`, `LLM_API_KEY`, `LLM_API_BASE`, `STRIX_REASONING_EFFORT / LYRASHIELD_REASONING_EFFORT`, and example `openai/gpt-5.6-luna`.
- Removes `PERPLEXITY_API_KEY` from missing optional vars.

### `warm_up_llm()` warm-up token capture (lines 372–443+)
- New `usages: list[tuple[str, Any]] | None = None` parameter.
- Calls `StrixProvider(settings=settings).get_model(...)` instead of `StrixProvider().get_model(...)`.
- Appends `(model, response.usage)` to `usages` after main and dedupe model warm-up.
- Imports `dedupe_extra_args` (renamed from `_dedupe_extra_args`).

### `get_version()` (line 556)
- Returns `version("lyrashield-engine")` instead of `version("strix-agent")`.

### `parse_arguments()` changes (lines 587–794)
- `--update` help text changed to state that self-update is disabled and exits with code 1.
- `--max-budget` keeps `--max-budget-usd` alias.
- New `--run-name` argument validated by `validate_run_name`.
- `--resume` now also validated by `validate_run_name`.
- `--resume` and `--run-name` cannot be combined.

### Target and resume hardening (lines 754–979)
- Adds typed `target_strs`, `target_list_paths`, `mount_paths`, `targets_info` variables.
- `_load_resume_state()`:
  - Validates the resolved run directory is under `runs_base_dir()`.
  - Rejects symlinks for `run.json`, `agents.json`, `agents.db`.
  - Validates `targets_info` is a list of dicts.
  - Validates cloned repo paths are under `(tempfile.gettempdir() / "strix_repos")` and not symlinks.

### `display_completion_message()` (lines 986–1063)
- Removed `notify_update(console)` call; comment notes upstream update notice would suggest the wrong package for LyraShield Engine.

### `pull_docker_image()` digest verification (lines 1065–1156)
- Adds `_normalize_digest(value)` and `_verify_image_digest(client, image, expected_digest)`.
- Reads `STRIX_IMAGE_DIGEST` env var; re-pulls if local image digest does not match.

### `main()` orchestration (lines 1175–1354)
- Auto-loads engine `.env` with `override=False`.
- `auth` subcommand is blocked when `is_lyrashield_product()` is true and `is_chatgpt_subscription_allowed()` is false.
- New `provider-contract` subcommand is dispatched to `strix.interface.provider_contract_cli.run_provider_contract`.
- Removes `start_background_check()` and `prompt_update_if_available()` calls.
- Calls `validate_environment()` before Docker setup.
- Skips LLM warm-up in non-interactive runs; otherwise runs `warm_up_llm(show_model_warning=False, usages=warm_up_usages)` and attaches `args.warm_up_usages`.
- `args.run_name = args.resume or args.run_name or generate_run_name(...)`.
- Telemetry calls to `posthog.start(...)` and `scarf.start(...)` expanded to explicit keyword args.
- Unhandled exceptions call `_exit_noninteractive_failure(non_interactive=args.non_interactive)`.
- New `_non_interactive_exit_code(report_state)` mapping: `0/2` completed, `3` budget_exceeded, `4` rate_limited, `5` otherwise.
- New `_exit_noninteractive_failure(non_interactive)` raises `SystemExit(1) from None` for non-interactive runs.

## 5. `strix/interface/cli.py`

- **Attribution banner (line 1)**
  - `# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)`.

- **Safe failure labeling (lines 30–43)**
  - New `_SAFE_PROVIDER_ERROR_COMPONENT` regex.
  - New `_noninteractive_failure_label(exc)` extracts a safe `ExceptionName.<code/type/param>` label from provider exception bodies.

- **`run_cli()` non-interactive mode (lines 55–267)**
  - Reads `non_interactive = bool(getattr(args, "non_interactive", False))`.
  - Skips the startup panel when non-interactive.
  - Vulnerability display logs `Finding recorded: id=%s severity=%s` in non-interactive mode instead of printing a panel.
  - Records `warm_up_usages` as SDK usage with `agent_id="warmup"`.
  - Extracts `execute_scan()` helper.
  - Uses separate `try/finally` paths for non-interactive vs `Live` TUI.
  - On exception, non-interactive logs a redacted failure label and re-raises; interactive prints the error.
  - Final report panel only printed in interactive mode.

## 6. `strix/interface/auth_cli.py`

- **Attribution banner and imports (lines 1–29)**
  - Adds `# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)`.
  - Imports `is_chatgpt_subscription_allowed` and `is_lyrashield_product` from `strix.config.settings`.

- **`run_auth()` product gate (lines 49–56)**
  - Immediately returns `1` with "LyraShield does not support ChatGPT subscription authentication." when `is_lyrashield_product()` and not `is_chatgpt_subscription_allowed()`.

- **Ruff / signature cleanups (around lines 143, 171, 220)**
  - Removes redundant `BLE001` noqa comments.
  - Adds `format` parameter name to `Handler.log_message` and `noqa: A002`.

## 7. `strix/interface/provider_contract_cli.py` (new, lines 1–76)

- Attribution banner on line 1.
- New subcommand implementation for `lyrashield provider-contract`.
- Helpers:
  - `_positive_int(value)` (1–128)
  - `_positive_float(value)` (>0)
  - `build_parser()` — adds flags:
    - `--config`
    - `--max-output-tokens`
    - `--timeout-seconds`
    - `--require-programmatic-tool-calling`
    - `--require-previous-response-id`
  - `run_provider_contract(argv)` — applies config override, runs `probe_provider_contract()` from `strix.provider_contract`, prints JSON result, and returns non-zero if requirements are not met.

## 8. `strix/interface/update_check.py`

- **Attribution and imports (lines 1–34)**
  - Adds banner.
  - `import subprocess  # nosec B404`
  - Imports `is_lyrashield_product` from `strix.config.settings`.

- **`_is_disabled()` (lines 50–58)**
  - Adds `or is_lyrashield_product()` so LyraShield never runs the upstream update/self-update checks.

- **Security linting comments (lines 103–382)**
  - Removes redundant `BLE001` noqa markers.
  - Adds `# nosec B110` and `# nosec B603` comments for bandit.

## 9. `strix/interface/tui/renderers/web_search_renderer.py`

- **Attribution and imports (lines 1–14)**
  - Adds banner.
  - Adds `from __future__ import annotations` and `import json`.

- **`WebSearchRenderer.render()` (lines 21–59)**
  - Reads `status` from `tool_data` instead of hardcoding `"completed"`.
  - Parses `result` from JSON string if needed.
  - Uses `args.get("query") or args.get("search_query")` to fetch the query.
  - Renders `Search` with `bold #f59e0b` style.
  - Displays result `content` (first 500 chars), `success=False` message, or `No results returned` / `Searching...`.
  - Uses `cls.get_css_classes(status)` for the widget classes.

## 10. Cross-cutting product-boundary themes

| Theme | Where enforced | Key names |
|---|---|---|
| Product entry point | `lyrashield_adapter/cli.py` | `main()`, `prepare_environment()` |
| Process marker | `lyrashield_adapter/cli.py`, `strix/config/settings.py` | `LYRASHIELD_PRODUCT_BOUNDARY=1`, `is_lyrashield_product()` |
| Env alias bridge | `lyrashield_adapter/cli.py` | `_build_env_aliases()`, `ENV_ALIASES`, `LYRASHIELD_*` → `STRIX_*` |
| ChatGPT subscription rejection | `lyrashield_adapter/cli.py`, `strix/interface/main.py`, `strix/interface/auth_cli.py` | `_SUBSCRIPTION_PREFIX="chatgpt/"`, `_reject_subscription_models()`, `_reject_resolved_subscription_models()`, `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION`, `is_chatgpt_subscription_allowed()` |
| GPT-5.6 provider gating | `lyrashield_adapter/cli.py`, `strix/interface/main.py` | `is_gpt56_supported_provider()`, `is_gpt56_model()`, `_reject_unsupported_gpt56_providers()` |
| Telemetry off | `lyrashield_adapter/cli.py` | `STRIX_TELEMETRY=0` |
| Self-update off | `lyrashield_adapter/cli.py`, `strix/interface/main.py`, `strix/interface/update_check.py` | `STRIX_NO_UPDATE_CHECK=1`, `--update` disabled, `notify_update()` removed, `is_lyrashield_product()` disables checks |
| Attribution banners | 6 of 10 files | `# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)` |
| Lazy imports | `lyrashield_adapter/cli.py`, `strix/interface/main.py` | `_run_upstream()` imports, subcommand dispatch in `main()`, `_reject_unsupported_gpt56_providers()` imports, `.env` import |
| Web search TUI | `strix/interface/tui/renderers/web_search_renderer.py` | `WebSearchRenderer.render()` |
| New `provider-contract` subcommand | `strix/interface/main.py`, `strix/interface/provider_contract_cli.py` | `run_provider_contract()`, `--max-output-tokens`, `--timeout-seconds`, `--require-programmatic-tool-calling`, `--require-previous-response-id` |
| Non-interactive worker contract | `strix/interface/main.py`, `strix/interface/cli.py` | `--non-interactive`, `_non_interactive_exit_code()`, `_exit_noninteractive_failure()`, `_noninteractive_failure_label()` |


---

# Hunk-level diff summary: Model and provider gating

**Theme:** LyraShield product-boundary changes for GPT-5.6 model/provider gating, `LYRASHIELD_*` environment aliases, and web search configuration.

**Base:** `2e7040240d` (upstream Strix)  
**Head:** `b59a7c31e0` (current LyraShield HEAD)

Files analyzed:

- `strix/config/models.py`
- `strix/config/settings.py`
- `strix/config/codex.py`
- `strix/config/loader.py`
- `strix/config/__init__.py`

Each section follows the `git diff --unified=2 2e7040240d..HEAD -- <file>` hunk order.

---

## `strix/config/models.py`

### Hunk `@@ -1,2 +1,3` — module banner
- Adds copyright line: `Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)`.

### Hunk `@@ -6,6 +7,8` — imports
- Adds `import re` and `import threading`.
- Adds `cast` to the `typing` import.

### Hunk `@@ -56,4 +59,95` — GPT-5.6 model / provider / programmatic-tool gating
This is the core model-gating block. Three new public helpers are introduced:

- `is_gpt56_model(model_name: str | None) -> bool`
  - Returns `True` only for Terra or Luna GPT-5.6 deployments.
  - Regex `(?:^|[/.-])gpt-5\.6-(?:terra|luna)(?:$|[/.-])` allows provider namespacing such as `azure/eu/gpt-5.6-luna` or `bedrock_mantle/openai.gpt-5.6-luna`.
  - Rejects retired or unsupported tiers at startup before budget enforcement.

- `_GPT56_SUPPORTED_PROVIDERS: frozenset[str]`
  - Allowed LiteLLM provider markers: `openai`, `azure`, `azure_ai`, `bedrock_mantle`, `chatgpt`.

- `is_gpt56_supported_provider(model_name: str | None) -> bool`
  - Combines `is_gpt56_model` with the provider allow-list.
  - Lets bare model names and `chatgpt/` prefixes pass through.
  - Strips `litellm/` and `any-llm/` passthrough prefixes before checking provider parts.

- `model_supports_programmatic_tool_calling(model_name: str | None) -> bool`
  - The actual function implementing the requested `is_programmatic_tool_calling_allowed` gate; there is no separate `is_programmatic_tool_calling_allowed` symbol.
  - Reads `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING` or `STRIX_PROGRAMMATIC_TOOL_CALLING`.
  - Enabled by default only for direct `openai/` GPT-5.6 deployments.
  - Explicit `1/true/yes` enables it for any GPT-5.6 model; `0/false/no` disables it.
  - Azure AI `azure_ai/gpt-5.6-*` requires explicit opt-in.

### Hunk `@@ -84,12 +178,12` — `_CodexResponsesModel._codex_settings` reasoning clamp
- Replaces `match`/`case` with explicit `if/elif` and a `cast("ReasoningEffort", effort)` fallback.
- Clamps `minimal` → `low` and `xhigh`/`max` → `high`.

### Hunk `@@ -97,4 +191,6` — `_CodexResponsesModel._fetch_response` kwargs handling
- Applies `_codex_settings` to `kwargs["model_settings"]` when present, in addition to the positional arg handling.

### Hunk `@@ -141,5 +237,5` — `_CodexResponsesModel.__aexit__`
- Wraps `await aclose()` in `cast("Any", aclose())`.

### Hunk `@@ -275,4 +371,30` — `StrixProvider.__init__`
- Adds constructor accepting `settings: Settings | None`.
- Detects Azure GPT-5.6 by checking both `model` and `delegate_model` via `_is_azure_model` and `is_gpt56_model`.
- When `_azure_responses_enabled` is set, requires `llm.api_base` and initializes the parent `MultiProvider` with `openai_api_key`, `openai_base_url=_azure_responses_base_url(llm.api_base)`, and `openai_use_responses=True`.

### Hunk `@@ -282,4 +404,14` — `StrixProvider._resolve_prefixed_model`
- Adds `azure` and `azure_ai` prefix handling for the Azure v1 Responses API.
- Extracts the final deployment/model segment (`rsplit("/", 1)[-1]`) and routes it through `self.openai_provider`.

### Hunk `@@ -293,5 +425,7` — `StrixProvider.get_model`
- Caches the resolved `Settings` in `self._settings` instead of calling `load_settings()` on every model lookup.

### Hunk `@@ -310,4 +444,14`
- Adds `_azure_responses_base_url(api_base: str) -> str`.
- Normalizes an Azure resource endpoint, appending `/openai/v1/` when not already present.
- Raises `RuntimeError` for an empty API base.

### Hunk `@@ -327,26 +471,6`
- Trims `RECOMMENDED_MODEL_NAMES` from a broad multi-provider list to only:
  - `openai/gpt-5.6-luna`
  - `openai/gpt-5.6-terra`

### Hunk `@@ -366,23 +490,69` — SDK-wide model default lifecycle
- Adds `_sdk_config_lock` and `_last_sdk_settings` for memoized, thread-safe configuration.
- Adds `reset_sdk_model_defaults()`:
  - Clears `codex._subscription_client`.
  - Resets `litellm.api_key`, `litellm.api_base`, `litellm.api_version`, `litellm.headers`.
  - Sets the default OpenAI key to empty and API mode to `responses`.
- Rewrites `configure_sdk_model_defaults(settings)`:
  - Guards against duplicate application with the same `Settings` object.
  - Calls `reset_sdk_model_defaults()` before applying new values.
  - Applies `api_version` via `_configure_litellm_default`.
  - Avoids setting `OPENAI_BASE_URL` for Azure models and keeps them on the `responses` path.
  - Calls the new `_mirror_azure_env` helper.
- Adds `_is_azure_model(model_name: str | None) -> bool`:
  - Strips `litellm/` / `any-llm/` prefixes and checks for `azure/` or `azure_ai/`.

### Hunk `@@ -398,10 +568,40` — API-key and Azure env mirroring
- Refactors `_mirror_api_key_to_provider_env`:
  - Casts `litellm.validate_environment` result to `dict[str, Any]`.
  - Iterates `missing_keys` safely with `isinstance` checks.
- Adds `_mirror_azure_env(model_name, api_base, api_version)`:
  - Sets `AZURE_API_BASE`, `AZURE_AI_API_BASE`, `AZURE_API_VERSION`, and `AZURE_AI_API_VERSION` when the model routes through Azure.

### Hunk `@@ -476,5 +676,5`
- Adjusts `_configure_openrouter_attribution` to read `litellm.headers` via `getattr` and type it as `dict[str, str] | None`.

### Hunk `@@ -549,4 +749,8` — `uses_chat_completions_tool_schema`
- Adds an early `False` return when `model_supports_programmatic_tool_calling(model_name)` is true, keeping Azure on the JSON-function-tool path unless explicitly opted in.

### Hunk `@@ -559,4 +763,9`
- Adds `_model_cost_entry(model_cost, name) -> dict[str, Any] | None`, a safe cast wrapper for `litellm.model_cost` lookups.

### Hunk `@@ -567,8 +776,9` — `model_supports_reasoning`
- Casts `litellm.model_cost` and uses `_model_cost_entry` for the cost-map lookup.

### Hunk `@@ -651,6 +861,7` — `is_known_openai_bare_model`
- Uses `_model_cost_entry` and explicit `entry is not None` check.

---

## `strix/config/settings.py`

### Hunk `@@ -1,12 +1,24` — banner, imports, and `_lyra` alias helper
- Adds copyright line.
- Adds `import os`, `TYPE_CHECKING` guard for `Mapping`, and `Any`/`Literal` typing.
- Adds `field_validator` to the pydantic imports.
- Adds `_lyra(upstream: str) -> AliasChoices`:
  - Generates an `AliasChoices` pair: the original `STRIX_*` name and a LyraShield-branded `LYRASHIELD_*` name.
  - Used pervasively across all settings classes.

### Hunk `@@ -18,11 +30,71` — product boundary, ChatGPT gating, and `LlmSettings`
- Adds `PRODUCT_BOUNDARY_ENV_VAR = "LYRASHIELD_PRODUCT_BOUNDARY"`.
- Adds `is_lyrashield_product() -> bool` (truthy for `1`, `true`, or `yes`).
- Adds `is_chatgpt_subscription_allowed(environ) -> bool`:
  - Case-insensitive lookup of `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION` and `STRIX_ALLOW_CHATGPT_SUBSCRIPTION`.
  - Default enabled; disabled by `0`, `false`, `no`, or `off`.
- `LlmSettings` changes:
  - `model` now uses `validation_alias=_lyra("STRIX_LLM")`.
  - New `delegate_model` field with `validation_alias=_lyra("STRIX_DELEGATE_LLM")`.
  - `api_key` adds `AZURE_OPENAI_API_KEY` and `AZURE_AI_API_KEY` aliases.
  - `api_base` adds `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_BASE`, `AZURE_AI_API_BASE` aliases.
  - New `api_version` field with `LLM_API_VERSION`, `AZURE_API_VERSION`, `AZURE_OPENAI_API_VERSION`.
  - `extra_headers` adds `LYRASHIELD_EXTRA_HEADERS` alias.
  - `reasoning_effort` default changed from `high` to `medium`, alias `_lyra("STRIX_REASONING_EFFORT")`.
  - New `delegate_reasoning_effort` default `medium`, alias `_lyra("STRIX_DELEGATE_REASONING_EFFORT")`.
  - `prompt_cache` uses `_lyra("STRIX_PROMPT_CACHE")`.
  - `disable_streaming` adds `LYRASHIELD_DISABLE_STREAMING`.
  - `force_required_tool_choice` uses `_lyra("STRIX_FORCE_REQUIRED_TOOL_CHOICE")`.
  - `timeout` adds `LYRASHIELD_LLM_TIMEOUT`.
  - New `max_output_tokens` and `max_input_tokens` with `_lyra` aliases.
  - Adds `_empty_env_to_none` `field_validator` for `api_base`, `api_key`, `api_version` to coerce empty string values to `None`.

### Hunk `@@ -59,11 +175,30` — `DedupeSettings`
- `model` and `reasoning_effort` gain `validation_alias=_lyra(...)` while keeping their old `alias` for compatibility.
- `api_key` adds `LYRASHIELD_DEDUPE_LLM_API_KEY`.
- `api_base` adds `LYRASHIELD_DEDUPE_LLM_API_BASE`.
- Adds `_empty_env_to_none` validator for `api_base` and `api_key`.

### Hunk `@@ -77,16 +217,43` — `ContextSettings`
- All fields converted to `validation_alias=_lyra(...)`:
  - `auto_compact`, `compact_buffer_tokens`, `keep_tokens`, `fallback_context_tokens`, `summary_max_tokens`, `tool_output_max_tokens`, `tool_output_max_lines`, `tool_output_max_bytes`.

### Hunk `@@ -96,15 +263,32` — `RuntimeSettings`
- All fields converted to `validation_alias=_lyra(...)`:
  - `image` (default also changed from `ghcr.io/usestrix/strix-sandbox:1.1.0` to `strix-sandbox:dev`), `backend`, `max_local_copy_mb`, `max_context_images`.
- New `server_conversation` bool, alias `_lyra("STRIX_SERVER_CONVERSATION")`, default `False`.

### Hunk `@@ -112,11 +296,8` — telemetry and integrations
- `TelemetrySettings.enabled` default changed to `False`; alias `_lyra("STRIX_TELEMETRY")`.
- Removes `IntegrationSettings` and its `perplexity_api_key` field.

### Hunk `@@ -127,5 +308,96` — `ViewerSettings`, `WebSearchSettings`, `ProductSettings`, and `Settings`
- `ViewerSettings.app_url` adds `validation_alias=_lyra("STRIX_APP_URL")` while keeping the old `alias`.
- Adds `WebSearchSettings` for live Parallel Search OSINT:
  - `enabled`, `provider` (only `"parallel"`), `api_key`, `api_base`, `mode` (`"turbo"`, `"basic"`, `"advanced"`).
  - Budget and cost controls: `max_results`, `max_chars_total`, `max_calls_per_scan`, `budget_usd`, `turbo_cost_per_call`, `basic_cost_per_call`, `advanced_cost_per_call`.
  - Key aliases: `LYRASHIELD_WEB_SEARCH_API_KEY`, `PARALLEL_API_KEY`, `STRIX_WEB_SEARCH_API_KEY`, plus `_lyra`-generated `STRIX_WEB_SEARCH_*` / `LYRASHIELD_WEB_SEARCH_*` pairs.
  - `_empty_env_to_none` validator for `api_base` and `api_key`.
- Adds `ProductSettings`:
  - `allow_chatgpt_subscription` with aliases `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION` and `STRIX_ALLOW_CHATGPT_SUBSCRIPTION`.
- `Settings` composite model:
  - Removes `integrations: IntegrationSettings`.
  - Adds `product: ProductSettings` and `web_search: WebSearchSettings`.

---

## `strix/config/codex.py`

### Hunk `@@ -1,2 +1,3`
- Adds LyraShield copyright line.

### Hunk `@@ -21,5 +22,5`
- Adds `cast` to the `typing` import.

### Hunk `@@ -59,4 +60,11`
- Adds `_as_str_mapping(value: Any) -> dict[str, Any] | None`, a safe `dict[str, Any]` cast helper.

### Hunk `@@ -64,5 +72,7`
- `_read_store` now casts its parsed data to `dict[str, Any]`.

### Hunk `@@ -79,6 +89,6`
- `read_record` uses `_as_str_mapping` on the `PROVIDER` record.

### Hunk `@@ -189,6 +199,6`
- Adds `# nosec B105` comments to the hard-coded `id_token_add_organizations` and `codex_cli_simplified_flow` OAuth query parameters in `build_authorize_url`.

### Hunk `@@ -222,4 +232,5`
- Cosmetic blank line added before `_post_form` body.

### Hunk `@@ -237,5 +248,5`
- `_post_form` casts its parsed JSON response to `dict[str, Any]`.

### Hunk `@@ -304,14 +315,17`
- `_account_id_from_jwt` casts `payload` and uses `_as_str_mapping` when reading the `_ACCOUNT_CLAIM` and the first `organizations` entry.

---

## `strix/config/loader.py`

### Hunk `@@ -1,2 +1,3`
- Adds LyraShield copyright line.

### Hunk `@@ -8,5 +9,5`
- Adds `cast` to the `typing` import.

### Hunk `@@ -61,5 +62,5`
- `persist_current` uses `type(s).model_fields` instead of `s.model_fields`.

### Hunk `@@ -102,7 +103,11`
- `_read_json_overrides` casts both the top-level `data` and the nested `env_block` to `dict[str, Any]` after type checks.

---

## `strix/config/__init__.py`

### Hunk `@@ -4,7 +4,6`
- Updates module docstring: removes `IntegrationSettings` from the public-surface list.

### Hunk `@@ -17,8 +16,11`
- Adds imports of `configure_sdk_model_defaults` and `reset_sdk_model_defaults` from `strix.config.models`.
- Removes `IntegrationSettings` from `strix.config.settings` imports.

### Hunk `@@ -31,5 +33,4`
- Updates `__all__`: removes `IntegrationSettings`; adds `configure_sdk_model_defaults` and `reset_sdk_model_defaults`.


---

# LyraShield product-boundary diff report — Core runtime and budgets

- **Base:** `2e7040240d`
- **Head:** `b59a7c31e0` (`HEAD`)
- **Files:** `strix/core/hooks.py`, `strix/core/runner.py`, `strix/core/inputs.py`, `strix/core/agents.py`, `strix/core/execution.py`, `strix/core/sessions.py`

This report summarizes the LyraShield-specific hunks versus the pinned upstream Strix base. It focuses on cost/budget enforcement, web search reservations, prompt-injection sanitization, trust boundaries, context compaction, and lifecycle checks.

---

## `strix/core/hooks.py`

Cost modeling, pre-request budget reservation, context compaction, and trusted budget/turn warnings.

- **Header & imports** (`@@ -1,13 +1,19@@`) — adds the LyraShield copyright line, `asyncio`, `functools`, `json`, `Callable`, `cast`, and imports `_take_prefix` / `_take_suffix` from `strix.tools.output_store`.

- **Compaction & cost constants** (`@@ -20,4 +26,347@@` → new lines 31–77)
  - `MODEL_INPUT_COMPACTION_TRIGGER_TOKENS = 96_000` and `MODEL_INPUT_COMPACTION_TARGET_TOKENS = 64_000`
  - `_COMPACTION_NOTICE` user message explaining history compaction
  - `_COMPACTED_ITEM_MAX_BYTES = 64_000` and `_GPT56_LONG_CONTEXT_TOKENS = 272_000`
  - `_SYSTEM_NOTICE_TAG = "[SYSTEM-NOTICE]"` — trusted prefix for system-injected warnings
  - `_GPT56_RATES` / `_GPT56_CACHED_RATES` for `terra` and `luna` tiers
  - Conservative fallbacks: `_DEFAULT_FALLBACK_INPUT_RATE`, `_DEFAULT_FALLBACK_OUTPUT_RATE`, `_DEFAULT_FALLBACK_CACHE_RATE`
  - `_LONG_CONTEXT_SAFETY_MARGIN_TOKENS = 32_000`, `_COMPACTION_TARGET_RATIO`, `_MIN_COMPACTION_TARGET_TOKENS`

- **`resolve_compaction_thresholds`** (line 80) — clamps a caller-supplied `max_input_tokens` ceiling to `272_000 - 32_000` so the scan cannot accidentally enter the 2× input billing region. Returns `(trigger, target)`.

- **Model rate lookup** (`_model_rates` line 114, `_cached_input_rate` line 123, `_fallback_model_rates` line 132, `_fallback_cached_input_rate` line 154, `_lookup_litellm_cost` line 173)
  - `_model_rates` matches `terra`/`luna` substrings, otherwise falls back to LiteLLM `model_cost`.
  - Rates are returned in dollars per 1M tokens; unknown models use deliberately over-estimated defaults so budget enforcement errs on the side of not overspending.

- **Usage & cost helpers**
  - `_usage_value` (line 204), `_cached_tokens_from_entry` (line 212), `_usage_cost_upper_bound` (line 223)
  - `_usage_cost_upper_bound` walks `request_usage_entries`, applies a 2.0× multiplier to input costs above 272k tokens and a 1.5× multiplier to output costs in the long-context regime, and includes cached-token pricing.

- **Context compaction helpers**
  - `_compact_item` (line 242) serializes an item and truncates oversized JSON with `_take_prefix` / `_take_suffix`, adding an `...[older item compacted]...` marker.
  - `_item_type` (line 256) and `_history_groups` (line 263) keep tool-call/output pairs in the same compaction unit so providers never see orphaned outputs.
  - `_estimate_input_tokens` (line 289) uses `litellm.token_counter` when available, else UTF-8 bytes as a conservative ceiling, and adds a 4096-token pad.
  - `_compact_input_items` (line 319) does an O(log n) binary search over suffix groups to keep the first item, the `_COMPACTION_NOTICE`, and the most recent complete groups under the target token budget.

- **Active-hooks registry** (`@@ -32,4 +381,21@@` → lines 379–398)
  - `set_active_hooks` / `get_active_hooks` (lines 386–396) expose the running `ReportUsageHooks` so out-of-band calls (deduplication, web search) can reserve the same budget.

- **`ReportUsageHooks.__init__`** (`@@ -118,4 +484,6@@` / `@@ -129,4 +497,12@@` → line 481)
  - Adds `max_output_tokens` and `max_input_tokens` parameters.
  - Stores `resolve_compaction_thresholds(max_input_tokens)` in `self._compaction_thresholds`.
  - Adds `asyncio.Lock` `_reservation_lock`, `_reservations: dict[str, float]`, and `_committed_cost_floor: float`.

- **Out-of-band and web-search reservation APIs** (`@@ -138,16 +514,94@@` → lines 511–596)
  - `reserve_out_of_band_request` (line 516) — reserves token-based cost for direct LLM calls (e.g. deduplication) using `_model_rates` and long-context multipliers; raises `BudgetExceededError`.
  - `release_out_of_band_request` (line 554) — drops the reservation and adds `_usage_cost_upper_bound` to `_committed_cost_floor`.
  - `reserve_web_search_call` (line 561) — reserves a fixed per-call `estimated_cost` directly against `max_budget_usd`.
  - `release_web_search_call` (line 589) — drops the reservation and commits `actual_cost`.
  - `compaction_trigger_tokens` / `compaction_target_tokens` properties (lines 598–606).

- **Trusted budget/turn warnings** (`@@ -169,5 +623,6@@` through `@@ -213,5 +670,6@@` → lines 607–678)
  - `_maybe_warn_turns` and `_maybe_warn_budget` now prefix every injected warning with `_SYSTEM_NOTICE_TAG` so the model treats them as system-verified and ignores look-alike user/peer content.
  - Warnings are appended directly to `input_items` as `{"role": "user", "content": ...}` items.

- **`on_llm_start`** (`@@ -220,4 +678,76@@` → line 700)
  - Injects turn/budget warnings, then calls `_compact_input_items` to shrink history before the request.
  - Computes a per-agent reservation with `_model_rates`, long-context multipliers, and `self._agent_max_output_tokens(agent)`, then stores it under the `agent_id` key in `_reservations` if the total committed + reserved cost is within `max_budget_usd`.

- **`on_llm_end`** (`@@ -227,27 +757,28@@` → line 752)
  - Records SDK usage with `report_state.record_sdk_usage` using the resolved agent model (`_agent_model`).
  - Removes the agent reservation and updates `_committed_cost_floor` with `_usage_cost_upper_bound(model, response.usage)`.
  - Re-evaluates `max_budget_usd`: raises `BudgetExceededError` or `SubagentBudgetReservedError` for non-root sub-agents at the configured reserve fraction.

---

## `strix/core/runner.py`

Scan orchestration wiring: model/delegate routing, prompt-cache and output-token caps, prompt-injection hardening, server-managed conversations, terminal-state tracking.

- **Imports & top-level constants** (`@@ -1,2 +1,3@@`, `@@ -4,4 +5,5@@`, `@@ -9,8 +11,10@@`, `@@ -32,10 +36,19@@`, `@@ -51,11 +64,55@@`)
  - Adds `hashlib`, `PackageNotFoundError/version`, `ModelBehaviorError`, `set_active_hooks`, `_prompt_cache_explicit_enabled`, `_sanitize_prompt_value`, `build_root_initial_input`, `prompt_cache_options_for_model`.
  - `TYPE_CHECKING` now imports `Session` instead of `SQLiteSession`.
  - New constants: `_MODE_AGENT_LIMITS`, `_MODE_OUTPUT_TOKEN_LIMITS`, `_DEFAULT_OUTPUT_TOKENS`, `DELEGATE_OUTPUT_TOKEN_CEILING = 8_192`.

- **`resolve_max_output_tokens`** (line 83) — maps `quick/standard/deep` scan mode to `4_096 / 8_192 / 16_384` output tokens, allowing `LYRASHIELD_MAX_OUTPUT_TOKENS` to override.

- **`_engine_version`** (line 96) — returns the installed `lyrashield-engine` version or `"development"`.

- **`_coordinator_for_scan_mode`** (line 103) — creates or constrains the `AgentCoordinator` to the per-mode `max_agents` limit.

- **Prompt-injection / trust-boundary sanitization**
  - `_merge_root_prompt_context` (line 119) passes every string `extra_system_prompt_context` value through `_sanitize_prompt_value` and sanitizes list-of-strings.
  - `_compose_root_instructions_override` (line 144) is now non-optional, sanitizes the override with `_sanitize_prompt_value(..., max_len=8192)`, and wraps it in `<root_scan_instructions_override>` with explicit trust-boundary language.

- **`run_strix_scan`** (line 175)
  - Resolves `delegate_model` and `delegate_reasoning_effort` from settings, with separate `chat_completions_tools` flags for coordinator and delegate (lines 232–246).
  - Resume safety checks: `agents_path` and `agents_db` must be regular files, not symlinks (lines 220–227).
  - Applies `_coordinator_for_scan_mode` (line 259).
  - Builds `initial_input` using `build_root_initial_input(scan_config, model_name=resolved_model)` when not resuming (line 339–346).
  - Creates two `ModelSettings` via `make_model_settings`: one for the root with `prompt_cache_key=f"lyrashield:{scan_id}:coordinator"` and `prompt_cache_options_for_model(resolved_model)`, and one for delegates capped at `DELEGATE_OUTPUT_TOKEN_CEILING` with `prompt_cache_key=f"lyrashield:{scan_id}:delegates"` (lines 347–372).
  - `RunConfig.model_provider=StrixProvider(settings=settings)` (line 375).
  - `ReportUsageHooks` now receives `max_output_tokens` and `max_input_tokens` (lines 380–387).
  - `set_active_hooks(hooks)` (line 391); cleared in `finally` (line 669).
  - Records run metadata in `report_state.run_record` including `engine_version`, `prompt_bundle_hash`, `model`, `delegate_model`, `reasoning_effort`, `max_output_tokens`, `compaction_trigger_tokens`, `compaction_target_tokens`, and `max_agents` (lines 405–429).
  - Builds root and delegate `build_strix_agent` with explicit `model` and `model_settings` (lines 439–461).
  - Propagates `server_conversation` from `settings.runtime.server_conversation` to `spawn_child_agent`, `respawn_subagents`, `_start_child_runner`, and `open_agent_session` (lines 464–513).
  - Resume + budget pause: calls `coordinator.resume_from_budget_pause()` when appropriate (line 293–294).
  - `ModelBehaviorError` / `content_filter` fallback: if explicit prompt caching triggers a content-filter error, it disables `prompt_cache_options`, rebuilds the root agent, and retries once (lines 556–602).
  - Final output safety: checks `scan_completed`, logs only the output type (not content) when incomplete, and records `terminal_reason="incomplete"` (lines 603–629).
  - Clean shutdown: `coordinator.mark_shutting_down()`, `cancel_descendants`, sets root to `completed`, records `terminal_reason` for `budget_exceeded` / `rate_limited`, and closes sessions generically (lines 630–679).

---

## `strix/core/inputs.py`

Input builders, Jinja/control-character sanitization, prompt-cache breakpoint support, and bounded child-agent handoff.

- **Jinja tag sanitization** (`@@ -22,8 +26,56@@` → lines 33–49)
  - `_JINJA_TAG_RE` matches `{{...}}`, `{%...%}`, `{#...#}`.
  - `_CONTROL_CHAR_RE` matches ASCII control characters.
  - `_sanitize_prompt_value(value, *, max_len=4096)` strips both patterns, trims, and truncates to `max_len`.

- **Prompt-cache gating** (lines 62–78)
  - `_PROMPT_CACHE_EXPLICIT_ENV = "LYRASHIELD_PROMPT_CACHE_EXPLICIT"`
  - `_prompt_cache_explicit_enabled(model_name)` returns `True` only when the env var is enabled and `is_gpt56_model(model_name)`.
  - `prompt_cache_options_for_model` returns `{"mode": "explicit", "ttl": "30m"}` or `None`.

- **Model/tool-call compatibility helpers**
  - `_supports_parallel_tool_calls_setting` (line 91) returns `False` for `azure_ai/gpt-5.6-*`, causing `parallel_tool_calls` to be omitted (not `false`) and avoiding Azure 400 errors.

- **Hardened type coercion** (`_as_str_dict` line 107, `_as_str_list_of_dicts` line 111) for `targets` and `diff_scope`.

- **Task / initial input builders**
  - `_build_root_task_parts` (line 118) now returns `(parts, user_instructions)` separately and coerces target fields to `int`/`str` safely.
  - `build_root_task` (line 179) returns the single string version.
  - `build_root_initial_input` (line 188) emits a prompt-cache breakpoint message when explicit caching is enabled, splitting the stable task prefix from variable user instructions.
  - `build_scope_context` (line 221) now sanitizes every target value with `_sanitize_prompt_value`.

- **`make_model_settings`** (line 251)
  - Adds `max_output_tokens`, `prompt_cache_key`, and `prompt_cache_options` parameters.
  - Stores `prompt_cache_key` in `extra_args` and conditionally omits `parallel_tool_calls` for Azure.

- **`child_initial_input`** (line 333)
  - Truncates inherited parent history to `MAX_CHILD_INHERITED_HISTORY_BYTES = 24 * 1024` bytes and prefixes a notice that older history is omitted.

---

## `strix/core/agents.py`

Coordinator lifecycle, agent limits, parent/child trust-boundary messages, conversation-ID tracking for server sessions, and safer snapshots.

- **State constants** (lines 23–36)
  - `_ACTIVE_STATUSES = frozenset({"running", "waiting"})`
  - `_SNAPSHOT_SCHEMA` declares expected types for `statuses`, `parent_of`, `names`, `metadata`, `conversation_ids`, etc.

- **`AgentCoordinator.__init__`** (line 66)
  - Adds `max_agents: int = 64`, `conversation_ids: dict[str, str]`, `_snapshot_lock: asyncio.Lock`, and `self.max_agents`.

- **Safe lock-wrapped accessors** (lines 88–115)
  - `can_spawn_agent`, `get_status`, `get_parent_and_name`, `agents_with_metadata`, `maybe_snapshot` replace direct `_lock` access elsewhere.

- **Registration & status handling**
  - `register` (line 200) enforces `max_agents` before adding a new agent.
  - `mark_running` (line 241) only transitions statuses in `_ACTIVE_STATUSES`.
  - `set_status` (line 298) is typed to the `Status` Literal and no longer accepts arbitrary strings.

- **`consume_pending`** (line 358)
  - Wraps message conversion in `try/except`; if conversion fails it re-queues to the mailbox and snapshots.
  - Returns messages to the caller without persisting if no SDK `session` is attached.
  - Wraps `session.add_items` in `session_write_lock`; on failure re-queues messages and snapshots.

- **Parent notification on terminal states** (line 411)
  - `_notify_parent(agent_id, status, content=None)` sends a high-priority peer message to the parent for `crashed/failed/stopped/completed`, except when `budget_stopped`.

- **`request_stop` & `cancel_descendants`** (lines 444–479)
  - `request_stop` records whether the agent was active, notifies the parent if so, and sets status to `stopped`.
  - `cancel_descendants` now sets descendant statuses to `stopped` and wakes their parents after cancelling tasks.

- **Trust-boundary peer message wrapping** (`@@ -429,6 +551,9@@` → line 539)
  - `_message_to_session_item` now emits `[SYSTEM-VERIFIED PEER MESSAGE | id=... | from=... | type=... | priority=...]` and adds explicit instructions for the model to treat the metadata as system-verified while evaluating the content critically.

- **`track_conversation_id`** (line 571)
  - Captures `session.session_id` for `OpenAIConversationsSession` into `self.conversation_ids` so resumed/respawned agents can reuse server-managed conversations.

- **Snapshot / restore** (lines 590–629)
  - `snapshot` includes `conversation_ids`.
  - `restore` validates all `_SNAPSHOT_SCHEMA` entries and raises `TypeError` for unexpected types, then restores `conversation_ids`.
  - `_maybe_snapshot` uses `_snapshot_lock` and safely unlinks the temp file after `replace`.

---

## `strix/core/execution.py`

Agent execution loop: server-conversation propagation, lifecycle status checks, compaction model-provider passthrough, safe final-output logging, and `session_write_lock`.

- **Imports / types** (`@@ -1,2 +1,3@@`, `@@ -7,5 +8,5@@`, `@@ -33,4 +34,5@@`, `@@ -43,5 +45,5@@`)
  - Adds `session_write_lock` import; `TYPE_CHECKING` uses `Session` not `SQLiteSession`; `Sized` from `collections.abc`.

- **`_compact_session`** (line 101)
  - Extracts `model_provider` and `settings` from `run_config` and passes them into `maybe_compact`.

- **`_salvage_stream_to_session`** (line 160)
  - Calls `replace_session_items(..., expected_len=len(pre_run_items))` to detect unexpected length changes.

- **`run_agent_loop`** (line 178)
  - Calls `coordinator.consume_pending(agent_id)` before the run.
  - After lifecycle, fetches current status and returns early if the agent is not `running`/`waiting` (lines 241–244).

- **Child / subagent spawning** (lines 300–448)
  - `spawn_child_agent`, `respawn_subagents`, and `_start_child_runner` accept a new `server_conversation: bool` parameter.
  - `open_agent_session` is called with `server_conversation` and `conversation_id=coordinator.conversation_ids.get(child_id)`.
  - `sessions_to_close` is typed as `list[Session]`.
  - `respawn_subagents` uses `coordinator.agents_with_metadata()` instead of holding `_lock` and building the snapshot manually.

- **`_run_until_lifecycle`** (line 448)
  - Tracks `is_root = context.get("parent_id") is None`.
  - When `recoveries >= recovery_limit` for a non-root agent, sets status to `crashed`, calls `_notify_parent_on_terminal(..., "crashed")`, and returns `None` instead of exhausting recovery (lines 526–530).

- **`_run_cycle`** (line 645)
  - Case-insensitive check for `"after shutdown"` RuntimeError.
  - Calls `coordinator.track_conversation_id(agent_id)` after stream detachment (line 721).
  - Only re-raises unhandled exceptions for the root agent; non-root sub-agents are marked `failed`/`crashed` and notify their parent (lines 781–811).

- **`_final_output_metadata`** (line 821)
  - New helper that describes invalid model output by type and length, avoiding logging target-derived content.

- **`_append_tool_required_message`** (line 875)
  - Uses `async with session_write_lock(session):` before `session.add_items`.

- **`_notify_parent_on_terminal`** (line 930)
  - Returns early if `coordinator.budget_stopped` to avoid noisy parent notifications during budget shutdown.
  - Uses `coordinator.get_parent_and_name(agent_id)` instead of holding `_lock`.

- **`_start_child_runner`** (lines 955–1038)
  - Opens the child session with `server_conversation` / `conversation_id`.
  - Catches `asyncio.CancelledError` in the child loop and requests a clean stop.

---

## `strix/core/sessions.py`

Session backend selection, image-budget enforcement, and type-safe item rewriting.

- **Session backend selection** (`@@ -23,5 +24,24@@` → line 26)
  - `open_agent_session(agent_id, path, *, server_conversation=False, conversation_id=None)` tries `OpenAIConversationsSession(conversation_id=...)` when `server_conversation` is enabled, then fall back to `SQLiteSession`.

- **Image detection helpers** (lines 67–92)
  - `_output_has_image` and `_elided_output` refactored with explicit `cast` and structured conditionals; no behavior change, just hardened type handling.

- **`_rewrite_session`** (line 111)
  - Simplified `cast` usage and writes `rebuilt` directly without an intermediate `rebuilt_items` list.

- **`enforce_image_budget`** (line 186) and **`scrub_images_from_items`** (line 213)
  - Use explicit `cast` to `dict[str, Any]` before `.get()` / `.items()` access.

- **`session_write_lock`** (line 102)
  - Returns an `asyncio.Lock` stored in a `WeakKeyDictionary` per session.

---

## Cross-cutting LyraShield themes

| Theme | Key files / lines |
|---|---|
| Cost/budget enforcement | `strix/core/hooks.py` 80–801; `strix/core/runner.py` 175–679 |
| Web search reservations | `strix/core/hooks.py` 561–596 |
| Out-of-band (dedup) reservations | `strix/core/hooks.py` 516–589; `strix/core/runner.py` 391, 669 |
| Context compaction | `strix/core/hooks.py` 31–77, 242–351, 700–750 |
| Trusted budget/turn warnings | `strix/core/hooks.py` 48, 607–678 |
| Prompt-injection sanitization | `strix/core/inputs.py` 33–49; `strix/core/runner.py` 119–170; `strix/core/agents.py` 539–558 |
| Trust-boundary peer messages | `strix/core/agents.py` 539–558, 411–443 |
| Lifecycle & terminal status | `strix/core/agents.py` 358–479; `strix/core/execution.py` 178–1038; `strix/core/runner.py` 603–679 |
| Server-managed conversations | `strix/core/sessions.py` 26–45; `strix/core/runner.py` 464–513; `strix/core/agents.py` 571–588 |



---

# LyraShield diff summary: Reports and worker contract

Base: `2e7040240d` (upstream Strix).  
Head: current `HEAD`.  
Scope: the report- and state-management boundary files that define what the worker emits and how it accounts for spend.

---

## `strix/report/dedupe.py`

**LyraShield purpose:** add a fast, deterministic deduplication pre-check before any LLM call; constrain the dedupe LLM to a strict output schema and a hard payload-cost budget; guard scan budget with explicit token reservations.

### Hunks

- **`@@ -1,2 +1,3 @@`** — Adds LyraShield copyright header; no functional change.

- **`@@ -5,10 +6,14 @@` + `@@ -24,5 +29,5 @@`** — Import changes: adds `math`, `cast` from `typing`, `uuid4`; adds `pydantic.BaseModel`, `Field`, `ValidationError`; adds `AgentOutputSchema`; extends `TYPE_CHECKING` to import `Settings` alongside `DedupeSettings`. These imports support the schema-structured LLM judge and budget reservation code.

- **`@@ -30,5 +35,5 @@`** — Renames the private helper `_dedupe_extra_args` to `dedupe_extra_args` and updates its call site. The function still returns a `dict[str, str]` of per-call credentials/endpoints for a dedicated dedupe model.

- **`@@ -50,8 +55,11 @@` + `@@ -64,8 +72,8 @@`** — Refactors `_dedupe_model_settings`:
  - Adds an optional `settings: Settings | None` parameter (defaults to `load_settings()` when `None`).
  - Uses `settings.llm` directly instead of `load_settings().llm`.
  - Renames the local `settings` variable to `model_settings` and calls `dedupe_extra_args`.
  - Returns `model_settings`.

- **`@@ -155,5 +163,5 @@`** — In `_prepare_report_for_comparison`, type-annotates `cleaned: dict[str, Any]`.

- **`@@ -166,8 +174,188 @@`** — The largest single hunk. Adds the cost-guard and structured-judge machinery:
  - Constants: `_MAX_EXISTING_REPORTS_CHARS` (200,000), `_TRUNCATION_MARKER` (`"...[truncated]"`), `_PER_ITEM_ENCODING_OVERHEAD` (8), `_DEDUPE_MAX_OUTPUT_TOKENS` (512), `_CHARS_PER_TOKEN` (3.5).
  - Pydantic `DedupeJudgement` schema: fields `is_duplicate`, `duplicate_id`, `confidence` (clamped `0.0–1.0` via `Field`), `reason`.
  - `_DEDUPE_OUTPUT_SCHEMA` built with `AgentOutputSchema(DedupeJudgement, strict_json_schema=True)`; this is passed as `output_schema` so providers constrain the model reply.
  - `_estimate_reservation_tokens` over-approximates input tokens for budget reservations.
  - `_request_dedupe_judgement` calls the dedupe model and, via `get_active_hooks()`, explicitly reserves and releases a token budget with `reserve_out_of_band_request` / `release_out_of_band_request` so the scan `max_budget_usd` is not overshot by out-of-band dedupe traffic.
  - `_truncate_report_to_budget`, `_encoded_size`, and `_bound_existing_reports` keep the existing-report comparison payload under `_MAX_EXISTING_REPORTS_CHARS`, retaining newest-first and truncating oversized fields while preserving identity fields (`id`, `target`, `endpoint`, `method`).

- **`@@ -272,6 +460,61 @@`** — Adds deterministic identity extraction and safer JSON extraction helpers:
  - Adds `cast("dict[str, Any]", metadata)` in `_dependency_identity`.
  - Adds `_normalized_text(value)`, `_dynamic_identity(report)`, `_first_unquoted_brace(text)`, and the first part of `_extract_balanced_json(text)`.
  - `_dynamic_identity` returns a tuple of normalized `(target, endpoint, method, primary_location, cwe, title)` and derives `primary_location` from `report["code_locations"][0]` (`file`, `start_line`, `end_line`) when available.

- **`@@ -279,22 +522,66 @@`** — Completes `_extract_balanced_json` and rewrites `_parse_dedupe_response`:
  - `_extract_balanced_json` scans for the first unquoted `{` and counts brace depth inside/outside strings to extract one balanced top-level JSON object.
  - `_parse_dedupe_response` now calls `_extract_balanced_json`, tries `DedupeJudgement.model_validate_json` for strict validation, and falls back to the lenient parser on `ValidationError`/`ValueError`.

- **`@@ -327,4 +614,21 @@`** — In `check_duplicate`, before any LLM call, computes `candidate_identity = _dynamic_identity(candidate)` and short-circuits with `is_duplicate=True` and `confidence=1.0` when an existing report has the same identity. If none match, returns `is_duplicate=False` with the same confidence, eliminating non-deterministic LLM spend for obvious duplicates.

- **`@@ -340,5 +644,7 @@`** — In `check_duplicate`, wraps the prepared existing reports with `_bound_existing_reports(...)` so the LLM comparison payload stays bounded.

- **`@@ -351,16 +657,12 @@`** — Replaces the inline `model.get_response(...)` call in `check_duplicate` with `_request_dedupe_judgement(...)` and passes `_DEDUPE_OUTPUT_SCHEMA` as `output_schema` for a structured reply.

---

## `strix/report/state.py`

**LyraShield purpose:** harden the worker artifact contract (`run.json` / `vulnerabilities.json`), add stable progress/phase signals, record web search spend, and apply privacy redaction to report fields when not in whitebox mode.

### Hunks

- **`@@ -1,5 +1,8 @@`** — Adds LyraShield copyright header and a `Controlled subprocess boundary` comment; adjusts imports (`shutil` plus `subprocess` with `# nosec B404`).

- **`@@ -16,5 +19,5 @@` + `@@ -24,4 +27,5 @@`** — `from strix.report.usage` now also imports `_int_or_zero` and `_round_cost`; adds `from strix.utils.redaction import redact_text`.

- **`@@ -30,4 +34,6 @@`** — Defines `_ALLOWED_PHASES = frozenset({"setup", "running", "finalizing", "completed", "stopped"})`.

- **`@@ -68,8 +74,13 @@`** — Hardens `_git_head`:
  - Resolves the `git` executable with `shutil.which("git")`.
  - Uses the resolved path in `subprocess.run([git_executable, ...], ...)` instead of the literal string `"git"`; keeps `shell=False`, `capture_output=True`, `text=True`, `timeout=5`.

- **`@@ -94,5 +105,5 @@`** — `set_global_report_state` accepts `Optional["ReportState"]` instead of only `"ReportState"`.

- **`@@ -131,10 +142,15 @@`** — Extends `ReportState.__init__`:
  - Adds `"phase": "setup"` to `run_record`.
  - Adds `run_record["seq"]` and `run_record["turn_count"]` initialized to `0`.
  - Adds instance counters `_save_seq` and `_turn_count`.

- **`@@ -185,7 +201,12 @@`** — In `hydrate_from_run_dir`, on reload of `run.json`:
  - Casts `scan_results` to `dict[str, Any]`.
  - Restores `_save_seq` and `_turn_count` from `run_record["seq"]` and `run_record["turn_count"]` via `_int_or_zero`.
  - Writes them back to `run_record`.

- **`@@ -193,5 +214,5 @@` + `@@ -200,9 +221,11 @@`** — When loading `vulnerabilities.json`:
  - Renames the local `data` variable to `vuln_data`.
  - Casts list items to `dict[str, Any]` before assigning to `self.vulnerability_reports`.
  - Keeps raising on non-list files.

- **`@@ -238,4 +261,5 @@`** — Adds `control_ids: list[int] | None = None` parameter to `add_vulnerability_report`.

- **`@@ -250,22 +274,35 @@` + `@@ -285,8 +322,12 @@`** — Applies redaction to vulnerability fields:
  - Computes `_redact_paths = not self._is_whitebox`.
  - Wraps `description`, `impact`, `technical_analysis`, `poc_description`, `remediation_steps`, `evidence`, `assumptions`, `fix_pr_body` with `redact_text(..., include_internal_paths=_redact_paths)`.
  - `poc_script_code` is redacted with `include_internal_paths=False`.
  - `target` and `endpoint` are not redacted (only stripped).
  - `control_ids` are stored as `sorted(set(control_ids))`.
  - Calls `self._set_phase("running")` before `save_run_data()`.

- **`@@ -302,4 +343,5 @@`** — After adding a vulnerability, `add_vulnerability_report` calls `self._set_phase("running")` and `self.save_run_data()`.

- **`@@ -317,11 +359,13 @@`** — `record_sdk_usage` now always increments `self._turn_count`, sets phase to `"running"`, and saves run data (instead of only saving when `LLMUsageLedger.record` returned `True`).

- **`@@ -335,4 +379,33 @@`** — Adds web search cost tracking:
  - `record_web_search_cost(cost, *, query, mode, provider="parallel")` rounds cost with `_round_cost`, appends a dict with `provider`, `mode`, `query`, `cost`, `timestamp` to `run_record["web_search_usage"]`, records observed cost in `self._llm_usage`, and calls `save_run_data()`.
  - `get_web_search_stats()` returns `(call_count, total_cost)` from `run_record["web_search_usage"]`.

- **`@@ -342,10 +415,17 @@`** — `update_scan_final_fields` redacts `executive_summary`, `methodology`, `technical_analysis`, and `recommendations` using `redact_text(..., include_internal_paths=_redact_paths)` where `_redact_paths = not self._is_whitebox`.

- **`@@ -353,10 +433,21 @@`** — In `update_scan_final_fields`:
  - Pops `terminal_reason` from `run_record` when a scan succeeds.
  - Sets phase `"finalizing"`, saves run data, then calls `save_run_data(mark_complete=True)`.

- **`@@ -364,4 +455,5 @@`** — Adds the `_is_whitebox` property: returns `True` if `scan_config["targets"]` contains any entry with `"type": "local_code"`.

- **`@@ -379,4 +471,5 @@`** — `set_scan_config` also pops `terminal_reason` when a new scan starts; sets phase `"running"`.

- **`@@ -385,4 +478,5 @@`** — `save_run_data` sets `run_record["phase"]` to `"completed"` when `mark_complete=True`.

- **`@@ -393,8 +487,15 @@`** — `save_run_data`:
  - Validates/sets phase via `_set_phase(status)` when a non-complete status is given.
  - Calls `_sync_progress()` before `_sync_llm_usage_record()` and `_save_artifacts()`.

- **`@@ -421,34 +522,27 @@`** — Reworks `_save_artifacts` to strengthen the worker contract:
  - Always calls `write_vulnerabilities(...)` (even for zero-finding runs) so the worker can distinguish a clean scan from missing output.
  - Moves `write_sarif(...)` inside its own `try` block and logs non-fatal failures; SARIF errors must not break the core artifact path.
  - Removes the broad `try ... except (OSError, RuntimeError)` wrapper around the whole save path.
  - Keeps writing `run.json` and `executive_report.md`.

- **`@@ -465,21 +559,24 @@`** — Hardens `_derive_repository_context`:
  - Uses explicit `isinstance(..., dict)` checks and `cast("dict[str, Any]", ...)` on `targets`, `target`, and `details`.
  - Avoids defaulting `details` to `{}`; returns `None` if it is not a dict.

- **`@@ -503,4 +600,16 @@`** — Adds `_set_phase` and `_sync_progress`:
  - `_set_phase(phase)` restricts values to `_ALLOWED_PHASES` and writes `run_record["phase"]`.
  - `_sync_progress()` increments `_save_seq`, copies it to `run_record["seq"]`, and copies `_turn_count` to `run_record["turn_count"]`.

- **`@@ -511,4 +620,11 @@`** — Adds module-level `_as_dict(obj: Any) -> dict[str, Any] | None` helper; returns the input as a cast `dict[str, Any]` only when `isinstance(obj, dict)`.

- **`@@ -585,26 +701,26 @@` + `@@ -671,8 +787,10 @@` + `@@ -681,7 +799,8 @@` + `@@ -702,8 +821,9 @@`** — Cost-extraction functions (`litellm_cost_callback`, `_estimate_response_cost`) replace inline `isinstance(..., dict)` checks with `_as_dict(...)`, add explicit `None` handling for nested dicts like `_hidden_params`, `additional_headers`, `litellm_params`, and `completion_response`, and avoid defaulting to empty dicts.

---

## `strix/report/usage.py`

**LyraShield purpose:** preserve per-request usage receipts for exact pricing, track whether any real cost was observed, and rebuild the ledger cleanly on resume.

### Hunks

- **`@@ -1,2 +1,3 @@`** — Adds LyraShield copyright header.

- **`@@ -4,5 +5,5 @@`** — Adds `cast` to the typing imports.

- **`@@ -19,5 +20,7 @@`** — `LLMUsageLedger.__init__` adds `self._request_usage_entries: list[dict[str, Any]]` and `self._has_cost = False`.

- **`@@ -38,4 +41,5 @@`** — `LLMUsageLedger.record` now extends `self._request_usage_entries` with `_serialize_request_usage_entries(usage, model=model)`.

- **`@@ -49,12 +53,18 @@`** — `record` sets `self._has_cost = True` when an estimated cost is added.

- **`@@ -64,6 +74,21 @@`** — `LLMUsageLedger.to_record`:
  - Adds `record["request_usage_entries"]` when `self._request_usage_entries` is non-empty; removes it for multi-request aggregates.
  - Adds `record["cost"]` only when `self._has_cost` or `self.zero_cost`.
  - Adds `record["subscription"] = True` when `self.zero_cost`.
  - Builds agent records without a default `cost` key; only adds `agent_record["cost"]` when `self._has_cost` is `True`.

- **`@@ -82,9 +107,11 @@`** — Agent records no longer unconditionally include `"cost"`; it is added only if `self._has_cost`.

- **`@@ -93,8 +120,11 @@`** — `hydrate` resets `_request_usage_entries` and `_has_cost` and casts `raw_usage` to `dict[str, Any]`.

- **`@@ -104,26 +134,34 @@`** — `hydrate`:
  - Only sets total cost and `_has_cost` when `"cost"` is present in `raw_usage`.
  - Rehydrates `_request_usage_entries` from `raw_usage["request_usage_entries"]`.
  - Casts raw agent entries with `cast("dict[str, Any]", raw)`.

- **`@@ -161,5 +199,5 @@`** — `_estimate_litellm_cost` uses `usage.request_usage_entries or []` instead of assuming the attribute is always a list.

- **`@@ -249,4 +287,67 @@`** — Adds request-usage serialization helpers:
  - `_serialize_request_usage_entries(usage, *, model=None)` collects `usage.request_usage_entries or []`; if the aggregate covers exactly one request with activity and no entries, treats the whole `Usage` as a single entry.
  - `_serialize_request_usage_entry(entry)` returns `input_tokens`, `output_tokens`, `total_tokens`, and `input_tokens_details` including `cached_tokens` and optional `cache_write_tokens`.
  - `_hydrate_request_usage_entries(value)` rehydrates stored list entries.
  - `_UsageEntryAdapter` maps a stored `dict` back onto attributes used by `_serialize_request_usage_entry`.

---

## `strix/report/writer.py`

**LyraShield purpose:** type-safety and lexer hygiene for the `run.json`/`vulnerabilities.json`/`vulnerability.md` writers; no functional behavior change.

### Hunks

- **`@@ -1,2 +1,3 @@`** — Adds LyraShield copyright header.

- **`@@ -13,5 +14,5 @@`** — Removes unused `PythonLexer` import; keeps `get_lexer_by_name` and `guess_lexer`.

- **`@@ -75,8 +76,8 @@`** — In `resolve_lexer`, the fallback for undetected/unfenced code uses `get_lexer_by_name("python")` instead of instantiating `PythonLexer()` directly.

- **`@@ -104,5 +105,5 @@`** — `read_run_record` returns `cast("dict[str, Any]", data)` after the dict check.

- **`@@ -199,5 +200,8 @@`** — In `render_vulnerability_md`, reads `report.get("dependency_metadata")` as `dep_meta_raw: Any`, then normalizes to `dep_meta: dict[str, Any]` with an `isinstance` check and `cast`, falling back to `{}`.

---

## `strix/report/sarif.py`

**LyraShield purpose:** defensive typing in the SARIF 2.1.0 generator so malformed `code_locations` do not crash the integration artifact.

### Hunks

- **`@@ -1,2 +1,3 @@`** — Adds LyraShield copyright header.

- **`@@ -571,4 +572,5 @@`** — In `_build_fixes`, casts `location` to `dict[str, Any]` after the `isinstance` check.

- **`@@ -671,4 +673,5 @@`** — In `_build_physical_locations`, casts `location` to `dict[str, Any]` before reading `file`, `start_line`, `end_line`.

- **`@@ -851,9 +854,14 @@`** — In `_primary_fingerprint`, safely extracts `primary_physical.get("artifactLocation")` and `primary_physical.get("region")`, casts each to `dict[str, Any]` when it is a dict, then reads `uri` and `startLine`.

- **`@@ -895,5 +903,5 @@`** — In `_first_physical_location`, checks `isinstance(physical, dict)` before casting and returning the physical location.

---

## Theme cross-cut

| Concern | Files / symbols |
|---|---|
| **Deterministic deduplication** | `dedupe.py`: `_dynamic_identity`, `_normalized_text`, `DedupeJudgement` schema, `_parse_dedupe_response`, `check_duplicate` short-circuit. |
| **Privacy redaction in reports** | `state.py`: `redact_text` in `add_vulnerability_report` and `update_scan_final_fields`, `_is_whitebox`, `_redact_paths`. |
| **Web search cost tracking** | `state.py`: `record_web_search_cost`, `get_web_search_stats`, `run_record["web_search_usage"]`. |
| **Usage / cost ledger** | `usage.py`: `_request_usage_entries`, `_has_cost`, `_serialize_request_usage_entries`, `_serialize_request_usage_entry`, `_hydrate_request_usage_entries`, `_UsageEntryAdapter`; `LLMUsageLedger.record`, `record_observed_cost`, `to_record`, `hydrate`. |
| **Worker artifact contract** | `state.py`: `run_record["phase"]`, `seq`, `turn_count`, `terminal_reason`, `_save_artifacts` always writes `vulnerabilities.json`, `set_terminal_reason`; `writer.py`: `read_run_record`, `render_vulnerability_md` casts; `sarif.py`: defensive casts in `_build_fixes`, `_build_physical_locations`, `_primary_fingerprint`, `_first_physical_location`. |



---

# LyraShield diff summary: LLM, web search, and tools

Base: `2e7040240d` (upstream Strix).  
Head: current `HEAD`.  
Scope: the web search tool, agent factory tool wiring, LLM compaction redaction, and Caido proxy client that together move the worker from Perplexity to Parallel Search and harden secret handling.

---

## `strix/tools/web_search/tool.py`

**LyraShield purpose:** replace the Perplexity-backed search with a Parallel Search integration that redacts queries before egress, enforces an allowed topic list, tracks cost via `reserve_web_search_call`, and formats citation-style results.

### Hunks

- **`@@ -1,12 +1,13 @@`** — Module docstring and imports updated. Copyright is implied by new `__init__.py`. `asyncio` and `requests` removed; `re`, `uuid`, `TYPE_CHECKING`, `Literal`, `cast`, and `urlparse` added. `agents` and `strix.config` remain.

- **`@@ -14,166 +15,403 @@`** — Adds the configuration/validation layer:
  - `_ALLOWED_TOPICS` frozenset: `cve`, `version`, `exploit`, `advisory`, `framework`, `library`, `public-endpoints`, `osint`.
  - `_DEFAULT_API_BASE = "https://api.parallel.ai/v1"`.
  - `_STOP_WORDS` for keyword extraction.
  - `_TOPIC_OBJECTIVES` mapping each allowed topic to a sanitized search objective.
  - `_SENSITIVE_PATTERNS` list of `(name, compiled_re, placeholder)` tuples: `uuid`, `email`, `ipv4`, `ipv6`, `bearer`, `api_key`, `password`, `secret`, `long_hex`.
  - `_URL_PATTERN` and `_redact_query(query, topic, target_hosts)` to strip UUIDs, emails, IPs, bearer tokens, API keys, passwords, secrets, long hex strings, URLs, and any known target hostnames before the query leaves the worker.

- **`@@ -70,166 +15,403 @@` (mid-file)** — Adds query preparation helpers:
  - `_query_to_keywords(query, topic, keywords)` builds 1–2 short keyword phrases from the redacted query and topic.
  - `_build_objective(topic, query)` picks a topic-specific, sanitized objective.
  - `_estimate_cost(mode, settings)` returns `turbo`/`basic`/`advanced` cost from settings.

- **`@@ -70,166 +15,403 @@` (target discovery)** — `_target_hosts_from_report()` reads `get_global_report_state()` and extracts target hostnames/URLs from `run_record["targets_info"]` so they can be redacted as `[TARGET]` unless the topic is `public-endpoints`.

- **`@@ -70,166 +15,403 @@` (validation)** — `_validate_web_search_call(web_search_settings, topic, report_state)` gates calls on `enabled`, `api_key`, allowed topics, `max_calls_per_scan`, and `budget_usd`, returning an error string or `None`.

- **`@@ -70,166 +15,403 @@` (summarization)** — `_summarize_results(results, max_results)` formats Parallel Search results as a numbered Markdown list with title, URL, and first excerpt.

- **`@@ -340,20 +224,29 @@` through end** — Replaces the `web_search` tool implementation:
  - Signature now takes `query`, `topic` (default `advisory`), `mode` (default `turbo`), and `keywords`.
  - Calls `_validate_web_search_call`, `_redact_query`, and `_estimate_cost`.
  - Generates `reservation_key = f"web_search:{uuid.uuid4().hex}"`.
  - If hooks are active, awaits `hooks.reserve_web_search_call(key, estimated_cost)` before the request and `hooks.release_web_search_call(key, actual_cost)` after.
  - Uses `httpx.AsyncClient` to POST `{api_base}/search` with `x-api-key`, JSON body containing `mode`, `objective`, `search_queries`, `max_results`, `max_chars_total`.
  - Records actual cost with `report_state.record_web_search_cost(estimated_cost, query=redacted_query, mode=mode)`.
  - Returns JSON with `success`, `content`, `query` (redacted), `mode`, and `results`.
  - Error handling covers `httpx.HTTPError` and general `Exception`, releasing the reservation with `actual_cost=0.0`.

- **Removed code** — Perplexity `_SYSTEM_PROMPT`, `requests`-based `_do_search`, and the original single-parameter `web_search` wrapper are deleted.

---

## `strix/tools/web_search/__init__.py`

**LyraShield purpose:** brand the package as the Parallel Search-backed web research tool.

### Hunks

- **`@@ -0,0 +1,2 @@`** — Adds the LyraShield copyright header (`Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)`) and the module docstring `"""Parallel Search-backed web research tool."""`.

---

## `strix/agents/factory.py`

**LyraShield purpose:** register the new `web_search` tool in the base toolset, add programmatic tool-calling support, and split root orchestration tools so root agents get `view_agent_graph`, `create_agent`, and `stop_agent` while child agents do not.

### Hunks

- **`@@ -1,2 +1,3 @@`** — Adds the LyraShield copyright header.

- **`@@ -7,5 +8,5 @@`** — Imports: adds `cast`; imports `ModelSettings` under `TYPE_CHECKING`.

- **`@@ -13,9 +14,18 @@`** — Imports: adds `ApplyPatchTool`, `ProgrammaticToolCallingTool`, `ShellTool`, `ToolCaller`; adds `model_supports_programmatic_tool_calling` from `strix.config.models`.

- **`@@ -67,4 +77,5 @@`** — `TYPE_CHECKING` block adds `ModelSettings`.

- **`@@ -78,4 +89,10 @@`** — Adds `_PROGRAMMATIC_ALLOWED_CALLERS = ["direct", "programmatic"]` cast to `list[ToolCaller]`.

- **`@@ -207,20 +224,29 @@`** — Refactors `_configure_filesystem_tools` and `_make_filesystem_configurator` to accept `programmatic: bool`. Wraps `CustomTool`/`FunctionTool` once, then sets `wrapped.allowed_callers = _PROGRAMMATIC_ALLOWED_CALLERS` when `programmatic` is true.

- **`@@ -326,6 +352,6 @@` and `@@ -337,10 +363,15 @@`** — Refactors `_configure_shell_tools` and `_make_shell_configurator` with the same `programmatic` parameter and `allowed_callers` assignment.

- **`@@ -365,5 +396,8 @@` through `@@ -375,9 +409,8 @@`** — Replaces implicit `dict` access with `cast("dict[str, Any]", parsed)` and `context = cast("dict[str, Any]", ctx.context)` for type safety.

- **`@@ -404,6 +439,16 @@`** — Adds `_set_tools_programmatic_callers(tools, enabled)` to set `allowed_callers` on `FunctionTool`, `CustomTool`, `ShellTool`, and `ApplyPatchTool`, while skipping `ProgrammaticToolCallingTool`.

- **`@@ -418,5 +463,4 @@`** — `_BASE_TOOLS` reordered: `web_search` is moved from the end into the base toolset immediately after `think`. Root-only tools are split out.

- **`@@ -429,7 +473,11 @@`** — New `_ROOT_ORCHESTRATION_TOOLS` tuple: `view_agent_graph`, `create_agent`, `stop_agent`.

- **`@@ -467,5 +515,14 @@`** — `register_agent_tools` concatenates `_BASE_TOOLS`, `_ROOT_ORCHESTRATION_TOOLS`, `_EXTRA_TOOLS`, new tools, `finish_scan`, and `agent_finish`.

- **`@@ -491,4 +548,6 @@`** — `build_strix_agent` gains `model: str | None` and `model_settings: ModelSettings | None` parameters.

- **`@@ -519,7 +578,22 @@`** — `build_strix_agent` tool assembly:
  - Root tools now include `_ROOT_ORCHESTRATION_TOOLS`.
  - Computes `use_programmatic = not chat_completions_tools and model is not None and model_supports_programmatic_tool_calling(model)`.
  - Calls `_set_tools_programmatic_callers(tools, enabled=use_programmatic)`.
  - Appends `ProgrammaticToolCallingTool()` when enabled.
  - Logs `programmatic=%s` in the build log line.
  - Passes `agent_model_options` (`model` and/or `model_settings`) into `SandboxAgent`.
  - Filesystem and Shell configurator calls pass `programmatic=use_programmatic`.

- **`@@ -565,4 +648,6 @@`** — `make_child_factory` forwards `model` and `model_settings` to `build_strix_agent`.

---

## `strix/llm/compaction.py`

**LyraShield purpose:** redact text before it is summarized by the LLM and redact the resulting summary, so secrets never pass through the compaction stage; also add optional `model_provider`/`settings` injection.

### Hunks

- **`@@ -23,4 +23,5 @@`** — Adds `from strix.utils.redaction import redact_text`.

- **`@@ -28,4 +29,7 @@`** — `TYPE_CHECKING` block adds `ModelProvider` and `Settings`.

- **`@@ -91,7 +95,16 @@`** — Updates `_SUMMARY_INSTRUCTIONS`:
  - Removes `credentials`, `tokens`, `keys`, `hashes`, and `cracked passwords` from the "copy verbatim" list.
  - Adds explicit instruction that secrets have been redacted and placeholders like `[SECRET]`, `[TOKEN]`, `[JWT]`, `[AWS_KEY]`, `[PRIVATE_KEY]`, `[PII]`, and `[INTERNAL_PATH]` must be preserved verbatim.
  - Directs the model to record the placeholder *type* and *location* in the `## Credentials & Secrets` section (e.g., `"[SECRET] used for API authentication at /login"`).

- **`@@ -107,6 +120,8 @@`** — Updates the `## Credentials & Secrets` section instructions to use placeholder type/location instead of verbatim secrets.

- **`@@ -165,5 +180,9 @@`** — `_serialize_item` now emits `[reasoning] {_truncate(text, ...)}` when a reasoning item contains a summary or text; falls back to `[reasoning]` if empty.

- **`@@ -206,4 +225,8 @@`** — `_select_split` now folds leading orphan tool outputs after the split point back into the head so the provider never receives a tool output without a preceding tool call.

- **`@@ -234,10 +257,13 @@`** — `_summary_output_tokens` and `_summary_input_budget` gain optional `settings: Settings | None` parameters, using the supplied settings instead of always calling `load_settings()`.

- **`@@ -287,6 +313,17 @@`** — `_summarize` gains `model_provider: ModelProvider | None = None` and `settings: Settings | None = None` parameters. It now defaults to the supplied `settings` and `model_provider` instead of constructing `StrixProvider()` inline, allowing tests and callers to inject a provider.

- **`@@ -330,4 +363,6 @@`** — `maybe_compact` gains `model_provider` and `settings` parameters and uses the injected `settings.context`.

- **`@@ -365,13 +402,18 @@`** — Redaction integration in `maybe_compact`:
  - `serialized_head = _fit_to_tokens(...)` is now passed through `redact_text()` before `_build_summary_prompt(...)`.
  - The generated `summary` is also run through `redact_text()` before it is stored as a checkpoint.
  - Both `_summarize` calls pass `model_provider` and `settings`.

---

## `strix/tools/proxy/caido_api.py`

**LyraShield purpose:** harden the shared Caido GraphQL/replay client by blocking cloud metadata and link-local hosts, validating replay URLs, sanitizing request headers, and fixing a Caido SDK overload resolution bug.

### Hunks

- **`@@ -4,9 +4,12 @@`** — Imports: adds `ipaddress`, `re`, `socket`, and `cast`; removes unused? `urllib.request` and `Literal` still present.

- **`@@ -44,4 +47,18 @@`** — Adds network-level blocklist constants:
  - `_LINK_LOCAL_NETWORKS = (IPv4Network("169.254.0.0/16"), IPv6Network("fe80::/10"))`.
  - `_BLOCKED_METADATA_HOSTS` frozenset covering `metadata.google.internal` and variants.
  - `_BLOCKED_METADATA_IPS` frozenset with `100.100.100.200` (Alibaba Cloud IMDS).

- **`@@ -58,13 +75,101 @@`** — Adds host validation helpers:
  - `_host_gateway_allowed()` reads `STRIX_SANDBOX_ALLOW_HOST_GATEWAY`.
  - `_check_replay_url_host(url)` blocks non-HTTP(S) schemes, cloud metadata hosts, and `host.docker.internal` unless explicitly allowed; returns a human-readable reason or `None`.
  - `_resolve_hostname_ips(hostname)` resolves DNS to IPs and strips IPv6 scope IDs.
  - `_check_ip_against_blocklist(ip)` raises `ValueError` for cloud metadata or link-local IPs.
  - `_validate_caido_url_host(url)` raises `ValueError` for the Caido GraphQL base URL, resolving hostnames first to catch DNS aliases pointing to metadata/link-local addresses.

- **`@@ -58,13 +75,101 @@` (caido_url / _graphql_url)** — `_graphql_url()` now calls `_validate_caido_url_host(base_url)` and lowercases the scheme check.

- **`@@ -148,5 +253,8 @@`** — `list_requests_with_client` uses `getattr(builder, "descending" if sort_order == "desc" else "ascending")` to avoid an unresolvable SDK overload.

- **`@@ -169,4 +277,5 @@`** — Adds `_INVALID_HEADER_RE = re.compile(r"[\r\n\x00]")`.

- **`@@ -181,4 +290,7 @@`** — `build_raw_request` now calls `_check_replay_url_host(url)` and raises `ValueError` for blocked replay targets.

- **`@@ -191,4 +303,7 @@`** — Header sanitization: `build_raw_request` raises `ValueError` if any header name or value contains CR, LF, or NUL characters.


---

# Privacy, Redaction, and Telemetry — Hunk-Level Diff Summary

**Base:** `2e7040240d`  
**HEAD:** `b59a7c3` (`docs: add AI audit report for security hardening pass`)

Theme: LyraShield product boundary hardens privacy by (1) adding a cross-cutting redaction library for secrets/PII/internal paths, and (2) forcing telemetry off while removing hardcoded analytics endpoints/API keys.

---

## `strix/utils/redaction.py` (new file)

Entire file added, lines 1–176. This is the central redaction utility used for web-search query sanitization, customer-facing reports, and conversation compaction.

- **Placeholders** (`_SECRET_PLACEHOLDER`, `_PII_PLACEHOLDER`, `_TOKEN_PLACEHOLDER`, `_JWT_PLACEHOLDER`, `_AWS_KEY_PLACEHOLDER`, `_PRIVATE_KEY_PLACEHOLDER`, `_INTERNAL_PATH_PLACEHOLDER`, `_SPILL_PATH_PLACEHOLDER`) — line 13–20.
- **`_SENSITIVE_PATTERNS`** — line 24–102. Ordered regex list covering: `private_key`, `jwt`, `aws_access_key`, `uuid`, `email`, `ipv4`, `ipv6`, `bearer`, `api_key`, `password`, `secret_or_token`.
- **`_ALWAYS_REDACT_PATH_PATTERNS`** — line 105–116. Always matches `strix_spill_path` (`/workspace/.strix/tool-output/...`) and `strix_tmp_state` (`/tmp/.strix...`).
- **`_MODE_DEPENDENT_PATH_PATTERNS`** — line 120–126. Contains `workspace_path` (`/workspace/...`); redacted by default but preserved in whitebox mode.
- **`redact_secrets(text)`** — line 129–134. Applies `_SENSITIVE_PATTERNS`.
- **`redact_internal_paths(text)`** — line 137–150. Applies always-redact and mode-dependent path patterns.
- **`redact_spill_paths(text)`** — line 153–158. Applies only always-redact patterns, preserving general workspace paths.
- **`redact_text(text, *, include_internal_paths=True)`** — line 161–176. Composes `redact_secrets` with either `redact_internal_paths` (blackbox/default) or `redact_spill_paths` (whitebox).

---

## `strix/telemetry/posthog.py`

- **Attribution banner** added at line 1: `# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)`.
- **Imports** (line 1–15): adds `import os`; `typing` becomes `Any, cast`; `ReportState` is now imported from `strix.telemetry._common` instead of a `TYPE_CHECKING` import from `strix.report.state`.
- **Hardcoded credentials removed** (line 21–27): upstream constants `_POSTHOG_PUBLIC_API_KEY` and `_POSTHOG_HOST` are replaced by lazy env getters:
  - `_posthog_api_key()` → `os.environ.get("STRIX_POSTHOG_API_KEY", "")`
  - `_posthog_host()` → `os.environ.get("STRIX_POSTHOG_HOST", "https://us.i.posthog.com")`
- **`_send` guard** (line 33–58): in addition to `_is_enabled()`, it now returns early with a debug log if `_posthog_api_key()` is empty. Payload uses `api_key` from `_posthog_api_key()` and URL from `_posthog_host()`; `cast("dict[str, Any]", payload)` added.
- **`end` signature & LLM usage handling** (line 106–150): `end(report_state: ReportState, ...)` no longer uses a forward-reference string; removes the `isinstance(usage, dict)` guard and builds `llm_props` directly with `.get` fallbacks.

---

## `strix/telemetry/scarf.py`

- **Attribution banner** added at line 1.
- **Imports** (line 1–18): adds `import os`; removes `TYPE_CHECKING`; `ReportState` imported from `strix.telemetry._common`.
- **Hardcoded endpoint removed** (line 25–26): constant `_SCARF_ENDPOINT = "https://strix.gateway.scarf.sh"` replaced by `_scarf_endpoint()` → `os.environ.get("STRIX_SCARF_ENDPOINT", "")`.
- **`_send` guard** (line 33–57): returns early if `_scarf_endpoint()` is empty; URL built with the configured `endpoint`.
- **`end` signature & LLM usage handling** (line 108–155): `end(report_state: ReportState, ...)` changed from forward reference and removes `isinstance(usage, dict)` guard, same pattern as `posthog.py`.

---

## `strix/telemetry/__init__.py`

- **Attribution banner** at line 1.
- **`STRIX_TELEMETRY=0` product-boundary gate** (line 2–9): adds `import os` and `os.environ["STRIX_TELEMETRY"] = "0"` with a comment explaining telemetry is always disabled for this controlled derivative, regardless of entry point.

---

## `strix/telemetry/_common.py`

- **Attribution banner** at line 1.
- **`Protocol` import** (line 9): `from typing import Any, Protocol`.
- **`ReportState` Protocol** (line 16–27): adds a local protocol with `posthog_scan_ended_sent`, `scarf_scan_ended_sent`, `scan_ended_exit_reason`, `start_time`, `end_time`, `vulnerability_reports`, `run_record`, and `get_total_llm_usage()`. This removes the runtime/circular dependency on `strix.report.state`.
- **Style rename** (line 32, 44–57): `_FIRST_RUN_CACHED` renamed to `_first_run_cached` in the global declaration and all references in `is_first_run()`.

---

## `strix/telemetry/logging.py`

- **Attribution banner** at line 1.
- **`importlib` import** (line 7): adds `import importlib`.
- **`configure_dependency_logging` litellm import** (line 81–89): replaces top-level `import litellm` with `litellm = importlib.import_module("litellm")` and removes the `# type: ignore[no-untyped-call]` comment. Defers the heavy import and avoids type-checker suppression.

---

## `strix/telemetry/README.md`

- **Complete rewrite** (line 1–30): replaced the upstream "telemetry is optional, here's what we track" document with a LyraShield boundary notice.
- **Product boundary claims**: `lyrashield_adapter.cli.prepare_environment` unconditionally sets:
  - `STRIX_TELEMETRY=0`
  - `STRIX_NO_UPDATE_CHECK=1`
  - `LYRASHIELD_PRODUCT_BOUNDARY=1`
- **No remote analytics in production**; inherited PostHog/Scarf clients are retained for code review and bare `strix` dev-CLI behavior only.
- **No supported re-enablement** through the product boundary.

---

## `strix/skills/__init__.py`

- **Attribution banner** at line 1.
- **`load_settings` import** (line 9): `from strix.config import load_settings`.
- **`_track_skill_loaded` telemetry gate** (line 184–186): adds `if not load_settings().telemetry.enabled: return` before any PostHog/Scarf calls, making skill-load tracking respect the product-boundary telemetry setting.

---

## Cross-Cutting LyraShield Purpose

1. **Privacy redaction**: `strix/utils/redaction.py` provides deterministic, pattern-based redaction of secrets, PII, and internal sandbox paths, with mode-aware handling of workspace paths.
2. **Forced-off telemetry**: `strix/telemetry/__init__.py` hard-sets `STRIX_TELEMETRY=0`, and `strix/telemetry/posthog.py` / `scarf.py` no longer embed upstream API keys/endpoints, instead reading empty-by-default env vars. Even if an entry point missed the env override, missing keys prevent outbound analytics.
3. **Attribution**: every modified upstream file carries the `# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)` banner; `README.md` documents the product boundary.


---

# LyraShield Product-Boundary Test Diff Summary

Base: `2e7040240d` → HEAD: `b59a7c31e07e4c5dd8a9cd61043ee34677afa460`

This report summarizes the hunks added to the LyraShield product-boundary test suite versus the pinned upstream base. Each file is a distinct product boundary; added test functions are named exactly as in the source.

## 1. `tests/test_lyrashield_adapter.py` — adapter boundary (new file, lines 1–316)

### Hunk 1 (new lines 1–316)

Whole file is the adapter/CLI product-boundary test suite. It adds an `autouse` fixture `_isolated_product_env` that scrubs product-boundary env vars before each test, then 20 test functions:

- Environment alias mapping (`test_prepare_environment_maps_product_variable`) — maps 18 `LYRASHIELD_*` variables to upstream `STRIX_*` / `PARALLEL_API_KEY` equivalents.
- Precedence & gating (`test_prepare_environment_keeps_explicit_upstream_value`, `test_prepare_environment_forces_telemetry_off`, `test_prepare_environment_disables_update_check`, `test_main_prints_product_version`, `test_main_delegates_non_version_arguments`, `test_cli_update_flag_is_disabled`).
- Subscription & GPT-5.6 model gating (`test_prepare_environment_rejects_subscription_models_when_disabled`, `test_prepare_environment_rejects_subscription_model_via_product_alias_when_disabled`, `test_prepare_environment_accepts_chatgpt_by_default`, `test_prepare_environment_accepts_supported_gpt56_providers`, `test_prepare_environment_rejects_unsupported_gpt56_providers`, `test_prepare_environment_accepts_api_key_deployments`).
- Config-file validation (`test_config_file_can_use_subscription_model`, `test_config_file_can_use_supported_gpt56_provider`, `test_config_file_rejects_unsupported_gpt56_provider`, `test_config_file_rejects_subscription_model_when_disabled`, `test_config_subscription_model_rejected_when_disabled`).
- Subscription helper (`test_is_chatgpt_subscription_allowed_defaults_to_true`, `test_is_chatgpt_subscription_allowed_is_case_insensitive`).

## 2. `tests/test_redaction.py` — redaction/DLP boundary (new file, lines 1–184)

### Hunk 1 (new lines 1–184)

Whole file tests the cross-cutting redaction utility and DLP integration:

- Secret redaction (`test_redact_secrets_strips_api_keys`, `test_redact_secrets_strips_passwords`, `test_redact_secrets_strips_bearer_tokens`, `test_redact_secrets_strips_jwt`, `test_redact_secrets_strips_aws_keys`, `test_redact_secrets_strips_private_keys`, `test_redact_secrets_strips_emails`).
- Internal path/spill-path redaction (`test_redact_internal_paths_strips_workspace`, `test_redact_text_combines_both`, `test_redact_text_preserves_normal_content`).
- Report-field DLP at storage: vulnerability reports and final scan narrative redaction (`test_vulnerability_report_redacts_secrets`, `test_final_report_redacts_secrets`).
- Whitebox path preservation in vulnerability and final reports while spill paths remain redacted (`test_whitebox_report_preserves_internal_paths`, `test_whitebox_final_report_preserves_paths`).
- PoC script path preservation in blackbox mode for reproducibility (`test_poc_script_preserves_paths_in_blackbox`).

## 3. `tests/test_telemetry_keys.py` — telemetry boundary (new file, lines 1–92)

### Hunk 1 (new lines 1–92)

Whole file tests telemetry key externalization and lazy env-var reads:

- PostHog skip when API key missing, lazy API key and host reads (`test_posthog_skips_when_api_key_not_configured`, `test_posthog_reads_api_key_lazily`, `test_posthog_reads_host_lazily`).
- Scarf skip when endpoint missing, lazy endpoint read (`test_scarf_skips_when_endpoint_not_configured`, `test_scarf_reads_endpoint_lazily`).
- Skill-load telemetry gated by `STRIX_TELEMETRY` (`test_skills_telemetry_gated_by_telemetry_enabled`).

## 4. `tests/test_web_search.py` — web search boundary (new file, lines 1–366)

### Hunk 1 (new lines 1–366)

Whole file tests the `web_search` tool and `WebSearchSettings`:

- Settings defaults and env aliases, including product-specific `LYRASHIELD_WEB_SEARCH_API_KEY` vs `PARALLEL_API_KEY` (`test_web_search_settings_defaults`, `test_web_search_env_aliases`, `test_web_search_env_aliases_product_api_key`).
- Query redaction: sensitive patterns, public-endpoints domain preservation, target-host replacement (`test_redact_query_handles_sensitive_patterns`, `test_redact_query_preserves_public_endpoints_domain`, `test_redact_query_replaces_target_hosts`).
- Keyword/objective/cost helpers (`test_query_to_keywords_uses_provided_keywords`, `test_query_to_keywords_derives_from_query`, `test_build_objective_prefixes_by_topic`, `test_estimate_cost_per_mode`, `test_target_hosts_from_report`).
- Tool guard: disabled, missing API key, invalid topic, per-scan call cap (`test_web_search_disabled`, `test_web_search_missing_api_key`, `test_validate_web_search_call_invalid_topic`, `test_web_search_call_count_cap`).
- API success and error paths (`test_web_search_hits_api`, `test_web_search_api_error`).
- Budget reserve/release (`test_reserve_web_search_call_enforces_budget`).

## 5. `tests/test_provider_contract.py` — provider contract boundary (new file, lines 1–120)

### Hunk 1 (new lines 1–120)

Whole file tests provider capability probing and the `provider-contract` CLI without a live endpoint. Adds `_FakeModel`, `_settings`, and `_use_fake_model` helpers, then:

- Baseline and dependent capability probing, including previous-response-id and programmatic tool calling (`test_probe_reports_supported_contract`, `test_probe_fails_closed_when_programmatic_tool_is_rejected`, `test_probe_skips_dependents_when_baseline_fails`).
- CLI surfaces configuration errors cleanly without a traceback (`test_cli_reports_configuration_errors_without_a_traceback`).

## 6. `tests/test_dedupe_model.py` — dedupe boundary (modified, 2 hunks)

### Hunk 1 (new lines 4–25)

Import and setup changes: adds `pytest`, `pathlib.Path`, `types.SimpleNamespace`, and exposes `strix.report.dedupe` internals (`_MAX_EXISTING_REPORTS_CHARS`, `DedupeJudgement`, `_bound_existing_reports`, `_extract_balanced_json`, `_parse_dedupe_response`) plus `strix.core.hooks` so the new tests can drive and observe hook reservations.

### Hunk 2 (new lines 132–354)

Adds 16 tests for the deduplication model and existing-report handling:

- `_bound_existing_reports` budget cap behavior: small lists preserved, oldest dropped beyond budget, oversized newest truncated, encoded payload cap honored, unshrinkable identity dropped (`test_bound_existing_reports_keeps_small_lists_intact`, `test_bound_existing_reports_drops_oldest_beyond_budget`, `test_bound_existing_reports_truncates_an_oversized_newest_report`, `test_bound_existing_reports_encoded_payload_never_exceeds_the_cap`, `test_bound_existing_reports_drops_a_report_whose_identity_alone_overflows`).
- Dedupe call reservation and release against the scan budget, release on failure, and safe operation without active hooks (`test_dedupe_call_reserves_and_releases_against_the_scan_budget`, `test_dedupe_releases_its_reservation_when_the_request_fails`, `test_dedupe_works_without_active_hooks`).
- Runner lifecycle: active hooks must be cleared in the `finally` block on every exit path (`test_runner_clears_active_hooks_on_every_exit_path`).
- Response parsing: `extract_balanced_json` handles code fences, nested objects, missing/unbalanced JSON; `_parse_dedupe_response` coerces/truncates fields, validates via Pydantic, falls back on invalid schema; `DedupeJudgement` schema validation (`test_extract_balanced_json_handles_fences_and_nesting`, `test_extract_balanced_json_rejects_missing_object`, `test_extract_balanced_json_rejects_unbalanced_object`, `test_parse_dedupe_response_coerces_fields_and_truncates`, `test_parse_dedupe_response_validates_via_schema`, `test_parse_dedupe_response_falls_back_on_invalid_schema`, `test_dedupe_judgement_schema_validates_correct_fields`).

## 7. `tests/test_execution.py` — execution boundary (modified, 1 hunk)

### Hunk 1 (new lines 1089–1253)

Adds 9 tests around `AgentCoordinator` runtime edges and runner finalization:

- Mailbox/session handling (`test_consume_pending_restores_mailbox_on_session_failure`, `test_consume_pending_clears_mailbox_without_session`).
- Subtree cancellation (`test_cancel_descendants_marks_subtree_stopped`).
- Finalization status guards: failed/crashed/stopped roots are not overwritten with `completed`; still-running roots are promoted; the exact runner finalization sequence preserves failed and promotes running states (`test_finalization_does_not_overwrite_failed_status`, `test_finalization_promotes_running_to_completed`, `test_finalization_sequence_preserves_failed_status`, `test_finalization_sequence_promotes_running_to_completed`).
- Trust boundary: inter-agent messages include a `SYSTEM-VERIFIED PEER MESSAGE` prefix, while user messages do not (`test_inter_agent_message_has_trust_boundary`, `test_user_message_has_no_trust_boundary`).

## 8. `tests/test_hooks.py` — hooks boundary (modified, 2 hunks)

### Hunk 1 (new lines 13–17)

Import update: adds `_compact_item` to the `strix.core.hooks` imports.

### Hunk 2 (new lines 493–537)

Adds 3 tests:

- `_compact_item` preserves whole multibyte characters when compacting long assistant messages (`test_compact_item_keeps_whole_multibyte_characters`).
- Budget and turn warnings are prefixed with `[SYSTEM-NOTICE]` so they cannot be spoofed (`test_budget_warning_has_system_notice_tag`, `test_turn_warning_has_system_notice_tag`).

## 9. `tests/test_models.py` — models boundary (modified, 5 hunks)

### Hunk 1 (new lines 5–21)

Import updates: adds `OpenAIResponsesModel` and the GPT-5.6/Azure provider helpers (`_azure_responses_base_url`, `is_gpt56_model`, `is_gpt56_supported_provider`, `uses_chat_completions_tool_schema`).

### Hunk 2 (new lines 25–44)

Adds `test_gpt56_supported_providers_are_accepted`: openai, azure/eu, azure_ai, bedrock_mantle, and chatgpt GPT-5.6 models are accepted as supported.

### Hunk 3 (new lines 62–192)

Adds 8 tests for GPT-5.6 and Azure model routing:

- Deployment-name acceptance and rejection for GPT-5.6 models, including retired `gpt-5.6-sol` (`test_gpt56_deployment_names_are_accepted`, `test_non_gpt56_deployment_names_are_rejected`).
- Azure response base URL construction (`test_azure_responses_base_url`).
- Azure GPT-5.6 routing through OpenAI Responses with deployment name stripped and multi-segment names (`test_azure_gpt56_routes_through_responses_with_stripped_deployment_name`, `test_azure_multi_segment_name_uses_final_deployment`, `test_azure_gpt56_route_fails_closed_without_endpoint`).
- JSON tool schema behavior with and without `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING` opt-in (`test_azure_gpt56_keeps_json_tools_without_programmatic_opt_in`, `test_azure_gpt56_uses_responses_tools_when_programmatic_is_opted_in`).

### Hunk 4 (new lines 235–242)

Test-data update: adds unsupported GPT-5.6 provider slugs (`openrouter/gpt-5.6-luna`, `bedrock/gpt-5.6-terra`, `vertex_ai/gpt-5.6-luna`, `novita/gpt-5.6-luna`) to the `test_non_frontier_models_are_rejected` parametrize list.

### Hunk 5 (new lines 245–260)

Adds `test_gpt56_unsupported_providers_are_rejected`: the same four providers are explicitly rejected as unsupported GPT-5.6 routes.

## 10. `tests/test_output_token_cap.py` — output token cap boundary (new file, lines 1–48)

### Hunk 1 (new lines 1–48)

Whole file tests `resolve_max_output_tokens` and `DELEGATE_OUTPUT_TOKEN_CEILING`:

- When `LYRASHIELD_MAX_OUTPUT_TOKENS` is unset, scan-mode defaults are preserved (`test_unset_cap_preserves_scan_mode_defaults`).
- A configured cap replaces and may exceed the scan-mode default (`test_configured_cap_replaces_the_scan_mode_default`, `test_configured_cap_may_exceed_the_scan_mode_default`).
- The delegate ceiling bounds a raised coordinator cap but does not raise a lower one (`test_delegate_ceiling_bounds_a_raised_coordinator_cap`, `test_delegate_ceiling_does_not_raise_a_lower_coordinator_cap`).

## 11. `tests/test_runner_root_prompt.py` — runner root prompt boundary (modified, 4 hunks)

### Hunk 1 (new lines 18–22)

Import update: adds `_sanitize_prompt_value` from `strix.core.inputs`.

### Hunk 2 (new lines 76–80)

Scaffold update: patches `build_root_task`, `build_scope_context`, and `make_model_settings` into the engine test harness.

### Hunk 3 (new lines 87–91)

Scaffold update: patches `open_agent_session` and `make_child_factory` into the engine test harness.

### Hunk 4 (new lines 176–249)

Adds 5 tests for root prompt sanitization:

- `_sanitize_prompt_value` strips Jinja tags, removes control characters, and truncates long input (`test_sanitize_prompt_value_strips_jinja_tags`, `test_sanitize_prompt_value_strips_control_chars`, `test_sanitize_prompt_value_truncates_long_input`).
- `run_strix_scan` sanitizes `root_instructions_override` and `extra_system_prompt_context` before passing them to `build_strix_agent` (`test_root_instructions_override_sanitized`, `test_extra_system_prompt_context_sanitized`).

## 12. `tests/test_usage_ledger.py` — usage ledger boundary (new file, lines 1–116)

### Hunk 1 (new lines 1–116)

Whole file tests `LLMUsageLedger` hydration and token accounting:

- Cache write receipt handling: preserve, don't invent missing, omit zero (`test_usage_ledger_preserves_provider_cache_write_receipts`, `test_usage_ledger_does_not_invent_missing_cache_write_tokens`, `test_usage_ledger_omits_zero_cache_write_tokens`).
- Cost handling: omit unavailable native provider cost, retain observed provider cost (`test_usage_ledger_omits_unavailable_native_provider_cost`, `test_usage_ledger_retains_observed_provider_cost`).
- Aggregate/receipt edge cases: do not treat multi-request aggregates as receipts, handle missing provider request entries (`test_usage_ledger_does_not_treat_multi_request_aggregate_as_a_receipt`, `test_usage_ledger_handles_missing_provider_request_entries`).
- Model preservation during hydration (`test_usage_ledger_preserves_request_model_during_hydration`).


---

# LyraShield product-boundary docs and scripts — diff summary

Base: `2e7040240d` → HEAD  
Method: `git diff --unified=2 2e7040240d..HEAD -- <file>` for each listed file.

---

## README.md

**Hunk:** `@@ -1,320 +1,129 @@` (`README.md:1-129`)

The upstream Strix README (320 lines) is replaced by a LyraShield controlled-derivative landing page (129 lines). Key additions:

- **Title and identity** (`README.md:1-5`): declares the repository as the sandboxed analysis process for the LyraShield AI worker, a controlled derivative of Strix pinned at `8157ccba276c8fdd5eaa07a1a9d8d686315f6bd1` under Apache-2.0, and points to `NOTICE` and `UPGRADES.md`.
- **Project map** (`README.md:7-14`): links to the public site, application repository, and internal anchors for ownership boundary, worker artifact contract, verification, and the upgrade ledger.
- **Build Week provenance** (`README.md:16-24`): explains that the repository contains imported Strix history and that the Build Week source of truth is the application repository pre-event baseline `72ba1e2`; gives a `git log` command to inspect LyraShield-only engine history.
- **Ownership boundary** (`README.md:26-36`): enumerates what LyraShield owns (GPT-5.6 policy, context/budget limits, non-interactive lifecycle, deterministic finding identities, worker artifacts) and what remains upstream (sandbox/session mechanics, tools, agent SDK, skill library).
- **Security hardening** (`README.md:38-47`): summarizes the audit-driven hardening pass — trust boundaries, secret redaction in compaction, output hygiene, structured output enforcement, telemetry hygiene, and prompt sanitization.
- **Supported execution** (`README.md:49-99`): documents the `lyrashield` CLI, Python/uv/Docker requirements, GPT-5.6 Terra/Luna provider list (`openai`, `azure`, `azure_ai`, `bedrock_mantle`), ChatGPT subscription path, unsupported endpoints, and the `provider-contract` probe commands.
- **Worker artifact contract** (`README.md:102-111`): describes `run.json` and `vulnerabilities.json` as bounded, schema-validated artifacts and warns the TypeScript worker treats engine output as untrusted.
- **Verification** (`README.md:113-125`): references `scripts/verify-thin-fork.sh`, lists the checks it runs, and explicitly states these prove implementation compatibility, not detection accuracy; points to `benchmarks/README.md` for quality claims.
- **License** (`README.md:127-129`): retains Apache-2.0 attribution and upstream mark notice.

---

## UPGRADES.md

**Hunk:** `@@ -0,0 +1,327 @@` (`UPGRADES.md:1-327`)

New file; the single hunk adds the entire ownership and upstream-import ledger.

- **Purpose** (`UPGRADES.md:1-8`): defines the controlled-derivative policy and the boundary between LyraShield-owned behavior and the retained Strix substrate.
- **LyraShield-owned contract** (`UPGRADES.md:9-26`): GPT-5.6 Terra/Luna acceptance and provider gate, optional Parallel Search `web_search` tool, context/budget/lifecycle ownership, and the `run.json` / `vulnerabilities.json` worker protocol.
- **Compatibility patches** (`UPGRADES.md:28-63`): retained `lyrashield_adapter` behavior, out-of-band budget reservations, bounded dedupe, telemetry and self-update defaults, Pydantic fixes, pre-Docker validation, per-instance binds, worker output compatibility, Apache banners, and formatter/typing compatibility holds.
- **Current upstream base** (`UPGRADES.md:65-86`): pins `8157ccba...`, documents the 2026-07-26 tree-delta import from `08126eb..upstream/main`, and lists the root-agent rename and five report fence-handling fixes that were imported.
- **PR history** (`UPGRADES.md:88-125`): per-PR sections for #20 (cost accounting/telemetry), #22 (token caps / Sol retirement), #26 (8157ccb sync / dedupe reservation), #33 (Azure gates), #35 (cache/cost review), #36 (sync session close), #39 (lint/viewer extra), and #40 (`run.json` progress fields).
- **Deep code review v11** (`UPGRADES.md:127-138`): attribution banner additions and `verify-thin-fork.sh` ledger enforcement.
- **Sync to upstream 2e70402** (`UPGRADES.md:140-203`): major v1.4.1 import themes (LLM lifecycle, prompt caching, model support, budget/resilience, viewer, reporting) and the list of 31 files with meaningful merge work.
- **Independence decision** (`UPGRADES.md:205-212`): states the criteria for when the fork would become fully independent.
- **Documentation reconciliation** (`UPGRADES.md:214-235`): rewrites to `CONTRIBUTING.md`, `docs/usage/cli.mdx`, `docs/advanced/configuration.mdx`, `docs/llm-providers/local.mdx`, and `strix/telemetry/README.md`.
- **Parallel Search web_search tool** (`UPGRADES.md:237-254`): lists the files added/updated for the optional redacted web search tool.
- **Security hardening pass** (`UPGRADES.md:256-327`): per-domain breakdown of the AI_AUDIT_REPORT-driven hardening (trust boundaries, privacy, structured output, telemetry, prompt sanitization) and the new test files added.

---

## AI_AUDIT_REPORT.md

**Hunk:** `@@ -0,0 +1,158 @@` (`AI_AUDIT_REPORT.md:1-158`)

New file; a static AI/LLM safety and production-readiness audit of the Strix-derived engine.

- **Executive Summary** (`AI_AUDIT_REPORT.md:9-21`): characterizes LyraShield as an agentic, multi-LLM security scanner and summarizes the three hardening themes (prompt-injection, privacy, structured-output reliability).
- **AI Feature Classification** (`AI_AUDIT_REPORT.md:25-34`): tables classifying the implementation as agent/tool automation, retrieval, extraction, ranking, and generation.
- **System Boundary Map** (`AI_AUDIT_REPORT.md:37-47`): tables mapping Inputs, Retrieval sources, Model calls, Validation steps, Outputs, and Logging/telemetry with file/line references.
- **Core Concern Audit Findings** (`AI_AUDIT_REPORT.md:50-113`): 21 findings across Factual Grounding, Structured Output Reliability, Fallback Behavior, Cost Ceilings, Latency Budgets, Privacy Exposure, and Prompt Injection Resilience. Each finding includes ID, severity before/after, location, guardrails, gaps, and recommended fix. Many are marked resolved after the hardening pass; open items remain for provider error classification, wall-clock deadlines, and skill pack signing.
- **Strengths and Existing Guardrails** (`AI_AUDIT_REPORT.md:117-125`): lists existing controls such as provider contract probes, budget reservations, tool output bounding, model gating, dedupe pre-checks, context compaction pairing, and report validation.
- **Recommended Fixes** (`AI_AUDIT_REPORT.md:129-153`): prioritized P0/P1/P2 list; most P0 and several P1/P2 items are marked resolved.
- **Conclusion** (`AI_AUDIT_REPORT.md:156-158`): states that the hardening pass addressed the most critical risks and tracks the remaining open items.

---

## scripts/verify-thin-fork.sh

**Hunk:** `@@ -0,0 +1,82 @@` (`scripts/verify-thin-fork.sh:1-82`)

New file; the controlled-derivative gate script.

- **Upstream base validation** (`scripts/verify-thin-fork.sh:10-41`): requires `.lyrashield-upstream-base` to exist and contain a SHA, ensures an `upstream` remote points to `usestrix/strix.git`, and fetches the pinned base if it is not already present.
- **Sync commit discovery** (`scripts/verify-thin-fork.sh:43-49`): finds the fork commit that imported the pinned base into `strix/` by grepping for the short SHA in `strix/` commit messages.
- **Documentation drift check** (`scripts/verify-thin-fork.sh:51-72`): diffs `strix/` between the sync commit and `HEAD`; for each modified file, fails if the file lacks a "Modifications...LyraShield" banner in the first two lines and is not listed in `UPGRADES.md`.
- **Quality gates** (`scripts/verify-thin-fork.sh:74-82`): runs `uv sync --frozen --extra viewer`, `ruff check`, `ruff format --check`, `pytest`, `mypy strix lyrashield_adapter`, and `bandit`.

---

## scripts/verify-worker-contract.sh

**Hunk:** `@@ -0,0 +1,47 @@` (`scripts/verify-worker-contract.sh:1-47`)

New file; cross-repository worker artifact contract gate.

- **App checkout validation** (`scripts/verify-worker-contract.sh:4-19`): takes a path to the `lyrashield-ai` checkout, checks for `package.json`, and confirms the existence of `apps/worker/src/engine/command-builder.test.ts` and `apps/worker/src/engine/output-parser.test.ts`.
- **CLI flag gate** (`scripts/verify-worker-contract.sh:21-39`): runs the `lyrashield` CLI (or the binary in `LYRASHIELD_BIN`) and asserts `--help` contains `--non-interactive`, `--target`, `--scan-mode`, `--instruction`, and `--max-budget-usd`.
- **Worker contract tests** (`scripts/verify-worker-contract.sh:41-47`): enables `corepack`, installs with `pnpm --frozen-lockfile`, and runs the contract tests with `vitest`.

---

## scripts/list-gpt56-providers.py

**Hunk:** `@@ -0,0 +1,25 @@` (`scripts/list-gpt56-providers.py:1-25`)

New file; utility to refresh the GPT-5.6 provider allow-list.

- **Purpose** (`scripts/list-gpt56-providers.py:1-7`): scans the bundled LiteLLM model cost map for `gpt-5.6` model entries and emits the matching `litellm_provider` values, used to update `strix/config/models.py`.
- **Implementation** (`scripts/list-gpt56-providers.py:14-21`): builds a set of provider strings from `litellm.model_cost`, filters by case-insensitive `gpt-5.6` substring, and prints sorted unique providers.

---

## Summary of changes versus base

| File | Change | Hunk | Lines in HEAD |
|------|--------|------|---------------|
| `README.md` | Replaced upstream Strix README with LyraShield controlled-derivative landing | `@@ -1,320 +1,129 @@` | 1-129 |
| `UPGRADES.md` | Added ownership/upstream-import ledger | `@@ -0,0 +1,327 @@` | 1-327 |
| `AI_AUDIT_REPORT.md` | Added AI feature, safety, and production-readiness audit report | `@@ -0,0 +1,158 @@` | 1-158 |
| `scripts/verify-thin-fork.sh` | Added controlled-derivative verification gate | `@@ -0,0 +1,82 @@` | 1-82 |
| `scripts/verify-worker-contract.sh` | Added worker artifact contract verification gate | `@@ -0,0 +1,47 @@` | 1-47 |
| `scripts/list-gpt56-providers.py` | Added LiteLLM GPT-5.6 provider discovery helper | `@@ -0,0 +1,25 @@` | 1-25 |
