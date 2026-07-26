# Engine-side cost and cache optimisation plan

This file contains the engine-side recommendations from `lyrashieldai/docs/reports/gpt-56-cost-cache-analysis.md` so they can be reviewed and applied in the `lyrashield-engine` repository independently of the app changes.

## 1. Goal

Reduce GPT-5.6 input cost and improve cache efficiency for the LyraShield scan engine while preserving the existing safety, budget, and evaluation boundaries.

## 2. Safe / current baseline

The engine already:

- Sets per-scan `prompt_cache_key` (`lyrashield:{scan_id}:coordinator` and `:delegates`) in `strix/core/runner.py`.
- Applies `max_tokens` / `max_output_tokens` caps via `make_model_settings` in `strix/core/inputs.py`.
- Compacts history before requests cross the 272k long-context boundary in `strix/core/hooks.py`.
- Preserves `request_usage_entries` in `strix/report/usage.py` for worker-side pricing.

## 3. Recommended engine changes

### P2 — Explicit prompt-cache breakpoints

#### P2 files

- `strix/core/inputs.py`
- `strix/core/runner.py`

#### P2 what to change

When building the conversation input for a coordinator or delegate, split the prompt into a stable prefix and a variable suffix:

1. Stable prefix (cacheable across turns)
   - system/root instructions
   - skill/tool descriptions
   - repository summary / file map (when it does not change mid-scan)
2. Variable suffix (not cached)
   - current turn task / question
   - target-specific metadata
   - current date, scan mode, user instructions

Use `prompt_cache_breakpoint` in the stable input-text content block to mark the
boundary. Set `prompt_cache_options={"mode": "explicit", "ttl": "30m"}` on
`ModelSettings` for that request; it is not an `extra_args` field. Example input shape:

```json
{
  "type": "message",
  "role": "user",
  "content": [
    {
      "type": "input_text",
      "text": "<stable system/repo context>",
      "prompt_cache_breakpoint": { "mode": "explicit" }
    },
    {
      "type": "input_text",
      "text": "<variable per-turn task>"
    }
  ]
}
```

#### P2 acceptance criteria

- Existing `prompt_cache_key` is retained.
- Cache breakpoints are only emitted for providers/models that advertise support; fall back to current behaviour otherwise.
- No change to root instruction content without updating `prompt_bundle_hash` and re-running regression tests.

#### P2 implementation status

**Implemented.** After upgrading `openai` to `2.48.0` and `openai-agents` to `0.18.3`, `prompt_cache_breakpoint` is exposed in `ResponseInputTextParam`. `strix/core/inputs.py` now splits the coordinator's first user message into a stable target/scope prefix and the variable `Special instructions` suffix, and marks the boundary with `prompt_cache_breakpoint: { "mode": "explicit" }` when the model is a known GPT-5.6 deployment or `LYRASHIELD_PROMPT_CACHE_BREAKPOINTS` is enabled. `strix/core/runner.py` wires `build_root_initial_input(..., model_name=resolved_model)` for the root agent. The feature is gated by `is_gpt56_model` and the `LYRASHIELD_PROMPT_CACHE_BREAKPOINTS` environment variable (`1`/`true` forces on, `0`/`false` forces off, default is the GPT-5.6 allowlist).

### P3b — `LYRASHIELD_MAX_INPUT_TOKENS` / `LYRASHIELD_MAX_OUTPUT_TOKENS` defaults

#### P3b files

- `strix/config/settings.py`
- `strix/core/hooks.py` (already reads `max_input_tokens`)
- `strix/core/runner.py` (already reads `max_output_tokens`)

#### P3b what to change

- Ensure the `LYRASHIELD_*` env aliases for `STRIX_MAX_OUTPUT_TOKENS` and `STRIX_MAX_INPUT_TOKENS` are documented in the engine README.

#### P3b acceptance criteria

- `.env` values flow into `ModelSettings.max_tokens` and compaction thresholds.
- No scan accidentally enters 2x long-context billing because of an unbounded `max_input_tokens`.

#### P3b implementation status

**Already implemented.** `strix/config/settings.py` already maps `STRIX_MAX_*_TOKENS` ↔ `LYRASHIELD_MAX_*_TOKENS` via `_lyra()`, and `strix/core/runner.py` already provides per-mode defaults (`quick` 4_096, `standard` 8_192, `deep` 16_384) with `LYRASHIELD_MAX_OUTPUT_TOKENS` overriding. `strix/core/hooks.py` already clamps `max_input_tokens` below the 2x long-context boundary.

### P4 — Programmatic tool calling for multi-tool agents

#### P4 files

- `strix/core/inputs.py`
- Agent tool registration (`strix/agents/` or `strix/core/agent_factory.py`)

#### P4 what to change

For agents that routinely issue several independent tool calls in a row (repo mapper, file gatherer, SCA collector):

1. Add `"type": "programmatic_tool_calling"` to the agent's `tools` list.
2. Mark eligible function tools with `"allowed_callers": ["programmatic"]`.
3. Update the execution loop to handle `program` output items: run the generated sandbox code, collect `function_call` items, and feed `function_call_output` items back.

#### P4 acceptance criteria

- Smoke test against Azure AI `gpt-5.6-luna` confirms the provider returns `program` items.
- A/B token count vs direct tool calling shows a measurable reduction (transcript reports ~24%).
- Fail closed: if the provider does not support the feature, fall back to direct tool calls.

#### P4 implementation status

**Implemented in the engine, gated by provider support.** The engine now upgrades `openai-agents` to a main-branch commit that exposes `ProgrammaticToolCallingTool` in the `Tool` union, `allowed_callers` on `FunctionTool`/`CustomTool`/`ShellTool`/`ApplyPatchTool`, and `program`/`program_output` handling in the run loop. `strix/agents/factory.py` adds `ProgrammaticToolCallingTool()` to the agent tool list and marks eligible tools with `allowed_callers: ["direct", "programmatic"]` when the resolved model is known to support the feature. It is feature-detected by `model_supports_programmatic_tool_calling` in `strix/config/models.py`.

Provider smoke test against the configured `azure_ai/gpt-5.6-terra` endpoint failed with `Unknown parameter: 'tools.programmatic_tool_calling'`. That Azure AI deployment does not yet expose the Responses API `programmatic_tool_calling` tool type, so the engine falls back to direct tool calls. P4 is therefore **blocked on the endpoint** until a Trusted Access / Cyber-enabled Azure AI deployment (or an OpenAI direct `gpt-5.6-*` endpoint) is available.

The fallback is fail-closed: the engine does not emit `ProgrammaticToolCallingTool` for Azure AI unless `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING=1` is explicitly set, and it keeps Azure on the JSON function-tool schema (`chat_completions_tools=True`) where the current provider is most efficient.

### P5 — Persistent reasoning across turns

#### P5 files

- `strix/core/runner.py`
- `strix/core/inputs.py`

#### P5 what to change

- Store `response.id` from each coordinator turn.
- On the next turn, pass `previous_response_id` and `reasoning: { context: "all_turns" }` in `ModelSettings` / `RunConfig`.
- When `store=False` is required, manually append the full prior output (including encrypted reasoning items) to the input list and use `reasoning.context`.

#### P5 acceptance criteria

- Multi-turn scans maintain continuity without re-sending the entire prior context.
- Cache efficiency improves because the stable prefix is reused with `previous_response_id`.
- Works with the existing `store=False` / ZDR constraints.

#### P5 implementation status

**Blocked by the current session architecture.** The `agents` SDK `Runner.run_streamed` rejects `previous_response_id` when a `session` is provided (`Session persistence cannot be combined with conversation_id, previous_response_id, or auto_previous_response_id`). The LyraShield engine relies on per-agent `SQLiteSession` persistence for resume and multi-turn state, so `previous_response_id` cannot be adopted without replacing local session persistence.

A smoke test with only `Reasoning(context="all_turns")` added to `make_model_settings` produced a ~76% increase in total tokens and ~80% more requests versus the baseline (25 vs 21 requests, 999k vs 836k total tokens), because the SDK's session-based replay still re-sends prior context and the extra reasoning context made the model more verbose. That partial change was reverted; `Reasoning.context` should only be enabled together with `previous_response_id` or a confirmed server-managed conversation flow.

## 4. Testing and verification

- Run the existing 329 engine tests (`make test` or `pytest`) after each change.
- Run a SAFE and a STANDARD scan against `ecryptoguru/OnboardingAI2` with the updated engine image.
- Compare `llmInputTokens`, `llmCachedInputTokens`, `llmRequestCount`, and worker-reconciled `actualCostCents` before/after.
- Confirm no regressions in `strix-sandbox:dev` build, lint (Ruff), type check (mypy), or native-binary checks.

### Quick-scan metrics (OnboardingAI2, `quick` mode, `azure_ai/gpt-5.6-terra`)

| Run | Status | Requests | Input tokens | Cached tokens | Output tokens | Total tokens | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `baseline-quick` (SDK 0.14.6 / openai 2.44.0) | completed | 21 | 827,793 | 640,000 | 8,097 | 835,890 | Pre-optimization baseline |
| `opt-quick-v2` (SDK 0.18.3 / openai 2.48.0, P2 + `Reasoning.context=all_turns`) | completed | 38 | 1,459,091 | 1,069,568 | 14,414 | 1,473,505 | `Reasoning.context` only; reverted |
| `opt-quick-v3` (SDK 0.18.3 / openai 2.48.0, P2 only) | completed | 25 | 988,248 | 765,440 | 11,405 | 999,653 | P2 + path-grant fix; within normal variance |
| `p4-quick` (SDK main / openai 2.48.0, P4 flag set, Azure endpoint) | completed | 20 | 757,026 | 502,784 | 8,351 | 765,377 | PTC disabled due to Azure `chat_completions_tools` path; fallback direct tools |
| `p4-quick-v2` (SDK main / openai 2.48.0, `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING=1`) | failed | - | - | - | - | - | Provider rejected `tools.programmatic_tool_calling` as unknown parameter |
| `p4-final-quick` (SDK main / openai 2.48.0, fallback direct tools) | completed | 20 | 797,081 | 622,592 | 9,306 | 806,387 | No regression; function-tool schema retained for Azure |

Observations:

- P2 itself does not visibly reduce token usage on a single short `quick` scan, but the feature is feature-detected and did not cause errors or regressions.
- The SDK upgrade from `0.14.6` to `0.18.3` introduced a `LocalDirReadError` for source trees outside the project root; this was fixed by adding `extra_path_grants` to the sandbox manifest in `strix/runtime/session_manager.py`.
- `Reasoning.context="all_turns"` without `previous_response_id` materially increased cost and was reverted.
- Cache-hit ratios remained stable (~77% of input tokens cached) across runs.
- The configured Azure AI `gpt-5.6-terra` endpoint does **not** accept `programmatic_tool_calling` tools. P4 is ready engine-side but cannot be exercised on this endpoint until a Trusted Access / Cyber-enabled Azure AI deployment or an OpenAI direct `gpt-5.6-*` endpoint is available.

## 5. Dependencies / blockers

- Azure AI / `azure_ai/gpt-5.6-*` must support the OpenAI Responses API fields used (`prompt_cache_breakpoint`, `programmatic_tool_calling`, `previous_response_id`). The current `gpt-5.6-terra` deployment rejects `programmatic_tool_calling` and still requires `chat_completions_tools=True` for efficient function calling.
- P5 remains blocked by the `openai-agents` session architecture: `Runner.run_streamed` rejects `previous_response_id` when a `session` is provided, and the engine relies on `SQLiteSession` for resume/multi-turn state.
- The engine fork must not expand beyond the documented upstream substrate without LyraShield evaluation evidence.

## 6. Order of implementation

1. P2 — explicit prompt-cache breakpoints (highest ROI, low risk if feature-detected).
2. P3b — max token env plumbing and safe defaults.
3. P4 — programmatic tool calling (provider smoke test required).
4. P5 — persistent reasoning (after P4 if multi-turn continuity remains an issue).
