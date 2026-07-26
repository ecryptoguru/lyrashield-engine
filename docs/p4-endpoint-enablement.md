# P4 Endpoint Enablement — Programmatic Tool Calling

The engine-side implementation of programmatic tool calling (P4) is complete and fail-closed. It cannot be exercised in a live scan until the configured LLM endpoint supports the Responses API `programmatic_tool_calling` tool type. This document lists the exact coordination steps to enable P4 for LyraShield smoke tests and production.

## Current state

- `strix/agents/factory.py` adds `ProgrammaticToolCallingTool()` to the agent tool list and marks eligible tools with `allowed_callers=["direct", "programmatic"]` when `model_supports_programmatic_tool_calling` returns `True`.
- `strix/config/models.py` gates that support on the model/provider set (OpenAI direct `gpt-5.6-*`, Azure AI when `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING=1` is set).
- The configured Azure AI `gpt-5.6-terra` deployment rejected the parameter with `Unknown parameter: 'tools.programmatic_tool_calling'`, so the engine fell back to the JSON function-tool schema.

## Goal

Run a SAFE or STANDARD scan end-to-end where the engine emits `ProgrammaticToolCallingTool` and the provider returns `program` / `program_output` items, with a measurable token-count reduction versus direct tool calls.

## Prerequisites for the endpoint

1. **Responses API support.** The endpoint must implement OpenAI Responses API (`/v1/responses`) rather than Chat Completions.
2. **`programmatic_tool_calling` tool type.** The provider's model schema must accept `tools` entries with `type: "programmatic_tool_calling"`.
3. **`program` output item support.** The response must be able to return items of type `program` and receive follow-up `program_output` function results.
4. **GPT-5.6 family.** LyraShield only allows `gpt-5.6-terra` or `gpt-5.6-luna` deployments; the endpoint must expose one of these.

## Option A — OpenAI direct endpoint

1. Provision a project or use an existing one that has access to `gpt-5.6-terra` or `gpt-5.6-luna`.
2. Set engine/worker env:

   ```bash
   LYRASHIELD_LLM=gpt-5.6-terra
   OPENAI_API_KEY=<key>
   OPENAI_BASE_URL=https://api.openai.com/v1
   ```

3. Run the provider contract probe:

   ```bash
   uv run python -m strix.interface.provider_contract --require-programmatic-tool-calling
   ```

   Expected: `programmatic_tool_calling.supported = true` and `program` in `output_types`.

4. Run a SAFE scan against `ecryptoguru/OnboardingAI2`:

   ```bash
   LYRASHIELD_PROGRAMMATIC_TOOL_CALLING=1 uv run python -m strix scan --mode safe --target ecryptoguru/OnboardingAI2
   ```

5. Verify in the run transcript that `program` items appear and that `llmRequestCount` / total tokens are lower than the direct-tool baseline.

## Option B — Azure AI Trusted Access / Cyber-enabled deployment

1. Open a support case or partner request with Microsoft to enable the **Trusted Access** (formerly Cyber) feature set on the Azure AI Foundry project.
2. Request that the `gpt-5.6-terra` or `gpt-5.6-luna` deployment be configured for Responses API preview access and `programmatic_tool_calling`.
3. Confirm the deployment endpoint and API version by running:

   ```bash
   curl -H "api-key: $AZURE_AI_API_KEY" \
     "$AZURE_AI_API_BASE/openai/responses?api-version=$AZURE_API_VERSION" \
     -d '{"model":"gpt-5.6-terra","input":"hello"}'
   ```

   A `200` with an `id` field confirms Responses API availability.

4. Set engine/worker env:

   ```bash
   LYRASHIELD_LLM=azure_ai/gpt-5.6-terra
   AZURE_AI_API_KEY=<key>
   AZURE_AI_API_BASE=https://<resource>.services.ai.azure.com
   AZURE_API_VERSION=<preview version>
   ```

5. Run the provider contract probe and a SAFE scan as in Option A.

## Smoke-test checklist

- [ ] `provider_contract` reports `programmatic_tool_calling.supported = true`.
- [ ] Scan completes without `Unknown parameter: 'tools.programmatic_tool_calling'`.
- [ ] Transcript contains `program` output items.
- [ ] `llmRequestCount` is at or below the direct-tool baseline for the same target/mode.
- [ ] No regression in finding count or false-positive rate.
- [ ] Worker `actualCostCents` reconciles with the provider usage response.

## What to do if the endpoint is not ready

Leave `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING` unset or `0`. The engine will continue to use the JSON function-tool schema, which is the verified, no-regression fallback for the current Azure AI deployment.
