# Migration Audit — Pre-Execution Verification

> Source-verified against `openai-agents` v0.14.6 at `/tmp/openai-agents` and Strix at `9fb1012`. Five parallel deep-dives covering: agent loop, tool execution, sandbox, LLM/sessions/tracing, and Strix internals.
>
> **Verdict: GO.** No architectural blockers. Five concrete corrections to the plan must be applied before Phase 1; all are <300 LOC total. Migration today is feasible if we apply the corrections below in the listed order.

---

## 1. Verified bridges (no change needed)

These claims from `MIGRATION_EVALUATION.md` were **confirmed against source** — proceed as planned:

| Plan claim | Verification | Source |
|---|---|---|
| `call_model_input_filter` runs before every model call | ✓ Confirmed at `turn_preparation.py:55-80`. **Bonus: filter runs ONCE per turn — its output is captured in a lambda closure for retries (`model_retry.py:34-35`). Inbox messages will NOT be drained twice on retry.** Open question #1 in plan §11 is resolved. | `run_internal/turn_preparation.py:48-82`, `run_internal/run_loop.py:1363-1369, 1803-1809` |
| `asyncio.create_task(Runner.run(...))` is isolation-safe | ✓ Each task gets own `RunContextWrapper`; contextvars properly isolated. No global state mutation inside `Runner.run`. | `run.py:486-615`, `run_context.py:42-51` |
| Shared `SandboxRunConfig(session=...)` across parallel runs | ✓ SDK does NOT tear down sandbox sessions at run end; caller owns lifecycle. Safe to reuse one session across N children. | `run_config.py:115-138`, `docker.py:1372-1401` |
| `RunContextWrapper.context` mutable across turns | ✓ Dict is by-reference; mutations persist. Bus + agent_id stash will work as designed. | `run_context.py:42-51`, `run.py:615` |
| `RunHooks.on_agent_end` fires once per Runner.run | ✓ Single fire when `final_output` established. | `run_internal/turn_resolution.py:204-255` |
| Custom Docker image accepted | ✓ `DockerSandboxClientOptions(image=str)` is verbatim pass-through to `containers.create(image=...)`. No assumed binaries. | `sandbox/sandboxes/docker.py:106-122, 1340, 1444-1456` |
| `Manifest.environment` reaches container | ✓ Resolved via `await manifest.environment.resolve()` and passed to `containers.create(environment=...)`. | `sandbox/sandboxes/docker.py:1448-1450` |
| `Manifest` entries are a strict superset (LocalDir, GitRepo, mounts) | ✓ Direct LocalDir maps to our tar-pipe with concurrency limits. | `sandbox/entries/__init__.py`, `artifacts.py:127-179` |
| Capability lifecycle (clone, bind, tools, instructions, process_manifest) | ✓ Per-run cloned; bound after container start; can hold mutable state. CaidoCapability viable. | `sandbox/capabilities/capability.py:15-100`, `sandbox/runtime.py:180-256` |
| MultiProvider with custom prefix routing | ✓ `MultiProviderMap.add_provider("strix", StrixModelProvider())` works exactly. | `models/multi_provider.py:16-49, 138-232` |
| Custom `ModelProvider` interface | ✓ Just `get_model(model_name) -> Model`. Post-prefix-strip name received. | `models/interface.py:127-151` |
| LitellmModel reasoning effort priority | ✓ Exact: `reasoning.effort` > `extra_body["reasoning_effort"]` > `extra_args["reasoning_effort"]`. | `extensions/models/litellm_model.py:162-199` |
| LitellmModel streaming + tool-call assembly across providers | ✓ `ChatCmplStreamHandler.handle_stream()` unifies provider-native streaming (Anthropic, OpenAI, etc.) into common stream format. | `extensions/models/litellm_model.py:315-351` |
| `add_trace_processor()` / `set_trace_processors()` | ✓ Both exist; can disable defaults entirely. | `tracing/__init__.py:94-130` |
| `RunHooks` 7-hook surface area | ✓ All 7 hooks fire as documented. RunHooks + AgentHooks both fire (gathered). | `lifecycle.py:13-99, 102-199` |
| Per-tool timeout default is `None` | ✓ Confirmed. Our `strix_tool()` factory will re-impose 120s. | `tool.py:337-338` |
| `RunState.to_json()/from_json()` resumable across processes | ✓ Schema v1.9; full serialization. | `run_state.py:1-200` |
| `tracing_disabled` per-RunConfig | ✓ Disables ALL tracing for that run. | `run_config.py:186-188` |
| `OPENAI_AGENTS_DONT_LOG_MODEL_DATA` env | ✓ Logging only; independent from tracing. | `_debug.py:12-21` |
| Sync function tools auto-offload via `asyncio.to_thread` | ✓ **Plan was wrong** — SDK DOES auto-thread sync `@function_tool` bodies. We can drop the manual `asyncio.to_thread` wrapping in our libtmux/IPython tools and just write sync functions. ~30 LOC saved. | `tool.py:1820-1829` |
| `ToolGuardrailFunctionOutput.reject_content("nope")` continues run | ✓ Model sees "nope" as tool output and proceeds. Run NOT halted. | `tool_guardrails.py:79-105` |
| Multi-agent stat aggregation via hooks | ✓ `on_llm_end` + `on_agent_end` fire on each child Runner.run; bus aggregation works. | `lifecycle.py`, `run_internal/turn_resolution.py:204-255` |

---

## 2. Critical corrections (must apply before / during Phase 1)

Five corrections to the plan. All are concrete and small.

### 2.1 [BLOCKER] Strix tool server slot serialization vs SDK parallel tool calls

**The collision.** SDK fires N tool calls in one turn as N concurrent `asyncio.create_task` (`run_internal/tool_execution.py:1414`, `:1424-1430`). Strix tool server cancels the previous in-flight task for the same agent on every new request (`tool_server.py:94-97`). When SDK issues `terminal_execute` + `web_search` simultaneously for the same agent, the second cancels the first.

**Fix (Phase 1 — safe default).** Add to the default RunConfig for every Strix run:

```python
RunConfig(
    model_settings=ModelSettings(
        parallel_tool_calls=False,   # model-side hint: emit one tool call per turn
        ...
    ),
    isolate_parallel_failures=False, # if model emits multiple anyway, don't cascade-cancel
    ...
)
```

**Caveat.** `parallel_tool_calls` is a **provider hint** (`model_settings.py:89-96`), not enforced SDK-side. The model may still emit multiple. With `isolate_parallel_failures=False`, sibling tools survive a single failure; but the tool server still cancels prev-task on same-agent collision.

**Fix (Phase 2 — proper).** Relax `tool_server.py:94-97` to allow concurrent same-agent tool calls. The cancellation logic was Strix's old serialization; we don't need it under the SDK's orchestration. ~10 LOC removal. Re-test multi-agent end-to-end.

**Effort:** 0.5 day (safe default in Phase 1) + 0.5 day (proper fix + tests in Phase 2).

---

### 2.2 [BLOCKER] Anthropic prompt cache placement is wrong in plan

**The defect.** Plan §3.2 said: set `ModelSettings(extra_body={"cache_control": {"type": "ephemeral"}})`. Verified at `extensions/models/litellm_model.py:509-516` — this lands `cache_control` in the **request-level** `extra_body`, not on the system message. **Anthropic requires `cache_control` on the system message itself** (per Anthropic API spec). Plan would silently cache nothing.

**Fix.** Build a thin `LitellmModel` subclass that injects `cache_control` into the message list before delegating to parent:

```python
# strix/llm/anthropic_cache_wrapper.py  (~40 LOC)
from agents.extensions.models.litellm_model import LitellmModel

class AnthropicCachingLitellmModel(LitellmModel):
    def _patch_system_message_for_cache(self, input_items: list) -> list:
        if not _is_anthropic(self.model):
            return input_items
        patched = []
        for item in input_items:
            if isinstance(item, dict) and item.get("role") == "system":
                content = item["content"]
                if isinstance(content, str):
                    content = [{"type": "text", "text": content,
                                "cache_control": {"type": "ephemeral"}}]
                patched.append({**item, "content": content})
            else:
                patched.append(item)
        return patched

    async def get_response(self, *, input, **kwargs):
        return await super().get_response(input=self._patch_system_message_for_cache(input), **kwargs)

    async def stream_response(self, *, input, **kwargs):
        async for ev in super().stream_response(input=self._patch_system_message_for_cache(input), **kwargs):
            yield ev
```

Wire into our `MultiProviderMap` so any `litellm/anthropic/...` route uses this wrapper.

**Effort:** 0.5 day (~40 LOC + tests).

---

### 2.3 [BLOCKER] DockerSandboxClient subclass requires full method duplication

**The reality.** Audit #2 verified that `_create_container()` (`sandbox/sandboxes/docker.py:1434-1477`) builds `create_kwargs` locally and **does not** expose a hook for kwarg injection. Subclass must reimplement the method body. ~100-120 LOC duplication. Plan said "~80 LOC" — bump to ~120 LOC.

**Fix.** Subclass and copy the parent body verbatim, adding our injections before the final `containers.create(**create_kwargs)` line:

```python
# strix/runtime/strix_docker_client.py  (~120 LOC)
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient, _build_docker_volume_mounts,
    _manifest_requires_fuse, _manifest_requires_sys_admin,
    _docker_port_key, parse_repository_tag,
)

class StrixDockerSandboxClient(DockerSandboxClient):
    async def _create_container(self, image, *, manifest=None, exposed_ports=(), session_id=None):
        # --- copy of parent _create_container body (lines 1442-1476) ---
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        environment = None
        if manifest:
            environment = await manifest.environment.resolve()

        create_kwargs = {
            "entrypoint": ["tail"],
            "image": image,
            "detach": True,
            "command": ["-f", "/dev/null"],
            "environment": environment,
        }

        if manifest is not None:
            mounts = _build_docker_volume_mounts(manifest, session_id=session_id)
            if mounts:
                create_kwargs["mounts"] = mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.setdefault("devices", []).append("/dev/fuse")
                create_kwargs.setdefault("cap_add", []).append("SYS_ADMIN")
                create_kwargs.setdefault("security_opt", []).append("apparmor:unconfined")
            if _manifest_requires_sys_admin(manifest):
                create_kwargs.setdefault("cap_add", []).append("SYS_ADMIN")

        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(p): ("127.0.0.1", None) for p in exposed_ports
            }

        # --- STRIX INJECTIONS ---
        create_kwargs.setdefault("cap_add", []).extend(["NET_ADMIN", "NET_RAW"])
        create_kwargs.setdefault("extra_hosts", {})["host.docker.internal"] = "host-gateway"

        return self.docker_client.containers.create(**create_kwargs)
```

**Risk.** SDK upstream changes to `_create_container` won't propagate. Pin SDK version; track upstream in CI; consider upstream PR for `additional_create_kwargs` hook.

**Effort:** 0.5 day (~120 LOC + integration test).

---

### 2.4 [BLOCKER] Subagent must exit cleanly via `agent_finish` — needs `tool_use_behavior` configuration

**The risk.** When subagent calls `agent_finish` and we return a result string from the tool, SDK's loop checks `Agent.tool_use_behavior` (`turn_resolution.py:512-544`). If not configured to permit early exit, the loop continues until `max_turns`. Children would burn budget instead of finishing.

**Fix.** On every Strix subagent's `Agent`, configure:

```python
child_agent = Agent(
    name=name,
    instructions=...,
    tools=[..., agent_finish, ...],
    tool_use_behavior={
        "stop_at_tool_names": ["agent_finish"],
    },
    ...
)
```

This tells the SDK: as soon as `agent_finish` returns, treat that as final output. Same pattern for root agent + `finish_scan`:

```python
root_agent = Agent(
    name="strix-root",
    tool_use_behavior={"stop_at_tool_names": ["finish_scan"]},
    ...
)
```

**Effort:** Trivial — one config line per agent factory.

---

### 2.5 [HIGH] Streaming TUI integration needs a planned shape

**The reality.** Plan §10 phase 5 said "TUI re-pointed at `Runner.run_streamed().stream_events()`" — true, but Strix's current TUI polls `tracer.streaming_content` at 2 Hz with **per-chunk granularity**. SDK `stream_events()` exposes `RawResponsesStreamEvent` (raw chunks) and `RunItemStreamEvent` (semantic items) — sufficient, but we lose Strix's `update_streaming_content(agent_id, accumulated_text)` API that aggregates incremental text.

**Fix.** Build a `StrixStreamAccumulator` that consumes `Runner.run_streamed().stream_events()` and synthesizes the same shape Strix's tracer used to expose:

```python
async for event in result.stream_events():
    if event.type == "raw_response_event":
        delta = _extract_text_delta(event.data)
        if delta:
            tracer.append_streaming_content(agent_id, delta)
    elif event.type == "run_item_stream_event":
        if event.name == "tool_called":
            tracer.log_tool_start(agent_id, event.item.tool_name)
        elif event.name == "tool_output":
            tracer.log_tool_end(agent_id, event.item.tool_name, event.item.output)
```

Plus, `RunHooks.on_llm_start/on_llm_end/on_tool_start/on_tool_end` fire regardless of streaming mode, so child agents launched via `Runner.run` (not streamed) still feed the tracer through hooks. The TUI subscribes to the same tracer.

**Effort:** 1.5 days for both stream accumulator + hook bridge + TUI repoint.

---

## 3. Medium-severity adjustments (Phase 1-2)

| # | Issue | Source | Fix | Effort |
|---|---|---|---|---|
| M1 | Cost tracking — SDK has `Usage(input/output/cached_tokens)` but no cost field. `litellm.completion_cost()` requires raw litellm response, not SDK's `ModelResponse`. | `usage.py`, `extensions/models/litellm_model.py:254-293` | Inside our `AnthropicCachingLitellmModel` and a similar light wrapper for OpenAI, capture the litellm response and store cost in `ModelResponse.usage` via `litellm.cost_per_token(...)` (which takes tokens, not response). Then `RunHooks.on_llm_end` reads it. | 0.5 day |
| M2 | Vision-less model image stripping — SDK has none, will pass-through and provider rejects. | None | If we end up routing to a non-vision model, build a wrapper Model that strips images. Defer; current models (Claude Sonnet 4.6, GPT-5, Gemini) are all vision-capable. | Defer (0 day) |
| M3 | SQLiteSession uses `threading.RLock`, not `asyncio.Lock`. Concurrent async writes from parallel children may interleave. | `memory/sqlite_session.py:17-175` | Use a separate `Session` per child (history is per-agent anyway); only share `SandboxRunConfig.session`. Plan §4.7 already says this — emphasize it in code review. | 0 day (already in plan) |
| M4 | Trace processor memory pressure on 300-turn runs. | `tracing/processor_interface.py` | Custom processor batches every 100 spans + `force_flush()` periodically. | 0.5 day |
| M5 | Streaming events don't expose token deltas — only raw chunks. | `stream_events.py` | Parse `RawResponsesStreamEvent.data` chunks for token text manually in our accumulator. | (rolled into 2.5) |
| M6 | `trace_include_sensitive_data` is binary, no field-level. | `run_config.py:193-199` | Custom trace processor scrubs PII via existing `TelemetrySanitizer`. Plan already says this. | 0 day (already in plan) |
| M7 | Caido + tool server readiness check needs a place to await — Capability.bind() is sync. | `sandbox/capabilities/capability.py:29-31` | Spawn a background task in bind() (`_healthcheck_task`); await it inside `RunHooks.on_agent_start`. ~30 LOC. | 0.5 day |
| M8 | `vulnerability_found_callback` (TUI popup trigger) — no SDK-native equivalent. | Strix `telemetry/tracer.py:89` | Wrap `create_vulnerability_report` tool with an output guardrail that fires the callback on success. | 0.5 day |
| M9 | `<agent_delegation>` XML wrapper today contains structured identity that the system prompt has rules to ignore. | Strix `system_prompt.jinja:19-22`, `agents_graph_actions.py:238-266` | Replicate exact XML envelope when `inject_messages_filter` adds the parent's task message OR when `create_agent` builds the child's initial input. Keeps system prompt rules intact unchanged. | 0.5 day |
| M10 | Whitebox wiki note auto-update on subagent finish (side effect on `agent_finish` tool). | Strix `agents_graph_actions.py:161-202` | Implement directly inside our `agent_finish` function tool body, just like today. | 0 day (free port) |
| M11 | `_force_stop` mid-turn soft-interrupt has no SDK equivalent. | Strix `base_agent.py:84` | Use `result.cancel(mode="after_turn")` for cooperative cancel; for mid-turn hard cancel, `.cancel(mode="immediate")`. | 0 day (use `result.cancel`) |
| M12 | 85% / N-3 turn warnings as user messages. | Strix `base_agent.py:186-211` | `RunHooks.on_llm_start` checks `ctx.usage` turn count; if at threshold, mutate `input_items` (passed by reference per `lifecycle.py:18-26`). Verify mutation visibility in source: hook signature shows `input_items` is the list; mutations propagate. | 0.5 day |

---

## 4. Pre-Phase-1 spike (1 day)

Before writing production code, validate the assumptions in a tiny throwaway script:

1. **Two-children messaging smoke test.** Build minimal `MessageBus` + `inject_messages_filter` + 2 child agents that exchange one message each. Run with `LitellmModel("anthropic/claude-sonnet-4-5-20250929")` (or whatever Anthropic alias is current). Verify: messages arrive, hooks fire, no deadlock, no message duplication on retry.
2. **Anthropic cache wrapper smoke test.** Send 3 requests with identical system prompt; check Anthropic response usage `cache_creation_input_tokens` on call 1 and `cache_read_input_tokens` on calls 2-3.
3. **`StrixDockerSandboxClient` smoke test.** Pull our Kali image, create a session, run `nmap -sS scanme.nmap.org` via `session.exec()` to verify NET_RAW works.
4. **`tool_use_behavior={"stop_at_tool_names": [...]}` smoke test.** Toy agent with `agent_finish`-equivalent; verify SDK terminates exactly when expected.
5. **Tool server parallel-call smoke test.** Issue two POSTs to local tool server with same `agent_id` simultaneously; observe whether second cancels first under current code.

If any spike fails, fix before Phase 1. If all pass, proceed.

**Effort:** 1 day.

---

## 5. Updated migration plan (rev 3 sequencing)

Replaces `MIGRATION_EVALUATION.md` §10. Same scope, with corrections folded in.

### Phase 0 — Spike & corrections (1.5 days)
- Run the 5 spikes above.
- Build `AnthropicCachingLitellmModel` (~40 LOC). Smoke-tested.
- Build `StrixDockerSandboxClient` (~120 LOC). Smoke-tested.
- Decide tool server fix: relax serialization (recommended) OR set `parallel_tool_calls=False` + `isolate_parallel_failures=False` (safe default).

### Phase 1 — Foundation (4 days)
- `MultiProvider` + `MultiProviderMap` with `StrixModelProvider` for our aliases.
- Wire `AnthropicCachingLitellmModel` into the provider map.
- `strix_tool` decorator (~30 LOC; just `function_tool` with default `timeout=120, timeout_behavior="error_as_result"`).
- Custom `Session` subclass with our memory compressor strategy.
- Custom `TracingProcessor` with JSONL + scrubadub PII scrub. `set_trace_processors([StrixProcessor()])` to disable defaults.
- `RunConfig` factory that bakes in: `tracing_disabled=False`, `isolate_parallel_failures=False`, `model_settings.parallel_tool_calls=False` (until Phase 6 relaxes), our processors.
- Cost tracking inside the model wrapper (M1).

### Phase 2 — Tool ports (8 days)
- Sandbox dispatcher: one helper that POSTs to FastAPI tool server with httpx (`Timeout(connect=10, total=150)`) + Bearer auth.
- All 30+ tools as `@strix_tool`. Sync ones use `def`, SDK auto-threads them.
- Browser as `ComputerTool` + `AsyncComputer` subclass (or as a single `@strix_tool` if `ComputerTool` semantics don't match).
- Stateful tools key off `RunContextWrapper.context["agent_id"]` (helper: `get_agent_id(ctx)`).
- `create_vulnerability_report` wraps `ToolOutputGuardrail` to fire the TUI popup callback (M8).
- Verify reentrancy on browser singleton, tmux sessions, IPython kernels.

### Phase 3 — Multi-agent orchestration (4 days)
- `AgentMessageBus` + tests.
- `inject_messages_filter` + tests including retry simulation (verified safe by audit; no de-dup needed).
- `StrixOrchestrationHooks` for stat aggregation + tracer wiring.
- Six graph tools (`create_agent`, `send_message_to_agent`, `wait_for_message`, `agent_status`, `view_agent_graph`, `agent_finish`).
- Every child Agent: `tool_use_behavior={"stop_at_tool_names": ["agent_finish"]}`.
- Root Agent: `tool_use_behavior={"stop_at_tool_names": ["finish_scan"]}`.
- Identity injection via `<agent_delegation>` XML in the **first user message** of the child Runner (M9).
- Wiki auto-update on whitebox `agent_finish` (M10).

### Phase 4 — Sandbox + Caido capability (2 days)
- `StrixDockerSandboxClient` (already in Phase 0).
- `CaidoCapability` with `process_manifest` (env vars), `tools()` (7 Caido tools), `instructions()` (proxy-aware system block), `bind()` (spawn healthcheck task).
- `RunHooks.on_agent_start` awaits Caido + tool server readiness via the capability's healthcheck task (M7).
- Container reuse keyed by scan_id in our session map.

### Phase 5 — Interface + persistence (3 days)
- Streaming accumulator wires `Runner.run_streamed().stream_events()` → tracer (replaces today's per-chunk `update_streaming_content`).
- TUI keeps its 2 Hz polling against the tracer; tracer is now event-driven from the accumulator.
- 85% / N-3 turn warnings via `RunHooks.on_llm_start` mutating `input_items` (M12).
- Run-directory layout via custom `TracingProcessor` writing `events.jsonl`, `vulnerabilities/`, etc.
- CLI / config / argparse layer unchanged.

### Phase 6 — Validation + tool server relaxation (4 days)
- Smoke: every tool runs in sandbox.
- Multi-agent: 2+ parallel children + messaging + cancel.
- Bedrock + Anthropic + OpenAI parity.
- Memory compression at 90K.
- PII redaction.
- Real pentest end-to-end vs Strix baseline diff.
- **Now relax tool_server.py:94-97** (remove per-agent task cancellation), set `parallel_tool_calls=True` and `isolate_parallel_failures=True`. Re-run multi-agent test. If clean → ship parallelism.

### Buffer (2 days)
For unforeseen issues from spike feedback or test failures.

**Total: ~28.5 days** (vs plan's 25–35). Within budget.

---

## 6. Final go/no-go

✅ **GO.**

**Why:**
- All architectural assumptions validated. No showstoppers found.
- The 5 corrections in §2 are concrete, small, and isolated to specific phases.
- The 12 medium adjustments in §3 are sensible and most are already implicit in the plan.
- The plan's rev-2 effort estimate (25–35 days) holds with corrections (~28.5 days).

**Day-1 first commits (in order):**
1. `strix/llm/anthropic_cache_wrapper.py` — `AnthropicCachingLitellmModel`.
2. `strix/runtime/strix_docker_client.py` — `StrixDockerSandboxClient`.
3. `strix/orchestration/bus.py` — `AgentMessageBus`.
4. `strix/orchestration/filter.py` — `inject_messages_filter`.
5. `strix/orchestration/hooks.py` — `StrixOrchestrationHooks`.
6. `strix/tools/_decorator.py` — `strix_tool` factory.
7. `strix/llm/multi_provider_setup.py` — `MultiProviderMap` wiring + `StrixModelProvider`.

These seven files (~600 LOC total) form the migration's load-bearing foundation. Everything else is incremental ports onto this foundation.

Branch is already on `harness-migration`. Ready when you are.
