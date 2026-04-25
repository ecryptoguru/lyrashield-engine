# Migration Audit — Round 3 Findings

> Five new deep-dives covering scenario walkthroughs, type/signature compatibility, CLI/interface migration, pathological edge cases, and build/deps/deployment. Adds 13 more concrete corrections (C13–C25) and 3 critical type-signature fixes that must be applied to `PLAYBOOK.md` before Phase 0 starts.

---

## 1. Critical type/signature fixes (PLAYBOOK skeletons are wrong)

These three fixes are **applied inline to `PLAYBOOK.md`** in this round. The skeletons as written would not compile against SDK v0.14.6.

### F1 — `AnthropicCachingLitellmModel` method signature wrong

**PLAYBOOK §2.1 was:** `async def get_response(self, *, system_instructions, input, model_settings, ...)`

**SDK reality** (`models/interface.py:57-89`): The first 7 params (`system_instructions, input, model_settings, tools, output_schema, handoffs, tracing`) are **positional-first**, then `*,` then keyword-only (`previous_response_id`, `conversation_id`, `prompt`).

Same fix applies to `stream_response`. Both must drop the leading `*,` and pass the first 7 params positionally to `super()`.

**Status:** Inline-corrected in `PLAYBOOK.md` §2.1 below.

### F2 — `RunHooks` lifecycle hook signatures wrong

**PLAYBOOK §2.5 was:** `on_agent_start(self, ctx, agent)` and `on_agent_end(self, ctx, agent, output)` typed `ctx` as `RunContextWrapper`.

**SDK reality** (`lifecycle.py:37-59`): These two specific hooks receive `context: AgentHookContext[TContext]`, not `RunContextWrapper`. `AgentHookContext` is a different generic wrapper with the same `.context` attribute pattern but a distinct type.

Also: `on_tool_end(self, ctx, agent, tool, result)` — the `result` parameter is typed `str`, not `Any`.

**Status:** Inline-corrected in `PLAYBOOK.md` §2.5 below.

### F3 — `TracingProcessor` hook methods are SYNC

**PLAYBOOK §2.9 was:** All hook methods (`on_trace_start`, `on_trace_end`, `on_span_start`, `on_span_end`, `force_flush`, `shutdown`) shown without explicit `async` keyword — implementation accidentally implied async.

**SDK reality** (`tracing/processor_interface.py:53-129`): All hooks are **synchronous** (`def`, not `async def`). Our processor must use sync methods. JSONL writes are sync I/O which is fine; if we ever want async export, we'd need to schedule via `asyncio.run_coroutine_threadsafe()` from the sync hook.

**Status:** Inline-corrected in `PLAYBOOK.md` §2.9 below.

---

## 2. New corrections (C13–C25)

Additive to the 12 corrections in `AUDIT.md` + `AUDIT_R2.md`.

### C13 [HIGH] Bus must clear inbox/parent_of/names on finalize (Round 3.4)

**Defect.** When an agent finishes, `bus.finalize` only updates statuses and stats — but children whose parent already finished may still call `bus.send(parent_id, msg)`, accumulating messages in `bus.inboxes[parent_id]` forever. Memory leak bounded by agent count × messages per cycle.

**Fix.** Update `AgentMessageBus.finalize()`:

```python
async def finalize(self, agent_id: str, status: str) -> None:
    async with self._lock:
        self.statuses[agent_id] = status
        self.stats_completed[agent_id] = self.stats_live.pop(agent_id, {})
        self.inboxes.pop(agent_id, None)        # NEW
        self.parent_of.pop(agent_id, None)      # NEW
        self.names.pop(agent_id, None)          # NEW
```

**Apply in Phase 3** (in `strix/orchestration/bus.py`).

### C14 [HIGH] `inject_messages_filter` must be defensive

**Defect.** If a bug in the filter raises, SDK treats it as a model invocation failure and retries. Filter raises on every retry → run fails after `max_retries` exhausted.

**Fix.** Wrap filter body in try/except; return unmodified `data.model_data` on exception:

```python
async def inject_messages_filter(data: CallModelData) -> ModelInputData:
    try:
        if not isinstance(data.context, dict):
            return data.model_data
        bus = data.context.get("bus")
        agent_id = data.context.get("agent_id")
        if bus is None or agent_id is None:
            return data.model_data
        pending = await bus.drain(agent_id)
        if not pending:
            return data.model_data
        new_input = list(data.model_data.input)
        for msg in pending:
            # ... XML wrapping
        return ModelInputData(input=new_input, instructions=data.model_data.instructions)
    except Exception:
        logger.exception("inject_messages_filter failed; proceeding without injection")
        return data.model_data
```

**Apply in Phase 3** (in `strix/orchestration/filter.py`).

### C15 [HIGH] `RunHooks` must be defensive

**Defect.** If our hook bodies raise (e.g., bus operation fails, tracer disk error), exception propagates and tears down the run.

**Fix.** Each hook wraps its body in try/except; logs and continues:

```python
async def on_llm_start(self, context, agent, system_prompt, input_items):
    try:
        # ... mutate input_items, increment turn count, etc.
    except Exception:
        logger.exception("on_llm_start failed")

# Same for on_llm_end, on_agent_start, on_agent_end, on_tool_start, on_tool_end, on_handoff
```

**Apply in Phase 3** (in `strix/orchestration/hooks.py`).

### C16 [HIGH] Custom `TracingProcessor` must catch disk errors

**Defect.** PLAYBOOK §2.9 `_emit()` opens file with `"a"` mode; OSError (disk full, permission denied) propagates from sync hook. SDK's hook caller may not gracefully handle. Run dies.

**Fix.** Wrap `_emit` body in try/except; log and continue:

```python
def _emit(self, event: dict[str, Any]) -> None:
    try:
        clean = self.sanitizer.sanitize(event)
        with _lock_for(self.events_path):
            with self.events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(clean, ensure_ascii=True) + "\n")
    except OSError:
        logger.exception("Failed to write event to JSONL")
```

**Apply in Phase 1** (in `strix/telemetry/strix_processor.py`).

### C17 [MEDIUM] `StrixModelProvider` must validate model alias

**Defect.** If `STRIX_LLM=strix/typo-model-name` (alias not in `STRIX_MODEL_MAP`), our provider falls through to `(model_name, model_name)` and the LLM call later fails with provider's "model not found" — opaque diagnostic.

**Fix.** Validate at `get_model()` entry; raise `UserError` with the list of valid aliases:

```python
def get_model(self, model_name: str | None) -> Model:
    if model_name is None:
        raise UserError("Model name required for StrixModelProvider")
    if model_name not in STRIX_MODEL_MAP:
        raise UserError(
            f"Unknown Strix alias '{model_name}'. "
            f"Valid: {list(STRIX_MODEL_MAP.keys())}"
        )
    api_model, _ = STRIX_MODEL_MAP[model_name]
    if "anthropic/" in api_model or "claude" in api_model.lower():
        return AnthropicCachingLitellmModel(model=api_model, base_url=STRIX_API_BASE)
    return LitellmModel(model=api_model, base_url=STRIX_API_BASE)
```

**Apply in Phase 1** (in `strix/llm/multi_provider_setup.py`).

### C18 [MEDIUM] Model output size cap on sandbox tools

**Defect.** A tool returning 50MB binary output (e.g., browser screenshot of a huge map) gets base64-encoded into JSON; httpx loads the response into RAM; OOM on small hosts.

**Fix.** Configure `httpx.Limits(max_content_size=...)` in `post_to_sandbox`:

```python
_TIMEOUT = httpx.Timeout(connect=10.0, read=150.0, write=150.0, pool=150.0)
_LIMITS = httpx.Limits(max_connections=10, max_keepalive_connections=5)

async def post_to_sandbox(ctx, tool_name, kwargs) -> dict:
    # ...
    async with httpx.AsyncClient(timeout=_TIMEOUT, limits=_LIMITS) as client:
        r = await client.post(url, json=body, headers=headers)
        if int(r.headers.get("content-length", 0)) > 50_000_000:
            return {"error": "Sandbox response too large (>50MB)"}
        # ...
```

Plus: cap on the sandbox side too (tool server limits its own response payload).

**Apply in Phase 2** (in `strix/tools/_sandbox_dispatch.py`).

### C19 [MEDIUM] `tool_choice="required"` requires at least one enabled tool

**Defect.** If `is_enabled` callbacks gate out all tools and `ModelSettings(tool_choice="required")`, model has no legal response. SDK raises `ModelBehaviorError`. Run fails opaquely.

**Fix.** Assert at agent build time:

```python
def build_strix_agent(name, tools, ...) -> Agent:
    enabled_count = len([t for t in tools if not _statically_disabled(t)])
    if enabled_count == 0:
        raise UserError(f"Agent {name} has no enabled tools but tool_choice='required'")
    return Agent(name=name, tools=tools, ...)
```

**Apply in Phase 1** (in agent factory).

### C20 [MEDIUM] Per-tool `timeout_behavior` discrimination

**Defect.** If `timeout_behavior="error_as_result"` on a critical sandbox tool (e.g., `terminal_execute`), model sees the timeout error string and may retry the same tool with same args → infinite loop.

**Fix.** For critical sandbox tools, use `timeout_behavior="raise_exception"` so the model is told via SDK's error machinery that the tool genuinely failed (not just timed out gracefully). For idempotent local tools (notes, todos), `error_as_result` is fine.

**Apply in Phase 2** — when porting each tool, pick the appropriate behavior.

### C21 [MEDIUM] `make_run_config` and `make_agent_context` need overrides

**Defect.** Plan §H1: today there's no path for per-run override of `model_settings` (e.g., user wants `tool_choice="auto"` for a specific run). And `is_whitebox` flag isn't propagated to context — wiki auto-update on subagent finish (M10) reads `ctx.context.get("is_whitebox")` but it's never set.

**Fix.**

```python
def make_run_config(*, sandbox_session, bus, model="strix/claude-sonnet-4.6",
                    max_turns=300, model_settings_override: dict | None = None) -> RunConfig:
    base_settings = ModelSettings(parallel_tool_calls=False, tool_choice="required", retry=...)
    if model_settings_override:
        base_settings = base_settings.model_copy(update=model_settings_override)
    return RunConfig(model_settings=base_settings, ...)


def make_agent_context(*, bus, sandbox_session, sandbox_token,
                       tool_server_host_port, caido_host_port, agent_id, agent_name,
                       parent_id, tracer, model_settings, max_turns=300,
                       is_whitebox: bool = False,                     # NEW
                       diff_scope: dict | None = None,                # NEW (J1)
                       run_id: str | None = None) -> dict:            # NEW (run-id propagation)
    return {
        "bus": bus, "sandbox_session": sandbox_session,
        "sandbox_token": sandbox_token,
        "tool_server_host_port": tool_server_host_port,
        "caido_host_port": caido_host_port,
        "agent_id": agent_id, "agent_name": agent_name,
        "parent_id": parent_id, "tracer": tracer,
        "model_settings": model_settings, "max_turns": max_turns,
        "turn_count": 0, "agent_finish_called": False,
        "is_whitebox": is_whitebox,
        "diff_scope": diff_scope,
        "run_id": run_id,
    }
```

**Apply in Phase 1** (in `strix/run_config_factory.py`).

### C22 [MEDIUM] `finish_scan` must check children status before exit

**Defect.** Strix today's `finish_scan` validates that all child agents are not running/stopping (`tools/finish/finish_actions.py:98`). PLAYBOOK §4.2 didn't carry this forward. Without the check, root could finish while children are still in-flight.

**Fix.** Inside `finish_scan` tool body:

```python
@strix_tool(timeout=30)
async def finish_scan(ctx, executive_summary: str, methodology: str,
                       technical_analysis: str, recommendations: str) -> str:
    if ctx.context.get("parent_id") is not None:
        return "Error: finish_scan is for the root agent only. Subagents must call agent_finish."
    bus = ctx.context["bus"]
    me = ctx.context["agent_id"]
    async with bus._lock:
        in_flight = [
            child_id for child_id, parent in bus.parent_of.items()
            if parent == me and bus.statuses.get(child_id) in ("running", "waiting")
        ]
    if in_flight:
        names = [bus.names.get(c, c) for c in in_flight]
        return (
            f"Cannot finish: subagents still running: {names}. "
            f"Wait for completion (or call stop_agent) before finishing the scan."
        )
    ctx.context["agent_finish_called"] = True
    # ... write narrative fields, persist final report
    return "Scan completed. Report written."
```

**Apply in Phase 2** (when porting `finish_scan`).

### C23 [MEDIUM] Diff-scope context injection point

**Defect.** Plan §J1: PLAYBOOK doesn't say where the diff scope context (from `resolve_diff_scope_context()`) is injected post-migration.

**Fix.** Two-part:
1. CLI parses `--scope-mode=diff` + `--diff-base=...` and computes `DiffScopeResult` (same as today).
2. The `instruction_block` from the result is **prepended to the user's instruction** in the first message of `Runner.run`. (Same as Strix today; the agent sees it as part of its task.)

```python
# strix/interface/cli.py (or main.py)
diff_scope = resolve_diff_scope_context(args)
user_instruction = args.instruction or ""
if diff_scope.instruction_block:
    user_instruction = f"{diff_scope.instruction_block}\n\n{user_instruction}".strip()

context = make_agent_context(..., diff_scope=diff_scope.metadata, ...)
result = await Runner.run(
    agent,
    input=[{"role": "user", "content": user_instruction or "Conduct a thorough penetration test."}],
    ...
)
```

**Apply in Phase 5** (CLI/interface migration).

### C24 [MEDIUM] Run-name uniqueness + Docker availability checks

**Defect.** Plan §28 + §32: nothing prevents two parallel `strix` invocations colliding on `run_name` and competing for the same container name. And nothing surfaces a clear error when Docker daemon isn't running.

**Fix.** Pre-flight checks at CLI startup:

```python
def main():
    args = parse_arguments()
    apply_config_override(args.config)
    if args.use_sdk_harness:
        if not _docker_daemon_available():
            sys.exit("Docker daemon unavailable. Start Docker Desktop / dockerd and try again.")
    run_dir = Path("strix_runs") / args.run_name
    if run_dir.exists() and (run_dir / "events.jsonl").exists():
        sys.exit(
            f"Run '{args.run_name}' already exists at {run_dir}. "
            f"Use a different --name or rm the directory."
        )
    # ... continue with scan
```

**Apply in Phase 5** (in `strix/interface/main.py`).

### C25 [MEDIUM] Hook cancel mode mapping + cleanup

**Defect.** Plan §C8: PLAYBOOK §C9 mentions `result.cancel(mode=...)` but doesn't specify which mode for which trigger.

**Fix.**
- **Ctrl+C from user** → `result.cancel(mode="immediate")` + `await bus.cancel_descendants(root_id)`.
- **TUI "stop agent" button (graceful)** → `result.cancel(mode="after_turn")` + `await bus.cancel_descendants(root_id)`.
- **`stop_agent(child_id)` tool called by parent** → directly `bus.tasks[child_id].cancel()`.
- **Run finished naturally** → no cancellation needed; `on_agent_end` hooks finalize.

**Apply in Phase 5** (signal handler + TUI binding).

---

## 3. New scenario gaps from walkthrough audit (Round 3.1)

| # | Scenario | Gap | Fix |
|---|---|---|---|
| **W1** | Cold-start single-agent | Most gaps already in C1–C12 | Use new C13–C25 |
| **W2** | Multi-agent parallel | `finish_scan` had no children-running check | C22 |
| **W3** | Mid-run Ctrl+C | Cancel-mode mapping ambiguous | C25 |
| **W4** | Subagent silent crash | Background post-invoke task exceptions don't trigger crash detection | Document — exceptions in `post_invoke_task` are logged async, not via `on_agent_end`. Bus watchdog optional. |
| **W5** | Compressor cascade fail | After compression fails once, next iteration retries forever | Set `_compression_disabled=True` in context after first failure; subsequent calls skip. Apply in Phase 1 custom Session. |
| **W6** | Container dies mid-run | No periodic liveness check | Optional: background asyncio task pings `/health` every N turns. Phase 5 / Phase 6 enhancement. |
| **W7** | Whitebox wiki on finish | `is_whitebox` not propagated to context | C21 |
| **W8** | RunConfig override | No injection point | C21 |
| **W9** | Resume from RunState | Out of scope for MVP | Defer; document as Phase 7+ |
| **W10** | Diff-scope mode | Injection point unspecified | C23 |

---

## 4. CLI/interface migration spec (Round 3.3 highlights)

Full spec in the audit; key takeaways folded into PLAYBOOK and corrections above.

**Survives unchanged:** All argparse flags, `Config` class, target inference, run-name generation, scope-diff resolution, helper utilities (`format_*`, `infer_target_type`, `clone_repository`, etc.), exit code logic.

**Refactor needed:**

- **`run_cli()` headless** — wrap `Runner.run_streamed()` with `StrixStreamAccumulator`; same Rich panels, same exit codes.
- **`run_tui()` interactive** — Textual app subscribes to tracer reactive fields; tracer fed by accumulator + hooks.
- **Vulnerability popup** — direct call from `create_vulnerability_report` tool body to `tracer.vulnerability_found_callback` (simpler than `ToolOutputGuardrail`; both viable).
- **Live stats** — `build_live_stats_text(tracer, agent_config)` reads tracer; tracer fed via hooks; no change to read path.
- **Interactive resume** — after `Runner.run()` returns, re-run with appended history + new user message; SDK `Session` makes this clean.

**`infer_target_type()` → Manifest entries:**

| Inferred type | Manifest action |
|---|---|
| `local_code` | `LocalDir(src=Path(...))` mounted under `/workspace/<subdir>` |
| `repository` (git URL) | Pre-clone via existing `clone_repository()`; mount cloned dir as `LocalDir`. (Keep pre-clone logic; don't use SDK's `GitRepo` until after MVP.) |
| `web_application` / `domain` / `ip_address` | No mount; agent reaches via Caido proxy |

---

## 5. Build/deps/deployment (Round 3.5 highlights)

### pyproject.toml diff

**Drop:**
```diff
- "litellm[proxy]>=1.81.1,<1.82.0",
```

**Add:**
```diff
+ "openai-agents[litellm]==0.14.6",
```

**Transitive new (no action):** `griffelib`, `mcp`, `websockets`, `types-requests`, `openai>=2.26.0`. Pulled in by `openai-agents`.

**Container image (`containers/Dockerfile`):** **NO changes.** `[sandbox]` extras stay in image. SDK's host-side code does not run inside the container.

**`strix.spec` (PyInstaller):** Add SDK hidden imports:

```python
hiddenimports += [
    "agents", "agents.agent", "agents.run", "agents.run_config",
    "agents.memory.session", "agents.memory.sqlite_session",
    "agents.sandbox.sandboxes.docker", "agents.sandbox.manifest",
    "agents.sandbox.capabilities.capability", "agents.sandbox.entries",
    "agents.extensions.models.litellm_model",
    "agents.tool", "agents.tool_context", "agents.tool_guardrails",
    "agents.lifecycle", "agents.guardrail",
    "agents.tracing.processor_interface", "agents.tracing.spans", "agents.tracing.traces",
    "agents.models.interface", "agents.models.multi_provider",
    "agents.retry", "mcp", "websockets",
]
```

### Config bridge

`strix/config/config.py` adds an env-var bridge before SDK init:

```python
def bridge_to_sdk_env() -> None:
    """Map legacy Strix env vars to SDK-native names where applicable."""
    if Config.get("llm_api_key") and not os.environ.get("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = Config.get("llm_api_key")
    if Config.get("llm_api_base") and not os.environ.get("OPENAI_BASE_URL"):
        os.environ["OPENAI_BASE_URL"] = Config.get("llm_api_base")
```

Call from `main.py` before any SDK import.

### CI

`.github/workflows/build-release.yml` — unchanged. Add new test workflow (`tests.yml`) for pytest + mypy + ruff on PRs (recommended but not blocking for cutover).

### Feature flag

`STRIX_USE_SDK_HARNESS` env var, default `0`. CLI entry checks; routes to legacy or SDK harness implementation.

---

## 6. Consolidated correction register (full)

After Rounds 1, 2, 3 — twenty-five corrections to apply.

| # | Severity | Phase | Source | Topic |
|---|---|---|---|---|
| C1 | Blocker | 1/6 | AUDIT.md §2.1 | Tool-server slot serialization vs SDK parallel calls |
| C2 | Blocker | 0 | AUDIT.md §2.2 | Anthropic cache-control on system message |
| C3 | Blocker | 0 | AUDIT.md §2.3 | DockerSandboxClient subclass |
| C4 | Blocker | 3 | AUDIT.md §2.4 | Subagent `tool_use_behavior` |
| C5 | High | 5 | AUDIT.md §2.5 | StrixStreamAccumulator |
| C6 | Critical | 2 | AUDIT_R2.md §1.1 | Notes JSONL write lock |
| C7 | Critical | 1 | AUDIT_R2.md §1.2 | events.jsonl write lock |
| C8 | High | 3 | AUDIT_R2.md §1.3 | Subagent crash detection |
| C9 | High | 3 | AUDIT_R2.md §1.4 | Cancellation cascade |
| C10 | Medium | 1 | AUDIT_R2.md §1.5 | Compressor try/except |
| C11 | Medium | 1 | AUDIT_R2.md §1.6 | Retry policy excludes 401/403/400 |
| C12 | Medium | 3 | AUDIT_R2.md §1.7 | Stats snapshot under lock |
| **F1** | **Critical** | **0** | **AUDIT_R3 §1** | **AnthropicCachingLitellmModel signature** |
| **F2** | **Critical** | **3** | **AUDIT_R3 §1** | **RunHooks signature (`AgentHookContext`, `result: str`)** |
| **F3** | **Critical** | **1** | **AUDIT_R3 §1** | **TracingProcessor methods are sync** |
| C13 | High | 3 | AUDIT_R3 §2 | Bus.finalize cleans up stale state |
| C14 | High | 3 | AUDIT_R3 §2 | Filter try/except |
| C15 | High | 3 | AUDIT_R3 §2 | Hooks try/except |
| C16 | High | 1 | AUDIT_R3 §2 | TracingProcessor catches OSError |
| C17 | Medium | 1 | AUDIT_R3 §2 | Model alias validation |
| C18 | Medium | 2 | AUDIT_R3 §2 | Sandbox response size cap |
| C19 | Medium | 1 | AUDIT_R3 §2 | Assert ≥1 enabled tool when `tool_choice='required'` |
| C20 | Medium | 2 | AUDIT_R3 §2 | Per-tool `timeout_behavior` discrimination |
| C21 | Medium | 1 | AUDIT_R3 §2 | RunConfig override + context fields (`is_whitebox`, `diff_scope`, `run_id`) |
| C22 | Medium | 2 | AUDIT_R3 §2 | `finish_scan` checks children running |
| C23 | Medium | 5 | AUDIT_R3 §2 | Diff-scope injection in user message |
| C24 | Medium | 5 | AUDIT_R3 §2 | Run-name + Docker preflight |
| C25 | Medium | 5 | AUDIT_R3 §2 | Cancel mode mapping (immediate/after_turn) |

---

## 7. Outcome

**No new architectural blockers.** All corrections are bounded.

The three F-fixes (type/signature corrections) are inline-applied to `PLAYBOOK.md` in this round. C13–C25 are added to the playbook's correction register and the relevant phases. After this round, the playbook's load-bearing skeletons compile against SDK v0.14.6, and defensive error handling is wired through filter, hooks, processor, and bus.

Ready for Phase 0.
