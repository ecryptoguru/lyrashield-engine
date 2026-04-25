# Migration Audit — Round 2 Findings

> Five-agent deep verification of areas not covered in `AUDIT.md`: SDK surface area exhaustive catalog, Strix port-readiness contracts, concurrency forensics, data-flow mapping, error-handling forensics. Source-verified against `openai-agents` v0.14.6 and Strix at `9fb1012`. Adds seven new concrete corrections to the migration plan.

---

## 1. New corrections discovered

These are additive to the five blockers in `AUDIT.md` §2. Each was missed in earlier rounds.

### 1.1 [CRITICAL] notes/notes.jsonl writes are not lock-protected

**Defect.** `strix/tools/notes/notes_actions.py:40-54` (`_append_note_event`) opens the JSONL file and writes without holding `_notes_lock`. Today this is invisible because Strix daemon-thread subagents serialize on Python's GIL during the `f.write(...)` call — but **the file `open + seek + write + close` is not atomic across multiple threads**. Two simultaneous notes operations from sibling agents can interleave bytes mid-line, corrupting the JSONL file.

**Post-migration risk.** Same bug. SDK runs tool calls in parallel within a turn (`run_internal/tool_execution.py:1414, 1424`), so two `create_note` invocations on different agents in the same event loop tick will hit the file simultaneously.

**Fix.**

```python
# notes_actions.py:40-54 (today)
def _append_note_event(op, note_id, note=None):
    notes_path = _get_notes_jsonl_path()
    if not notes_path:
        return
    event = {"timestamp": datetime.now(UTC).isoformat(), "op": op, "note_id": note_id}
    if note is not None:
        event["note"] = note
    with _notes_lock:                                        # <- ADD
        with notes_path.open("a", encoding="utf-8") as f:
            f.write(f"{json.dumps(event, ensure_ascii=True)}\n")
```

Same fix for `_persist_wiki_note()` (write to `wiki/<slug>.md`).

**Apply during Phase 2** when porting notes tool.

### 1.2 [CRITICAL] events.jsonl writes are not lock-protected either

**Defect.** `strix/telemetry/tracer.py:162-268` (`_emit_event` → `_append_event_record`) calls `append_jsonl_record(self.events_file_path, record)` **without** acquiring the lock that `_get_events_write_lock()` (line 106-108) is designed to provide. The lock exists in the codebase but is unused at the call site.

**Post-migration risk.** Even more acute. Our custom `TracingProcessor` will write SDK spans → `events.jsonl` from multiple concurrent agent tasks. JSONL corruption guaranteed under load.

**Fix.**

```python
# tracer.py:_append_event_record (today)
def _append_event_record(self, record):
    try:
        with self._get_events_write_lock():                  # <- ADD
            append_jsonl_record(self.events_file_path, record)
    except OSError:
        logger.exception("Failed to append JSONL event record")
```

In our custom processor (the migration-phase replacement), apply the same lock.

**Apply in Phase 1** when wiring the custom `TracingProcessor`.

### 1.3 [HIGH] Subagent crash silent — parent never learns

**Defect.** `strix/tools/agents_graph/agents_graph_actions.py:281-287` catches the daemon-thread exception, sets the graph node status to `"error"`, and **re-raises** inside the thread. The thread dies. The parent agent calling `wait_for_message(timeout=600)` polls for 600s and resumes with "Timed out" — never knows the child was dead.

**Post-migration risk.** Same problem in different shape. If a child `Runner.run` task raises, our `MessageBus.tasks[child_id]` is in `done` state with exception, but parent's `wait_for_message` only checks `inboxes`.

**Fix.** In `StrixOrchestrationHooks.on_agent_end` (Phase 3), if exit was due to exception, push a synthetic completion report to parent's inbox so `call_model_input_filter` surfaces it on parent's next turn:

```python
class StrixOrchestrationHooks(RunHooks):
    async def on_agent_end(self, ctx, agent, output):
        bus = ctx.context["bus"]
        me = ctx.context["agent_id"]
        parent = bus.parent_of.get(me)
        # Detect crash: did agent_finish run? if not, output is None or the run errored.
        crashed = (output is None) or (ctx.context.get("agent_finish_called") is not True)
        if crashed and parent is not None:
            await bus.send(parent, {
                "from": me,
                "content": f"<agent_crash agent_id='{me}' name='{bus.names.get(me)}'>"
                           f"Agent terminated without calling agent_finish. "
                           f"Parent should not wait further on this child."
                           f"</agent_crash>",
                "type": "crash",
            })
        await bus.finalize(me, "completed" if not crashed else "crashed")
```

The `agent_finish_called` flag is set by the `agent_finish` tool body. Also add a watchdog in the bus: any task in `tasks` whose `done()` is True but `bus.statuses` is still `running` is reaped.

### 1.4 [HIGH] Cancellation cascade incomplete

**Defect.** Strix's `stop_agent(agent_id)` (`agents_graph_actions.py:688-748`) requires explicit invocation. Today if the user Ctrl+C's the root, only the root agent loop is cancelled — children running in daemon threads keep executing.

**Post-migration risk.** Same. SDK's `result.cancel()` cancels the root task; child `Runner.run` tasks (spawned by `asyncio.create_task` in `create_agent` tool) are NOT cancelled by SDK and continue.

**Fix.** Top-level run wrapper walks `bus.parent_of` to enumerate descendants and explicitly cancels each:

```python
# strix/orchestration/cancellation.py
async def cancel_run_with_descendants(bus: AgentMessageBus, root_agent_id: str):
    descendants = []
    queue = [root_agent_id]
    while queue:
        aid = queue.pop()
        descendants.append(aid)
        queue.extend(child for child, parent in bus.parent_of.items() if parent == aid)
    for aid in reversed(descendants):  # leaves first
        task = bus.tasks.get(aid)
        if task is not None and not task.done():
            task.cancel()
    # Wait briefly for cancellations to settle
    await asyncio.gather(*(t for t in bus.tasks.values() if not t.done()),
                         return_exceptions=True)
```

Wire from CLI signal handler and TUI stop button.

### 1.5 [MEDIUM] Memory compressor has no graceful fallback

**Defect.** `strix/llm/memory_compressor.py:152-219` makes a separate LLM call to summarize old messages. If that call times out or fails, the exception bubbles to the agent loop and **fails the iteration** — the only purpose of the compressor (avoiding context-window overflow) is undermined by an even harsher failure.

**Post-migration risk.** Same. Custom `Session` subclass calling our compressor inherits the brittleness.

**Fix.** Wrap compressor invocations:

```python
# In our custom Session subclass
async def _compress_if_needed(self, items):
    try:
        return await self._compressor.compress_history(items)
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning("Compression failed (%s); returning uncompressed history", e)
        return items  # let context-window error happen later if it must
```

The downstream context-window error (if it happens) is itself retryable via SDK retry policies, so we degrade rather than fail.

### 1.6 [MEDIUM] 401 retry policy mismatch between Strix and SDK

**Detail.** Strix's `_should_retry` (`llm/llm.py:326-330`) treats `status_code is None` as retryable AND defers HTTP codes to `litellm._should_retry(code)` — which does NOT retry 401. So Strix fails fast on auth errors.

The SDK's retry default (configurable via `ModelRetrySettings.retry_policies`) may include 401 retries depending on policy composition. We don't want to retry 401 (it wastes time and clutters traces).

**Fix.** Explicit retry policy in our `RunConfig` factory:

```python
from agents.retry import retry_policies, ModelRetrySettings, ModelRetryBackoffSettings

DEFAULT_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0, multiplier=2.0, max_delay=90.0, jitter=0.0,
    ),
    policy=retry_policies.any(
        retry_policies.network_error(),
        retry_policies.http_status([429, 500, 502, 503, 504]),
        # explicitly NOT including 401, 403, 400
    ),
)
```

Bake into our `make_run_config()` factory so every Strix run gets it automatically.

### 1.7 [MEDIUM] `_completed_agent_llm_totals` read without lock from tracer

**Defect.** `agents_graph_actions.py:35` declares the dict; finalize writes hold `_agent_llm_stats_lock`. Tracer's `get_total_llm_stats()` (`telemetry/tracer.py:801-834`) reads it without acquiring the lock. Possible partial-update read.

**Post-migration risk.** Reduced (single asyncio loop), but our `MessageBus.total_stats()` should still snapshot under the bus's own `asyncio.Lock`.

**Fix.** Already in `MessageBus` design — `total_stats` acquires lock. Just confirm the implementation does this.

---

## 2. Round 1 verification snapshot

What the five Round 1 audits actually verified:

| Audit | Output | Key new finding |
|---|---|---|
| 1.1 SDK surface | Exhaustive catalog (~55 sections) — every `Agent` field, every `RunConfig` knob, every `ModelSettings` field, every span type, every error class, every hook, every Session impl, every Model interface method | No surprises — confirms Strix-side decisions in plan |
| 1.2 Strix port-readiness | Per-tool exact contract reference (params, return shapes, side effects, threading) | Confirms tool-level mapping; surfaces no new blockers |
| 1.3 Concurrency forensics | Lock-by-lock inventory both repos + post-migration topology | **Discovered the two JSONL race conditions (§1.1, §1.2 above) and cancellation cascade gap (§1.4)** |
| 1.4 Data flow & persistence | Every artifact + every in-memory structure mapped pre/post | Confirms invariants survive migration; no data loss paths |
| 1.5 Error handling forensics | 60+ failure modes catalogued with detection/error class/retry/fallback/visibility | **Discovered subagent-crash silence (§1.3), compressor fail-open (§1.5), 401 retry mismatch (§1.6)** |

---

## 3. Updated correction set (consolidated from `AUDIT.md` + Round 1)

| # | Severity | Defect | Phase to apply |
|---|---|---|---|
| **C1** | Blocker | Strix tool-server slot serialization vs SDK parallel calls (`AUDIT.md` §2.1) | Phase 0 (set safe `parallel_tool_calls=False`/`isolate_parallel_failures=False`) → Phase 6 (relax) |
| **C2** | Blocker | Anthropic `cache_control` placement on system message (`AUDIT.md` §2.2) | Phase 0 (`AnthropicCachingLitellmModel`) |
| **C3** | Blocker | `DockerSandboxClient` subclass needs full method-body copy (`AUDIT.md` §2.3) | Phase 0 (`StrixDockerSandboxClient`) |
| **C4** | Blocker | Subagent `tool_use_behavior={"stop_at_tool_names": [...]}` required (`AUDIT.md` §2.4) | Phase 3 (multi-agent) |
| **C5** | High | Streaming TUI integration via `StrixStreamAccumulator` (`AUDIT.md` §2.5) | Phase 5 |
| **C6** | Critical | notes JSONL write race (Round 1 §1.1) | Phase 2 (notes tool port) |
| **C7** | Critical | events.jsonl write race (Round 1 §1.2) | Phase 1 (custom processor) |
| **C8** | High | Subagent crash silent — synthetic completion-report on `on_agent_end` (Round 1 §1.3) | Phase 3 |
| **C9** | High | Cancellation cascade walks `bus.parent_of` tree (Round 1 §1.4) | Phase 3 |
| **C10** | Medium | Memory compressor try/except → degrade to uncompressed (Round 1 §1.5) | Phase 1 (custom Session) |
| **C11** | Medium | Retry policy excludes 401/403/400 (Round 1 §1.6) | Phase 1 (RunConfig factory) |
| **C12** | Medium | Bus stats snapshot under lock (Round 1 §1.7) | Phase 3 (already in design) |

Plus the original twelve medium adjustments from `AUDIT.md` §3 (M1–M12).

---

## 4. Verified-safe areas (no further investigation needed)

| Area | Verification |
|---|---|
| `call_model_input_filter` retry safety | Filter runs once per turn; output captured in lambda closure, not re-invoked on retry. Inbox drain is safe. (Round 1 §1.1 confirmed via `turn_preparation.py:55-80` + `model_retry.py:34-35`.) |
| `asyncio.create_task(Runner.run)` isolation | Each task gets fresh `RunContextWrapper`; contextvars isolated per task; no global state mutation in `Runner.run`. |
| Shared `SandboxRunConfig.session` across parallel runs | SDK does NOT auto-tear-down sandbox sessions; safe to reuse one session across N children. |
| `RunHooks.on_agent_end` firing | Once per `Runner.run` invocation (verified `turn_resolution.py:204-255`). |
| `RunContextWrapper.context` mutability | Dict by-reference; mutations persist within and across turns. |
| Sync function tools | SDK auto-threads sync `@function_tool` bodies via `asyncio.to_thread` (`tool.py:1820-1829`) — drop manual offload. |
| Custom Docker image | `DockerSandboxClientOptions(image=str)` pass-through; no assumed binaries. |
| `Manifest.entries` superset of Strix needs | `LocalDir`, `LocalFile`, `GitRepo`, `Mount` types cover all Strix patterns. |
| MultiProvider routing | `MultiProviderMap.add_provider("strix", StrixModelProvider())` works as designed. |
| Tracing API | `set_trace_processors([...])` disables defaults; custom processors can write to JSONL/OTel. |
| `RunState.to_json/from_json` | Serializable (`CURRENT_SCHEMA_VERSION=1.9`); cross-process resumable. |
| Sandbox capability hooks | `process_manifest`, `tools()`, `instructions()`, `bind()` cover `CaidoCapability` needs. |

---

## 5. Areas flagged for monitoring during implementation

These aren't blockers but warrant attention during Phase work:

- **Browser singleton event-loop init race** — low risk, double-check pattern recommended in `_ensure_event_loop` (`browser_instance.py:34-48`).
- **`agent_tasks` dict in tool server** — currently unprotected; if we ever switch uvicorn to threaded workers, needs `asyncio.Lock`.
- **SQLiteSession async-task ordering** — `threading.RLock` doesn't serialize asyncio tasks deterministically. Mitigated by per-child Sessions (already in plan).
- **Trace processor memory pressure on long runs** — `BatchTraceProcessor` accumulates spans; periodic `force_flush()` recommended.
- **Bus.inboxes resize race** — asyncio.Lock around all dict mutations covers this; verify lock scope in implementation.

---

## 6. Round 1 outcome

**No new architectural blockers.** Plan structure remains sound. Twelve corrections (five from `AUDIT.md`, seven from Round 1) all bounded, all implementable in their assigned phase.

Next: **Round 2** dispatches deep-dives on file-by-file implementation specs, per-tool migration contracts, test plans, and cross-cutting concerns. Round 2 output is the actual day-1 engineering reference, not more audit findings.
