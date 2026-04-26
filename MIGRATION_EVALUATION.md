# Migration Evaluation: Strix Custom Harness → OpenAI Agents SDK

> Evaluated against `openai/openai-agents-python` v0.14.6 (`/tmp/openai-agents`). Maps every Strix subsystem from `HARNESS_WIKI.md` (Strix at `9fb1012`) onto SDK primitives.
>
> **Revision 2** — incorporates: (a) confirmed multi-agent + messaging is bridgeable via `call_model_input_filter`; (b) accepted tradeoffs on XML tool format, skills-as-tool-output, sandbox subclass; (c) tool-execution threading & timeout deltas (sequential→parallel, no default timeouts, no auto sync offload).

---

## Table of Contents

1. [TL;DR](#1-tldr)
2. [SDK overview](#2-sdk-overview)
3. [Per-subsystem mapping (revised)](#3-per-subsystem-mapping-revised)
4. [Multi-agent design — concrete bridge](#4-multi-agent-design--concrete-bridge)
5. [Tool execution semantics — what changes](#5-tool-execution-semantics--what-changes)
6. [Sandbox bridge](#6-sandbox-bridge)
7. [What we still lose control over](#7-what-we-still-lose-control-over)
8. [What we gain](#8-what-we-gain)
9. [Effort estimate (revised)](#9-effort-estimate-revised)
10. [Migration plan (step-by-step)](#10-migration-plan-step-by-step)
11. [Risks & open questions](#11-risks--open-questions)

---

## 1. TL;DR

**Verdict: full migration is feasible.** ~25–35 engineer-days for full parity, including parallel multi-agent + messaging, with three accepted tradeoffs and one custom Docker-client subclass.

| Concern | Original status | Revised status |
|---|---|---|
| Concurrent multi-agent graph | "Critical / not bridgeable" | **Bridgeable.** `call_model_input_filter` + `asyncio.create_task` + shared `Session` + a `MessageBus` we own. Architecturally identical to today's `_agent_messages` injection in `_check_agent_messages`. ~400 LOC, full parity (true parallel, peer-to-peer messaging, wait_for_message, view_agent_graph, identity injection, stat aggregation). |
| XML tool-call format | "Critical" | **Accepted tradeoff.** SDK is JSON-native (provider-native via LiteLLM extension for non-OpenAI). No real loss — provider-native tool use is cleaner. Multi-provider survives. |
| `load_skill` mid-run prompt mutation | "High loss" | **Accepted tradeoff.** Skills returned as tool output; model sees them in conversation history. Slightly more memory-compressor-eviction-prone, but cleaner semantics. |
| Sandbox `cap_add` / `extra_hosts` | "High" | **Solvable.** Subclass `DockerSandboxClient` and inject the kwargs. ~50–80 LOC. |
| Tool execution semantics | not addressed | **Net upgrade.** SDK runs tool calls in **parallel** within a turn (Strix is sequential). No default per-tool timeout (Strix has 120s) — we add a `strix_tool()` factory to re-impose defaults. No auto sync→thread offload (Strix's tool server `asyncio.to_thread`s every call) — we wrap sync code ourselves. |

**No remaining showstoppers.** All gaps now have concrete bridges.

---

## 2. SDK overview

`openai-agents` v0.14.6, MIT, Python 3.10+. Core abstractions:

| Concept | Purpose | File |
|---|---|---|
| `Agent` | LLM + instructions + tools + handoffs + guardrails | `src/agents/agent.py` |
| `Runner` / `AgentRunner` | Run loop, max_turns, streaming | `src/agents/run.py`, `run_internal/` |
| `RunState` / `RunResult` | Run state + result, resumable serialization | `run_state.py`, `result.py` |
| `Session` | Conversation history persistence (8+ backends) | `memory/`, `extensions/memory/` |
| `function_tool` / `FunctionTool` | Tool decorator (native function-calling) | `tool.py:1725` |
| `Handoff` | Linear delegation to another agent | `handoffs/` |
| `Agent.as_tool()` | Nested agent invocation (blocking) | `tool.py` (`_is_agent_tool`) |
| `RunHooks` / `AgentHooks` | 7 lifecycle hooks | `lifecycle.py` |
| Guardrails (input/output/tool) | Three-layer validation | `guardrail.py`, `tool_guardrails.py` |
| Tracing | Built-in spans, processors, OpenAI dashboard default | `tracing/` |
| **`call_model_input_filter`** | **Mutate input list before every model call** | `run_config.py:61`, `run_internal/turn_preparation.py:55-80` |
| `SandboxAgent` (v0.14.0) | Pre-configured agent with sandbox session | `sandbox/`, `extensions/sandbox/` |
| `Manifest` + capabilities + entries | Sandbox config (env, mounts, capabilities) | `sandbox/manifest.py`, `sandbox/capabilities/` |
| `MultiProvider`, `LitellmModel`, `AnyLLMModel` | Non-OpenAI provider routing | `models/multi_provider.py`, `extensions/models/` |
| MCP support | 4 transports (HostedMCPTool, StreamableHttp, Sse, Stdio) | `mcp/` |

Sandbox backends shipped: **UnixLocal, Docker, E2B, Daytona, Modal, Runloop, Vercel, Blaxel, Cloudflare**.

---

## 3. Per-subsystem mapping (revised)

### 3.1 Agent loop & multi-agent (Strix §5)

| Strix capability | SDK equivalent | Match | Notes |
|---|---|---|---|
| Single-agent loop with `max_iterations=300` | `Runner.run(max_turns=...)` | Partial | Default is 10; raise via `RunConfig(max_turns=300)`. |
| 85% / N-3 turn warnings | `RunHooks.on_llm_start` checks `len(input_items)` and pushes a warning user-message | Bridgeable | ~20 LOC. |
| Streaming early-truncate at `</function>` | `result.cancel(mode="after_turn")` (turn-level only) | Partial | Lose token savings on over-generating models. ~50–100 LOC custom Model wrapper if we want it back. |
| `AgentState` (parent_id, sandbox_id, audit) | `RunState` (per-run) + `RunContextWrapper.context` (per-agent dict) | Partial | Audit trail moves into hooks/tracer; identity into context dict. |
| **Concurrent multi-agent graph** | **`asyncio.create_task(Runner.run(...))` + shared `SandboxRunConfig.session` + `MessageBus` + `call_model_input_filter`** | **1:1 (bridge built in §4)** | True parallel children, peer-to-peer messaging, wait/timeout, agent graph view. |
| `view_agent_graph` text rendering | Bus traversal helper | 1:1 | Ours, ~30 LOC. |
| Subagent identity injection (`<agent_delegation>` XML) | Set `agent_id`/`parent_id`/`agent_name` in `RunContextWrapper.context`; child instructions are a callable that pulls from context | 1:1 | Same effect, no XML. |
| Cancellation (`cancel_current_execution`) | `task.cancel()` on the `asyncio.Task` we own (one per agent in the bus) | 1:1 | Identical primitive. |
| Interactive "waiting state" with timeout | `wait_for_message` tool polls bus inbox via `asyncio.sleep` | 1:1 | Same semantics, ~20 LOC. |
| Subagent stat aggregation | `RunHooks.on_llm_end` pushes usage to bus; `on_agent_end` finalizes | 1:1 | Cleaner than today's `_completed_agent_llm_totals` lock-protected dict. |
| Lifecycle hooks (implicit today) | `RunHooks` + `AgentHooks` (7 hooks) | **Gain** | Use these to wire tracer + stats. |
| Memory compression (90K, last-15 floor, LLM summary) | Custom `Session` subclass with `compact()` hook | Bridgeable | ~150 LOC. Ports our existing `MemoryCompressor` strategy. |

### 3.2 LLM layer (Strix §6)

| Strix capability | SDK equivalent | Match |
|---|---|---|
| `litellm.acompletion` multi-provider | Native OpenAI + `LitellmModel` (extras: `litellm`) + `AnyLLMModel` (extras: `any-llm`) | 1:1 — pick `LitellmModel` for parity. |
| `MultiProvider` prefix routing (`openai/`, `litellm/anthropic/`) | `MultiProvider` + `MultiProviderMap` | 1:1 — direct equivalent. |
| Strix model aliasing (`strix/claude-sonnet-4.6` → `anthropic/claude-sonnet-4-6` + custom `api_base`) | Custom `ModelProvider` subclass reading our alias map | Bridgeable | ~50 LOC. |
| Anthropic prompt caching auto-injection | `ModelSettings(extra_body={"cache_control": {"type": "ephemeral"}})` per Anthropic agent | Partial | Per-agent manual or via a small `make_anthropic_settings()` helper. ~30 LOC. |
| Reasoning effort (env > config > scan-mode default) | `ModelSettings(reasoning=Reasoning(effort=...))` | 1:1. |
| Streaming early-exit at `</function>` | None native | Partial — lose token savings; custom Model subclass to restore. |
| Per-chunk streaming timeout (Bedrock fix) | None native | Partial — wrap streaming in custom Model subclass if Bedrock matters. |
| Retries (`min(90, 2*2^n)`, max 5, custom `_should_retry`) | `ModelSettings(retry=ModelRetrySettings(...))` + `retry_policies.*` | **Gain** — composable. |
| Memory compression with pentest-tuned summary prompt | Custom `Session` subclass | Bridgeable | ~150 LOC. |
| `_strip_images()` for vision-less models | None automatic | Wrap as Model subclass or pre-filter. ~40 LOC. |
| Per-call `RequestStats` w/ cost via `litellm.completion_cost` | `Usage` (tokens only) | Partial — wire `litellm.completion_cost` in `on_llm_end` hook. ~20 LOC. |
| Vulnerability dedup (separate LLM call) | Function tool that calls a nested `Runner.run` or direct LiteLLM | 1:1 — port as-is. |
| Custom Jinja system prompt | `Agent.instructions: str | Callable[..., str]` | 1:1 — pre-render Jinja before agent creation, or pass an async callable. |

### 3.3 Tool system (Strix §7)

All 13 Strix tools port. Multi-agent-graph tools are now in §4.

| Strix tool | SDK primitive | Effort |
|---|---|---|
| `@register_tool` w/ env-conditional registration | `@function_tool` + per-agent `tools=[...]` list assembled via env checks at agent build time | Low |
| Local-vs-sandbox dispatch | All tools are `@function_tool` async. Sandbox tools are wrappers that POST to our existing FastAPI tool server. **Network isolation + Bearer auth survive at the transport layer.** | Medium |
| Result XML wrap + 10KB head/tail truncation + screenshot extraction | `ToolOutputText` / `ToolOutputImage` / `ToolOutputFileContent`; truncation logic in our wrapper | Low–Medium |
| Sequential tool execution | **SDK runs tool calls in parallel within a turn** (see §5). Net gain. Verify our stateful tools are reentrant-safe (browser singleton already is via its `threading.Lock`). | n/a |
| Argument validation → error string | Pydantic from signature; default `failure_error_function` returns error string | 1:1 |
| Browser (Playwright, 24 actions) | `ComputerTool(computer=AsyncComputer subclass)` — keeps our Playwright code as the implementation | ~200 LOC |
| Terminal (libtmux, custom PS1 exit-code regex) | `ShellTool(executor=...)` w/ libtmux, or `@function_tool`. **Wrap libtmux calls in `asyncio.to_thread` ourselves** | ~300 LOC |
| Python (IPython, stateful) | `@function_tool` + module-level kernel dict keyed by `agent_id` from context | ~200 LOC |
| Caido proxy (7 GraphQL tools) | 7× `@function_tool` | ~150 LOC |
| Notes (in-memory + JSONL + wiki MD) | 5× `@function_tool` | ~100 LOC |
| Todos (in-memory) | 6× `@function_tool` | ~80 LOC |
| Reporting (CVSS, dedup) | `@function_tool` + Pydantic + cvss lib + nested Runner for dedup | ~150 LOC |
| Web search (Perplexity) | `@function_tool` (we keep Perplexity, ignore SDK's OpenAI-only `WebSearchTool`) | ~50 LOC |
| File edit (openhands-aci + ripgrep) | `@function_tool` wrappers | ~60 LOC |
| Finish scan (root-only guard) | `@function_tool` + context-introspection guard (`parent_id is None`) | ~50 LOC |
| Thinking | Trivial `@function_tool` | ~10 LOC |
| **Multi-agent graph (6 tools)** | **§4** — `function_tool` over `MessageBus` | ~400 LOC |
| **`load_skill`** | **`function_tool` returning skill content as tool output (accepted tradeoff)** | ~60 LOC |
| `current_agent_id` ContextVar propagation | `RunContextWrapper.context["agent_id"]` + `get_agent_id(ctx)` helper | Low |
| Tool guardrails (manual arg validation today) | `ToolInputGuardrail` / `ToolOutputGuardrail` | **Gain** |

### 3.4 Sandbox / runtime (Strix §8)

| Strix capability | SDK equivalent | Match |
|---|---|---|
| Custom Kali image | `DockerSandboxClientOptions(image="ghcr.io/.../strix-sandbox:0.2.0")` | 1:1 |
| `cap_add=NET_ADMIN,NET_RAW` + `extra_hosts=host.docker.internal` | **Subclass `DockerSandboxClient`, inject into `containers.create()` kwargs** | Bridgeable | ~80 LOC |
| Caido HTTPS proxy + CA cert + system-wide proxy env | Image-baked (Dockerfile + entrypoint stay as-is); `Manifest.environment` for runtime overrides; custom `CaidoCapability` for the 7 Caido tools + system-prompt instruction block | Bridgeable | ~200 LOC capability |
| FastAPI tool server + Bearer auth | **Stays in the image.** Function tools wrap HTTP calls to it. Network isolation + Bearer auth preserved at transport layer. SDK's "in-process tools" model becomes "function tool that POSTs to localhost:48081 inside our shared session." | 1:1 in effect |
| One container per scan, shared by all agents | `SandboxRunConfig(session=shared_session)` passed into every `Runner.run` call | 1:1 |
| Random host port allocation | We pre-allocate via `socket.bind(0)` and pass to `DockerSandboxClientOptions(exposed_ports=...)` | 1:1 |
| Healthcheck polling | External loop after `client.create()`, polling `session.exec("curl -fs localhost:48081/health")` | Bridgeable | ~30 LOC |
| Container reuse keyed by scan_id | We track our own session map | 1:1 |
| Local source tar-pipe to `/workspace` | `Manifest.entries={"sources": LocalDir(src=Path)}` | 1:1+ — SDK is a strict superset (LocalDir, LocalFile, GitRepo, S3Mount, …) |
| Multi-agent silo via `agent_id` ContextVar | `RunContextWrapper.context["agent_id"]` extracted in stateful tools | 1:1 (explicit instead of implicit) |
| Cleanup via async `docker rm -f` | `await client.delete(session)` wrapped in `try/finally` | 1:1 |

### 3.5 Interface, prompts, skills, config, telemetry (Strix §9–§13)

| Strix capability | SDK equivalent | Match |
|---|---|---|
| Textual TUI | Re-point at `Runner.run_streamed().stream_events()` | Bridgeable — our existing TUI code, new event source |
| Headless / `-n` flag / exit code 2 | `Runner.run()` + app-layer exit codes | 1:1 |
| CLI args | App layer; SDK has no CLI | 1:1 — keep our argparse |
| Run directory layout | Custom trace processor + result-persistence layer | Bridgeable | ~100 LOC |
| Built-in tracing | `tracing/` w/ custom processors; default exports to OpenAI dashboard — disable for local-only | Partial | ~40 LOC custom JSONL processor |
| OTel / Traceloop export | Custom processor wrapping OTLP | ~30 LOC |
| Scrubadub PII redaction | Custom trace processor — keeps our scrubadub + regex stack | ~60 LOC |
| Live streaming content updates 2 Hz | `RunResultStreaming.stream_events()` (event-driven, not polled) | **Gain** |
| PostHog anonymous telemetry | Keep our own implementation | 1:1 |
| Sessions / persistence | 8+ backends (SQLite, Redis, SQLAlchemy, Mongo, Dapr, Encrypted, OpenAIResponsesCompaction, …) | **Gain** — we have nothing today |
| Input/output/tool guardrails | Three-layer guardrail system | **Gain** |
| Lifecycle hooks | `RunHooks` / `AgentHooks` | **Gain** |
| Jinja system prompt rendering (32 KB) | `Agent.instructions: Callable[..., str]` runs at run start | 1:1 — pre-render Jinja in callable |
| Tool-call requirement enforcement | `ModelSettings(tool_choice="required")` + `Agent.reset_tool_choice=True` | **Gain** — native enforcement |
| Skills as Markdown playbooks | App-layer string management (read MD, render to instructions or tool output) | 1:1 |
| Dynamic skill injection mid-run | **`load_skill` returns skill content as tool output (accepted tradeoff)** | Lossy but acceptable |
| Vulnerability prompts (NoSQLi etc.) | App-layer string management | 1:1 |
| Config file `~/.strix/cli-config.json` w/ `--config` override | Keep our `Config` class; sets env vars before SDK init | 1:1 |
| `RunConfig` per-run knobs | `RunConfig` dataclass — strict superset | **Gain** |
| Agent graph visualization | `agents.extensions.visualization.draw_graph()` (static Graphviz) + our `view_agent_graph` tool (live) | 1:1 |
| Logging | `openai.agents` + `openai.agents.tracing` loggers | 1:1 |

---

## 4. Multi-agent design — concrete bridge

This was the contested section in the previous evaluation. **It's bridgeable, the bridge is small, and the architecture is identical to today's Strix in shape — just lives in our code on top of SDK primitives.**

### 4.1 The key SDK hook

`run_config.py:61` defines:

```python
CallModelInputFilter = Callable[[CallModelData[Any]], MaybeAwaitable[ModelInputData]]
```

This filter runs **before every model call** (`run_internal/turn_preparation.py:55-80`). It receives the input list + instructions and returns a (possibly mutated) `ModelInputData(input=[...], instructions=...)`. **This is the exact injection point Strix uses today** in `_check_agent_messages` at the top of every iteration. It's the missing piece.

### 4.2 Architecture

```
                 ┌──────────────────────────────────────────────┐
                 │  AgentMessageBus  (we own; ~150 LOC)         │
                 │   inboxes:    {agent_id -> list[msg]}        │
                 │   tasks:      {agent_id -> asyncio.Task}     │
                 │   statuses:   {agent_id -> running|...}      │
                 │   parent_of:  {agent_id -> parent_id|None}   │
                 │   stats_live, stats_completed (under lock)   │
                 └─┬──────────────────────────────────┬─────────┘
                   │                                  │
                   │ create_agent (function_tool)     │ on_llm_end / on_agent_end
                   │ asyncio.create_task(             │ (RunHooks)
                   │   Runner.run(child, ...,         │
                   │     run_config=RunConfig(        │ ──► record_usage,
                   │       sandbox=SandboxRunConfig(  │     finalize_stats
                   │         session=SHARED),         │
                   │       call_model_input_filter=   │
                   │         inject_messages_filter,  │
                   │     ),                           │
                   │     context={"bus": bus,         │
                   │              "agent_id": child,  │
                   │              "parent_id": me,    │
                   │              "session": ...})    │
                   │ )                                │
                   ▼                                  ▼
                 Child Runner runs in parallel    Parent's next LLM call:
                 (asyncio task, true             call_model_input_filter
                  I/O concurrency).              drains inbox, appends msgs
                                                  as user-role items.
```

### 4.3 The bus (~150 LOC)

```python
# strix/orchestration/bus.py
import asyncio
from dataclasses import dataclass, field

@dataclass
class AgentMessageBus:
    inboxes: dict[str, list[dict]] = field(default_factory=dict)
    tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    parent_of: dict[str, str | None] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    stats_live: dict[str, dict] = field(default_factory=dict)
    stats_completed: dict[str, dict] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def register(self, agent_id, name, parent_id):
        async with self._lock:
            self.inboxes[agent_id] = []
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name

    async def send(self, target, msg):
        async with self._lock:
            self.inboxes.setdefault(target, []).append(msg)

    async def drain(self, agent_id):
        async with self._lock:
            msgs = self.inboxes.get(agent_id, [])
            self.inboxes[agent_id] = []
            return msgs

    async def record_usage(self, agent_id, usage):
        async with self._lock:
            stats = self.stats_live.setdefault(agent_id, {"in": 0, "out": 0, "cached": 0, "cost": 0})
            stats["in"] += usage.input_tokens
            stats["out"] += usage.output_tokens
            stats["cached"] += usage.input_tokens_details.cached_tokens or 0

    async def finalize(self, agent_id, status):
        async with self._lock:
            self.statuses[agent_id] = status
            self.stats_completed[agent_id] = self.stats_live.pop(agent_id, {})

    async def total_stats(self):
        async with self._lock:
            agg = {"in": 0, "out": 0, "cached": 0, "cost": 0}
            for s in (*self.stats_live.values(), *self.stats_completed.values()):
                for k, v in s.items():
                    agg[k] = agg.get(k, 0) + v
            return agg
```

### 4.4 The injector (~30 LOC)

```python
# strix/orchestration/filter.py
from agents.run_config import CallModelData, ModelInputData

async def inject_messages_filter(data: CallModelData) -> ModelInputData:
    bus = data.context["bus"]
    agent_id = data.context["agent_id"]
    pending = await bus.drain(agent_id)
    if not pending:
        return data.model_data
    new_input = list(data.model_data.input)
    for msg in pending:
        sender = msg.get("from", "unknown")
        if sender == "user":
            new_input.append({"role": "user", "content": msg["content"]})
        else:
            new_input.append({
                "role": "user",
                "content": (
                    f"<inter_agent_message from='{sender}' "
                    f"type='{msg.get('type', 'info')}' "
                    f"priority='{msg.get('priority', 'normal')}'>"
                    f"{msg['content']}"
                    f"</inter_agent_message>"
                ),
            })
    return ModelInputData(input=new_input, instructions=data.model_data.instructions)
```

### 4.5 The hooks (~50 LOC)

```python
# strix/orchestration/hooks.py
from agents import RunHooks

class StrixOrchestrationHooks(RunHooks):
    async def on_llm_end(self, ctx, agent, response):
        bus = ctx.context["bus"]
        await bus.record_usage(ctx.context["agent_id"], response.usage)

    async def on_agent_end(self, ctx, agent, output):
        bus = ctx.context["bus"]
        await bus.finalize(ctx.context["agent_id"], "completed")

    async def on_tool_start(self, ctx, agent, tool):
        # Bridge to our existing Tracer
        ctx.context["tracer"].log_tool_start(ctx.context["agent_id"], tool.name)

    async def on_tool_end(self, ctx, agent, tool, result):
        ctx.context["tracer"].log_tool_end(ctx.context["agent_id"], tool.name, result)
```

### 4.6 The six multi-agent tools (~250 LOC, replacing 839 LOC of `agents_graph_actions.py`)

```python
# strix/tools/agents_graph.py
import asyncio, uuid
from agents import function_tool, RunContextWrapper, Runner
from agents.run import RunConfig
from agents.sandbox import SandboxRunConfig

@function_tool
async def create_agent(
    ctx: RunContextWrapper,
    name: str,
    task: str,
    inherit_context: bool = True,
    skills: list[str] | None = None,
) -> str:
    bus = ctx.context["bus"]
    parent_id = ctx.context["agent_id"]
    child_id = uuid.uuid4().hex[:8]
    await bus.register(child_id, name, parent_id)

    child_agent = build_strix_agent(name=name, skills=skills or [])
    history = (
        await ctx.context["session"].get_items() if inherit_context else []
    )

    bus.tasks[child_id] = asyncio.create_task(
        Runner.run(
            child_agent,
            input=history + [{"role": "user", "content": task}],
            run_config=RunConfig(
                sandbox=SandboxRunConfig(session=ctx.context["sandbox_session"]),
                call_model_input_filter=inject_messages_filter,
                model_settings=ctx.context["model_settings"],
                max_turns=300,
            ),
            context={
                "bus": bus,
                "agent_id": child_id,
                "parent_id": parent_id,
                "agent_name": name,
                "session": ctx.context["session"],
                "sandbox_session": ctx.context["sandbox_session"],
                "tracer": ctx.context["tracer"],
                "model_settings": ctx.context["model_settings"],
            },
            hooks=StrixOrchestrationHooks(),
        )
    )
    return f"Spawned agent {child_id} ({name}) running in parallel."

@function_tool
async def send_message_to_agent(
    ctx: RunContextWrapper,
    target_agent_id: str,
    message: str,
    message_type: str = "info",
    priority: str = "normal",
) -> str:
    await ctx.context["bus"].send(target_agent_id, {
        "from": ctx.context["agent_id"],
        "content": message,
        "type": message_type,
        "priority": priority,
    })
    return f"Message queued for {target_agent_id}."

@function_tool
async def wait_for_message(
    ctx: RunContextWrapper, reason: str, timeout_seconds: int = 600
) -> str:
    bus = ctx.context["bus"]
    me = ctx.context["agent_id"]
    bus.statuses[me] = "waiting"
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    while asyncio.get_event_loop().time() < deadline:
        if bus.inboxes.get(me):
            bus.statuses[me] = "running"
            return "Message arrived. Continue your task."
        await asyncio.sleep(1)
    bus.statuses[me] = "running"
    return f"Timed out after {timeout_seconds}s. Continue or call agent_finish."

@function_tool
async def agent_status(ctx: RunContextWrapper, agent_id: str) -> str:
    bus = ctx.context["bus"]
    if agent_id not in bus.statuses:
        return f"Unknown agent {agent_id}."
    return (
        f"agent={bus.names.get(agent_id)} status={bus.statuses[agent_id]} "
        f"parent={bus.parent_of.get(agent_id)} "
        f"pending_msgs={len(bus.inboxes.get(agent_id, []))}"
    )

@function_tool
async def view_agent_graph(ctx: RunContextWrapper) -> str:
    bus = ctx.context["bus"]
    lines = []
    roots = [aid for aid, p in bus.parent_of.items() if p is None]
    def render(aid, depth):
        lines.append("  " * depth + f"- {bus.names.get(aid, '?')} ({aid}) [{bus.statuses.get(aid)}]")
        for child, p in bus.parent_of.items():
            if p == aid:
                render(child, depth + 1)
    for root in roots:
        render(root, 0)
    return "\n".join(lines) or "No agents."

@function_tool
async def agent_finish(
    ctx: RunContextWrapper,
    result_summary: str,
    findings: list[dict] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> str:
    bus = ctx.context["bus"]
    me = ctx.context["agent_id"]
    parent = bus.parent_of.get(me)
    if parent is None:
        return "Error: agent_finish is for subagents. Root agent must call finish_scan."
    if report_to_parent:
        report_xml = (
            f"<agent_completion_report from='{bus.names.get(me)}' agent_id='{me}' "
            f"success='{success}'>\n"
            f"  <summary>{result_summary}</summary>\n"
            f"  <findings>{findings or []}</findings>\n"
            f"  <recommendations>{final_recommendations or []}</recommendations>\n"
            f"</agent_completion_report>"
        )
        await bus.send(parent, {"from": me, "content": report_xml, "type": "completion"})
    await bus.finalize(me, "completed" if success else "failed")
    return "Reported to parent. This agent will exit."
```

### 4.7 Capability-by-capability mapping

| Strix today | SDK bridge | Identical? |
|---|---|---|
| Daemon-thread subagent (`threading.Thread`) | `asyncio.create_task(Runner.run(...))` | **Yes in effect.** LLM calls are I/O-bound; both designs get the same effective concurrency. We were never CPU-bound at the agent level. |
| Shared `/workspace` Kali sandbox | Shared `SandboxRunConfig(session=...)` passed to every child's `RunConfig` | Yes |
| `_agent_messages` inbox | `AgentMessageBus.inboxes` | Yes (renamed) |
| Per-iteration message check (`_check_agent_messages` at top of `agent_loop`) | `call_model_input_filter` runs before every LLM call (SDK guarantees this in `turn_preparation.py:55-80`) | Yes |
| `<inter_agent_message>` XML wrap | Filter formats as user-role items with same XML envelope | Yes |
| `_completed_agent_llm_totals` aggregation | `RunHooks.on_agent_end` snapshots into `bus.stats_completed`, locked | Yes (cleaner) |
| `wait_for_message` tool with timeout | Tool that polls `bus.inboxes[me]` in `asyncio.sleep` loop | Yes |
| `view_agent_graph` text output | Bus traversal helper | Yes |
| Identity injection via `<agent_delegation>` XML | Set identity in `RunContextWrapper.context`; agent's instructions are a callable that pulls from context | Equivalent (no XML wrapping; identity still flows) |
| Cancellation cascade | `bus.tasks[child_id].cancel()` | Yes — same `asyncio.Task.cancel()` primitive |
| Stop on parent | Walk descendants via `parent_of`, cancel each task | Yes (same as Strix today) |

### 4.8 What this design does NOT lose

- **True concurrency** at the LLM-I/O boundary. (Python threading was never giving us CPU parallelism for our workload anyway.)
- **Shared sandbox** semantics — same Kali container, same `/workspace`, same Caido capture, same proxy state.
- **Cross-sibling messaging** — fully bridged via the bus + filter.
- **Stat aggregation** — cleaner via hooks.
- **Per-agent state silo** for stateful tools (browser, terminal, python) — `RunContextWrapper.context["agent_id"]` is the explicit equivalent of the implicit `current_agent_id` ContextVar.

### 4.9 What this design does lose (small)

- **Per-agent task slot serialization** (Strix's tool server cancels a previous in-flight tool when a new one for the same agent arrives). Not actually needed under the SDK because each agent's run loop only emits a new tool call after the previous resolves.
- **Implicit ContextVar magic** — became explicit `ctx.context["agent_id"]` extraction. ~3 LOC helper makes it ergonomic.

---

## 5. Tool execution semantics — what changes

This is the operational gotcha most likely to surprise during migration. Source-verified from `tool_execution.py` and `tool_server.py` (Strix), `run_internal/tool_execution.py` and `tool.py` (SDK).

### 5.1 Side-by-side

| Dimension | Strix | OpenAI SDK |
|---|---|---|
| **Tool calls within one model turn** | **Sequential** (`for inv in invocations` at `executor.py:324`) | **Parallel** (`asyncio.create_task` per call, drained via `asyncio.wait FIRST_COMPLETED` at `tool_execution.py:1412-1430`) |
| **Default per-tool timeout** | 120s (`STRIX_SANDBOX_EXECUTION_TIMEOUT`) + 30s host buffer = 150s outer | **None.** Must opt in via `@function_tool(timeout=N)` |
| **Local/host-side tool timeout** | None — runs in main loop | None unless `timeout_seconds` is set |
| **Sandbox/remote tool timeout** | 120s `asyncio.wait_for` server-side + 150s httpx outer client-side | N/A — SDK has no remote tool concept; we wrap HTTP in a function tool and set timeout ourselves |
| **Connect timeout** | 10s for httpx → sandbox | None built-in — pass `httpx.Timeout(connect=10)` in our tool body |
| **Sync function offload** | Tool server: `asyncio.to_thread(tool_func, ...)` always (`tool_server.py:83`) | **No auto-offload.** Sync code blocks the loop unless we wrap with `asyncio.to_thread` ourselves |
| **Per-agent serialization** | Yes — `agent_tasks[agent_id]`; new request cancels previous (`tool_server.py:94-97`) | No — concurrent calls allowed; not needed anyway since SDK only emits next tool after current resolves |
| **One-failure-cancels-siblings** | N/A (sequential) | `isolate_parallel_failures=True` by default for multi-call turns (`tool_execution.py:1370`) |
| **Cancellation primitive** | `task.cancel()` on host; SIGTERM cancels all server tasks | `asyncio.shield(invoke_task)` (`tool_execution.py:1766`) + outer cancellation; `result.cancel()` for whole-run |
| **Timeout error format** | Returns `"Tool timed out after 120s"` string to the LLM | `default_tool_timeout_error_message(...)` string (or `ToolTimeoutError` if `timeout_behavior="raise_exception"`) |
| **Stateful-tool threading (browser)** | Dedicated daemon thread + own event loop, lock-serialized (`browser_instance.py:34-48`) | Whatever we build inside the tool function (we keep our existing approach) |

### 5.2 Migration implications

1. **Parallel tool calls become a feature.** Strix is sequential; SDK runs them concurrently. For the model emitting `terminal_execute("nmap ...")` + `web_search("CVE-X")` in one turn, this is faster. We verify reentrancy on:
   - Browser singleton (already lock-serialized — fine).
   - Terminal: per-`(agent_id, terminal_id)` tmux session (fine).
   - Python: per-`(agent_id, session_id)` IPython kernel (fine).
   - Notes/Todos: thread-safe via existing RLocks (fine).

2. **We re-impose default timeouts via a small factory.**

   ```python
   # strix/tools/_decorator.py
   from agents import function_tool

   def strix_tool(*, timeout: float = 120, **kwargs):
       """Strix-flavored function_tool with our defaults."""
       return function_tool(
           timeout=timeout,
           timeout_behavior="error_as_result",
           **kwargs,
       )
   ```

   Used everywhere we'd write `@function_tool` today.

3. **Sync code wraps in `asyncio.to_thread`.** Our existing libtmux / IPython / Caido sync code goes inside an `async def` tool body:

   ```python
   @strix_tool(timeout=30)
   async def terminal_execute(ctx, command: str, ...) -> str:
       def _run():
           # libtmux sync code here
           return session.send_keys(...)
       return await asyncio.to_thread(_run)
   ```

   We lose the tool server's auto-offload-everything trick, but we gain explicit control.

4. **Connect timeout becomes our responsibility** for sandbox-bound function tools:

   ```python
   _SANDBOX_TIMEOUT = httpx.Timeout(timeout=150, connect=10)

   @strix_tool(timeout=160)  # outer SDK timeout > inner httpx
   async def _post_to_sandbox(tool_name, kwargs, ctx):
       async with httpx.AsyncClient() as client:
           r = await client.post(..., timeout=_SANDBOX_TIMEOUT)
       return r.json()
   ```

5. **Tool error formatting** — set a default `failure_error_function` on `RunConfig` to keep our existing `<tool_result><error>...</error></tool_result>` shape if we want it; otherwise the SDK's default error string is acceptable.

---

## 6. Sandbox bridge

### 6.1 Custom DockerSandboxClient (~80 LOC)

The SDK's `DockerSandboxClient.create()` doesn't expose `cap_add` or `extra_hosts`. Subclass and inject:

```python
# strix/runtime/strix_docker_client.py
from agents.sandbox.sandboxes.docker import DockerSandboxClient

class StrixDockerSandboxClient(DockerSandboxClient):
    """Adds NET_ADMIN, NET_RAW capabilities and host.docker.internal mapping
    needed for raw-socket pentest tools and host-served-app testing."""

    async def _create_container_kwargs(self, *args, **kwargs):
        create_kwargs = await super()._create_container_kwargs(*args, **kwargs)
        create_kwargs.setdefault("cap_add", []).extend(["NET_ADMIN", "NET_RAW"])
        create_kwargs.setdefault("extra_hosts", {})["host.docker.internal"] = "host-gateway"
        return create_kwargs
```

(Exact override point depends on SDK internals — may need to wrap `containers.create` directly. ~80 LOC including verification + tests.)

### 6.2 Caido as a Capability (~200 LOC)

Caido stays in the image (Dockerfile + entrypoint don't change). On the SDK side, it becomes a custom `Capability`:

```python
# strix/runtime/caido_capability.py
from agents.sandbox.capabilities import Capability

class CaidoCapability(Capability):
    async def process_manifest(self, manifest):
        manifest.environment.update({
            "http_proxy": "http://127.0.0.1:48080",
            "https_proxy": "http://127.0.0.1:48080",
            "ALL_PROXY": "http://127.0.0.1:48080",
        })

    def tools(self):
        return [list_requests, view_request, send_request,
                repeat_request, scope_rules, list_sitemap, view_sitemap_entry]

    async def instructions(self, manifest):
        return "<caido_proxy>All HTTP/HTTPS traffic in this sandbox is captured by Caido. ...</caido_proxy>"
```

### 6.3 Tool server stays put

The FastAPI tool server keeps running on `:48081` inside the container. Each Strix tool becomes an `@strix_tool` that POSTs to it with our existing Bearer token. **Network isolation, Bearer auth, and the entire image build pipeline are unchanged.** What changes is only the host-side dispatcher: instead of `tools/executor.py`, it's `function_tool` bodies that call the same endpoint.

---

## 7. What we still lose control over

Smaller list than before. All accepted as tradeoffs.

1. **Streaming early-truncate at `</function>`.** Token waste on over-generating models. Custom Model wrapper if Bedrock economics matter; otherwise live with it.
2. **Per-chunk streaming timeout** (the Bedrock `60abc09` fix). Same answer — wrap if Bedrock matters.
3. **Mid-run system prompt mutation (`load_skill`).** Skills become tool outputs (model sees them in conversation history). Slightly more memory-compressor-eviction-prone. Acceptable.
4. **Anthropic prompt cache auto-injection.** Becomes per-agent manual `extra_body` setting via a small `make_anthropic_settings()` helper.
5. **Cost tracking.** SDK tracks tokens, not cost. Wire `litellm.completion_cost` in `on_llm_end` hook (~20 LOC).
6. **Vision-less model image stripping.** No automatic fallback. Wrap as Model subclass if non-vision providers matter.
7. **Identity injection in delegation** moves from XML to context dict. Equivalent — no real loss.

---

## 8. What we gain

Net upgrades from the SDK. Things we don't have today:

| Gain | Detail |
|---|---|
| **Sessions / persistence** | 8+ backends (`SQLiteSession`, `RedisSession`, `SQLAlchemySession`, `MongoDBSession`, `DaprSession`, `EncryptedSession`, `OpenAIConversationsSession`, `OpenAIResponsesCompactionSession`). `RunState.to_json()` resumable runs. We currently have nothing. |
| **Three-layer guardrails** | `@input_guardrail` / `@output_guardrail` / `@tool_input_guardrail` / `@tool_output_guardrail` with `allow / reject_content / raise_exception` semantics. Our existing manual arg validation becomes a tool guardrail. |
| **Formal lifecycle hooks** | 7 explicit hooks (`on_llm_start/end`, `on_agent_start/end`, `on_handoff`, `on_tool_start/end`). Replaces our implicit tracer integration. |
| **Composable retry policies** | `retry_policies.any/provider_suggested/network_error/http_status(...)`. Cleaner than our hard-coded `min(90, 2*2^n)` loop. |
| **HITL approvals** | `@function_tool(needs_approval=True)`, `state.approve()/reject()` resume flow. We don't have this. |
| **Parallel tool calls within a turn** | Free speedup for multi-tool model turns. |
| **Native `tool_choice="required"` enforcement** | The hardened tool-call requirement (commit `4f90a56`) becomes a model setting. |
| **MCP support** | 4 transports — useful if we ever want to expose Strix tools to other agents (Claude.com, etc.). |
| **Built-in tracing dashboard** | When we send to the OpenAI backend (off by default for us). |
| **Active maintenance** | Backed by OpenAI; Strix's harness layer becomes mostly glue. |

---

## 9. Effort estimate (revised)

Wrapper / extension approach (no SDK forking).

| Area | LOC | Days |
|---|---:|---:|
| `MultiProvider` config + Strix model alias `ModelProvider` | 60 | 0.5 |
| Anthropic cache-control helper (`make_anthropic_settings`) | 30 | 0.25 |
| Streaming early-truncate Model wrapper *(optional, if Bedrock matters)* | 100 | 1.5 |
| Per-chunk timeout Model wrapper *(optional)* | 100 | 1.5 |
| Vision-less `_strip_images` Model wrapper *(optional)* | 50 | 0.5 |
| Cost tracking via `on_llm_end` hook | 30 | 0.5 |
| Custom `Session` w/ memory compression + pentest summary prompt | 150 | 2 |
| `strix_tool` decorator (re-imposes our defaults) | 30 | 0.25 |
| Sandbox tool wrapper (httpx → tool server, Bearer auth, connect timeout) | 80 | 0.5 |
| Tool ports: browser (AsyncComputer), terminal (libtmux executor + asyncio.to_thread), python (IPython), proxy (7×), notes (5×), todos (6×), reporting (CVSS+dedup), web_search (Perplexity), file_edit (openhands-aci+rg), finish, think | 1500 | 7 |
| **Multi-agent: `MessageBus` + `inject_messages_filter` + 6 graph tools + `StrixOrchestrationHooks`** | **400** | **4** |
| `StrixDockerSandboxClient` subclass (`cap_add` + `extra_hosts`) | 80 | 0.5 |
| `CaidoCapability` (env vars + 7 Caido tools + instructions block) | 200 | 1 |
| Healthcheck polling layer | 30 | 0.25 |
| Per-agent state silo helper + ports of stateful tools to use it | 100 | 1 |
| Custom JSONL trace processor + OTel + scrubadub | 150 | 1.5 |
| Run-directory persistence (vulns/, notes/, wiki/, penetration_test_report.md) | 100 | 1 |
| Jinja-rendered `Agent.instructions` callable builder | 60 | 0.5 |
| Skill-loading workaround (skill content as tool output) | 60 | 0.5 |
| Config file → env-var bridge | 30 | 0.25 |
| TUI re-pointing at `Runner.run_streamed().stream_events()` | 200 | 2 |
| End-to-end tests against migrated harness (smoke + multi-agent + sandbox) | 400 | 4 |
| **Core (single-provider, no streaming optimizations)** | **~3,800** | **~25 days** |
| **Full parity (multi-provider + streaming optimizations)** | **~4,000–4,500** | **~30–35 days** |

---

## 10. Migration plan (step-by-step)

Branch: `harness-migration` (already cut). Spike-first; mainline-last.

### Phase 1 — Foundation (~5 days)

1. **Provider layer.** Wire `MultiProvider` + `LitellmModel` for Anthropic. Custom `ModelProvider` for Strix model aliases. Verify our existing models all resolve.
2. **`strix_tool` decorator.** Re-imposes our 120s default timeout + `error_as_result` behavior + structured error formatting.
3. **`StrixDockerSandboxClient`.** Subclass injecting `cap_add` + `extra_hosts`. Verify `nmap` works inside a session.
4. **Custom `Session`.** Port `MemoryCompressor` strategy. Validate against current production transcripts.
5. **Trace processor.** Custom JSONL exporter + scrubadub PII filter. Wire into `set_default_trace_processors()`.

### Phase 2 — Tool ports (~8 days)

Port one tool category at a time, with end-to-end tests after each:

1. **Sandbox dispatcher** — single function tool that POSTs to FastAPI server. All sandbox-resident tools share this transport.
2. **Browser** as `ComputerTool` + `AsyncComputer` subclass that wraps existing Playwright code.
3. **Terminal** — `@strix_tool` wrapping libtmux behind `asyncio.to_thread`.
4. **Python** — `@strix_tool` wrapping IPython.
5. **Caido proxy** — 7 GraphQL tools.
6. **Notes / Todos / Reporting / Web search / File edit / Finish / Thinking** — straightforward `@strix_tool` ports.

### Phase 3 — Multi-agent orchestration (~4 days)

1. **`AgentMessageBus`** + tests.
2. **`inject_messages_filter`** + tests against synthetic message streams.
3. **`StrixOrchestrationHooks`** for stat aggregation + tracer wiring.
4. **6 graph tools** (`create_agent`, `send_message_to_agent`, `wait_for_message`, `agent_status`, `view_agent_graph`, `agent_finish`).
5. **End-to-end test**: root spawns 2 children in parallel, children exchange messages, both finish, root aggregates stats. Compare to today's baseline.

### Phase 4 — Sandbox + Caido capability (~2 days)

1. **`CaidoCapability`** wires env vars + 7 Caido tools + system-prompt instruction block.
2. **Healthcheck polling** loop after `client.create()`.
3. **Container reuse** keyed by scan_id (we own this map; SDK just gives us the session primitive).

### Phase 5 — Interface + persistence (~3 days)

1. **TUI** re-pointed at `Runner.run_streamed().stream_events()`.
2. **Run-directory layout** rebuilt as a custom processor + result-persistence layer.
3. **CLI flags** unchanged (we keep our argparse).
4. **Config file → env-var bridge** unchanged (we keep our `Config` class).

### Phase 6 — Validation (~4 days)

1. Smoke: every tool runs in a sandbox.
2. Multi-agent: parallel children + messaging + cancel.
3. Bedrock + Anthropic + OpenAI parity test.
4. Memory compression at 90K tokens.
5. PII redaction in traces.
6. Run an existing pentest end-to-end and diff outputs against the Strix baseline.

---

## 11. Risks & open questions

1. **`CallModelInputFilter` re-runs on every model call.** If we drain the inbox in the filter and the model call retries (e.g. retryable HTTP error), do we lose messages? Need to verify SDK retry behavior — does `call_model_input_filter` re-run on retry, or does the filtered input get cached for the retry? **Action: read `run_internal/turn_preparation.py:55-80` + retry path before Phase 3.** If messages would be lost, the fix is to drain into a per-call buffer that only commits on successful response.

2. **`Session` semantics under parallel children.** When children share the same `Session` for sandbox state, do their LLM histories cross-contaminate? Children should use distinct logical sessions for history (per-agent) but share the sandbox session. **Action: verify `Session` and `SandboxRunConfig.session` are independent — they are, but write a test.**

3. **`isolate_parallel_failures=True` default.** When the model emits multiple tool calls in one turn and one fails, all siblings get cancelled. We may want `False` for our use case (a failed `nmap` shouldn't kill an in-flight `web_search`). **Action: configure per `RunConfig` once we see real behavior.**

4. **Sandbox tool concurrency under parallel calls.** Today's tool server has per-agent task slot serialization (one tool in flight per agent). Under SDK's parallel-tool-calls model, we'd issue multiple POSTs concurrently for the same agent. Tool server's current behavior is to **cancel the previous task** (`tool_server.py:94-97`), which would break us. **Action: relax tool server to allow concurrent same-agent tool calls, OR set `parallel_tool_calls=False` on `ModelSettings` and stay sequential.** The latter is the safer migration default; revisit later.

5. **Bedrock per-chunk-timeout regression.** Without the custom Model wrapper, Bedrock TCP-stalls return as a class of failure. **Action: decide whether Bedrock matters enough to invest the 1.5 days. If it does, build the wrapper in Phase 1.**

6. **Streaming early-exit at `</function>` cost.** Wasted tokens on every multi-turn for over-generating models. Quantify against a representative scan; if cost delta is small, skip the wrapper.

7. **Memory-compressor eviction risk for tool-output skills.** When `load_skill` returns content as tool output, the compressor may summarize the skill content into oblivion after 15+ messages. **Action: tag skill-load tool outputs in the conversation and configure the compressor to preserve them.**

---

*Revision 2 — incorporates: (a) `call_model_input_filter`-based multi-agent bridge; (b) accepted tradeoffs on XML / skills / sandbox subclass; (c) tool execution semantic deltas (parallel by default, no default timeouts, no auto-offload).*
