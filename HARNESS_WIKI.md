# Strix Harness — Internal Architecture Wiki

> Internal deep-dive for the team. Maps every subsystem, every tool, every architectural decision, with `path:line` references throughout.
>
> Generated against `main` at `9fb1012` (`fix: --config flag now fully overrides ~/.strix/cli-config.json`). When code drifts, prefer `git log` and the source over this document.

---

## Table of Contents

1. [What Strix Is](#1-what-strix-is)
2. [Architecture at a Glance](#2-architecture-at-a-glance)
3. [Repository Layout](#3-repository-layout)
4. [Lifecycle of One Run](#4-lifecycle-of-one-run)
5. [Agent System](#5-agent-system)
6. [LLM Layer](#6-llm-layer)
7. [Tool System](#7-tool-system)
8. [Runtime & Sandbox](#8-runtime--sandbox)
9. [Interface (CLI / TUI / Headless)](#9-interface-cli--tui--headless)
10. [Prompts](#10-prompts)
11. [Skills](#11-skills)
12. [Config](#12-config)
13. [Telemetry & Persistence](#13-telemetry--persistence)
14. [Cross-Cutting Design Decisions](#14-cross-cutting-design-decisions)
15. [Recent Evolution (Notable Commits)](#15-recent-evolution-notable-commits)
16. [Quick File Index](#16-quick-file-index)

---

## 1. What Strix Is

`strix-agent` (PyPI: `strix-agent`, version `0.8.3` per `pyproject.toml:3`) is an **autonomous AI hacker harness**. The agent dynamically pentests apps — runs targets in a sandboxed Kali container, finds vulns, validates them with PoCs, and writes a report.

**Mission shape:** loop an LLM against a Kali-loaded sandbox until it produces a vulnerability report. Provider-agnostic via litellm. Multi-agent orchestration. Whitebox + blackbox + greybox modes.

**Core deps** (`pyproject.toml:25-39`): `litellm[proxy]`, `pydantic`, `rich`, `docker`, `textual`, `tenacity`, `cvss`, `traceloop-sdk`, `opentelemetry-exporter-otlp-proto-http`, `scrubadub`. Optional `sandbox` extra adds `fastapi`, `uvicorn`, `ipython`, `playwright`, `pyte`, `libtmux`, `gql`, `openhands-aci`.

**Entry point:** `strix.interface.main:main` (`pyproject.toml:43`).

---

## 2. Architecture at a Glance

```
                ┌──────────────────────────────────────────────────────┐
                │  HOST PROCESS                                         │
                │                                                       │
   user CLI ──▶ │  interface/main.py                                    │
                │       │                                               │
                │       ▼                                               │
                │  StrixAgent (root) ──spawns──▶ StrixAgent (subagent) │
                │       │                              │ thread        │
                │       │ agent_loop()                 │               │
                │       ▼                              ▼               │
                │  ┌──────────┐  ┌─────────────────────────┐           │
                │  │ LLM      │  │ Tool Executor           │           │
                │  │ litellm  │  │ ──local────▶ in-process │           │
                │  │ stream   │  │ ──sandbox──▶ HTTP POST  │           │
                │  └──────────┘  └─────────────┬───────────┘           │
                │                              │                       │
                │  Tracer ──▶ events.jsonl     │                       │
                │             OTel/Traceloop   │                       │
                │             PostHog          │                       │
                └──────────────────────────────┼───────────────────────┘
                                               │ Bearer-auth HTTP
                                               ▼
                ┌──────────────────────────────────────────────────────┐
                │  SANDBOX CONTAINER (Kali, one per scan)              │
                │                                                       │
                │   FastAPI tool server :48081                          │
                │     POST /execute → registry → tool fn               │
                │                                                       │
                │   Caido HTTP proxy :48080  (CA-injected)             │
                │   Playwright Chromium      (headless, no-sandbox)    │
                │   tmux + IPython           (terminal, python)        │
                │   /workspace               (shared FS)               │
                │   nmap, sqlmap, nuclei, semgrep, trivy, ...           │
                └──────────────────────────────────────────────────────┘
```

**Two key boundaries:**

1. **Host ↔ sandbox**: HTTP/JSON over Bearer-token auth. Host owns LLM + telemetry; sandbox owns dangerous tools.
2. **Provider-agnostic LLM**: everything goes through `litellm.acompletion`; tool calls are **custom XML in text**, not native function-calling — provides multi-provider compatibility at the cost of native streaming schemas.

---

## 3. Repository Layout

```
strix/
├── agents/            # Agent loop, state, multi-agent graph orchestration
│   ├── base_agent.py            # Core loop, ~620 lines
│   ├── state.py                 # AgentState pydantic model
│   └── StrixAgent/
│       ├── strix_agent.py       # execute_scan() entry, task assembly
│       └── system_prompt.jinja  # 32 KB Jinja system prompt
├── llm/               # Completion wrapper, provider routing, memory mgmt
│   ├── llm.py                   # acompletion wrapper, streaming, retries
│   ├── config.py                # LLMConfig dataclass
│   ├── memory_compressor.py     # Token-budget pruning + LLM summarization
│   ├── utils.py                 # Tool-format normalization, XML parsing
│   └── dedupe.py                # Vulnerability dedup via LLM similarity
├── tools/             # Every tool the agent can call
│   ├── registry.py              # @register_tool decorator, schema loader
│   ├── executor.py              # Dual local/sandbox dispatch, result fmt
│   ├── context.py               # contextvar agent_id propagation
│   ├── argument_parser.py       # Type coercion of XML string args
│   ├── browser/                 # Playwright Chromium (24 actions)
│   ├── terminal/                # tmux + libtmux interactive shell
│   ├── python/                  # IPython kernel, persistent
│   ├── proxy/                   # Caido GraphQL client
│   ├── notes/                   # Wiki + categorized notes (JSONL persisted)
│   ├── todo/                    # In-memory todo list
│   ├── reporting/               # create_vulnerability_report w/ CVSS
│   ├── web_search/              # Perplexity sonar-reasoning-pro
│   ├── file_edit/               # openhands-aci str_replace_editor + rg
│   ├── finish/                  # finish_scan (root only)
│   ├── thinking/                # think tool (planning escape hatch)
│   ├── load_skill/              # Runtime skill injection
│   └── agents_graph/            # create_agent, send_message_to_agent, ...
├── runtime/           # Docker-side container management
│   ├── docker_runtime.py        # Host-side: launch/healthcheck/cleanup
│   └── tool_server.py           # Sandbox-side FastAPI tool server
├── interface/         # CLI + Textual TUI + headless
│   ├── main.py                  # argparse, validation, mode dispatch
│   ├── cli.py                   # Headless mode (Rich)
│   ├── tui.py                   # Textual app, modal screens
│   └── utils.py                 # Helpers (target inference, run-dir, ...)
├── prompts/           # Vulnerability-specific Jinja prompts (e.g. NoSQLi)
├── skills/            # Markdown playbooks (vulns, frameworks, scan modes)
├── config/            # Config class, env layering, file persistence
├── telemetry/         # Tracer, OTel, Scrubadub PII redaction, PostHog
└── utils/             # resource_paths.py for frozen-vs-dev path resolution

containers/
├── Dockerfile                   # Kali rolling, all the pentest tools
└── docker-entrypoint.sh         # Caido boot, CA install, tool server start
```

---

## 4. Lifecycle of One Run

End-to-end trace of `strix --target ./app`:

1. **CLI parse** (`interface/main.py:267-426`): parse args, validate, infer target types via `infer_target_type()` (`interface/utils.py`). Resolve diff scope if `--scope-mode=diff`.
2. **Config layering** (`config/config.py`): apply `~/.strix/cli-config.json` (or `--config <path>` override) into `os.environ`; resolve `STRIX_LLM`, `LLM_API_KEY` via `resolve_llm_config()` at `config/config.py:199-224`.
3. **LLM warm**: validate model reachable.
4. **Docker pull** if needed; image pin `ghcr.io/usestrix/strix-sandbox:0.1.13` (`config/config.py:43`).
5. **Run name + run dir**: `strix_runs/<run-name>/`. Tracer init (`telemetry/tracer.py:50+`).
6. **Mode dispatch**: TUI (`tui.py`) or CLI (`cli.py`). Both end up calling `StrixAgent.execute_scan(scan_config)`.
7. **Sandbox launch** (`runtime/docker_runtime.py:111-173`): container created with name `strix-scan-{scan_id}`, two random host ports mapped to container ports `48080` (Caido) and `48081` (tool server), 32-byte bearer token generated, `local_sources` tar-copied into `/workspace`.
8. **Container boot** (`containers/docker-entrypoint.sh`): start Caido → fetch GraphQL token via `loginAsGuest` → create temp project → install CA cert into NSS + system trust → set system-wide proxy env vars → spawn tool server as `pentester` user → wait for `/health` ready.
9. **Agent loop** (`agents/base_agent.py:152-260`): see §5.
10. **Termination**: root agent calls `finish_scan` (`tools/finish/finish_actions.py`) when work is done; tracer writes final report `penetration_test_report.md` and per-finding JSONs under `vulnerabilities/`.
11. **Cleanup**: `docker rm -f` async-spawned (`runtime/docker_runtime.py:334-352`).
12. **Exit code**: `0` clean, `2` if vulns found in headless mode (per `cli.py`).

---

## 5. Agent System

### 5.1 Single-Agent Loop

`agents/base_agent.py:152-260` (`agent_loop`). Each iteration:

1. `_initialize_sandbox_and_state()` once at start (`base_agent.py:158`).
2. Check messages: `_check_agent_messages()` (`base_agent.py:448-531`) drains the inter-agent message queue, wrapping each in `<inter_agent_message>` XML and appending to history.
3. Iteration counter bump and warning watchdog: at 85% of `max_iterations` (default 300) emit warning; at `max-3` emit critical "next message MUST be finish" warning (`base_agent.py:186-211`).
4. `_process_iteration()` (`base_agent.py:214-216`):
   - Compress history (memory compressor, see §6.4).
   - Build messages, call LLM via async generator (`llm.py:156-218`).
   - Parse tool invocations from streamed response (custom XML parser, see §6.5).
   - `_execute_actions()` → `process_tool_invocations()` (`tools/executor.py:313-342`) — sequential per-action dispatch.
   - Append observation XML to history.
5. Loop until `state.should_stop()` (`state.py`): `completed | stop_requested | iteration >= max_iterations`.

In **interactive mode**, after `completed=True` the loop pauses in `_enter_waiting_state()` (`base_agent.py:287-329`) instead of exiting — user can send more input. `_wait_for_input()` resumes on message arrival or `waiting_timeout` (default 600 s for subagents, 0 = forever for root, `base_agent.py:265-266`).

### 5.2 State Model

`agents/state.py:12-173` (Pydantic `AgentState`):

| Field | Purpose |
|---|---|
| `agent_id`, `agent_name`, `parent_id` | Identity. `parent_id is None` ⇔ root agent. |
| `task` | Initial task string. |
| `messages` | Conversation history list (role/content tuples; multimodal-capable). |
| `iteration`, `max_iterations` | Hard budget (default 300). |
| `waiting_for_input`, `waiting_start_time`, `waiting_timeout` | Interactive-mode pause state. |
| `completed`, `stop_requested`, `final_result` | Termination signals. |
| `sandbox_id`, `sandbox_token`, `sandbox_info` | Sandbox handles (port, ID). |
| `actions_taken`, `observations`, `errors` | Local audit trail. |
| `start_time`, `last_updated` | ISO timestamps. |

Snapshots (`state.model_dump()`) are stored verbatim in the agent-graph node when the agent is registered (`base_agent.py:122-134`).

### 5.3 Multi-Agent Graph

`tools/agents_graph/agents_graph_actions.py` (839 lines) is the orchestration plane. Globals at `:9-37`:

- `_agent_graph = {"nodes": {agent_id: node}, "edges": [...]}` — node = full agent metadata; edges = `delegation` or `message`.
- `_agent_messages: dict[agent_id, list[msg]]` — per-agent inbox.
- `_agent_instances: dict[agent_id, agent_obj]` — live in-process instances (for stat snapshots).
- `_agent_states: dict[agent_id, AgentState]`.
- `_running_agents: dict[agent_id, threading.Thread]` — daemon threads.
- `_completed_agent_llm_totals` + `_agent_llm_stats_lock` — accumulated stats from finished subagents.

**Spawning** (`create_agent`, `:383-492`): validate skills → build child `LLMConfig` inheriting parent flags → `StrixAgent(config)` → optionally copy parent history (`inherit_context=True`) → spawn daemon thread running `_run_agent_in_thread()` (`:205-298`). The thread creates a fresh asyncio event loop and runs `agent.agent_loop(state.task)`. On finish, status flips to `completed | stopped | failed`, `_finalize_agent_llm_stats()` is called.

**Identity injection**: parent task is wrapped in `<agent_delegation>...<agent_identity>` so the child knows its name/ID and is told to never echo it (`:238-266`).

**Finish from subagent** (`agent_finish`, `:567-685`): only callable when `parent_id != None`. Builds `<agent_completion_report>` XML with summary/findings/recommendations and pushes it onto the parent's inbox. If the agent is whitebox, the wiki note is updated with a delta.

**Finish from root** (`finish_scan`, `tools/finish/finish_actions.py:86-149`): only callable from root (`parent_id is None`); blocks if any sibling/child agent is still `running`/`stopping`. Triggers `tracer.update_scan_final_fields()` which writes `penetration_test_report.md`.

**Inter-agent messaging** (`send_message_to_agent`, `:495-563`): synchronous append to `_agent_messages[target]` with edge metadata. No broker, no durability, single-process only.

**Waiting** (`wait_for_message`, `:796-839`): subagent calls this to pause; `_check_agent_messages` resumes it on arrival.

**Graph view** (`view_agent_graph`, `:302-380`): traversal printout, root-first.

### 5.4 Stats Aggregation Across the Tree

Recent fix (`15c9571`). `_finalize_agent_llm_stats()` (`:54-68`) snapshots a finished subagent's `llm._total_stats` and adds it under lock to `_completed_agent_llm_totals`. The root's reported totals (via `tracer.get_total_llm_stats()` at `telemetry/tracer.py:801-834`) are: `sum(_completed_agent_llm_totals) + sum(live agent _total_stats)`. Before the fix, finalized children were dropped on cleanup — root undercounted.

### 5.5 Termination, Interrupts, and Cancellation

- **Hard limit**: `iteration >= max_iterations` → loop exits (`base_agent.py:174`). 85% / N-3 warnings give the model time to wrap up.
- **User Ctrl+C / parent kill**: `stop_agent(agent_id)` (`agents_graph_actions.py:688-748`) sets `state.request_stop()` + calls `agent_instance.cancel_current_execution()` (`base_agent.py:615-623`) which cancels the running asyncio task. `asyncio.CancelledError` is caught (`base_agent.py:232-243`) — interactive mode enters waiting state; non-interactive re-raises.
- **Finish tools**: see §5.3.

### 5.6 Streaming to TUI

The agent loop consumes the LLM async generator and after each chunk calls `tracer.update_streaming_content(agent_id, accumulated_text)` (`base_agent.py:373-375`). The TUI polls the tracer at 2 Hz and re-renders. On finalize, `tracer.clear_streaming_content()` and `tracer.log_chat_message()` snapshot the full message into the events log.

---

## 6. LLM Layer

### 6.1 Completion Wrapper

`strix/llm/llm.py:156-218` — `LLM.generate()` is an async generator yielding `LLMResponse` objects. Pipeline:

1. **Retry loop** (`:162-171`): max `STRIX_LLM_MAX_RETRIES` (default 5) attempts. Backoff `min(90, 2 * 2**attempt)` seconds. `_should_retry()` (`:326-330`) is True for network errors (no status_code) or `litellm._should_retry(code)` for HTTP statuses.
2. **Build args** (`_build_completion_args`, `:265-274`): model resolution, reasoning effort, drop unsupported params (`litellm.drop_params = True`, `litellm.modify_params = True`, set at `:25-26`).
3. **Stream** (`_stream`, `:173-218`):
   - `acompletion(...)` wrapped in `asyncio.wait_for(timeout=self.config.timeout)` — commit `60abc09`.
   - Each `await it.__anext__()` *also* wrapped in `asyncio.wait_for(timeout)` — needed because litellm's own timeout doesn't propagate to httpx for Bedrock streaming, which can accept TCP and then send no data forever.
   - Accumulate text; when a closing `</function>` tag is seen, set `done_streaming=1` and continue 5 more chunks for trailers, then stop.
4. **Stats** (`_update_usage_stats`, `:287-312`): extract `response.usage` (input, completion, cached tokens). Cost via `_extract_cost()` (`:314-324`) — prefers `response.usage.cost`, else `litellm.completion_cost(...)` with provider stripped.
5. **Tool parsing** (`:212-217`): `normalize_tool_format` → `fix_incomplete_tool_call` → `parse_tool_invocations` (all in `llm/utils.py`).

### 6.2 Provider Routing

`strix/llm/utils.py:34-61` defines `STRIX_MODEL_MAP` — `strix/<short>` aliases (e.g. `strix/claude-sonnet-4.6`) resolve to a tuple `(api_model, canonical_model)`:
- `api_model` is what gets passed to `acompletion` (typically OpenAI-compatible against the Strix proxy `https://models.strix.ai/api/v1` set at `config/config.py:8`).
- `canonical_model` is what's used for litellm capability checks like `supports_prompt_caching()` and `supports_reasoning()`.

For non-`strix/` prefixes, the model string is passed straight through. `LLMConfig.__init__` (`llm/config.py:8-41`) reads `LLM_API_BASE` → `OPENAI_API_BASE` → `LITELLM_BASE_URL` → `OLLAMA_API_BASE` from env in priority order.

Per-provider quirks:
- **Anthropic**: `_is_anthropic()` (`llm.py:338-341`) detects `anthropic/` or `claude` substrings and adds an ephemeral cache control block to the system message via `_add_cache_control()` (`:371-387`).
- **OpenAI reasoning**: if `supports_reasoning()` is true, set `reasoning_effort` (`:265-266`) — env `STRIX_REASONING_EFFORT` > config > scan-mode default (`medium` for quick, `high` otherwise).
- **Vision-less models**: `_strip_images()` (`:343-369`) replaces image content with `"[Image removed - model doesn't support vision]"`.
- **Vertex AI**: optional extra in `pyproject.toml:48`. Documented in `docs/llm-providers/vertex.mdx`.

### 6.3 Retries & Timeouts (the `60abc09` story)

Symptom: Bedrock converse-stream calls would TCP-connect, send no chunks, and hang the agent loop indefinitely. faulthandler showed the loop blocked in `selectors.select()`.

Fix: wrap **both** the initial `acompletion` call **and** every per-chunk read in `asyncio.wait_for`. Timeouts surface as `TimeoutError` (no `status_code` attr) which `_should_retry()` treats as retryable, kicking the backoff loop.

Default `LLM_TIMEOUT = 300` (`config/config.py:24`).

### 6.4 Memory Compression

`strix/llm/memory_compressor.py:152-219`. Hard ceiling `MAX_TOTAL_TOKENS = 100_000`; compression triggers above ~90 K.

- **Image budget**: keep last 3 images, replace older ones with `[Previously attached image removed]` (`:134-149`).
- **System messages**: never compressed.
- **Recent floor**: keep last 15 messages intact (`MIN_RECENT_MESSAGES = 15`).
- **Older messages**: chunk in groups of 10, summarize via LLM call (separate `acompletion`, 120 s timeout). The summary prompt (`:15-43`) emphasizes preserving exact technical details — URLs, payloads, credentials, failed attempts (so the agent doesn't repeat them) — wrapped as `<context_summary message_count='N'>...</context_summary>`.
- Token counting via `litellm.token_counter()` with a fallback of `len(text) / 4`.

This runs every iteration. Anthropic prompt cache helps with system-prompt cost but not history (which mutates).

### 6.5 Tool-Call Format (custom XML, NOT native function-calling)

Tools are injected into the system prompt as XML descriptions via `get_tools_prompt()` (`tools/registry.py:280-300`). The model is instructed to emit:

```xml
<function=tool_name>
  <parameter=key>value</parameter>
  <parameter=other>value</parameter>
</function>
```

Parser (`llm/utils.py`):
- `normalize_tool_format` (`:12-31`): converts Anthropic-style `<invoke name="X">` and other variants to the canonical form.
- `fix_incomplete_tool_call` (`:110-121`): auto-closes unclosed tags when streaming is truncated.
- `parse_tool_invocations` (`:80-133`): regex extraction; HTML-entity-decodes values.
- `clean_content` (`:135-160`): strips tool XML and inter-agent control tags before logging to telemetry.

**Why XML over native tool use?** Multi-provider compatibility (works on any text LLM), graceful streaming truncation (early-exit at `</function>`), and full client-side control of formatting. Cost: tool descriptions are re-injected as text every call (no native streaming of schemas), and content has to be parsed by hand.

### 6.6 Prompt Assembly

`_prepare_messages` (`llm.py:220-248`):
1. Render system prompt from Jinja template (`agents/StrixAgent/system_prompt.jinja`) with: `interactive` flag, `system_prompt_context` (authorized targets), `loaded_skill_names`, tools prompt.
2. Insert agent-identity user message (hidden control block) — see §5.3.
3. Run `MemoryCompressor.compress_history()` over conversation.
4. If last message is assistant, append a `<meta>Continue the task.</meta>` continuation prompt (autonomous mode).
5. Apply Anthropic cache control on the system message if applicable.

### 6.7 Stats / Cost

Per-call: extracted into `RequestStats` dataclass and accumulated in `LLM._total_stats`. Across the tree: see §5.4. Tracer renders these into the live TUI status panel and the final summary text (`utils/format_token_count`, etc.).

### 6.8 Vulnerability Deduplication

`strix/llm/dedupe.py` (~213 lines) — separate LLM call to compare a new finding against existing ones. Wired into `tools/reporting/reporting_actions.py` so duplicate vuln reports get rejected on submission.

---

## 7. Tool System

### 7.1 Registry & Schema Loading

`strix/tools/registry.py`:

- Decorator: `@register_tool(sandbox_execution: bool, requires_browser_mode: bool = False, requires_web_search_mode: bool = False)` (`:190-250`).
- Conditional registration via `_should_register_tool()` (`:175-187`): in sandbox mode, only `sandbox_execution=True` tools register. If `STRIX_DISABLE_BROWSER=true`, browser tools are skipped. If `PERPLEXITY_API_KEY` is missing, `web_search` is skipped.
- Schema: each tool group has `<group>_actions_schema.xml` next to the implementation. Parsed via `_parse_param_schema()` (`:131-149`) → `_tool_param_schemas[name] = {params, required, has_params}`.
- `get_tools_prompt()` (`:280-300`) emits the XML descriptions injected into the system prompt. Includes a `{{DYNAMIC_SKILLS_DESCRIPTION}}` placeholder filled by the load-skill subsystem.

### 7.2 Executor (Local vs Sandbox Dispatch)

`strix/tools/executor.py`:

- `execute_tool()` is the single entrypoint. `should_execute_in_sandbox(tool_name)` (`:29-37`) decides routing.
- **Sandbox path** (`_execute_tool_in_sandbox`, `:39-99`): POST to `http://{host}:{tool_server_port}/execute` with `{agent_id, tool_name, kwargs}` and `Authorization: Bearer {token}`. Connect timeout `STRIX_SANDBOX_CONNECT_TIMEOUT=10`, request timeout `STRIX_SANDBOX_EXECUTION_TIMEOUT + 30 = 150` s.
- **Local path** (`_execute_tool_locally`, `:101-115`): look up function, coerce arg types via `argument_parser.convert_arguments()`, inject `agent_state` if the function requests it (introspection over signature), `await` if async.
- **Argument validation** (`_validate_tool_arguments`, `:130-186`): unknown params and missing required params → formatted error string returned to the LLM (no exception).
- **Result formatting** (`_format_tool_result`, `:227-256`): truncate >10 KB to 4 KB head + `... [middle content truncated] ...` + 4 KB tail. Wrap in `<tool_result><tool_name>...</tool_name><result>...</result></tool_result>`. Extract any `screenshot` key into a separate base64 image attachment.
- **Process orchestrator** (`process_tool_invocations`, `:313-342`): iterate actions sequentially, aggregate result text, attach images as multimodal content blocks, return `should_agent_finish` boolean.

**Sequential, not parallel.** No `asyncio.gather` over tools — could be a future optimization.

### 7.3 Tool Catalog

#### Browser (`strix/tools/browser/`) — `browser_action`
Playwright Chromium singleton per container, shared event loop in a daemon thread (`browser_instance.py:34-48`). 24 actions:
- Navigation: `launch`, `goto`, `back`, `forward`
- Interaction: `click`, `double_click`, `hover`, `type`, `press_key`, `scroll_up`, `scroll_down`
- Tabs: `new_tab`, `switch_tab`, `close_tab`, `list_tabs`
- Misc: `wait`, `execute_js`, `save_pdf`, `get_console_logs`, `view_source`, `close`

Returns `{screenshot: base64-png, url, title, tab_id, all_tabs, js_result, console_logs, page_source}`. Viewport 1280×720, screenshot is viewport-only (not full-page) by default. Page source truncated to 20 KB; JS result to 5 KB; console logs capped at 200 entries / 30 KB total / 1 KB each. Browser launched with `--no-sandbox --disable-web-security` — intentional for XSS/CORS pentesting.

State keyed by `get_current_agent_id()` (contextvar). Tabs persist with sequential IDs (`tab_1`, `tab_2`, ...). `atexit` registered via `_register_cleanup_handlers()`.

#### Terminal (`strix/tools/terminal/`) — `terminal_execute`
libtmux-backed (`>=0.46.2`). One tmux session per `(agent_id, terminal_id)`, default `terminal_id="default"`. PS1 customized to `[STRIX_$?]$ ` so the **exit code can be regex-extracted** from the prompt (`terminal_session.py:49-54`). Pane history limited to 10 K lines.

Params: `command`, `is_input` (false=new command, true=feed input to running process), `timeout` (default 30 s), `no_enter`, `terminal_id`. Returns `{content, status, exit_code, working_dir}` where status is `completed | running | error` (with sub-states `CONTINUE`, `NO_CHANGE_TIMEOUT`, `HARD_TIMEOUT`).

Special-key sequences supported: `C-c`, `^X`, `S-X`, `M-X`, `F1-F12`, arrow keys, `Enter`, `Tab`, `BSpace`. Output deduplication strips previous output prefix to show only new bytes.

#### Python (`strix/tools/python/`) — `python_action`
Persistent IPython kernel (`>=9.3.0`) per `(agent_id, session_id)`. Actions: `new_session`, `execute`, `close`, `list_sessions`. cwd `/workspace`. Stdout truncated to 10 K, stderr to 5 K, repr to 10 K. Execution timeout enforced via thread join + cancellation flag (default 30 s).

Pre-injects proxy helper functions into the user namespace so the agent can `send_request(...)` directly (`python_instance.py:30-47`).

`KeyboardInterrupt` and `SystemExit` are caught and returned as errors rather than propagating.

#### HTTP Proxy (`strix/tools/proxy/`) — 7 tools
GraphQL client against Caido at `http://127.0.0.1:48080/graphql` (`proxy_manager.py:25`). Bearer token from env `CAIDO_API_TOKEN`. Tools: `list_requests`, `view_request`, `send_request`, `repeat_request`, `scope_rules`, `list_sitemap`, `view_sitemap_entry`.

Supports HTTPQL filter syntax for request queries. Pagination (`offset`, `limit`). `view_request` supports regex search through captured request/response pairs. Caido all-traffic capture is enabled because `/etc/profile.d/proxy.sh` sets `http_proxy`/`https_proxy` system-wide and the Caido CA cert is installed into the system + NSS trust stores.

Hardcoded port `48080`. Caido v0.48.0 pinned in `containers/Dockerfile`.

#### Notes (`strix/tools/notes/`) — `create_note`, `list_notes`, `get_note`, `update_note`, `delete_note` (+ internal `append_note_content`)
In-memory dict + JSONL persistence at `{run_dir}/notes/notes.jsonl`. Wiki-category notes additionally rendered as Markdown to `{run_dir}/wiki/{note_id}-{title}.md` so they're human-readable artifacts of the run.

Categories: `general | findings | methodology | questions | plan | wiki`. IDs are 5-char UUID hex (collision-retry up to 20 attempts). Thread-safe via RLock. List preview defaults to 280 chars per note.

The wiki note in particular is **the shared whitebox knowledge base** between root and subagents; `agent_finish` for whitebox subagents auto-appends a delta (see §5.3).

#### Todos (`strix/tools/todo/`) — 6 tools
Per-agent in-memory storage; **not persisted**. Priorities `critical | high | normal | low`; statuses `pending | in_progress | done`. Bulk create/update via JSON list. IDs are 6-char UUID hex.

#### Reporting (`strix/tools/reporting/`) — `create_vulnerability_report`
Saves a CVSS-scored vulnerability to the run. Required fields: title, description, impact, target, technical_analysis, poc_description, **poc_script_code** (mandatory), remediation_steps, cvss_breakdown (XML with AV/AC/PR/UI/S/C/I/A enums).

Optional fields: endpoint, method, cve (`CVE-\d{4}-\d{4,}`), cwe (`CWE-\d+`), code_locations (XML with file/start_line/end_line/snippet/label/fix_before/fix_after — relative paths only, no `..`).

CVSS computed via the `cvss` library. Deduplication via LLM similarity check (`llm/dedupe.py`). Persisted via tracer to `{run_dir}/vulnerabilities/vuln_{id}.json`.

#### Web Search (`strix/tools/web_search/`) — `web_search`
Perplexity API (`sonar-reasoning-pro` model). 300 s timeout. System prompt tailored for security professionals — vuln details, CVEs, OWASP, exploit info. Skipped from registry if `PERPLEXITY_API_KEY` not set.

#### File Edit (`strix/tools/file_edit/`) — `str_replace_editor`, `list_files`, `search_files`
Wraps openhands-aci's file_editor (`>=0.3.0`). Commands `create | str_replace | view | insert`. Relative paths auto-prefixed with `/workspace/`. `search_files` uses ripgrep (`rg`); recursive listings capped at 500 results.

#### Finish (`strix/tools/finish/`) — `finish_scan`
Root-only. Validates: caller is root, all child agents not running/stopping, all four narrative fields non-empty (executive_summary, methodology, technical_analysis, recommendations). On success: tracer writes the final report.

#### Thinking (`strix/tools/thinking/`) — `think`
Minimal — records a thought string, validates non-empty, returns char count. Acts as the "free turn" escape hatch for planning so the agent can satisfy the per-message tool-call requirement (see §10) without doing real work.

#### Agents Graph (`strix/tools/agents_graph/`) — 6 tools
`view_agent_graph`, `create_agent`, `agent_status`, `agent_finish`, `wait_for_message`, `send_message_to_agent`. Mechanics covered in §5.3.

#### Load Skill (`strix/tools/load_skill/`) — `load_skill`
Runtime injection of additional skill content into the agent's context. Validates names against the registry. Replaces the `{{DYNAMIC_SKILLS_DESCRIPTION}}` placeholder. Max 5 skills per agent context.

### 7.4 Result Sanitization (commit `4934bb8`)

Three layers of defense before tool output reaches the model or telemetry:

1. **Screenshot extraction** (`executor.py:345-353`): if a result dict has key `screenshot` whose value is a base64 string, pull it out into a separate image attachment, replace its dict value with `"[Image data extracted - see attached image]"`.
2. **Length truncation** (`:246-249`): >10 KB results are split head + truncation marker + tail, 4 KB each side.
3. **Error truncation** (`:182-183`): error strings capped at 500 chars with `[truncated]` suffix.
4. **Telemetry sanitization** (`telemetry/utils.py:67-150`): scrubadub + regex on dict/list/tuple keys/values, redacting `screenshot`, sensitive-key patterns (`api[-_]?key|token|secret|password|...`), and bearer-style tokens (`ghp_`, `ghs_`, `xox*`).
5. **Content cleaning before logging** (`llm/utils.py:135-160`, `clean_content`): strips tool XML, inter-agent control blocks, agent-identity blocks before they hit the JSONL events log — keeps the audit log readable and prevents log-injection of tool schemas.

### 7.5 Agent Context Propagation

`strix/tools/context.py` defines a single `ContextVar` `current_agent_id`. Set on every tool invocation in `tool_server._run_tool` (`runtime/tool_server.py:71-83`) and used by stateful tools (browser, terminal, python, todos) to silo per-agent state without explicit threading.

---

## 8. Runtime & Sandbox

### 8.1 Image (`containers/Dockerfile`)

- Base: `kalilinux/kali-rolling:latest` (line 1).
- Non-root `pentester` user with NOPASSWD sudo (lines 10-13) — needed for raw-socket pentest tools.
- Pre-installed: `nmap`, `nuclei`, `subfinder`, `naabu`, `ffuf`, `sqlmap`, `zaproxy`, `wapiti`, `caido-cli` (v0.48.0); Go tools `httpx`, `katana`, `gospider`, `interactsh`; Python `arjun`, `dirsearch`, `wafw00f`, `semgrep`, `bandit`, `trufflehog`; JS `retire`, `eslint`, `js-beautify`, `jshint`, `@ast-grep/cli`, `tree-sitter-cli`; tree-sitter parsers for Java/JS/Python/Go/Bash/JSON/YAML/TS; `gitleaks`, `trivy`.
- Sandbox-extra Python deps: `fastapi`, `uvicorn`, `ipython`, `playwright`, `pyte`, `libtmux`, `gql`, `openhands-aci`.
- Self-signed CA chain at `/app/certs/{ca.key,ca.crt,ca.p12}`, 3650-day validity (lines 52-71).
- Workspace `/workspace` owned by pentester (line 194).
- Ports `48080` (Caido), `48081` (tool server) exposed.
- Image pin: `ghcr.io/usestrix/strix-sandbox:0.1.13` (`strix/config/config.py:43`, bumped in `640bd67`).

### 8.2 Boot Sequence (`containers/docker-entrypoint.sh`)

1. **Caido start** (lines 12-17): `caido-cli --listen 0.0.0.0:48080 --allow-guests --no-logging --import-ca-cert /app/certs/ca.p12`.
2. **Caido readiness poll** (24-38): GET `/graphql/` until 200/400, 30 attempts × 1 s.
3. **Login** (50-74): GraphQL `loginAsGuest` mutation → bearer token, 5 retries with backoff. Exported as `CAIDO_API_TOKEN`.
4. **Project setup** (79-109): create + select temp Caido project for capture.
5. **System-wide proxy** (113-146): write `/etc/profile.d/proxy.sh` setting `http_proxy/https_proxy/HTTP_PROXY/HTTPS_PROXY/ALL_PROXY=127.0.0.1:48080`; mirror into `/etc/environment`, `/etc/wgetrc`. Import CA into NSS db so Chromium trusts it.
6. **Tool server start** (154-180): `sudo -u pentester python -m strix.runtime.tool_server` with token, port, timeout. Wait for `/health` 200, 10 retries × 1 s.
7. **Ready** (182): emit "✅ Container ready" and `exec` the trailing args (typically `sleep infinity`).

### 8.3 Host-Side Runtime (`strix/runtime/docker_runtime.py`)

- **One container per scan** (not per agent). All agents in a scan share the same container, the same `/workspace`, the same Caido proxy capture, the same browser/terminal/python sessions (keyed by `agent_id` contextvar).
- **Port allocation** (`:43-46`): `socket.bind(("", 0))` to grab two free host ports, mapped to container 48080 and 48081.
- **Token** (`:131`): `secrets.token_urlsafe(32)` per container.
- **Container creation** (`:111-173`): name `strix-scan-{scan_id}`, label `strix-scan-id={scan_id}`, capabilities `NET_ADMIN | NET_RAW`, `extra_hosts={"host.docker.internal": "host-gateway"}`, env passthrough including `TOOL_SERVER_PORT` / `TOOL_SERVER_TOKEN` / `STRIX_SANDBOX_EXECUTION_TIMEOUT` / `HOST_GATEWAY`. Reuses a running container if one exists for the same scan_id.
- **Healthcheck** (`:87-109`): poll `/health` for 30 s with backoff before declaring ready.
- **Local source mount** (`:222-269`): tar-pipe local sources into `/workspace`. (Not a Docker bind mount — copy on init.)
- **Reattach** (`:72-85`): on existing container, re-extract token+ports from `docker inspect` env.
- **Cleanup** (`:322-352`): `docker stop` + `docker rm` spawned as detached subprocess so the host doesn't block on shutdown.

**No CPU/memory/network egress limits configured.** Container has full host outbound access. Kill switches are: tool server `asyncio.wait_for` request timeout (default 120 s), and host-driven `docker stop`. There is no seccomp/AppArmor profile beyond Docker defaults.

### 8.4 Tool Server (`strix/runtime/tool_server.py`)

FastAPI app, served via Uvicorn on `0.0.0.0:{TOOL_SERVER_PORT}`. Auth via `HTTPBearer` (`:36-37, 42-57`); the `/health` endpoint is unauth.

- `POST /execute` (`:86-127`): JSON `{agent_id, tool_name, kwargs}` → `_run_tool` (`:71-83`). Sets `current_agent_id` contextvar, looks up registry, calls function via `asyncio.to_thread()`. Per-agent task tracking in `agent_tasks: dict[agent_id, asyncio.Task]` (`:39`) — a new request for the same agent **cancels the previous task** (`:94-97`). Hard timeout `asyncio.wait_for(REQUEST_TIMEOUT)` default 120 s.
- `POST /register_agent` (`:130-135`): registers an agent_id (used by host to pre-allocate state).
- `GET /health` (`:138-147`): readiness/liveness.
- Signal handling (`:150-162`): SIGTERM/SIGINT cancel all in-flight tasks; SIGPIPE ignored.
- Returns `{"result": ..., "error": ...}` shape; HTTP 401 on bad token.

### 8.5 openhands-aci

Listed as sandbox dep (`pyproject.toml:54`). Used by `strix/tools/file_edit/` to back `str_replace_editor` (the same primitive as in OpenHands / Claude Code's `Edit` semantics — view/create/str_replace/insert with strict matching).

### 8.6 Multi-Agent in One Sandbox

Subagents inherit `sandbox_id`/`sandbox_token`/`sandbox_info` via the parent's state (passed implicitly through the LLMConfig copy in `create_agent`). They share `/workspace`, the Caido proxy capture, and stateful tools (each agent gets its own browser tab manager / terminal session / python kernel keyed by `agent_id`). **No per-agent process or container isolation.**

---

## 9. Interface (CLI / TUI / Headless)

### 9.1 CLI Args (`strix/interface/main.py:267-426`)

| Flag | Purpose |
|---|---|
| `-t / --target` (multi) | Target — URL / repo / local dir / domain / IP. Type inferred via `infer_target_type()`. |
| `--instruction` | Inline directive. Mutex with `--instruction-file`. |
| `--instruction-file` | File path. Read into `args.instruction`. |
| `-n / --non-interactive` | Headless mode (`cli.py`) instead of TUI. |
| `-m / --scan-mode {quick,standard,deep}` | Default `deep`. Controls breadth/depth via prompt-injected skill. |
| `--scope-mode {auto,diff,full}` | Default `auto`. In CI/headless, `auto`→`diff`. |
| `--diff-base` | Branch/commit to diff against (e.g. `origin/main`). Auto-detected if missing. |
| `--config` | Path to custom `cli-config.json` — **fully overrides** `~/.strix/cli-config.json` (commit `9fb1012`). |

`localhost` targets are rewritten to `host.docker.internal` so the sandbox can reach host-served apps.

### 9.2 Scan Modes

Implemented as **prompt content**, not control-flow branching. `LLMConfig.scan_mode` flows through to the agent's loaded skill set:

- **quick** (`strix/skills/scan_modes/quick.md`): time-boxed, prioritize high-impact (auth, IDOR, RCE, SQLi, SSRF, secrets), skip exhaustive enumeration, breadth>depth, minimal PoC validation.
- **standard** (`strix/skills/scan_modes/standard.md`): balanced. Whitebox = repo map → semgrep → AST → secrets/deps. Blackbox = crawl, fingerprint, capture proxy traffic. Phase 2 = business logic; Phase 3 = systematic input/auth/access tests.
- **deep** (default): exhaustive — every file, every endpoint, every parameter, every edge case, every user role, complete state-machine and trust-boundary modeling, maximum chaining.

Reasoning effort defaults flow off scan mode (`llm/llm.py:74-82`): quick→`medium`, else→`high`.

### 9.3 Scope Modes

`resolve_diff_scope_context()` (`interface/utils.py:40+`): computes `DiffScopeResult` from `git diff <base>...HEAD`. The result's `instruction_block` is **injected into the user instruction** rather than filtering files on disk — the agent decides prioritization. Used heavily for CI/PR workflows where you only want to test what changed.

### 9.4 Textual TUI (`strix/interface/tui.py`)

`StrixTUIApp` with modal screens: `SplashScreen`, `HelpScreen`, `StopAgentScreen`, `VulnerabilityDetailScreen`, plus the main agent-tree + log widgets. Multi-line `ChatTextArea` (Shift+Enter = newline, Enter = send). Keys: F1 help, Ctrl+Q/C quit, ESC stop, Tab cycle panels.

Live updates: an updater thread polls the tracer at 2 Hz and refreshes `reactive` widgets. Vulnerability discoveries trigger the modal popup via `tracer.vulnerability_found_callback`.

### 9.5 Headless / CLI (`strix/interface/cli.py`)

Async run loop. Rich panels for vuln-found events, live stats panel updated every 2 s. Exit codes: `0` clean, `2` if `tracer.vulnerability_reports` is non-empty (used to fail CI). Final completion panel includes target, duration, stats, output path.

### 9.6 Run Directory Layout (`strix_runs/<run_name>/`)

Created and managed by `telemetry/tracer.py`. Contents:
- `events.jsonl` — every span/event in append-only JSONL (thread-safe writes).
- `vulnerabilities/vuln_{id}.json` — one file per finding, sorted by severity, dedup-checked.
- `penetration_test_report.md` — final markdown report (executive summary + methodology + technical analysis + recommendations).
- `notes/notes.jsonl` — note ops audit log.
- `wiki/{note_id}-{slug}.md` — human-readable wiki notes.
- `<target_subdir>/` — local source clones, per-target.

There is **no execution checkpointing** — if the process crashes mid-run, the agent restarts from scratch on retry. Resumability is limited to the interactive-mode wait/resume on inbound messages.

---

## 10. Prompts

### 10.1 The System Prompt

`strix/agents/StrixAgent/system_prompt.jinja` (~32 KB). Single template, two behavioral modes via `{% if interactive %} ... {% else %} ... {% endif %}`. Sections:

1. **Core capabilities** (4-9): security assessment, validation, remediation.
2. **Communication rules** (11-44): CLI markdown only; never echo control XML (`inter_agent_message`, `agent_completion_report`, `agent_identity`).
3. **Tool-call requirement** (24-44, hardened in `4f90a56`):
   - Interactive: a message **without** a tool call **immediately stops the entire execution**. "Planning..." and "I'll now scan..." both halt. The only exceptions are genuinely done or explicitly asking the user. The `think` tool is the planning escape hatch.
   - Autonomous: minimize chatter, never empty messages, use `wait_for_message` or finish when idle.
4. **Execution guidelines** (47+):
   - System-verified scope block (injected at runtime with the authorized targets).
   - Authorization status: full authz for in-scope targets, **don't question permission**.
   - Refusal-avoidance language: treat as internal security engineering, not generic offensive activity.
   - Validation mandate: persist, iterate, assume more issues are hidden.
   - Multi-target coordination: build target map, correlate findings, reuse secrets/endpoints.
   - Testing modes: black-box, white-box, combined.
   - Methodology: scope → recon → automated scanning → targeted validation → continuous iteration → impact documentation.
   - Efficiency tactics: automate via Python, batch operations, parallel scans, fuzzers (ffuf/sqlmap/nuclei/semgrep) before custom payloads. For SQLi/XSS/RCE, spray via python/terminal not manual browser.
5. **Vulnerability methodology** (230+): per-class attack surface, detection channels, chaining strategies, WAF bypasses for IDOR / SQLi / SSRF / RCE / XSS / XXE / path-traversal / race conditions / auth bypass / CSRF.

### 10.2 Vulnerability-Specific Prompts (`strix/prompts/`)

Currently only `vulnerabilities/nosql_injection.jinja` (~266 lines) — operator injection (`$ne`, `$gt`), boolean/timing/error oracles, auth bypass, regex-based extraction, JS execution, WAF bypass, deduplication. Covers MongoDB, CouchDB, Redis, Cassandra, Neo4j, GraphQL.

### 10.3 Persona System

There **is no separate persona file**. All agents are `StrixAgent` instances using the same Jinja system prompt. Differentiation comes from:
- `parent_id` (root agent vs subagent → different finish tools, different prompts injected).
- Loaded skills (root gets `root_agent`; whitebox gets `coordination/source_aware_whitebox` + `custom/source_aware_sast`).
- `system_prompt_context.authorized_targets` (only set on root).
- `is_whitebox` flag (toggles wiki-note auto-update on subagent finish).

---

## 11. Skills

`strix/skills/` — Markdown playbooks loaded into the agent's system prompt. Categories:

| Dir | Contents |
|---|---|
| `vulnerabilities/` | Auth/JWT, IDOR, SQLi, NoSQL, XSS, XXE, SSRF, CSRF, business logic, race conditions, path traversal, RCE, auth bypass, info disclosure, mass assignment, open redirect, insecure uploads, subdomain takeover. |
| `frameworks/` | FastAPI, NestJS, Next.js. |
| `technologies/` | Firebase/Firestore, Supabase. |
| `protocols/` | GraphQL. |
| `tooling/` | ffuf, httpx, katana, naabu, nmap, nuclei, semgrep, sqlmap, subfinder. |
| `cloud/` | Kubernetes (RBAC, container escapes, etcd, supply chain — added in `#394`). |
| `reconnaissance/` | placeholder. |
| `custom/` | `source_aware_whitebox` (whitebox coordination), `source_aware_sast` (triage). |
| `scan_modes/` | quick, standard, deep. |

**Loading**: skills passed to `LLMConfig(skills=[...])` are rendered into the system prompt via the Jinja `get_skill(name)` macro (`llm/llm.py:96`). Whitebox automatically pulls in `coordination/source_aware_whitebox` + `custom/source_aware_sast`. **Max 5 skills per agent** (per `skills/README.md`). Mid-run skill loading via the `load_skill` tool replaces the `{{DYNAMIC_SKILLS_DESCRIPTION}}` placeholder.

**Recent additions:**
- NoSQL injection guide (#168) — see §10.2.
- Kubernetes security testing (#394).

---

## 12. Config

`strix/config/config.py` — hand-rolled `Config` class (no Pydantic). All knobs are class attributes; `Config.get(name)` resolves `os.environ[name.upper()]` first, then the default.

| Knob | Default | Purpose |
|---|---|---|
| `strix_llm` | `None` | Model string; required. |
| `llm_api_key` | `None` | Provider API key. |
| `llm_api_base` / `openai_api_base` / `litellm_base_url` / `ollama_api_base` | `None` | Base URL fallbacks (resolved in priority order). |
| `strix_reasoning_effort` | `"high"` | `low`/`medium`/`high`. |
| `strix_llm_max_retries` | `"5"` | LLM retry count. |
| `strix_memory_compressor_timeout` | `"30"` | Compressor LLM timeout. |
| `llm_timeout` | `"300"` | Outer LLM timeout. |
| `perplexity_api_key` | `None` | Web search. |
| `strix_disable_browser` | `"false"` | Skip browser tool registration. |
| `strix_image` | `"ghcr.io/usestrix/strix-sandbox:0.1.13"` | Sandbox image pin. |
| `strix_runtime_backend` | `"docker"` | Only `docker` supported. |
| `strix_sandbox_execution_timeout` | `"120"` | Tool exec timeout (s). |
| `strix_sandbox_connect_timeout` | `"10"` | Tool server connect timeout. |
| `strix_telemetry` | `"1"` | Master telemetry switch. |
| `strix_otel_telemetry` / `strix_posthog_telemetry` | `None` | Per-stream override. |
| `traceloop_base_url` / `traceloop_api_key` / `traceloop_headers` | `None` | OTel/Traceloop endpoint config. |

### 12.1 Layering

Order (highest first): `os.environ` → class default. Config files apply by writing into `os.environ`.

Two file locations:
- `~/.strix/cli-config.json` (default) auto-applied at `Config.apply_saved()`.
- `--config <path>` (CLI flag) overrides via `apply_config_override()` (`interface/main.py:531-539`).

The `--config` override fix (commit `9fb1012`):
- Track applied vars in `Config._applied_from_default: ClassVar[dict]` (`config.py:59-61`).
- On override, **clear those tracked vars from `os.environ` first**, then load the custom file.
- Test: `tests/test_config_override.py` validates the leak doesn't happen.

### 12.2 LLM Config Resolution

`resolve_llm_config()` (`config.py:199-224`): if model starts with `strix/`, force `api_base = STRIX_API_BASE`; else cascade through `llm_api_base` → `openai_api_base` → `litellm_base_url` → `ollama_api_base`.

### 12.3 Telemetry Opt-Out

- `STRIX_TELEMETRY=0` kills both streams.
- `STRIX_OTEL_TELEMETRY=0` kills OTel only.
- `STRIX_POSTHOG_TELEMETRY=0` kills PostHog only.
- Checked via `strix/telemetry/flags.py`.

---

## 13. Telemetry & Persistence

### 13.1 Tracer (`strix/telemetry/tracer.py`)

Holds `run_id`, `start_time`, agents map, tool_executions, chat_messages, vulnerability_reports, scan_results, run_metadata. Emits structured events into `events.jsonl` (thread-safe with `_get_events_write_lock`) and OTel spans.

Event types include: `run.started`, `run.configured`, `agent.created`, `agent.status.updated`, `tool.execution.started`, `tool.execution.updated`, `chat.message`, `finding.created`.

### 13.2 OpenTelemetry / Traceloop

`bootstrap_otel()` wires an OTLP HTTP exporter (`opentelemetry-exporter-otlp-proto-http`). If Traceloop SDK is installed, spans also stream to `TRACELOOP_BASE_URL` with `TRACELOOP_API_KEY` headers. `TRACELOOP_HEADERS` (JSON string) allows custom headers. Graceful degradation if Traceloop SDK is missing.

### 13.3 Scrubadub PII Redaction (`strix/telemetry/utils.py:67-150`)

`TelemetrySanitizer`:
- Recurses dict/list/tuple structures.
- `_SCREENSHOT_KEY_PATTERN`: keys matching `screenshot` → `[SCREENSHOT_OMITTED]`.
- `_SENSITIVE_KEY_PATTERN`: `api[-_]?key|token|secret|password|...` → `[REDACTED]`.
- `_SENSITIVE_TOKEN_PATTERN`: bearer tokens, GitHub `ghp_`/`ghs_`, Slack `xox*`.
- Strings additionally run through `scrubadub.Scrubber()` for emails, IPs, phone numbers, names; placeholders `{{...}}` replaced with `[REDACTED]`.

Applied on every event payload before write/export (`tracer.py:159-160, 223-227`).

### 13.4 PostHog (`strix/telemetry/posthog.py`)

Anonymous usage telemetry. Per-process `_SESSION_ID = uuid4().hex[:16]` — no user identifier. Public API key embedded; events go to `https://us.i.posthog.com/capture/`. Events include: scan start/end, finding reported, error. Payload metadata: OS, arch, Python version, Strix version, scan mode, finding count, LLM tokens.

Disabled by `STRIX_POSTHOG_TELEMETRY=0` or `STRIX_TELEMETRY=0`.

---

## 14. Cross-Cutting Design Decisions

| Decision | Rationale | Tradeoff |
|---|---|---|
| **XML tool calls in text, not native function-calling** | Multi-provider compatibility, streaming truncation control, client-side parsing, partial-tag recovery. | Tool descriptions re-injected as text every call (no schema cache); custom parser to maintain. |
| **Thread-based subagents (daemon threads, own event loops)** | Simple parent-child coordination, shared sandbox, true `asyncio.create_task` not enough because some tools are blocking. | GIL-bound; no real CPU parallelism; daemon threads die on process exit (acceptable for CLI). |
| **Direct dict messaging, no broker** | Simple, fast, in-process. | Single-process only; no durability; zero distribution. |
| **One container per scan, not per agent** | Shared `/workspace` + Caido capture is the common case for security work; less Docker overhead. | No per-agent isolation — a buggy/exploited tool can affect other agents in the same scan. |
| **No CPU/memory/network limits on sandbox container** | Pentest tools (nmap, etc.) need raw socket access and can be heavy. `NET_ADMIN`+`NET_RAW` capabilities granted. | Container could exhaust host resources or DoS targets if the agent goes wrong. Operator's responsibility. |
| **`--disable-web-security` on Chromium** | Required for XSS / CORS testing. | Browser isn't a realistic UA mirror — can yield findings that don't repro in a normal browser. |
| **System-wide proxy via `/etc/profile.d/proxy.sh` + CA installed in NSS + system trust** | Caido captures all HTTP/HTTPS from the container by default — agents don't need to configure proxies per-tool. | Anything in the container talking off-box is observable to Caido; don't run untrusted secrets through there. |
| **Custom PS1 for tmux exit-code extraction** | Reliable exit code detection across arbitrary shells (`[STRIX_$?]$ ` → regex). | Breaks if user-supplied scripts mess with PS1. |
| **Memory compressor summarizes via *separate* LLM call** | Preserves operationally-critical findings instead of dropping them. | Extra cost per compression cycle; compression timeout 120 s can stall the loop. |
| **Ephemeral Anthropic prompt cache only** | Simple — system prompt cache resets per request. | Lost cache benefit between calls if conversation history mutates (which it always does). |
| **Subagent stats finalized into a global dict on exit** | Avoids race conditions when the root queries during child execution. Required for accurate root-level totals. | Slight complexity in `_finalize_agent_llm_stats`. |
| **Tool result truncation at 10 KB head/tail** | Keeps context spend bounded. | Loses information; the model sometimes can't see the part it needs. |
| **Vulnerability dedup via LLM similarity** | Catches semantic duplicates that hash-based dedup would miss. | Costs another LLM call per finding submission. |
| **Hard tool-call requirement enforced by prompt** | Models prone to outputting "Planning..." with no tool call, which the loop interprets as "wait for user" and halts. | Strong language in system prompt; need `think` as escape hatch. |
| **Diff scope as prompt-injected metadata, not filesystem filter** | Agent can still read related files (imports, helpers) when investigating diffed code. | Larger context spend; relies on model self-restraint to actually focus on the diff. |
| **Skills are Markdown files, not Python plugins** | Lower contributor friction, no import system to maintain, easy to ship. | No programmatic logic in skills — they're always pure prompt content. |

---

## 15. Recent Evolution (Notable Commits)

| Commit | Subject | What Changed |
|---|---|---|
| `9fb1012` | `--config` flag now fully overrides `~/.strix/cli-config.json` (#457) | Track default-applied vars in `Config._applied_from_default`; clear them before loading custom config. New test in `tests/test_config_override.py`. |
| `60abc09` | wrap acompletion in asyncio.wait_for to prevent indefinite hangs (#453) | Wrap **both** `acompletion()` and per-chunk `__anext__()` in `asyncio.wait_for`. Bedrock TCP-accept-then-silence stalls now raise `TimeoutError` (status_code=None) → retried via `_should_retry`. |
| `8841294` | feat(skills): add Kubernetes security testing skill (#394) | New `strix/skills/cloud/kubernetes.md`. RBAC, container escapes, etcd, supply chain. |
| `5c13348` | feat: Add NoSQL injection vulnerability guide (#168) | New `strix/prompts/vulnerabilities/nosql_injection.jinja` covering Mongo/Couch/Redis/Cassandra/Neo4j/GraphQL. |
| `15c9571` | fix: ensure LLM stats tracking is accurate by including completed subagents (#441) | `_finalize_agent_llm_stats()` snapshots subagent stats into `_completed_agent_llm_totals` under lock; tracer aggregates live + completed. Root no longer undercounts. |
| `62e9af3` | Add Strix GitHub Actions integration tip | README addition only. |
| `38b2700` | feat: Migrate from Poetry to uv (#379) | Build system now `hatchling`; deps managed by `uv`; lockfile `uv.lock`. |
| `e78c931` | feat: Better source-aware testing (#391) | Whitebox skill set hardened (`coordination/source_aware_whitebox`, `custom/source_aware_sast`). |
| `4934bb8` | chore: upgrade litellm and sanitize tool result text | Bump litellm to `>=1.81.1,<1.82.0`; tool result sanitization (screenshot extraction, length truncation, error truncation). |
| `7d5a45d` | chore: bump version to 0.8.3 | PyPI version bump. |
| `dec2c47` | fix: use anthropic model in anthropic provider docs example | Doc only. |
| `4f90a56` | fix: strengthen tool-call requirement in interactive and autonomous modes | Hardens `system_prompt.jinja:24-44`. Explicit "message without tool call IMMEDIATELY STOPS execution" and named exceptions. Adds the `think` tool escape hatch. |
| `640bd67` | chore: bump sandbox image to 0.1.13 | `strix/config/config.py:43`. |

---

## 16. Quick File Index

| Path | Role |
|---|---|
| `strix/interface/main.py` | CLI entrypoint. |
| `strix/interface/cli.py` | Headless mode. |
| `strix/interface/tui.py` | Textual TUI app. |
| `strix/interface/utils.py` | Run-name, target inference, diff-scope helpers. |
| `strix/agents/base_agent.py` | Core agent loop. |
| `strix/agents/state.py` | `AgentState` model. |
| `strix/agents/StrixAgent/strix_agent.py` | Root agent + `execute_scan`. |
| `strix/agents/StrixAgent/system_prompt.jinja` | System prompt. |
| `strix/llm/llm.py` | LLM wrapper. |
| `strix/llm/config.py` | `LLMConfig`. |
| `strix/llm/memory_compressor.py` | History compaction. |
| `strix/llm/utils.py` | Tool-format normalization, XML parser. |
| `strix/llm/dedupe.py` | Vulnerability dedup. |
| `strix/tools/registry.py` | Tool registry + decorator. |
| `strix/tools/executor.py` | Local + sandbox dispatcher. |
| `strix/tools/context.py` | Agent ID contextvar. |
| `strix/tools/argument_parser.py` | XML arg type coercion. |
| `strix/tools/agents_graph/agents_graph_actions.py` | Multi-agent orchestration. |
| `strix/tools/finish/finish_actions.py` | `finish_scan` (root only). |
| `strix/tools/browser/` | Playwright Chromium tool. |
| `strix/tools/terminal/` | tmux/libtmux tool. |
| `strix/tools/python/` | IPython tool. |
| `strix/tools/proxy/` | Caido GraphQL client. |
| `strix/tools/notes/` | Notes + wiki. |
| `strix/tools/todo/` | In-memory todos. |
| `strix/tools/reporting/` | Vulnerability reports + CVSS. |
| `strix/tools/web_search/` | Perplexity. |
| `strix/tools/file_edit/` | openhands-aci editor. |
| `strix/tools/thinking/` | `think` tool. |
| `strix/tools/load_skill/` | Runtime skill injection. |
| `strix/runtime/docker_runtime.py` | Host-side container orchestration. |
| `strix/runtime/tool_server.py` | Sandbox-side FastAPI tool server. |
| `containers/Dockerfile` | Sandbox image. |
| `containers/docker-entrypoint.sh` | Container boot sequence. |
| `strix/config/config.py` | Config + env layering. |
| `strix/telemetry/tracer.py` | Run tracer + JSONL events. |
| `strix/telemetry/utils.py` | Scrubadub redaction. |
| `strix/telemetry/posthog.py` | Anonymous usage telemetry. |
| `strix/telemetry/flags.py` | Telemetry opt-out resolution. |
| `strix/utils/resource_paths.py` | Frozen-vs-dev path resolution. |
| `strix/skills/**/*.md` | Vulnerability + tooling + scan-mode playbooks. |
| `strix/prompts/vulnerabilities/nosql_injection.jinja` | NoSQLi prompt. |
| `pyproject.toml` | Deps, entry point, lint config. |

---

*This wiki captures the harness as of `9fb1012`. When in doubt, source wins.*
