# Migration Testing Strategy

> Seven-layer safety net to prove the SDK-migrated harness produces behavior identical to the legacy harness, with no silent feature loss. Centered on **behavioral parity diffing** (the only test that doesn't require knowing in advance what could break) and a **feature inventory matrix** (every feature has a row, every row has a test, no row → no proof).

---

## Table of contents

1. [Threat model — what we're afraid of](#1-threat-model)
2. [Testing layers (cheap → expensive)](#2-testing-layers)
3. [Feature inventory matrix](#3-feature-inventory-matrix)
4. [Behavioral parity diffing — how it actually works](#4-behavioral-parity-diffing)
5. [Replay infrastructure (deterministic LLM + sandbox)](#5-replay-infrastructure)
6. [Live shadow mode (production-grade canary)](#6-live-shadow-mode)
7. [Per-correction test mapping](#7-per-correction-test-mapping)
8. [CI gating and cutover criteria](#8-ci-gating-and-cutover-criteria)
9. [Manual smoke checklist](#9-manual-smoke-checklist)
10. [Post-cutover monitoring](#10-post-cutover-monitoring)
11. [What to do when a parity diff fails](#11-what-to-do-when-a-parity-diff-fails)

---

## 1. Threat model

Concrete categories of regression we want to catch — every test below targets at least one row.

| # | Threat | Detection difficulty | Where it hides |
|---|---|---|---|
| T1 | A tool stops being invocable (typo, registration miss) | Easy | Agent runs, never calls it |
| T2 | A tool's args don't validate the same way | Medium | LLM gets different error string; no exception |
| T3 | A tool's output format changes (XML vs structured, truncation cap, screenshot extraction) | Hard | Findings still happen, but different shape |
| T4 | An LLM provider quirk lost (Anthropic cache, Bedrock timeout, vision strip) | Hard | Cost+latency drift; no functional break |
| T5 | A side effect lost (wiki note auto-update, vulnerability dedup, PII scrub) | **Critical-silent** | Reports persist but a feature stops firing |
| T6 | An event type stops being emitted to events.jsonl | Hard | Run completes, dashboards have gaps |
| T7 | Cancellation cascade incomplete (Ctrl+C leaves orphan tasks) | Medium | Looks fine on success path; only visible on cancel |
| T8 | Memory leak / resource leak (orphan inboxes, stale sessions) | Hard | Long runs degrade |
| T9 | Concurrency regression (parallel tools collide, message ordering breaks) | **Critical-silent** | Pass once, fail on second concurrent run |
| T10 | Schema drift in persisted artifacts (events.jsonl, vuln JSON, report MD) | Medium | Downstream consumers break |
| T11 | Config / env var stops being read | Easy | Default kicks in instead of user override |
| T12 | Exit-code change | Easy | CI integrations break |
| T13 | TUI / CLI output format change | Easy | User experience drift |
| T14 | A skill / prompt section silently dropped | **Critical-silent** | Agent's behavior subtly worse on specific vuln types |
| T15 | Subagent crash silent (parent waits forever) | **Critical-silent** | Run hangs without diagnosis |
| T16 | LLM provider routing wrong (`strix/foo` → wrong model) | Easy | API error within seconds |

**Critical-silent** rows are the dangerous ones — the run *looks* fine but a feature is gone. Layer 4 (parity diffing) is specifically designed to catch these.

---

## 2. Testing layers

Bottom-up. Each layer catches a different class of bug; together they're complementary.

```
┌────────────────────────────────────────────┐
│  Layer 7: Manual smoke (humans, TUI, etc.) │  rare, high signal
├────────────────────────────────────────────┤
│  Layer 6: Live shadow / canary             │  prod-grade, expensive
├────────────────────────────────────────────┤
│  Layer 5: Recorded replay (deterministic)  │  end-to-end, reproducible
├────────────────────────────────────────────┤
│  Layer 4: Behavioral parity diffing        │  **most powerful**
├────────────────────────────────────────────┤
│  Layer 3: Integration (modules together)   │
├────────────────────────────────────────────┤
│  Layer 2: Unit (one module, mocked deps)   │
├────────────────────────────────────────────┤
│  Layer 1: Static (mypy, ruff, signatures)  │  cheapest, fastest
└────────────────────────────────────────────┘
```

### Layer 1 — Static / pre-runtime

Catches type-level mismatches without running the code.

- **`mypy --strict`** against `strix/` after migration. With `openai-agents[litellm]==0.14.6` installed, mypy verifies our subclasses honor SDK's ABC contracts. **Catches: F1, F2, F3 type-fix regressions, future SDK signature drift.**
- **`ruff` + `pyright`** as secondary type checkers; they sometimes catch what mypy misses (e.g., Pyright's stricter overload resolution).
- **Import-surface test** (`tests/static/test_imports.py`): a test that just imports every module in `strix/` and instantiates every `RunHooks`/`Capability`/`Model`/`Session` subclass with valid kwargs. If any abstract method is unimplemented, instantiation raises. Catches T2, T11.
- **Inventory completeness test** (`tests/static/test_inventory.py`): asserts every row in `tests/inventory/features.csv` (see §3) has a non-empty `test_id` field. Prevents adding a feature without a test.
- **SDK version pin guard** (`tests/static/test_sdk_version.py`): asserts `agents.__version__ == "0.14.6"` exactly. We duplicate `_create_container` body; an SDK bump must be intentional. Fails CI on accidental upgrade.

### Layer 2 — Unit

Each module tested in isolation with mocked dependencies. One file per source file.

- `tests/orchestration/test_bus.py` — `AgentMessageBus` register/send/drain/cancel_descendants/total_stats. Concurrency stress: 1000 concurrent send/drain ops, FIFO assertion.
- `tests/orchestration/test_filter.py` — `inject_messages_filter` with synthetic `CallModelData`. Empty inbox → passthrough; 3 messages → 3 user items; user-from-user no XML wrap; bus exception → return unchanged (C14).
- `tests/orchestration/test_hooks.py` — `StrixOrchestrationHooks`. Crash detection (output=None or `agent_finish_called=False`); turn warnings at 85% / N-3; bus errors don't propagate (C15).
- `tests/llm/test_anthropic_cache.py` — `AnthropicCachingLitellmModel._patch`. Anthropic model → `cache_control` present; non-Anthropic → passthrough; system message wrapped correctly.
- `tests/llm/test_multi_provider.py` — `StrixModelProvider.get_model`. Known alias → correct concrete model + base URL; unknown alias → `UserError` (C17).
- `tests/llm/test_session.py` — `StrixSession`. Compression triggers above 90K; compressor exception → uncompressed history (C10); subsequent calls skip compression after first failure.
- `tests/runtime/test_strix_docker_client.py` — `StrixDockerSandboxClient._create_container` with mocked `docker_client`. Assert `cap_add ⊇ {NET_ADMIN, NET_RAW}` and `extra_hosts["host.docker.internal"] == "host-gateway"`.
- `tests/sandbox/test_caido_capability.py` — `CaidoCapability.process_manifest` injects proxy env; `tools()` returns 7 tools; `instructions()` returns non-empty string; `bind()` spawns healthcheck task.
- `tests/sandbox/test_session_manager.py` — `create_or_reuse` cache hit returns same session; `cleanup` removes container.
- `tests/telemetry/test_processor.py` — `StrixTracingProcessor`. Concurrent writes, JSONL is line-valid; PII patterns scrubbed; `OSError` doesn't propagate (C16).
- `tests/tools/test_decorator.py` — `strix_tool` factory. Default 120s timeout applied; sync function auto-threaded; `error_as_result` returns string.
- `tests/tools/test_sandbox_dispatch.py` — `post_to_sandbox`. 401 → error string; size cap enforced (C18); timeout returns error string.
- `tests/tools/test_<each>.py` — one per ported tool. Each: smoke test (valid args → expected output shape) + one edge case (bad args, timeout, network error).

### Layer 3 — Integration

Multiple modules wired together; LLM and sandbox still mocked.

- `tests/integration/test_single_agent_mocked.py` — Build root `Agent`, run with mocked `Model` that emits scripted tool calls; assert tracer captured expected events; assert `RunResult.final_output` populated.
- `tests/integration/test_multi_agent_mocked.py` — Root spawns 2 children via `create_agent` tool; mocked Model scripts each child's responses; bus messaging between children; both `agent_finish`; root `finish_scan`. Assert: stat aggregation correct; messages delivered FIFO; `bus.statuses` all `completed`.
- `tests/integration/test_cancellation_cascade.py` — Build a tree, then `bus.cancel_descendants(root)`; assert all child tasks `cancelled()`; assert leaves cancelled before parents (C9).
- `tests/integration/test_subagent_crash.py` — Mock child raising `RuntimeError`; assert `<agent_crash>` arrives in parent inbox via filter (C8).
- `tests/integration/test_compressor_fallback.py` — Mock compressor LLM raising; assert run continues with uncompressed history (C10).
- `tests/integration/test_finish_scan_blocks_with_running_children.py` — Root calls `finish_scan` while child still `running`; assert error returned (C22).
- `tests/integration/test_jsonl_concurrent_writes.py` — 50 concurrent agents writing to events.jsonl; assert every line is valid JSON (C7); same for notes (C6).

### Layer 4 — Behavioral parity diffing

**The most important layer.** Run the same scenario through legacy and SDK harness; diff every artifact. Detail in §4 below.

### Layer 5 — Recorded replay

Deterministic end-to-end tests using captured LLM and sandbox traces. Detail in §5.

### Layer 6 — Live shadow / canary

Run both harnesses in production for a small slice of real users; diff results in real time. Detail in §6.

### Layer 7 — Manual smoke

Humans operating the TUI, headless mode, multi-target scans. Detail in §9.

---

## 3. Feature inventory matrix

The single artifact that prevents silent feature loss. **One CSV file (`tests/inventory/features.csv`) with one row per feature.** CI fails if any row is missing a test reference.

### Schema

```csv
feature_id,subsystem,description,source_ref,test_id,owner,phase,status
```

- `feature_id` — stable opaque identifier (e.g., `F-AGENT-LOOP-001`).
- `subsystem` — `agents | llm | tools | sandbox | telemetry | interface | config`.
- `description` — one sentence.
- `source_ref` — `path:line` to the legacy implementation OR `path:line` to the migration playbook spec.
- `test_id` — name of the test (or test marker) that proves it survives. Empty = blocker.
- `owner` — engineer responsible.
- `phase` — Phase 0–6 in which the feature lands.
- `status` — `legacy-only | both | sdk-only | parity-verified`.

### Sample rows (~250 features expected)

```csv
F-AGENT-LOOP-001,agents,Agent loop with max_iterations=300,strix/agents/base_agent.py:152,test_runner_max_turns_300,allam,1,parity-verified
F-AGENT-LOOP-002,agents,85%/N-3 turn warnings,strix/agents/base_agent.py:186,test_turn_warnings_injection,allam,3,parity-verified
F-AGENT-LOOP-003,agents,Streaming early-truncate at </function>,strix/llm/llm.py:212,,allam,defer,legacy-only
F-LLM-001,llm,Anthropic prompt cache control,strix/llm/llm.py:371,test_anthropic_cache_present,allam,0,parity-verified
F-TOOL-BROWSER-001,tools,launch action,strix/tools/browser/browser_actions.py:75,test_browser_launch,allam,2,parity-verified
F-TOOL-BROWSER-002,tools,goto action,strix/tools/browser/browser_actions.py:80,test_browser_goto,allam,2,parity-verified
... (24 browser actions)
F-TOOL-CAIDO-001,tools,list_requests with HTTPQL filter,strix/tools/proxy/proxy_actions.py:9,test_caido_list_requests,allam,2,parity-verified
... (7 caido tools)
F-MULTIAGENT-MSG-001,orchestration,send_message_to_agent FIFO,strix/tools/agents_graph/agents_graph_actions.py:495,test_bus_send_drain_fifo,allam,3,parity-verified
F-MULTIAGENT-MSG-002,orchestration,inter_agent_message XML wrap,base_agent.py:491,test_filter_xml_wrap,allam,3,parity-verified
F-EVENT-001,telemetry,run.started event in events.jsonl,strix/telemetry/tracer.py:87,test_event_run_started_emitted,allam,1,parity-verified
F-EVENT-002,telemetry,tool.execution.started event,strix/telemetry/tracer.py:300,test_event_tool_execution_started,allam,1,parity-verified
... (every event type)
F-CLI-FLAG-target,interface,--target,--t accepts URL/repo/path,strix/interface/main.py:267,test_cli_target_inference,allam,5,parity-verified
F-CLI-FLAG-scan-mode,interface,--scan-mode quick|standard|deep,strix/interface/main.py:295,test_cli_scan_mode,allam,5,parity-verified
... (every CLI flag)
F-OUTPUT-EXIT-CODE-2,interface,exit code 2 on findings in headless,strix/interface/main.py:640,test_headless_exit_code_2,allam,5,parity-verified
F-OUTPUT-VULN-JSON,telemetry,vulnerabilities/vuln_*.json schema,strix/telemetry/tracer.py:365,test_vuln_json_schema,allam,2,parity-verified
F-OUTPUT-REPORT-MD,interface,penetration_test_report.md template,strix/telemetry/tracer.py:400,test_report_md_template,allam,5,parity-verified
F-PII-001,telemetry,scrubadub OpenAI key pattern,strix/telemetry/utils.py:87,test_pii_scrub_openai_key,allam,1,parity-verified
F-PII-002,telemetry,scrubadub bearer token pattern,strix/telemetry/utils.py:91,test_pii_scrub_bearer,allam,1,parity-verified
... (every regex pattern)
F-SKILL-NoSQL,prompts,NoSQL injection skill,strix/prompts/vulnerabilities/nosql_injection.jinja,test_skill_nosql_loadable,allam,2,parity-verified
F-SKILL-K8s,skills,Kubernetes security skill,strix/skills/cloud/kubernetes.md,test_skill_k8s_loadable,allam,2,parity-verified
... (every skill file)
```

### Workflow

1. **Bootstrap**: a script (`scripts/build_inventory.py`) walks the legacy code and emits a draft CSV. Engineer fills `test_id` per row.
2. **CI gate**: `tests/static/test_inventory_completeness.py` asserts every row has `test_id` non-empty. Empty row → CI fails.
3. **Coverage check**: a separate test asserts every `test_id` listed in the inventory actually exists as a test function (no typos, no orphans).
4. **PR review rule**: any code change touching `strix/` must update the inventory if it adds/removes/modifies a feature.
5. **Cutover gate**: ≥98% of inventory rows must be `parity-verified`. The remaining ≤2% are `legacy-only` (intentionally dropped) with explicit owner approval recorded in the row.

This matrix is the single artifact that proves "we didn't lose anything." It's the audit trail.

---

## 4. Behavioral parity diffing

**The strongest non-trivial test we have.** Same input, same env, both harnesses, diff every output. If the diff is empty, parity is proved.

### What we diff

For a fixed scenario (same target, same instruction, same model, same env):

| Artifact | Diff strategy |
|---|---|
| `events.jsonl` | Per-line JSON normalized + sorted by `event_type` + key fields; some fields ignored (timestamps, UUIDs, span IDs); deep diff |
| `vulnerabilities/*.json` | Group by stable identifier (target+endpoint+CVE), normalize, deep-diff each group's contents |
| `penetration_test_report.md` | Length within ±10%; heading set identical; CWE histogram identical |
| `notes/notes.jsonl` | Sorted by category + title; content body fuzzy-match (Levenshtein > 0.95) |
| `wiki/*.md` | File set identical; per-file content fuzzy-match |
| Tool call sequence (extracted from events) | Tool name multiset identical; arg signature shapes identical |
| Token usage | Within ±5% (LLM nondeterminism + caching variance) |
| Wall-clock duration | Within ±50% (allow for SDK overhead and parallel tool gains) |

### Normalization (the careful part)

LLMs are nondeterministic. We **must** normalize away noise before diffing or every diff fails.

```python
# tests/parity/normalize.py
def normalize_events(events_jsonl_path: Path) -> list[dict]:
    out = []
    for line in events_jsonl_path.read_text().splitlines():
        evt = json.loads(line)
        # Strip noise
        evt.pop("timestamp", None)
        evt.pop("trace_id", None)
        evt.pop("span_id", None)
        evt.pop("agent_id", None)            # different IDs in old vs new
        evt.pop("scan_id", None)
        # Normalize content fields
        if "payload" in evt and "content" in evt["payload"]:
            evt["payload"]["content"] = _normalize_text(evt["payload"]["content"])
        out.append(evt)
    # Sort by event_type, then by stable shape hash
    out.sort(key=lambda e: (e.get("event_type", ""), _shape_hash(e)))
    return out
```

The diff library is `deepdiff`; failures point to specific keys.

### The runner

```python
# tests/parity/run_parity.py
def run_parity(scenario_id: str) -> ParityResult:
    """Run scenario through both harnesses with identical inputs and recorded LLM."""
    inputs = load_scenario(scenario_id)  # target, instruction, env, model

    legacy_run = run_legacy(inputs, recorded_llm=RECORDED[scenario_id])
    sdk_run = run_sdk(inputs, recorded_llm=RECORDED[scenario_id])

    return ParityResult(
        events_diff=diff_events(legacy_run.events_jsonl, sdk_run.events_jsonl),
        vulns_diff=diff_vulns(legacy_run.vulns, sdk_run.vulns),
        report_diff=diff_report(legacy_run.report, sdk_run.report),
        tool_call_diff=diff_tool_calls(legacy_run.events, sdk_run.events),
        usage_drift=compute_usage_drift(legacy_run.usage, sdk_run.usage),
    )
```

### Scenarios to fix as parity baselines

A small, hand-picked, *stable* set:

| Scenario | Target | Mode | Why |
|---|---|---|---|
| `S01-static-blackbox` | https://juice-shop.local | quick | Standard OWASP target; many findings; broad tool exercise |
| `S02-static-whitebox` | ./examples/vulnerable-flask-app | deep | Whitebox path; semgrep+ast paths; wiki notes |
| `S03-multi-target` | repo + url combined | standard | Multi-target coordination |
| `S04-diff-mode` | ./examples/vulnerable-flask-app `--scope-mode=diff` | quick | Diff scope injection |
| `S05-cancellation` | juice-shop, kill at iter 10 | quick | Cancellation cascade |
| `S06-multi-agent-explicit` | DVWA, instruction triggers `create_agent` | deep | Subagent flow |
| `S07-empty-target` | nonexistent.local | quick | Failure path |
| `S08-large-codebase` | ./examples/big-repo | standard | Compression triggered |

Every scenario has a recorded LLM trace (§5). Every scenario runs in CI. Failure on any scenario blocks cutover.

### What "diff is empty" means

After normalization, an empty diff on every artifact means: every event the legacy harness emits, the SDK harness emits; every finding the legacy harness reports, the SDK harness reports; every tool call sequence is the same set; the report has the same structure. **It does NOT mean every byte is identical** — that's impossible with LLMs.

### Bidirectional comparison

We diff in both directions:
- "What does legacy have that SDK doesn't?" — the dangerous direction (silent feature loss).
- "What does SDK have that legacy doesn't?" — safer (new behavior), but worth review.

A row like `event_type=agent.created` missing in SDK → blocker. A row like `event_type=tool.guardrail.rejected` only in SDK → review.

---

## 5. Replay infrastructure

LLM and sandbox calls are nondeterministic (LLM) or environment-dependent (sandbox). For deterministic CI, we record once and replay forever.

### LLM recording

A `RecordedLLM` model that intercepts `Model.get_response`/`stream_response`, looks up the request in a fixture file, returns the recorded response.

```python
# tests/replay/recorded_llm.py
from agents.models.interface import Model

class RecordedLLM(Model):
    def __init__(self, recording_path: Path):
        self.recordings = json.loads(recording_path.read_text())
        self.cursor = 0

    async def get_response(self, system_instructions, input, model_settings, tools, ...):
        key = _hash_request(system_instructions, input, model_settings)
        if key not in self.recordings:
            raise ValueError(f"No recording for request hash {key[:8]}; capture with --record")
        recording = self.recordings[key]
        return ModelResponse(
            output=[_deserialize_item(it) for it in recording["output"]],
            usage=Usage(**recording["usage"]),
            response_id=recording.get("response_id"),
        )

    async def stream_response(self, ...):
        # Same lookup; replay chunks one by one
        ...
```

**How requests are keyed:** hash of `(system_instructions, input_items, model, tools, model_settings excerpts)`. PII-stripped before hashing. Hash collisions are vanishingly rare; if they happen, append a sequence counter.

**Capture mode:** `pytest --record-llm` runs scenarios against a real LLM with a flag set; all `acompletion` calls are intercepted at a wrapper layer and serialized to `tests/replay/recordings/<scenario_id>.json`. PII scrubbed via existing `TelemetrySanitizer` before write.

**Replay mode (default):** `pytest` uses `RecordedLLM` instead of real LLM; deterministic.

### Sandbox recording

Same pattern for sandbox HTTP calls. Wrap `post_to_sandbox`:

```python
class RecordedSandbox:
    def __init__(self, recording_path: Path):
        self.recordings = json.loads(recording_path.read_text())

    async def post(self, agent_id, tool_name, kwargs):
        key = _hash_call(agent_id, tool_name, kwargs)
        if key not in self.recordings:
            raise ValueError(f"No sandbox recording for {tool_name} hash {key[:8]}")
        return self.recordings[key]
```

Inject via test fixture; production code path unchanged.

### Recording vs replay in CI

- **Replay** (default, fast): every PR runs scenarios against recorded LLM + sandbox. Catches behavioral regressions in the harness itself.
- **Re-record** (manual, scheduled): a recurring CI job (or operator command) re-records scenarios against real LLM + real sandbox. Generates fresh recordings if the model output drifts.
- **Drift detection**: if a re-record produces output that fails the parity diff, the migration broke (or the legacy harness changed in main; check git history).

This is exactly the pattern the SDK uses internally (`inline_snapshot` library). We can adopt it directly.

---

## 6. Live shadow mode

For the highest-confidence pre-cutover signal: run both harnesses in production, on real user runs, diff results.

### Shadow runner

A CLI mode `strix --target ... --shadow` that:

1. Spawns the legacy harness against the target.
2. Spawns the SDK harness against the same target (separate sandbox container).
3. Both run to completion independently.
4. After both finish, computes parity diff and emits a report.

User sees the legacy result (no UX disruption); engineering team sees the diff.

```python
# strix/interface/shadow.py
async def run_shadow(args):
    legacy_task = asyncio.create_task(run_legacy(args, run_dir=Path("strix_runs/shadow_legacy")))
    sdk_task = asyncio.create_task(run_sdk(args, run_dir=Path("strix_runs/shadow_sdk")))
    legacy_result, sdk_result = await asyncio.gather(legacy_task, sdk_task)

    diff = run_parity(legacy_result.run_dir, sdk_result.run_dir)
    write_diff_report(diff, Path("strix_runs/shadow_diff.json"))
    upload_diff_to_telemetry(diff)
    return legacy_result  # user gets the legacy answer; safe rollback
```

### Sampling

Not every run shadows — too expensive in tokens. Configurable sampling:

```bash
STRIX_SHADOW_SAMPLE_RATE=0.1   # 10% of runs go through shadow mode
STRIX_SHADOW_FORCE=1           # always (for engineering / staging)
```

### What we look for

- **Parity rate**: % of shadow runs where diff is empty. Target: ≥99% before cutover.
- **Drift class histograms**: which fields differ most? Track per-field over time.
- **Resource drift**: token cost, wall-clock, sandbox memory. Plot distributions.

Shadow runs **don't gate cutover** by themselves (too noisy with 1 sample), but a sustained drop in parity rate is a stop signal.

---

## 7. Per-correction test mapping

Every one of the 25 corrections from `AUDIT.md` + `AUDIT_R2.md` + `AUDIT_R3.md` needs a test that would have caught the bug. Defensive code without proof-of-defense is theater.

| # | Correction | Test | Layer |
|---|---|---|---|
| C1 | Tool-server slot serialization vs SDK parallel calls | `test_parallel_tool_calls_safe_default_no_collision` (Layer 3) + `test_tool_server_relax_phase6_concurrent_works` (Layer 3) | 3 |
| C2 | Anthropic cache_control on system message | `test_anthropic_cache_control_on_system_message` (Layer 2) + `test_anthropic_cache_hit_rate` (Layer 5, recorded) | 2, 5 |
| C3 | DockerSandboxClient subclass injects caps | `test_strix_docker_client_caps_injected` (Layer 2, mocked) + `test_strix_docker_client_nmap_works` (Layer 7, live) | 2, 7 |
| C4 | Subagent `tool_use_behavior` | `test_subagent_exits_on_agent_finish` (Layer 3) | 3 |
| C5 | StrixStreamAccumulator parity | `test_stream_accumulator_event_coverage` (Layer 4 vs Layer 5 baseline) | 4, 5 |
| C6 | Notes JSONL write lock | `test_notes_jsonl_concurrent_writes_no_corruption` (Layer 3) | 3 |
| C7 | events.jsonl write lock | `test_events_jsonl_concurrent_writes_no_corruption` (Layer 3) | 3 |
| C8 | Subagent crash detection | `test_subagent_crash_emits_agent_crash_to_parent` (Layer 3) | 3 |
| C9 | Cancellation cascade | `test_cancel_descendants_walks_tree_leaf_first` (Layer 3) | 3 |
| C10 | Compressor try/except | `test_compressor_failure_returns_uncompressed` (Layer 2) | 2 |
| C11 | Retry policy excludes 401/403/400 | `test_retry_policy_does_not_retry_401` (Layer 2) | 2 |
| C12 | Stats snapshot under lock | `test_total_stats_consistent_under_concurrent_writes` (Layer 2) | 2 |
| F1 | LitellmModel signature positional-first | mypy / `test_anthropic_caching_litellm_model_overrides_correctly` | 1, 2 |
| F2 | RunHooks AgentHookContext + result:str | mypy / `test_hooks_signatures_match_sdk` | 1, 2 |
| F3 | TracingProcessor methods sync | mypy / `test_processor_methods_are_sync` | 1, 2 |
| C13 | Bus.finalize cleans up state | `test_finalize_clears_inbox_parent_name` (Layer 2) | 2 |
| C14 | Filter try/except | `test_filter_exception_returns_unmodified` (Layer 2) | 2 |
| C15 | Hooks try/except | `test_hooks_exception_does_not_propagate` (Layer 2) | 2 |
| C16 | Processor catches OSError | `test_processor_oserror_caught_run_continues` (Layer 2) | 2 |
| C17 | Model alias validation | `test_unknown_alias_raises_user_error` (Layer 2) | 2 |
| C18 | Sandbox response size cap | `test_sandbox_response_too_large_returns_error` (Layer 2) | 2 |
| C19 | Assert ≥1 enabled tool | `test_agent_build_fails_with_no_tools` (Layer 2) | 2 |
| C20 | Per-tool timeout_behavior | `test_critical_tool_timeout_raises` + `test_idempotent_tool_timeout_returns_string` | 2 |
| C21 | RunConfig override + context fields | `test_run_config_override_merges` + `test_context_has_is_whitebox` | 2 |
| C22 | finish_scan checks children | `test_finish_scan_blocks_with_running_children` (Layer 3) | 3 |
| C23 | Diff-scope injection | `test_diff_scope_in_first_user_message` (Layer 4) | 4 |
| C24 | Run-name + Docker preflight | `test_collision_detected` + `test_docker_unavailable_clear_error` (Layer 7) | 7 |
| C25 | Cancel mode mapping | `test_ctrl_c_immediate` + `test_tui_stop_after_turn` (Layer 7) | 7 |

Every test name above is a placeholder for a real test function. The grid is the contract. CI runs all of these.

---

## 8. CI gating and cutover criteria

### Per-PR CI (every commit)

| Check | Layer | Failure means |
|---|---|---|
| `mypy --strict` | 1 | Type contract drift |
| `ruff check + format` | 1 | Lint failure |
| `pytest tests/static/` | 1 | Inventory incomplete or imports broken |
| `pytest tests/<module>/` (unit) | 2 | Module-level regression |
| `pytest tests/integration/` | 3 | Cross-module regression |
| `pytest tests/parity/` against recorded scenarios | 4, 5 | Behavioral drift |
| Inventory completeness | 1 | A feature row has no test_id |
| Inventory test existence | 1 | A test_id is missing the test |
| SDK version pin | 1 | Accidental SDK upgrade |

### Nightly CI (scheduled, longer-running)

| Check | Purpose |
|---|---|
| Re-record scenarios against real LLM+sandbox | Detect drift in legacy or SDK behavior over time |
| Mutation testing on critical modules (bus, filter, hooks) | Verify tests actually catch bugs |
| Multi-platform PyInstaller build + smoke | Catch packaging regressions on macOS arm64/x86_64, Linux, Windows |
| Memory-pressure soak (300-turn run) | Catch leaks |

### Cutover criteria

To flip `STRIX_USE_SDK_HARNESS` default from `0` to `1`:

- [ ] All 25 corrections (C1–C25 + F1–F3) have green tests in the grid above.
- [ ] Inventory matrix: ≥98% of rows are `parity-verified`. Remaining ≤2% are explicitly `legacy-only` with owner sign-off.
- [ ] Layer 4 parity diffing: 8 baseline scenarios all empty-diff (post-normalization).
- [ ] Layer 5 replay: all recorded scenarios green.
- [ ] Layer 7 manual smoke: TUI works on macOS + Linux; headless mode produces correct exit codes.
- [ ] Shadow mode (Layer 6): ≥99% parity rate over a 7-run sample at minimum.
- [ ] Mutation testing: ≥80% mutation kill rate on critical modules.
- [ ] Memory soak: 300-turn run completes; memory growth < 1 GB; no orphan containers.
- [ ] Engineering team signoff via PR review.

### Post-cutover gates (kept for one release after flip)

- Legacy harness still ships (gated by `STRIX_USE_SDK_HARNESS=0`).
- CI continues to run parity diffing on every PR.
- Nightly re-record runs detect any post-cutover legacy/SDK drift.
- Production telemetry on parity rate from real users (sampled).

If parity rate drops below 95% in production: emergency rollback.

---

## 9. Manual smoke checklist

Things a human verifies before cutover. Run these on macOS and Linux at minimum.

### TUI mode
- [ ] `strix --target https://juice-shop.local` launches splash screen.
- [ ] Agent tree renders; root expands to show subagents when spawned.
- [ ] Streaming text appears in real time as agent generates.
- [ ] F1 opens help screen; ESC closes.
- [ ] Vulnerability popup appears when first finding logged.
- [ ] Ctrl+C → confirm dialog → ESC dismisses, Y stops agent.
- [ ] Tab cycles panels; arrow keys navigate agent tree.
- [ ] Ctrl+Q quits cleanly; container removed; run dir intact.
- [ ] After agent completes, prompt for follow-up message; user can type.

### Headless mode
- [ ] `strix -n --target ./examples/vulnerable-flask-app --scan-mode quick` runs.
- [ ] Rich panels render: startup, live stats, vuln-found.
- [ ] Final summary panel shows.
- [ ] Exit code 2 if findings; 0 if none.
- [ ] Ctrl+C exits 130 cleanly; container removed.

### Multi-target
- [ ] `strix -t ./repo -t https://app.local` handles both.
- [ ] Each target gets its own `/workspace/<subdir>` mount.
- [ ] Findings tagged by target.

### Diff scope
- [ ] `strix -n --target ./repo --scope-mode diff --diff-base origin/main` includes diff block in instruction.
- [ ] Agent's first turn references the diff.

### Config override
- [ ] `strix --config /path/to/custom.json --target ...` overrides defaults.
- [ ] Env vars from custom config apply; default config vars cleared.

### Resilience
- [ ] Kill the sandbox container mid-run (`docker stop`); agent surfaces error, exits gracefully.
- [ ] Run with invalid `STRIX_LLM=strix/typo`; clear error message naming valid aliases.
- [ ] Run without Docker daemon; preflight error message tells user to start Docker.

---

## 10. Post-cutover monitoring

Once SDK harness is the default, watch for slow regressions.

### Daily metrics

- Parity rate from shadow sample (rolling 7-day).
- Token cost per scan (rolling 7-day per scan_mode).
- Wall-clock per scan (rolling 7-day).
- Findings count distribution by CWE.
- Crash rate by category (LLM, sandbox, tool, agent).

### Alerts

- Parity rate drops below 95% → page engineer.
- Token cost rises >20% week-over-week (with same scan mix) → review.
- Crash rate rises >2× baseline → page.
- Any new error class appears in events.jsonl that wasn't present pre-cutover → review.

### Telemetry (existing PostHog + custom)

- Per-scan: legacy-vs-sdk path used, total cost, total findings, exit code, duration, scan_mode.
- Per-tool: invocation count, error rate, p50/p99 latency.
- Per-error: category, count, first/last seen.

---

## 11. What to do when a parity diff fails

Standard incident playbook. Don't let a failed diff sit; chase root cause.

1. **Examine the diff** — `tests/parity/run_parity.py` outputs a structured diff. Identify the specific field/event that drifted.
2. **Classify the drift**:
   - **Code bug** in our migration → fix, re-test.
   - **Acceptable behavior change** (e.g., SDK emits a new event the legacy didn't) → update normalizer to ignore the field, document in `tests/parity/normalization_notes.md`.
   - **Recording staleness** → re-record affected scenario; investigate why output changed.
3. **Add a new test** if the drift wasn't caught by an existing assertion. Update inventory matrix.
4. **Don't suppress** — never `# noqa` a parity failure. The matrix is the contract.

### Common drift causes (anticipated)

| Drift | Root cause | Fix |
|---|---|---|
| Tool call sequence differs | LLM nondeterminism on retries | Recording captures multiple valid sequences; diff accepts any |
| Event count off by 1 | SDK emits an extra `agent.start` for handoff | Normalizer filters handoff events |
| Token count drift > 5% | Anthropic cache hit/miss timing | Replay against recorded; if still drifts, investigate cache wrapper |
| Vulnerability missing | Dedup decided differently | Check dedup LLM call recording; verify same prompt produces same answer |
| Wiki note shape differs | Update format changed | Normalize whitespace; check `append_note_content` invocation |

---

## TL;DR

Five mechanisms catch the categories of regression we're worried about:

1. **Layer 4 parity diffing on 8 baseline scenarios** — catches every silent regression in tool calls, events, findings, reports. The diff itself is the signal; we don't need to enumerate failures.
2. **Feature inventory matrix (~250 rows)** — every feature has a test; CI fails if the matrix has gaps. Prevents adding features without tests; prevents losing features without notice.
3. **Recorded LLM + sandbox replay (Layer 5)** — deterministic CI; same input always produces same output; no token burn per PR.
4. **Shadow mode in production (Layer 6)** — real-world parity validation; sampled at 10%; strongest signal pre-cutover.
5. **Per-correction tests (25+3 = 28 specific tests)** — every audit finding has a test that proves the fix works.

CI gates everything. Cutover criteria are explicit and measurable. Rollback is a flag flip. Post-cutover monitoring catches slow drift.

The migration cannot silently lose a feature unless: (a) the feature isn't in the inventory matrix, AND (b) it isn't exercised by any of the 8 baseline scenarios, AND (c) it doesn't appear in production within the shadow sampling window. That's a narrow gap, and it gets narrower with every scenario added.
