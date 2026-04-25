# Strix → OpenAI Agents SDK Migration Playbook

> The day-1 engineering reference. Distillation of two audit rounds and four implementation deep-dives into actionable specs. All SDK references verified against `openai-agents` v0.14.6 at `/tmp/openai-agents`. Strix references at `9fb1012`.

---

## Reading order

1. `HARNESS_WIKI.md` — what we have today.
2. `MIGRATION_EVALUATION.md` rev 2 — the architectural plan.
3. `AUDIT.md` — first audit; five plan corrections (C1–C5).
4. `AUDIT_R2.md` — Round 1 audit; seven additional corrections (C6–C12).
5. **This file** — file-by-file specs, per-tool contracts, test plans, standards.

---

## Table of contents

1. [Consolidated corrections register](#1-consolidated-corrections-register)
2. [Foundation files (concrete skeletons)](#2-foundation-files-concrete-skeletons)
3. [Sandbox + Caido capability](#3-sandbox--caido-capability)
4. [Per-tool migration contracts](#4-per-tool-migration-contracts)
5. [Standards: logging, error formatting, observability](#5-standards-logging-error-formatting-observability)
6. [Test plans per phase](#6-test-plans-per-phase)
7. [Rollback, CI, cross-cutting](#7-rollback-ci-cross-cutting)
8. [Phase ordering and day-1 commit list](#8-phase-ordering-and-day-1-commit-list)

---

## 1. Consolidated corrections register

Twelve corrections to apply, ordered by phase. Every fix is bounded and source-verified.

| # | Severity | Defect | Fix shape | Apply in |
|---|---|---|---|---|
| **C1** | Blocker | SDK runs tools in parallel within a turn (`run_internal/tool_execution.py:1414, 1424`); Strix tool server cancels previous task for same agent (`tool_server.py:94-97`). | Phase 1 safe default: `ModelSettings(parallel_tool_calls=False)` + `RunConfig(isolate_parallel_failures=False)`. Phase 6 relaxation: remove the cancel logic, allow concurrent same-agent tool calls. | Phase 1 / 6 |
| **C2** | Blocker | Plan §3.2 said `extra_body["cache_control"]` injects Anthropic prompt cache. Verified — that lands at request level, not on system message. Caches nothing. | `AnthropicCachingLitellmModel` subclass — override `get_response`/`stream_response` to inject `cache_control` on the system message before super delegation. | Phase 0 |
| **C3** | Blocker | `DockerSandboxClient._create_container()` (`sandbox/sandboxes/docker.py:1434-1477`) has no kwarg-injection hook. | Subclass + duplicate parent body verbatim, append `create_kwargs.setdefault("cap_add", []).extend(["NET_ADMIN","NET_RAW"])` and `create_kwargs.setdefault("extra_hosts", {})["host.docker.internal"] = "host-gateway"`. Pin SDK version. | Phase 0 |
| **C4** | Blocker | Subagent `agent_finish` returns from a tool; SDK loop continues to `max_turns` unless told to stop. | Every child Agent: `tool_use_behavior={"stop_at_tool_names": ["agent_finish"]}`. Root Agent: `tool_use_behavior={"stop_at_tool_names": ["finish_scan"]}`. | Phase 3 |
| **C5** | High | TUI today polls `tracer.streaming_content` per-chunk; SDK's `Runner.run_streamed().stream_events()` is event-driven. | `StrixStreamAccumulator` consumes `RawResponsesStreamEvent` + `RunItemStreamEvent` and synthesizes legacy tracer API. Hooks bridge for non-streamed children. | Phase 5 |
| **C6** | Critical | `notes/notes_actions.py:_append_note_event` writes JSONL without lock. Two concurrent agents corrupt file. | Wrap `f.write(...)` in `with _notes_lock:`. Same for `_persist_wiki_note()`. | Phase 2 |
| **C7** | Critical | `telemetry/tracer.py:_append_event_record` calls `append_jsonl_record` without acquiring `_get_events_write_lock()`. | Wrap append in the existing lock. Apply identically in our custom `TracingProcessor`. | Phase 1 |
| **C8** | High | Subagent crash in daemon thread is silent — parent's `wait_for_message` polls forever. Same shape post-migration if a child `Runner.run` task raises. | `StrixOrchestrationHooks.on_agent_end` detects crash (output is None or `agent_finish` flag absent in context); pushes synthetic `<agent_crash>` message to parent inbox so filter surfaces it. | Phase 3 |
| **C9** | High | Root cancellation does NOT cascade to children spawned via `asyncio.create_task` in `create_agent` tool. | `cancel_run_with_descendants(bus, root_id)` walks `bus.parent_of` tree leaf-first and `task.cancel()`s each. Wired to CLI signal handler + TUI stop. | Phase 3 |
| **C10** | Medium | Memory compressor LLM call exception bubbles to agent loop, killing the whole iteration. Defeats the purpose. | Custom `Session` wraps compressor invocation in try/except; on failure, returns uncompressed history. Downstream context-window error is itself retryable. | Phase 1 |
| **C11** | Medium | Strix today fails fast on 401/403/400. SDK retry policy default may include them. | Explicit `ModelRetrySettings.policy = retry_policies.any(network_error(), http_status([429,500,502,503,504]))` — note 401/403/400 NOT included. Bake into `make_run_config()` factory. | Phase 1 |
| **C12** | Medium | `_completed_agent_llm_totals` read by tracer without lock. | Bus `total_stats()` reads under `asyncio.Lock`; tracer goes through bus. | Phase 3 (in design) |

---

## 2. Foundation files (concrete skeletons)

Seven load-bearing modules, plus three supporting ones. Every skeleton is non-stub — copy-edit, fill, ship.

### 2.1 `strix/llm/anthropic_cache_wrapper.py`

```python
from typing import Any
from agents.extensions.models.litellm_model import LitellmModel
from agents.items import ModelResponse, TResponseInputItem
from agents.models.interface import ModelTracing
from agents.model_settings import ModelSettings
from agents.tool import Tool
from agents.handoffs import Handoff
from agents.agent_output import AgentOutputSchemaBase
from openai.types.responses.response_prompt_param import ResponsePromptParam


class AnthropicCachingLitellmModel(LitellmModel):
    """Inject cache_control on the system message for Anthropic models.

    Why: SDK ModelSettings.extra_body lands cache_control at request level,
    not on the system message — Anthropic only caches when cache_control is
    attached to the message itself.
    """

    def _is_anthropic(self) -> bool:
        m = self.model.lower()
        return "anthropic/" in m or "claude" in m

    def _patch(self, items: list[TResponseInputItem]) -> list[TResponseInputItem]:
        if not self._is_anthropic():
            return items
        out: list[TResponseInputItem] = []
        for item in items:
            if isinstance(item, dict) and item.get("role") == "system":
                content = item["content"]
                if isinstance(content, str):
                    content = [{
                        "type": "text", "text": content,
                        "cache_control": {"type": "ephemeral"},
                    }]
                out.append({**item, "content": content})
            else:
                out.append(item)
        return out

    # F1 (AUDIT_R3): SDK Model.get_response declares the first 7 params positional-first.
    async def get_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        *,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    ) -> ModelResponse:
        patched = self._patch(input if isinstance(input, list) else [input])
        return await super().get_response(
            system_instructions,
            patched,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )

    async def stream_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        *,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    ):
        patched = self._patch(input if isinstance(input, list) else [input])
        async for ev in super().stream_response(
            system_instructions,
            patched,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        ):
            yield ev
```

**Tests:** assert system message acquires `cache_control` for Anthropic; assert non-Anthropic passes through; `cache_read_input_tokens > 0` on call 2 of identical-prompt sequence.

---

### 2.2 `strix/runtime/strix_docker_client.py`

```python
import uuid
from typing import Any
from docker.models.containers import Container
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    _build_docker_volume_mounts,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
    _docker_port_key,
    parse_repository_tag,
)
from agents.sandbox.manifest import Manifest


class StrixDockerSandboxClient(DockerSandboxClient):
    """Adds NET_ADMIN, NET_RAW capabilities and host.docker.internal mapping.

    Body is a verbatim copy of DockerSandboxClient._create_container
    (sandbox/sandboxes/docker.py:1434-1477) with two appends before the
    final containers.create() call. SDK has no kwarg-injection hook;
    pin openai-agents version, re-merge on bump.
    """

    async def _create_container(
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()

        create_kwargs: dict[str, Any] = {
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
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )

        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(p): ("127.0.0.1", None) for p in exposed_ports
            }

        # ---- STRIX additions ----
        create_kwargs.setdefault("cap_add", []).extend(["NET_ADMIN", "NET_RAW"])
        create_kwargs.setdefault("extra_hosts", {})["host.docker.internal"] = "host-gateway"
        # -------------------------

        return self.docker_client.containers.create(**create_kwargs)
```

**Tests:** mock `docker_client.containers.create`; assert kwargs contain `cap_add ⊇ {NET_ADMIN, NET_RAW}` and `extra_hosts["host.docker.internal"] == "host-gateway"`. Live test: spin up real container, run `nmap -sS scanme.nmap.org` via `session.exec`, assert exit 0.

---

### 2.3 `strix/orchestration/bus.py`

```python
import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentMessageBus:
    inboxes: dict[str, list[dict]] = field(default_factory=dict)
    tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)  # running|waiting|completed|crashed|stopped
    parent_of: dict[str, str | None] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    stats_live: dict[str, dict[str, Any]] = field(default_factory=dict)
    stats_completed: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def register(self, agent_id: str, name: str, parent_id: str | None) -> None:
        async with self._lock:
            self.inboxes[agent_id] = []
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name
            self.stats_live[agent_id] = {"in": 0, "out": 0, "cached": 0, "cost": 0.0, "calls": 0}

    async def send(self, target: str, msg: dict) -> None:
        async with self._lock:
            self.inboxes.setdefault(target, []).append(msg)

    async def drain(self, agent_id: str) -> list[dict]:
        async with self._lock:
            msgs = self.inboxes.get(agent_id, [])
            self.inboxes[agent_id] = []
            return msgs

    async def record_usage(self, agent_id: str, usage) -> None:
        if usage is None:
            return
        async with self._lock:
            s = self.stats_live.setdefault(agent_id, {"in": 0, "out": 0, "cached": 0, "cost": 0.0, "calls": 0})
            s["in"] += getattr(usage, "input_tokens", 0) or 0
            s["out"] += getattr(usage, "output_tokens", 0) or 0
            details = getattr(usage, "input_tokens_details", None)
            s["cached"] += getattr(details, "cached_tokens", 0) or 0 if details else 0
            s["calls"] += 1

    async def finalize(self, agent_id: str, status: str) -> None:
        # C13 (AUDIT_R3): clear inbox/parent/name to avoid orphaned-message memory leak
        # when sibling agents try to send to a finished agent.
        async with self._lock:
            self.statuses[agent_id] = status
            self.stats_completed[agent_id] = self.stats_live.pop(agent_id, {})
            self.inboxes.pop(agent_id, None)
            self.parent_of.pop(agent_id, None)
            self.names.pop(agent_id, None)

    async def total_stats(self) -> dict[str, Any]:
        async with self._lock:
            agg = {"in": 0, "out": 0, "cached": 0, "cost": 0.0, "calls": 0}
            for s in (*self.stats_live.values(), *self.stats_completed.values()):
                for k, v in s.items():
                    agg[k] = agg.get(k, 0) + v
            return agg

    async def cancel_descendants(self, root_agent_id: str) -> None:
        """Walk parent_of tree leaf-first; cancel each task. (C9)"""
        async with self._lock:
            queue = [root_agent_id]
            order: list[str] = []
            while queue:
                aid = queue.pop()
                order.append(aid)
                queue.extend(c for c, p in self.parent_of.items() if p == aid)
            tasks = [self.tasks[a] for a in reversed(order) if a in self.tasks]
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*[t for t in tasks if not t.done()], return_exceptions=True)
```

**Tests:** stress concurrent `send`/`drain`; FIFO ordering; `cancel_descendants` cancels children before parent; `total_stats` snapshot is consistent.

---

### 2.4 `strix/orchestration/filter.py`

```python
import logging
from agents.run_config import CallModelData, ModelInputData

logger = logging.getLogger(__name__)


async def inject_messages_filter(data: CallModelData) -> ModelInputData:
    """Drain bus inbox; append as user-role items wrapped in <inter_agent_message>.

    Filter runs once per turn; output captured for retries (verified) — safe to drain.
    C14 (AUDIT_R3): wrap whole body in try/except so a filter bug never tears down
    the run. On any exception, return unmodified data.model_data.
    """
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
    except Exception:
        logger.exception("inject_messages_filter failed; proceeding without injection")
        return data.model_data
```

**Tests:** N pending messages → N items appended in FIFO; user-from-user skips XML wrap; empty inbox passes through; messages preserved across forced LLM retry.

---

### 2.5 `strix/orchestration/hooks.py`

```python
import logging
from agents.lifecycle import RunHooks
# F2 (AUDIT_R3): on_agent_start/on_agent_end receive AgentHookContext, NOT RunContextWrapper.
from agents.lifecycle import AgentHookContext  # type: ignore[attr-defined]
from agents.run_context import RunContextWrapper

logger = logging.getLogger(__name__)


class StrixOrchestrationHooks(RunHooks):
    # C15: every hook body wrapped in try/except so a hook bug never tears down the run.

    async def on_llm_start(
        self,
        context: RunContextWrapper,
        agent,
        system_prompt: str | None,
        input_items: list,
    ) -> None:
        try:
            if not isinstance(input_items, list):
                return
            max_turns = context.context.get("max_turns", 300)
            cur = context.context.get("turn_count", 0)
            if cur == int(max_turns * 0.85):
                input_items.append({
                    "role": "user",
                    "content": "<system_warning>You are at 85% of your iteration "
                               "budget. Begin consolidating findings.</system_warning>",
                })
            elif cur == max_turns - 3:
                input_items.append({
                    "role": "user",
                    "content": "<system_warning>You have 3 iterations left. Your next "
                               "tool call MUST be the finish tool.</system_warning>",
                })
        except Exception:
            logger.exception("on_llm_start failed")

    async def on_llm_end(self, context: RunContextWrapper, agent, response) -> None:
        try:
            bus = context.context.get("bus")
            if bus and (aid := context.context.get("agent_id")):
                await bus.record_usage(aid, getattr(response, "usage", None))
            context.context["turn_count"] = context.context.get("turn_count", 0) + 1
        except Exception:
            logger.exception("on_llm_end failed")

    async def on_agent_start(self, context: AgentHookContext, agent) -> None:
        # F2: context is AgentHookContext, not RunContextWrapper.
        try:
            cap = next(
                (c for c in (getattr(agent, "capabilities", None) or [])
                 if hasattr(c, "_healthcheck_task")),
                None,
            )
            if cap and getattr(cap, "_healthcheck_task", None) is not None:
                await cap._healthcheck_task
        except Exception:
            logger.exception("on_agent_start failed")

    async def on_agent_end(self, context: AgentHookContext, agent, output) -> None:
        # F2: context is AgentHookContext.
        try:
            bus = context.context.get("bus")
            if bus is None or (me := context.context.get("agent_id")) is None:
                return
            crashed = (output is None) or not context.context.get("agent_finish_called", False)
            parent = bus.parent_of.get(me)
            if crashed and parent is not None:
                await bus.send(parent, {
                    "from": me,
                    "content": (
                        f"<agent_crash agent_id='{me}' name='{bus.names.get(me, me)}'>"
                        "Agent terminated without calling agent_finish. "
                        "Stop waiting on this child."
                        "</agent_crash>"
                    ),
                    "type": "crash",
                })
            await bus.finalize(me, "crashed" if crashed else "completed")
        except Exception:
            logger.exception("on_agent_end failed")

    async def on_tool_start(self, context: RunContextWrapper, agent, tool) -> None:
        try:
            if tracer := context.context.get("tracer"):
                tracer.log_tool_start(context.context.get("agent_id", "?"), tool.name)
        except Exception:
            logger.exception("on_tool_start failed")

    # F2: on_tool_end's `result` param is typed `str` in the SDK.
    async def on_tool_end(
        self, context: RunContextWrapper, agent, tool, result: str,
    ) -> None:
        try:
            if tool.name in ("agent_finish", "finish_scan"):
                context.context["agent_finish_called"] = True
            if tracer := context.context.get("tracer"):
                tracer.log_tool_end(context.context.get("agent_id", "?"), tool.name, result)
        except Exception:
            logger.exception("on_tool_end failed")

    async def on_handoff(self, context: RunContextWrapper, from_agent, to_agent) -> None:
        # We don't use SDK handoffs in Strix; multi-agent goes through bus.
        pass
```

**Tests:** crash detection fires when agent_finish not called; warnings injected at thresholds; usage recording aggregates.

---

### 2.6 `strix/tools/_decorator.py`

```python
from agents import function_tool


def strix_tool(*, timeout: float = 120.0, timeout_behavior: str = "error_as_result", **kwargs):
    """function_tool with Strix defaults: 120s timeout, error-as-result behavior.

    SDK auto-threads sync function bodies via asyncio.to_thread (tool.py:1820-1829),
    so writing `def foo(...)` (sync) works for libtmux/IPython/etc.
    """
    return function_tool(
        timeout=timeout,
        timeout_behavior=timeout_behavior,
        **kwargs,
    )
```

**Tests:** decorated tool gets timeout; timeout returns error string not exception; sync function auto-threads.

---

### 2.7 `strix/llm/multi_provider_setup.py`

```python
from agents.models.multi_provider import MultiProvider, MultiProviderMap
from agents.models.interface import ModelProvider, Model
from agents.extensions.models.litellm_model import LitellmModel
from strix.llm.anthropic_cache_wrapper import AnthropicCachingLitellmModel

# Strix model alias map
STRIX_MODEL_MAP = {
    "claude-sonnet-4.6": ("anthropic/claude-sonnet-4-5-20250929", "claude-sonnet-4-5"),
    # ... port from strix/llm/utils.py:STRIX_MODEL_MAP
}
STRIX_API_BASE = "https://models.strix.ai/api/v1"


class StrixModelProvider(ModelProvider):
    """Resolve `strix/<short>` aliases via STRIX_MODEL_MAP, route to proxy."""

    def get_model(self, model_name: str | None) -> Model:
        if model_name is None:
            raise ValueError("Model name required")
        api_model, _canonical = STRIX_MODEL_MAP.get(model_name, (model_name, model_name))
        # Anthropic-prefixed → cache wrapper; otherwise vanilla
        if api_model.startswith("anthropic/") or "claude" in api_model.lower():
            return AnthropicCachingLitellmModel(model=api_model, base_url=STRIX_API_BASE)
        return LitellmModel(model=api_model, base_url=STRIX_API_BASE)


class LitellmAnthropicProvider(ModelProvider):
    """Resolve `litellm/anthropic/...` directly to AnthropicCachingLitellmModel."""

    def get_model(self, model_name: str | None) -> Model:
        # model_name arrives post-prefix-strip, e.g. "anthropic/claude-3-5-sonnet"
        return AnthropicCachingLitellmModel(model=model_name)


def build_multi_provider() -> MultiProvider:
    pmap = MultiProviderMap()
    pmap.add_provider("strix", StrixModelProvider())
    pmap.add_provider("litellm/anthropic", LitellmAnthropicProvider())
    # default openai/* and others fall through to MultiProvider's built-in routing
    return MultiProvider(provider_map=pmap)
```

**Tests:** alias resolution; route `strix/claude-sonnet-4.6` → `AnthropicCachingLitellmModel("anthropic/claude-sonnet-4-5-20250929", base_url=STRIX_API_BASE)`; unknown prefix falls through.

---

### 2.8 `strix/llm/strix_session.py`

```python
import logging
from typing import Any
from agents.memory.session import SessionABC

logger = logging.getLogger(__name__)


class StrixSession(SessionABC):
    """Wraps an underlying Session; injects memory compression at 90K tokens.

    On compressor failure: returns uncompressed history (C10) and logs warning.
    Downstream context-window error is itself retryable.
    """

    def __init__(self, underlying: SessionABC, compressor):
        self._underlying = underlying
        self._compressor = compressor  # Strix's existing MemoryCompressor

    async def get_items(self, limit: int | None = None) -> list[Any]:
        items = await self._underlying.get_items(limit=limit)
        try:
            return await self._compressor.compress_history(items)
        except Exception as e:
            logger.warning("Memory compression failed (%s) — returning uncompressed", e)
            return items

    async def add_items(self, items: list[Any]) -> None:
        await self._underlying.add_items(items)

    async def pop_item(self) -> Any | None:
        return await self._underlying.pop_item()

    async def clear_session(self) -> None:
        await self._underlying.clear_session()
```

**Tests:** compression triggers > 90K tokens; failure returns uncompressed; underlying contract satisfied.

---

### 2.9 `strix/telemetry/strix_processor.py`

```python
import json
import logging
import threading
from pathlib import Path
from typing import Any
from agents.tracing.processor_interface import TracingProcessor
from agents.tracing.spans import Span
from agents.tracing.traces import Trace
from strix.telemetry.utils import TelemetrySanitizer

logger = logging.getLogger(__name__)

_FILE_LOCKS: dict[Path, threading.Lock] = {}
_GUARD = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    with _GUARD:
        return _FILE_LOCKS.setdefault(path, threading.Lock())


class StrixTracingProcessor(TracingProcessor):
    """Custom processor: writes events.jsonl in our schema, scrubs PII, supports OTel.

    C7  — JSONL writes locked via per-path threading.Lock.
    C16 — every write wrapped in try/except so disk-full doesn't tear down the run.
    F3  — every hook method is SYNC (def, not async def) per SDK contract.
    """

    def __init__(self, run_dir: Path, sanitizer: TelemetrySanitizer | None = None):
        self.events_path = run_dir / "events.jsonl"
        self.run_dir = run_dir
        self.sanitizer = sanitizer or TelemetrySanitizer()

    def _emit(self, event: dict[str, Any]) -> None:
        try:
            clean = self.sanitizer.sanitize(event)
            with _lock_for(self.events_path):
                with self.events_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(clean, ensure_ascii=True) + "\n")
        except OSError:
            logger.exception("Failed to write event to JSONL")

    def on_trace_start(self, trace: Trace) -> None:  # SYNC — F3
        self._emit({
            "event_type": "run.started",
            "trace_id": trace.trace_id,
            "metadata": getattr(trace, "metadata", {}),
        })

    def on_trace_end(self, trace: Trace) -> None:  # SYNC — F3
        self._emit({"event_type": "run.completed", "trace_id": trace.trace_id})

    def on_span_start(self, span: Span[Any]) -> None:  # SYNC — F3
        sd = type(span.span_data).__name__
        if sd in ("AgentSpanData", "GenerationSpanData", "FunctionSpanData"):
            self._emit({
                "event_type": f"{sd.replace('SpanData', '').lower()}.started",
                "span_id": span.span_id,
                "trace_id": span.trace_id,
                "data": span.span_data.export(),
            })

    def on_span_end(self, span: Span[Any]) -> None:  # SYNC — F3
        sd = type(span.span_data).__name__
        self._emit({
            "event_type": f"{sd.replace('SpanData', '').lower()}.completed",
            "span_id": span.span_id,
            "trace_id": span.trace_id,
            "data": span.span_data.export(),
        })

    def force_flush(self) -> None:  # SYNC — F3
        # All writes are sync; nothing to flush.
        pass

    def shutdown(self) -> None:  # SYNC — F3
        pass
```

**Tests:** concurrent writes don't corrupt; PII scrubbed; OTel passthrough optional.

---

### 2.10 `strix/run_config_factory.py`

```python
from pathlib import Path
from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from agents.model_settings import ModelSettings
from agents.retry import ModelRetrySettings, ModelRetryBackoffSettings, retry_policies

from strix.runtime.strix_docker_client import StrixDockerSandboxClient
from strix.orchestration.bus import AgentMessageBus
from strix.orchestration.filter import inject_messages_filter
from strix.llm.multi_provider_setup import build_multi_provider


# Phase 1-5 default. Phase 6 flips parallel_tool_calls=True after relaxing tool server.
_PHASE1_PARALLEL_DEFAULT = False


def make_run_config(
    *,
    sandbox_session,
    bus: AgentMessageBus,
    model: str = "strix/claude-sonnet-4.6",
    max_turns: int = 300,
) -> RunConfig:
    return RunConfig(
        model=model,
        model_provider=build_multi_provider(),
        model_settings=ModelSettings(
            parallel_tool_calls=_PHASE1_PARALLEL_DEFAULT,  # C1 safe default
            tool_choice="required",
            retry=ModelRetrySettings(
                max_retries=5,
                backoff=ModelRetryBackoffSettings(
                    initial_delay=2.0, multiplier=2.0, max_delay=90.0, jitter=0.0,
                ),
                # C11: explicitly does NOT include 401/403/400
                policy=retry_policies.any(
                    retry_policies.network_error(),
                    retry_policies.http_status([429, 500, 502, 503, 504]),
                ),
            ),
        ),
        sandbox=SandboxRunConfig(
            client=StrixDockerSandboxClient(),
            session=sandbox_session,  # shared across all agents in the run
        ),
        call_model_input_filter=inject_messages_filter,
        isolate_parallel_failures=False,  # C1 — don't cascade-cancel siblings
        tracing_disabled=False,
        trace_include_sensitive_data=False,
        max_turns=max_turns,
    )


def make_agent_context(
    *,
    bus: AgentMessageBus,
    sandbox_session,
    sandbox_token: str,
    tool_server_host_port: int,
    caido_host_port: int,
    agent_id: str,
    agent_name: str,
    parent_id: str | None,
    tracer,
    model_settings,
    max_turns: int = 300,
) -> dict:
    return {
        "bus": bus,
        "sandbox_session": sandbox_session,
        "sandbox_token": sandbox_token,
        "tool_server_host_port": tool_server_host_port,
        "caido_host_port": caido_host_port,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "parent_id": parent_id,
        "tracer": tracer,
        "model_settings": model_settings,
        "max_turns": max_turns,
        "turn_count": 0,
        "agent_finish_called": False,
    }
```

**Tests:** RunConfig has all defaults; retry policy excludes 401; safe defaults for parallel.

---

## 3. Sandbox + Caido capability

### 3.1 `strix/sandbox/healthcheck.py`

```python
import asyncio
import httpx


class SandboxNotReadyError(Exception):
    pass


async def wait_for_ports_ready(ports: list[int], timeout: float = 30.0, interval: float = 0.5) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        all_ok = True
        async with httpx.AsyncClient(timeout=5.0) as client:
            for port in ports:
                try:
                    r = await client.get(f"http://localhost:{port}/health")
                    if r.status_code != 200:
                        all_ok = False
                        break
                except (httpx.RequestError, httpx.TimeoutException):
                    all_ok = False
                    break
        if all_ok:
            return
        await asyncio.sleep(interval)
    raise SandboxNotReadyError(f"Ports {ports} not ready after {timeout}s")
```

### 3.2 `strix/sandbox/caido_capability.py`

```python
import asyncio
from typing import Literal
from pydantic import Field
from agents.sandbox.capabilities.capability import Capability
from agents.sandbox.manifest import Manifest
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.tool import Tool

# 7 Caido tools defined in strix/tools/caido/*.py and imported here
from strix.tools.caido import (
    list_requests, view_request, send_request, repeat_request,
    scope_rules, list_sitemap, view_sitemap_entry,
)


class CaidoCapability(Capability):
    """Caido HTTPS proxy + 7 GraphQL function tools + system prompt block."""

    type: Literal["caido"] = "caido"
    _healthcheck_task: asyncio.Task | None = Field(default=None, exclude=True)

    def process_manifest(self, manifest: Manifest) -> Manifest:
        env = dict(manifest.environment.value or {})
        env.update({
            "http_proxy":  "http://127.0.0.1:48080",
            "https_proxy": "http://127.0.0.1:48080",
            "ALL_PROXY":   "http://127.0.0.1:48080",
        })
        manifest.environment.value = env
        return manifest

    def tools(self) -> list[Tool]:
        return [list_requests, view_request, send_request, repeat_request,
                scope_rules, list_sitemap, view_sitemap_entry]

    async def instructions(self, manifest: Manifest) -> str | None:
        return (
            "<caido_proxy>\n"
            "All HTTP/HTTPS traffic in this sandbox is captured by Caido (localhost:48080).\n"
            "Available tools: list_requests, view_request, send_request, repeat_request, "
            "scope_rules, list_sitemap, view_sitemap_entry.\n"
            "HTTPQL filter syntax: request.method == 'POST' && response.status >= 400.\n"
            "</caido_proxy>"
        )

    def bind(self, session: BaseSandboxSession) -> None:
        super().bind(session)
        from strix.sandbox.healthcheck import wait_for_ports_ready
        # Phase 4: caido :48080 + tool server :48081
        self._healthcheck_task = asyncio.create_task(wait_for_ports_ready([48080, 48081]))
```

`StrixOrchestrationHooks.on_agent_start` awaits `cap._healthcheck_task` (already in 2.5 above).

### 3.3 `strix/sandbox/session_manager.py`

```python
import socket
import secrets
from pathlib import Path
from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions
from agents.sandbox.manifest import Manifest
from agents.sandbox.entries import LocalDir
from strix.runtime.strix_docker_client import StrixDockerSandboxClient
from strix.sandbox.caido_capability import CaidoCapability
from strix.sandbox.healthcheck import wait_for_ports_ready

_session_cache = {}  # scan_id -> session


def _alloc_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def create_or_reuse(scan_id: str, image: str, sources_path: Path):
    if scan_id in _session_cache:
        return _session_cache[scan_id]

    bearer = secrets.token_urlsafe(32)
    manifest = Manifest(
        entries={"sources": LocalDir(src=sources_path)},
        environment={
            "TOOL_SERVER_TOKEN": bearer,
            "TOOL_SERVER_PORT": "48081",
            "CAIDO_PORT": "48080",
            "STRIX_SANDBOX_EXECUTION_TIMEOUT": "120",
            "PYTHONUNBUFFERED": "1",
        },
        capabilities=[CaidoCapability()],
    )

    client = StrixDockerSandboxClient()
    options = DockerSandboxClientOptions(image=image, exposed_ports=(48080, 48081))
    session = await client.create(options=options, manifest=manifest)

    # Resolve mapped host ports (sandbox/sandboxes/docker.py:211-260)
    tool_server_endpoint = await session._resolve_exposed_port(48081)
    caido_endpoint = await session._resolve_exposed_port(48080)
    await wait_for_ports_ready([tool_server_endpoint.port, caido_endpoint.port])

    bundle = {
        "client": client,
        "session": session,
        "tool_server_host_port": tool_server_endpoint.port,
        "caido_host_port": caido_endpoint.port,
        "bearer": bearer,
    }
    _session_cache[scan_id] = bundle
    return bundle


async def cleanup(scan_id: str) -> None:
    bundle = _session_cache.pop(scan_id, None)
    if bundle is None:
        return
    try:
        await bundle["client"].delete(bundle["session"])
    except Exception:
        pass  # best-effort orphan reaping
```

### 3.4 `strix/tools/_sandbox_dispatch.py`

```python
import httpx
from typing import Any
from agents import RunContextWrapper

_TIMEOUT = httpx.Timeout(connect=10.0, read=150.0, write=150.0, pool=150.0)


async def post_to_sandbox(
    ctx: RunContextWrapper, tool_name: str, kwargs: dict[str, Any],
) -> dict[str, Any]:
    """POST tool invocation to FastAPI tool server via host-mapped port.

    Returns {"result": ...} or {"error": ...}; never raises.
    """
    port = ctx.context.get("tool_server_host_port")
    token = ctx.context.get("sandbox_token")
    agent_id = ctx.context.get("agent_id", "unknown")
    if not (port and token):
        return {"error": "Sandbox not initialized"}

    url = f"http://127.0.0.1:{port}/execute"
    body = {"agent_id": agent_id, "tool_name": tool_name, "kwargs": kwargs}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.post(url, json=body, headers=headers)
        if r.status_code == 401:
            return {"error": "Sandbox auth failed"}
        if r.status_code >= 400:
            return {"error": f"Sandbox HTTP {r.status_code}: {r.text[:300]}"}
        try:
            return r.json()
        except ValueError:
            return {"error": f"Invalid sandbox response: {r.text[:200]}"}
    except httpx.TimeoutException:
        return {"error": f"Sandbox timeout (>{_TIMEOUT.read}s)"}
    except httpx.RequestError as e:
        return {"error": f"Sandbox request failed: {e!s}"[:300]}
```

---

## 4. Per-tool migration contracts

Compact table — one row per tool, expanded notes for non-trivial ones.

### 4.1 Sandbox tools (POST to tool server)

Every sandbox tool follows the same shape:

```python
from strix.tools._decorator import strix_tool
from strix.tools._sandbox_dispatch import post_to_sandbox
from agents import RunContextWrapper, ToolOutputText, ToolOutputImage


@strix_tool(timeout=160)  # outer SDK > inner httpx (150)
async def <name>(ctx: RunContextWrapper, ...args) -> str | list:
    result = await post_to_sandbox(ctx, "<server_tool_name>", {<kwargs>})
    if "error" in result:
        return result["error"]
    # Tool-specific result shaping (extract screenshot, truncate, etc.)
    return _shape_result(result)
```

| Tool | Server-side name | Args | Return shape | Notes |
|---|---|---|---|---|
| `browser_action` | `browser_action` | `action: str, **action_kwargs` | `[ToolOutputImage(base64), ToolOutputText(state)]` | Extract `screenshot` key as image; rest as text. 24 actions. Truncate page-source/console at server. |
| `terminal_execute` | `terminal_execute` | `command: str, is_input=False, timeout=30, terminal_id="default", no_enter=False` | `ToolOutputText(content + status + exit_code)` | Per-`(agent_id, terminal_id)` libtmux session at server. |
| `python_action` | `python_action` | `action: str, code: str | None, session_id="default", timeout=30` | `ToolOutputText(stdout + stderr + result_repr)` | Per-`(agent_id, session_id)` IPython kernel. |
| `list_requests` | `list_requests` | `httpql_filter: str | None, start_page=1, end_page=1, page_size=50, sort_by="timestamp", sort_order="desc"` | `ToolOutputText(json)` | Caido. |
| `view_request` | `view_request` | `request_id: str, search_pattern: str | None, part="response"` | `ToolOutputText(json)` | Caido. |
| `send_request` | `send_request` | `method: str, url: str, headers={}, body=""` | `ToolOutputText(json)` | Caido. |
| `repeat_request` | `repeat_request` | `request_id: str, modifications: dict` | `ToolOutputText(json)` | Caido. |
| `scope_rules` | `scope_rules` | `action: Literal["list","create","update","delete"], **kwargs` | `ToolOutputText(json)` | Caido. |
| `list_sitemap` | `list_sitemap` | `parent_id: str | None, page_size=50` | `ToolOutputText(json)` | Caido. |
| `view_sitemap_entry` | `view_sitemap_entry` | `node_id: str` | `ToolOutputText(json)` | Caido. |

### 4.2 Local tools (in-process)

| Tool | Module | Signature | Notes |
|---|---|---|---|
| `create_note` / `list_notes` / `get_note` / `update_note` / `delete_note` | `strix/tools/notes/` | per Strix today | **Apply C6**: lock JSONL writes. Per-agent state silo via `ctx.context["agent_id"]`. |
| `create_todo` / `list_todos` / `update_todo` / `mark_todo_done` / `mark_todo_pending` / `delete_todo` | `strix/tools/todo/` | per Strix today | In-memory only; not persisted. |
| `create_vulnerability_report` | `strix/tools/reporting/` | All current required+optional fields | Calls existing `llm/dedupe.py` via nested `Runner.run` or direct `litellm.acompletion`. Wires `vulnerability_found_callback` via `ToolOutputGuardrail` for TUI popup. |
| `web_search` | `strix/tools/web_search/` | `query: str` | Direct Perplexity API; do NOT use SDK's `WebSearchTool` (Responses-only, OpenAI-only). |
| `str_replace_editor` / `list_files` / `search_files` | `strix/tools/file_edit/` | per Strix today | Wrap openhands-aci + ripgrep. SDK auto-threads sync. |
| `finish_scan` | `strix/tools/finish/` | per Strix today | Root-only guard: `if ctx.context["parent_id"] is not None: return error`. Sets `ctx.context["agent_finish_called"] = True`. **Root agent uses `tool_use_behavior={"stop_at_tool_names": ["finish_scan"]}`.** |
| `think` | `strix/tools/thinking/` | `thought: str` | Trivial; `return f"Recorded {len(thought)} chars"`. |
| `load_skill` | `strix/tools/load_skill/` | `skills: list[str]` (max 5) | Returns skill content as `ToolOutputText` (accepted tradeoff). Validates against skill registry. |

### 4.3 Multi-agent graph tools

All in `strix/tools/agents_graph.py`. Use `bus = ctx.context["bus"]`, `me = ctx.context["agent_id"]`.

```python
@strix_tool(timeout=30)
async def view_agent_graph(ctx) -> str:
    bus = ctx.context["bus"]
    lines = []
    roots = [aid for aid, p in bus.parent_of.items() if p is None]

    def render(aid, depth):
        st = bus.statuses.get(aid, "?")
        lines.append("  " * depth + f"- {bus.names.get(aid, aid)} ({aid}) [{st}]")
        for c, p in bus.parent_of.items():
            if p == aid:
                render(c, depth + 1)

    for r in roots:
        render(r, 0)
    return "\n".join(lines) or "(no agents)"


@strix_tool(timeout=30)
async def agent_status(ctx, agent_id: str) -> str:
    bus = ctx.context["bus"]
    if agent_id not in bus.statuses:
        return f"Unknown agent {agent_id}"
    return (
        f"agent={bus.names.get(agent_id)} status={bus.statuses[agent_id]} "
        f"parent={bus.parent_of.get(agent_id)} "
        f"pending_msgs={len(bus.inboxes.get(agent_id, []))}"
    )


@strix_tool(timeout=30)
async def send_message_to_agent(ctx, target_agent_id: str, message: str,
                                 message_type: str = "info", priority: str = "normal") -> str:
    bus = ctx.context["bus"]
    if target_agent_id not in bus.statuses:
        return f"Unknown agent {target_agent_id}"
    await bus.send(target_agent_id, {
        "from": ctx.context["agent_id"],
        "content": message,
        "type": message_type,
        "priority": priority,
    })
    return f"Queued for {target_agent_id}"


@strix_tool(timeout=601)
async def wait_for_message(ctx, reason: str, timeout_seconds: int = 600) -> str:
    import asyncio
    bus = ctx.context["bus"]
    me = ctx.context["agent_id"]
    bus.statuses[me] = "waiting"
    end = asyncio.get_event_loop().time() + timeout_seconds
    while asyncio.get_event_loop().time() < end:
        if bus.inboxes.get(me):
            bus.statuses[me] = "running"
            return "Message arrived. Continue."
        await asyncio.sleep(1.0)
    bus.statuses[me] = "running"
    return f"Timed out after {timeout_seconds}s. Continue or call agent_finish."


@strix_tool(timeout=120)
async def create_agent(
    ctx, name: str, task: str,
    inherit_context: bool = True, skills: list[str] | None = None,
) -> str:
    import asyncio, uuid
    from agents import Runner
    from strix.run_config_factory import make_run_config, make_agent_context
    from strix.orchestration.hooks import StrixOrchestrationHooks
    from strix.agents.factory import build_strix_agent  # build child Agent w/ tool_use_behavior

    bus = ctx.context["bus"]
    parent = ctx.context["agent_id"]
    cid = uuid.uuid4().hex[:8]
    await bus.register(cid, name, parent)

    child_agent = build_strix_agent(name=name, skills=skills or [], is_root=False)

    # Inherited context: parent's session items
    parent_session = ctx.context.get("session")
    history = await parent_session.get_items() if (inherit_context and parent_session) else []
    initial_input = history + [
        # Identity injection (replaces Strix's <agent_delegation> XML)
        {"role": "user", "content": f"<agent_delegation>You are agent {name} ({cid}). "
                                     f"Parent is {parent}. Do not echo this block.</agent_delegation>"},
        {"role": "user", "content": task},
    ]

    child_ctx = make_agent_context(
        bus=bus,
        sandbox_session=ctx.context["sandbox_session"],
        sandbox_token=ctx.context["sandbox_token"],
        tool_server_host_port=ctx.context["tool_server_host_port"],
        caido_host_port=ctx.context["caido_host_port"],
        agent_id=cid,
        agent_name=name,
        parent_id=parent,
        tracer=ctx.context["tracer"],
        model_settings=ctx.context["model_settings"],
        max_turns=ctx.context["max_turns"],
    )

    bus.tasks[cid] = asyncio.create_task(
        Runner.run(
            child_agent,
            input=initial_input,
            run_config=make_run_config(
                sandbox_session=ctx.context["sandbox_session"],
                bus=bus,
                model=ctx.context.get("model", "strix/claude-sonnet-4.6"),
                max_turns=ctx.context["max_turns"],
            ),
            context=child_ctx,
            hooks=StrixOrchestrationHooks(),
        )
    )
    return f"Spawned {name} ({cid}) running in parallel"


@strix_tool(timeout=30)
async def agent_finish(
    ctx, result_summary: str, findings: list[dict] | None = None,
    success: bool = True, report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> str:
    bus = ctx.context["bus"]
    me = ctx.context["agent_id"]
    parent = bus.parent_of.get(me)
    if parent is None:
        return "Error: agent_finish is for subagents. Root must call finish_scan."
    ctx.context["agent_finish_called"] = True

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

    # Whitebox wiki update (M10 — preserved)
    if ctx.context.get("is_whitebox") and findings:
        # Append delta to shared wiki note via existing notes API
        from strix.tools.notes.notes_actions import append_note_content
        append_note_content("wiki", f"\n## Update from {bus.names.get(me)}\n{result_summary}\n")

    return "Reported to parent. This agent will exit."
```

**Every child agent built by `build_strix_agent`:** `tool_use_behavior={"stop_at_tool_names": ["agent_finish"]}` (C4).

---

## 5. Standards: logging, error formatting, observability

### 5.1 Logging

| Logger | Level | When |
|---|---|---|
| `strix.orchestration.bus` | DEBUG | every send/drain/finalize |
| `strix.orchestration.hooks` | INFO | agent start/end; WARNING on crash detection |
| `strix.tools.<name>` | DEBUG | tool entry/exit; WARNING on user-recoverable error |
| `strix.runtime.strix_docker_client` | INFO | container created; ERROR on creation failure |
| `strix.sandbox.caido_capability` | INFO | bind/healthcheck-task lifecycle |
| `strix.sandbox.session_manager` | INFO | session create/reuse/cleanup |
| `strix.llm.anthropic_cache_wrapper` | DEBUG | cache_control injection events |
| `strix.telemetry.strix_processor` | WARNING | sanitization mismatches |

Verbose mode flag: `--verbose` → `agents.set_default_logging("DEBUG")` + `enable_verbose_stdout_logging()`. Production keeps `OPENAI_AGENTS_DONT_LOG_MODEL_DATA=1` (default) so model I/O isn't logged.

Never logged anywhere: `LLM_API_KEY`, `TOOL_SERVER_TOKEN`, anything the existing `TelemetrySanitizer` patterns match.

### 5.2 Error formatting

| Layer | Recipient | Format |
|---|---|---|
| Tool body | LLM | Plain `str` returned from tool. Convention: `"Error: <reason>"` for failures. |
| Tool body | User | Visible only via TUI when popup-worthy (vulnerability popup hooks via `ToolOutputGuardrail`). |
| Sandbox dispatch | LLM | `{"error": "..."}` → returned as `Error: ...` string. |
| Hook | Logs only | `logger.exception(...)` for unhandled in hooks; never propagated (would tear down the run). |
| Agent crash | Parent | `<agent_crash agent_id='X' name='Y'>...</agent_crash>` user message via bus. |
| Run-level exception | CLI | Exit code 1 (general failure), 2 (vulns found in headless), 130 (Ctrl+C). |
| Run-level exception | Trace | `error.kind`, `error.message`, `error.traceback` span attributes (post-scrub). |

### 5.3 Observability during migration

While both old (Strix) and new (SDK-based) live in parallel:

- **Comparison metrics**: per-run, log `total_input_tokens`, `total_output_tokens`, `cost`, `findings_count`, `wall_clock_seconds`. Diff old vs new with same target set.
- **Drift detection**: identical `--target` should produce equivalent (not byte-identical) findings. Track findings-by-CWE histogram.
- **Canary mode**: feature flag `STRIX_USE_SDK_HARNESS=1` or separate CLI command (`strix-sdk`) until cut-over. Two CLIs let users opt in.
- **Event compatibility**: `events.jsonl` schema must remain compatible — the custom `TracingProcessor` emits the same `event_type` values as today's tracer.

---

## 6. Test plans per phase

### Phase 0 — Spike & corrections

**Smoke tests** (must all pass before Phase 1 starts):
- `test_anthropic_cache_wrapper_injection` — system message has `cache_control`; non-Anthropic passes through.
- `test_anthropic_cache_hit_rate` — three identical-prompt calls; call 2+ shows `cache_read_input_tokens > 0`.
- `test_strix_docker_client_caps` — mock `containers.create`; assert `cap_add ⊇ {NET_ADMIN, NET_RAW}` and `extra_hosts["host.docker.internal"]=="host-gateway"`.
- `test_strix_docker_client_live` — real Kali image; `session.exec(["nmap", "-sS", "scanme.nmap.org"])` returns exit 0.
- `test_message_bus_two_children_exchange` — minimal `MessageBus` with two synthetic agents; verify FIFO message delivery via filter injection.
- `test_tool_use_behavior_stop_on_finish` — toy agent with `agent_finish`-equivalent + `stop_at_tool_names`; assert SDK terminates exactly when tool is called.
- `test_tool_server_concurrent_same_agent_calls` — issue two simultaneous POSTs to local tool server with same `agent_id`; current code cancels first; observe behavior; choose Phase 1 default (`parallel_tool_calls=False`).

### Phase 1 — Foundation

**Unit tests:**
- `MultiProvider` resolution: `strix/claude-sonnet-4.6` → `AnthropicCachingLitellmModel` with correct base URL.
- `strix_tool` decorator: timeout applied; sync auto-threaded.
- `StrixSession`: 100K-token history triggers compression; compressor failure returns uncompressed.
- `StrixTracingProcessor`: 100 concurrent span writes, JSONL is valid (no interleaved bytes); PII patterns scrubbed.
- `RunConfig` factory: retry policy excludes 401 explicitly; `parallel_tool_calls=False` default.

**Integration tests:**
- Full single-agent run with `LitellmModel` against an Anthropic mock; verify cache_control reaches the model.
- Cost tracking via `RunHooks.on_llm_end` matches `litellm.cost_per_token` calculation within 1%.

### Phase 2 — Tool ports

**Per-tool smoke tests** (one per `@strix_tool`):
- Browser: `launch` → `goto("https://example.com")` → screenshot returned as `ToolOutputImage`; viewport 1280x720; per-agent tab keying.
- Terminal: `terminal_execute("echo hello")` → status=completed, exit_code=0. Special key: `terminal_execute("C-c", is_input=True)` no error.
- Python: `python_action(action="execute", code="x=1; x+1")` → result `"2"`.
- Caido: `list_requests(httpql_filter="request.method == 'GET'")` returns JSON with `requests` array.
- Notes: concurrent `create_note` from two agents; assert JSONL parses line-by-line (C6 fix).
- Reporting: full `create_vulnerability_report` payload; CVSS computed; persisted to `vulnerabilities/vuln_*.json`; dedup roundtrip works.
- File edit: `str_replace_editor("create", "/workspace/foo.txt", file_text="x")` → file exists.

**Reentrancy tests:** if/when Phase 6 enables parallel: assert two parallel `terminal_execute` calls on same agent with different `terminal_id` don't collide (different libtmux sessions).

### Phase 3 — Multi-agent

**Unit tests:**
- `AgentMessageBus`: 1000 concurrent `send`/`drain` ops; FIFO maintained; `total_stats` snapshot consistent.
- `inject_messages_filter`: pending messages appended in order; user-from-user skips XML wrap; idempotent under retry simulation.
- `StrixOrchestrationHooks.on_agent_end`: crash detection fires when `agent_finish_called` False; sends `<agent_crash>` to parent.
- `bus.cancel_descendants`: tree of N=10 agents; all cancelled leaf-first.

**Integration:**
- Root spawns 2 children in parallel; children exchange messages; both finish via `agent_finish`; root reads completion reports; `bus.total_stats` aggregates correctly.
- Root + 1 child; user Ctrl+C mid-run; both tasks cancelled; processor flushes all pending events.
- Crashed child scenario: child `Runner.run` raises `RuntimeError`; parent receives `<agent_crash>` within next turn.

### Phase 4 — Sandbox + Caido

**Integration:**
- `create_or_reuse(scan_id="x", ...)` twice → same session; `session.exec(["echo", "hi"])` works.
- Caido capability: container has `http_proxy=http://127.0.0.1:48080` env; `curl https://example.com` is captured by Caido (verify via `list_requests` shows the request).
- Healthcheck: stop tool server inside container; `wait_for_ports_ready` raises after 30s.

### Phase 5 — Interface + persistence

**Tests:**
- `StrixStreamAccumulator`: feed mock `RunResultStreaming` events; tracer's `streaming_content[agent_id]` updates.
- TUI: under simulated agent run, refresh latency < 500ms after each LLM chunk.
- Run-directory: post-run, `events.jsonl` valid; `vulnerabilities/` populated; `penetration_test_report.md` non-empty.

### Phase 6 — Validation + tool server relaxation

**End-to-end:**
- Full pentest against a stable target (a vulnerable webapp pinned in tests). Compare findings (count + CVSS distribution + CWE histogram) vs Strix baseline within agreed tolerance.
- Stress: 3 child agents, parallel tool calls within turn, no JSONL corruption, no message loss.
- After tool server relaxation: `parallel_tool_calls=True`; multi-tool turn fires correctly; sibling failure isolation works.

---

## 7. Rollback, CI, cross-cutting

### 7.1 Branching & cutover

- Branch: `harness-migration` (already created).
- Cutover trigger: Phase 6 acceptance criteria met (golden-output diff within tolerance).
- Pre-cutover: SDK-based path lives behind `STRIX_USE_SDK_HARNESS=1`. Old path unchanged.
- Cutover: flip default to SDK-based; legacy path stays for one release as fallback.
- Removal of legacy: after one release with no rollback signals.

### 7.2 Rollback procedure

If post-cut regression discovered:
1. Set `STRIX_USE_SDK_HARNESS=0` in deployed config (re-uses legacy harness).
2. Investigate via traces/events.jsonl from the failed run.
3. Fix, re-run end-to-end suite, re-cut.

### 7.3 Data compatibility

- `events.jsonl` schema preserved (custom processor emits same `event_type`s).
- `vulnerabilities/vuln_*.json` schema preserved (same Pydantic shape).
- `penetration_test_report.md` schema preserved.
- `notes/notes.jsonl` schema preserved.
- Old runs are still analyzable by new tooling (no migration script needed).

### 7.4 SDK version pinning

- `pyproject.toml`: `openai-agents==0.14.6` (exact pin while we duplicate `_create_container`).
- CI nightly: re-run our Phase 0 spike against SDK `latest`. If green, bump pin and re-test.
- Track upstream PR to add `additional_create_kwargs` hook that would let us drop the body duplication.

### 7.5 CI changes

- New test buckets: `tests/orchestration/`, `tests/sandbox/`, `tests/llm_wrappers/`, `tests/integration/`.
- Snapshot tests for golden outputs (one or two stable targets).
- Mypy strict on new SDK types; install `openai-agents` package types.
- Lint rules for tool decorators (`@strix_tool` not bare `@function_tool` for new tools).

### 7.6 Drop / add deps

- Drop direct: `litellm[proxy]>=1.81.1,<1.82.0` (becomes transitive via `openai-agents[litellm]`).
- Add: `openai-agents[litellm]==0.14.6`.
- Keep: `tenacity`, `pydantic`, `rich`, `docker`, `textual`, `cvss`, `traceloop-sdk`, `opentelemetry-exporter-otlp-proto-http`, `scrubadub`, `defusedxml`.

---

## 8. Phase ordering and day-1 commit list

### Phase ordering (compressed)

- **Phase 0** — Foundations + spikes. Land the 3 wrapper classes, run all Phase 0 smoke tests.
- **Phase 1** — Foundation files (rest), provider layer, `strix_tool`, custom `Session`, custom `TracingProcessor`, `RunConfig` factory.
- **Phase 2** — Tool ports. Sandbox dispatcher first, then all 30+ tools incrementally.
- **Phase 3** — Multi-agent: bus, filter, hooks, six graph tools. End-to-end parallel-children test.
- **Phase 4** — `CaidoCapability` + healthcheck + session cache by scan_id.
- **Phase 5** — TUI / streaming accumulator / run-directory persistence / turn warnings.
- **Phase 6** — Validation + tool server relaxation + parallel tool calls flip.

### Day-1 commits (Phase 0)

In order; each is independent until linked at Phase 0 acceptance.

1. `strix/llm/anthropic_cache_wrapper.py` — `AnthropicCachingLitellmModel`. Tests: cache injection + non-Anthropic passthrough.
2. `strix/runtime/strix_docker_client.py` — `StrixDockerSandboxClient`. Tests: kwarg injection mock + live nmap.
3. `strix/orchestration/bus.py` — `AgentMessageBus`. Tests: concurrency stress + cancel_descendants.
4. `strix/orchestration/filter.py` — `inject_messages_filter`. Tests: FIFO + retry-stable.
5. `strix/orchestration/hooks.py` — `StrixOrchestrationHooks`. Tests: crash detection + warning injection.
6. `strix/tools/_decorator.py` — `strix_tool`. Tests: timeout + sync auto-threading.
7. `strix/llm/multi_provider_setup.py` — `MultiProviderMap` + `StrixModelProvider`. Tests: alias resolution.

### Phase 0 acceptance gate

All seven module unit tests green. The seven Phase 0 smoke tests in §6 green. Tool server concurrent-call test executed; result documented. Only then proceed to Phase 1.

---

*This playbook merges every audit finding into a single engineering reference. When implementation discovers something the playbook missed, treat it as a bug in the playbook — update this file, then write the code.*
