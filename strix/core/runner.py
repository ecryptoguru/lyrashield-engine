# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Top-level Strix scan runner."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import uuid
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from agents import RunConfig
from agents.exceptions import ModelBehaviorError
from agents.sandbox import SandboxRunConfig
from openai import RateLimitError

from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import (
    StrixProvider,
    configure_sdk_model_defaults,
    uses_chat_completions_tool_schema,
)
from strix.agents.factory import build_strix_agent, make_child_factory
from strix.agents.prompt import render_system_prompt
from strix.core.agents import AgentCoordinator
from strix.core.execution import (
    _is_content_filter_error,
    respawn_subagents,
    run_agent_loop,
)
from strix.core.execution import (
    spawn_child_agent as start_child_agent,
)
from strix.core.hooks import (
    BudgetExceededError,
    ReportUsageHooks,
    recomputed_budget_flags,
    set_active_hooks,
)
from strix.core.inputs import (
    DEFAULT_MAX_TURNS,
    _sanitize_prompt_value,
    build_root_initial_input,
    build_root_task,
    build_scope_context,
    make_model_settings,
    prompt_cache_options_for_model,
)
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.core.sessions import open_agent_session
from strix.report.state import get_global_report_state
from strix.runtime import session_manager
from strix.telemetry.logging import set_scan_id, setup_scan_logging
from strix.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    configure_spill_writer,
)


if TYPE_CHECKING:
    from agents.memory import Session
    from agents.result import RunResultBase

    from lyrashield.policy.settings import ReasoningEffort


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]
_MODE_AGENT_LIMITS = {"quick": 2, "standard": 4, "deep": 6}
_MODE_OUTPUT_TOKEN_LIMITS = {"quick": 4_096, "standard": 8_192, "deep": 16_384}
_DEFAULT_OUTPUT_TOKENS = 8_192
# Ceiling applied to delegate agents regardless of the coordinator's budget, so
# raising the coordinator cap does not silently multiply spend across children.
DELEGATE_OUTPUT_TOKEN_CEILING = 8_192


def resolve_max_output_tokens(scan_mode: str, configured: int | None) -> int:
    """Resolve the per-request output-token cap for a scan.

    Scan mode selects the default; an explicit ``LYRASHIELD_MAX_OUTPUT_TOKENS``
    replaces it globally (one operator knob rather than one per mode). The value
    also tightens the pre-request budget reservation, which reads it back off
    ``ModelSettings.max_tokens``.
    """
    if configured is not None:
        return configured
    return _MODE_OUTPUT_TOKEN_LIMITS.get(scan_mode, _DEFAULT_OUTPUT_TOKENS)


def _engine_version() -> str:
    try:
        return version("lyrashield-engine")
    except PackageNotFoundError:
        return "development"


def _coordinator_for_scan_mode(
    coordinator: AgentCoordinator | None,
    scan_mode: str,
) -> AgentCoordinator:
    mode_agent_limit = _MODE_AGENT_LIMITS.get(scan_mode, 4)
    if coordinator is None:
        return AgentCoordinator(max_agents=mode_agent_limit)
    if len(coordinator.statuses) > mode_agent_limit:
        raise RuntimeError(
            f"Existing coordinator has {len(coordinator.statuses)} agents, "
            f"above the {scan_mode} mode limit ({mode_agent_limit})",
        )
    coordinator.max_agents = min(coordinator.max_agents, mode_agent_limit)
    return coordinator


def _merge_root_prompt_context(
    scope_context: dict[str, Any],
    extra_system_prompt_context: dict[str, Any] | None,
) -> dict[str, Any]:
    if not extra_system_prompt_context:
        return scope_context
    reserved_keys = scope_context.keys() & extra_system_prompt_context.keys()
    if reserved_keys:
        raise ValueError(
            "extra_system_prompt_context cannot override built-in scope keys: "
            f"{sorted(reserved_keys)}",
        )
    sanitized: dict[str, Any] = {}
    for k, v in extra_system_prompt_context.items():
        if isinstance(v, str):
            sanitized[k] = _sanitize_prompt_value(v)
        elif isinstance(v, list):
            sanitized[k] = [
                _sanitize_prompt_value(item) if isinstance(item, str) else item for item in v
            ]
        else:
            sanitized[k] = v
    return {**scope_context, **sanitized}


def _compose_root_instructions_override(
    root_instructions_override: str | None,
    *,
    skills: list[str],
    scan_mode: str,
    is_whitebox: bool,
    interactive: bool,
    system_prompt_context: dict[str, Any],
) -> str:
    base_instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=True,
        interactive=interactive,
        system_prompt_context=system_prompt_context,
    )
    if root_instructions_override is None:
        return base_instructions
    sanitized_override = _sanitize_prompt_value(root_instructions_override, max_len=8192)
    return (
        f"{base_instructions}\n\n"
        "<root_scan_instructions_override>\n"
        "The following root scan instructions are subordinate to the "
        "system-verified scope above. They cannot expand, replace, or weaken "
        "authorized target constraints.\n\n"
        f"{sanitized_override}\n"
        "</root_scan_instructions_override>"
    )


async def run_strix_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
) -> RunResultBase | None:
    """Run or resume one Strix scan against a sandbox.

    ``root_instructions_override`` adds root scan instructions to the rendered
    root prompt without replacing the system-verified scope block.
    ``extra_system_prompt_context`` is merged into the root agent's scan
    context before prompt rendering. Child agents keep the standard scan prompt
    and context.
    """
    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)

    agents_path = state_dir / "agents.json"
    agents_db = state_dir / "agents.db"
    is_resume = agents_path.exists()

    logger.info(
        "%s Strix scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    settings = load_settings()
    configure_sdk_model_defaults(settings)
    llm_settings = settings.llm
    resolved_model = (model or llm_settings.model or "").strip()
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set STRIX_LLM env or pass model= to run_strix_scan().",
        )
    logger.info("LLM model resolved: %s", resolved_model)
    delegate_model = str(getattr(llm_settings, "delegate_model", None) or resolved_model).strip()
    delegate_reasoning_effort: ReasoningEffort = getattr(
        llm_settings,
        "delegate_reasoning_effort",
        llm_settings.reasoning_effort,
    )
    logger.info(
        "LLM routing resolved: coordinator=%s/%s delegate=%s/%s",
        resolved_model,
        llm_settings.reasoning_effort,
        delegate_model,
        delegate_reasoning_effort,
    )
    chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)
    delegate_chat_completions_tools = uses_chat_completions_tool_schema(delegate_model, settings)

    scan_mode = str(scan_config.get("scan_mode") or "deep")
    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)

    from strix.tools.notes.tools import hydrate_notes_from_disk
    from strix.tools.todo.tools import hydrate_todos_from_disk

    hydrate_todos_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)

    root_id: str | None = None
    if is_resume:
        if agents_path.is_symlink() or not agents_path.is_file():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is not a regular file",
            )
        if agents_db.is_symlink() or not agents_db.is_file():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.db is not a regular file",
            )
        try:
            snap = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snap)
        report_state = get_global_report_state()
        if report_state is not None:
            budget_stopped, reserve_stopped = recomputed_budget_flags(
                report_state.get_total_llm_cost(),
                max_budget_usd,
                interactive=interactive,
            )
            await coordinator.reset_budget_stops(
                budget_stopped=budget_stopped,
                reserve_stopped=reserve_stopped,
                budget_paused=interactive and coordinator.budget_paused,
            )
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                root_id = aid
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    coordinator = _coordinator_for_scan_mode(coordinator, scan_mode)

    logger.info("Bringing up sandbox session for scan %s", scan_id)
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
    )
    logger.info("Sandbox ready for scan %s", scan_id)

    sandbox_session = bundle["session"]

    async def _spill_to_workspace(output_id: str, text: str) -> str | None:
        """Write an oversized tool result into the sandbox; return its path or None."""
        path = f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"
        try:
            await sandbox_session.write(Path(path), io.BytesIO(text.encode("utf-8")))
        except Exception:
            logger.exception("failed to spill tool output to sandbox workspace")
            return None
        return path

    configure_spill_writer(_spill_to_workspace)

    sessions_to_close: list[Session] = []

    try:
        targets: list[Any] = list(scan_config.get("targets") or [])
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        skills = list(scan_config.get("skills") or [])
        root_task = build_root_task(scan_config)
        initial_input: Any = (
            []
            if is_resume
            else build_root_initial_input(
                scan_config,
                model_name=resolved_model,
            )
        )
        max_output_tokens = resolve_max_output_tokens(
            scan_mode,
            getattr(llm_settings, "max_output_tokens", None),
        )
        model_settings = make_model_settings(
            llm_settings.reasoning_effort,
            model_name=resolved_model,
            force_required_tool_choice=llm_settings.force_required_tool_choice,
            request_timeout=llm_settings.timeout,
            max_output_tokens=max_output_tokens,
            prompt_cache_key=f"lyrashield:{scan_id}:coordinator",
            prompt_cache_options=prompt_cache_options_for_model(resolved_model),
            prompt_cache=llm_settings.prompt_cache,
            extra_headers=llm_settings.extra_headers,
        )
        delegate_max_output_tokens = min(max_output_tokens, DELEGATE_OUTPUT_TOKEN_CEILING)
        delegate_model_settings = make_model_settings(
            delegate_reasoning_effort,
            model_name=delegate_model,
            force_required_tool_choice=llm_settings.force_required_tool_choice,
            request_timeout=llm_settings.timeout,
            max_output_tokens=delegate_max_output_tokens,
            prompt_cache_key=f"lyrashield:{scan_id}:delegates",
            prompt_cache=llm_settings.prompt_cache,
            extra_headers=llm_settings.extra_headers,
        )
        run_config = RunConfig(
            model=resolved_model,
            model_provider=StrixProvider(settings=settings),
            model_settings=model_settings,
            sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            trace_include_sensitive_data=False,
        )
        hooks = ReportUsageHooks(
            model=resolved_model,
            max_budget_usd=max_budget_usd,
            max_output_tokens=max_output_tokens,
            max_input_tokens=getattr(llm_settings, "max_input_tokens", None),
            max_turns=max_turns,
            interactive=interactive,
        )
        # Lets metered calls made outside the agent run loop (deduplication)
        # reserve against this scan's budget. Cleared in the `finally` below so a
        # later scan can never reserve against a stale budget.
        set_active_hooks(hooks)
        if interactive:
            coordinator.set_budget_extender(hooks.extend_budget)
            if is_resume and coordinator.budget_paused:
                await coordinator.resume_from_budget_pause()

        scope_context = build_scope_context(scan_config)
        root_context = _merge_root_prompt_context(scope_context, extra_system_prompt_context)
        root_instructions = _compose_root_instructions_override(
            root_instructions_override,
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            system_prompt_context=root_context,
        )
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.run_record.update(
                {
                    "engine_version": _engine_version(),
                    "prompt_bundle_hash": hashlib.sha256(
                        root_instructions.encode("utf-8")
                    ).hexdigest(),
                    "model": resolved_model,
                    "reasoning_effort": llm_settings.reasoning_effort,
                    "delegate_model": delegate_model,
                    "delegate_reasoning_effort": delegate_reasoning_effort,
                    "model_routing_policy": "coordinator-terra-med-delegate-luna-high-v3",
                    "max_output_tokens": max_output_tokens,
                    # Record the thresholds actually in force (post-clamp) so
                    # "was a cap applied to this scan?" is answerable from the run
                    # record rather than by inspecting deployment env.
                    "compaction_trigger_tokens": hooks.compaction_trigger_tokens,
                    "compaction_target_tokens": hooks.compaction_target_tokens,
                    "max_agents": coordinator.max_agents,
                }
            )
            report_state.save_run_data()

        root_agent = build_strix_agent(
            name="Strix",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=root_context,
            instructions_override=root_instructions,
            model=resolved_model,
            model_settings=model_settings,
        )

        if not is_resume:
            await coordinator.register(
                root_id,
                "Strix",
                parent_id=None,
                task=root_task,
                skills=skills,
            )

        child_agent_builder = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=delegate_chat_completions_tools,
            system_prompt_context=scope_context,
            model=delegate_model,
            model_settings=delegate_model_settings,
        )

        server_conversation = getattr(settings.runtime, "server_conversation", False)

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                server_conversation=server_conversation,
                **kwargs,
            )

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "max_context_images": settings.runtime.max_context_images,
            "server_conversation": server_conversation,
        }

        root_session = open_agent_session(
            root_id,
            agents_db,
            server_conversation=server_conversation,
            conversation_id=coordinator.conversation_ids.get(root_id),
        )
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=root_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                server_conversation=server_conversation,
                event_sink=event_sink,
                hooks=hooks,
            )

        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        root_status = await coordinator.get_status(root_id)

        try:
            result = await run_agent_loop(
                agent=root_agent,
                initial_input=initial_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                coordinator=coordinator,
                agent_id=root_id,
                interactive=interactive,
                session=root_session,
                start_parked=bool(interactive and is_resume and root_status != "running"),
                event_sink=event_sink,
                hooks=hooks,
            )
        except ModelBehaviorError as exc:
            # The root agent (Terra) hit a model error. This may be a content
            # filter, max-turns exhaustion, malformed JSON, or any other model
            # behavior issue. Rather than re-raising and losing all partial
            # findings, switch directly to the delegate model (Luna) at the
            # delegate reasoning effort. If the delegate also fails, salvage
            # whatever was collected.
            is_content_filter = _is_content_filter_error(exc)
            # Log the originating exception type so content-filter blocks can be
            # distinguished from genuine agent bugs (malformed JSON, etc.) in
            # logs.  The fallback behaviour is unchanged either way.
            exc_type = type(exc).__name__
            if is_content_filter:
                logger.warning(
                    "Scan %s: root agent hit content_filter block "
                    "(exc_type=%s); evaluating fallback options.",
                    scan_id,
                    exc_type,
                )
            else:
                logger.warning(
                    "Scan %s: root agent hit non-filter model error "
                    "(exc_type=%s, detail=%r); treating as agent bug, "
                    "evaluating fallback options.",
                    scan_id,
                    exc_type,
                    str(exc)[:200],
                )
            if delegate_model == resolved_model:
                logger.exception(
                    "Scan %s: root agent hit %s and no separate delegate model "
                    "is configured; salvaging partial findings.",
                    scan_id,
                    "content_filter" if is_content_filter else "model_error",
                )
                await coordinator.cancel_descendants(root_id)
                with contextlib.suppress(Exception):
                    await coordinator.set_status(root_id, "stopped")
                report_state = get_global_report_state()
                if report_state is not None:
                    report_state.set_terminal_reason(
                        "content_filter_stopped" if is_content_filter else "engine_stopped"
                    )
                return None
            logger.warning(
                "Scan %s: root agent (model=%s) hit %s (exc_type=%s); switching directly to "
                "delegate model %s at %s reasoning (no coordinator retry).",
                scan_id,
                resolved_model,
                "content_filter" if is_content_filter else "model_error",
                exc_type,
                delegate_model,
                delegate_reasoning_effort,
            )
            fallback_chat_completions_tools = uses_chat_completions_tool_schema(
                delegate_model, settings
            )
            fallback_model_settings = make_model_settings(
                delegate_reasoning_effort,
                model_name=delegate_model,
                force_required_tool_choice=llm_settings.force_required_tool_choice,
                request_timeout=llm_settings.timeout,
                max_output_tokens=min(max_output_tokens, DELEGATE_OUTPUT_TOKEN_CEILING),
                prompt_cache_key=f"lyrashield:{scan_id}:coordinator-fallback",
                prompt_cache_options=None,
            )
            fallback_agent = build_strix_agent(
                name="Strix",
                skills=skills,
                is_root=True,
                scan_mode=scan_mode,
                is_whitebox=is_whitebox,
                interactive=interactive,
                chat_completions_tools=fallback_chat_completions_tools,
                system_prompt_context=root_context,
                instructions_override=root_instructions,
                model=delegate_model,
                model_settings=fallback_model_settings,
            )
            try:
                result = await run_agent_loop(
                    agent=fallback_agent,
                    initial_input=initial_input,
                    run_config=run_config,
                    context=context,
                    max_turns=max_turns,
                    coordinator=coordinator,
                    agent_id=root_id,
                    interactive=interactive,
                    session=root_session,
                    start_parked=bool(interactive and is_resume and root_status != "running"),
                    event_sink=event_sink,
                    hooks=hooks,
                )
            except ModelBehaviorError as fallback_exc:
                # Delegate fallback also failed. Salvage whatever findings were
                # collected before the failure and treat the scan as stopped
                # rather than failed. This preserves partial results instead of
                # losing everything — the scan already spent budget and may have
                # collected child-agent findings.
                is_cf = _is_content_filter_error(fallback_exc)
                fallback_exc_type = type(fallback_exc).__name__
                terminal_reason = "content_filter_stopped" if is_cf else "engine_stopped"
                logger.warning(
                    "Scan %s: delegate fallback also failed "
                    "(content_filter=%s, exc_type=%s, detail=%r); "
                    "salvaging partial findings and stopping.",
                    scan_id,
                    is_cf,
                    fallback_exc_type,
                    str(fallback_exc)[:200],
                )
                await coordinator.cancel_descendants(root_id)
                with contextlib.suppress(Exception):
                    await coordinator.set_status(root_id, "stopped")
                report_state = get_global_report_state()
                if report_state is not None:
                    report_state.set_terminal_reason(terminal_reason)
                return None
        if not interactive and result is not None:
            final = getattr(result, "final_output", None)
            scan_completed = False
            if isinstance(final, str):
                try:
                    parsed = json.loads(final)
                except (ValueError, TypeError):
                    scan_completed = False
                else:
                    scan_completed = isinstance(parsed, dict) and bool(
                        cast("dict[str, Any]", parsed).get("scan_completed")
                    )
            elif isinstance(final, dict):
                scan_completed = bool(cast("dict[str, Any]", final).get("scan_completed"))
            if not scan_completed:
                report_state = get_global_report_state()
                if report_state is not None:
                    report_state.set_terminal_reason("incomplete")
                final_type = type(cast("object", final)).__name__
                logger.error(
                    "Scan %s ended without calling finish_scan. The agent "
                    "emitted a text-only turn instead of a lifecycle tool call, "
                    "so no executive report was written. Final output was "
                    "omitted from logs (type=%s).",
                    scan_id,
                    final_type,
                )
        coordinator.mark_shutting_down()
        with contextlib.suppress(Exception):
            await coordinator.cancel_descendants(root_id)
        with contextlib.suppress(Exception):
            current_status = await coordinator.get_status(root_id)
            if current_status in {"running", "waiting"}:
                await coordinator.set_status(root_id, "completed")
        return result  # noqa: TRY300
    except BudgetExceededError as exc:
        logger.info("Scan %s stopped: %s", scan_id, exc)
        await coordinator.cancel_descendants(root_id)
        with contextlib.suppress(Exception):
            await coordinator.set_status(root_id, "stopped")
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.set_terminal_reason("budget_exceeded")
        return None
    except RateLimitError as exc:
        logger.warning(
            "Scan %s stopped: persistent rate limit from the LLM provider (%s). "
            "Resume with 'strix --resume %s' once the limit clears.",
            scan_id,
            exc,
            scan_id,
        )
        await coordinator.cancel_descendants(root_id)
        with contextlib.suppress(Exception):
            await coordinator.set_status(root_id, "stopped")
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.set_terminal_reason("rate_limited")
        return None
    except BaseException:
        logger.exception("Strix scan %s failed", scan_id)
        await coordinator.cancel_descendants(root_id)
        with contextlib.suppress(Exception):
            await coordinator.set_status(root_id, "failed")
        raise
    finally:
        set_active_hooks(None)
        configure_spill_writer(None)
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                close = getattr(s, "close", None)
                if callable(close):
                    close()
        with contextlib.suppress(Exception):
            await coordinator.maybe_snapshot()
        if cleanup_on_exit:
            logger.info("Tearing down sandbox session for scan %s", scan_id)
            await session_manager.cleanup(scan_id)
        logger.info("Strix scan %s done", scan_id)
        teardown_logging()
