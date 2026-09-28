# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Construct scan-scoped root/delegate agents and their runtime context."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, cast

from agents import RunConfig
from agents.sandbox import SandboxRunConfig


if TYPE_CHECKING:
    from collections.abc import Callable

    from lyrashield.lifecycle.scan_context import ScanContext


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RootAgentServices:
    build_root_task: Callable[..., Any]
    build_scope_context: Callable[..., Any]
    merge_root_prompt_context: Callable[..., Any]
    compose_root_instructions_override: Callable[..., Any]
    resolve_max_output_tokens: Callable[..., Any]
    prompt_cache_options_for_model: Callable[..., Any]
    prompt_cache_routing_enabled: Callable[..., Any]
    stable_prompt_cache_key: Callable[..., Any]
    build_root_initial_input: Callable[..., Any]
    make_model_settings: Callable[..., Any]
    build_strix_agent: Callable[..., Any]
    make_child_factory: Callable[..., Any]
    open_agent_session: Callable[..., Any]
    start_child_agent: Callable[..., Any]
    respawn_subagents: Callable[..., Any]
    set_active_hooks: Callable[..., Any]
    usage_hooks_factory: Callable[..., Any]
    engine_version: Callable[..., Any]
    model_routing_policy: Callable[..., Any]
    report_state_getter: Callable[..., Any]
    model_provider_factory: Callable[..., Any]
    build_scan_targets: Callable[..., Any]
    delegate_output_token_ceiling: int


@dataclass(slots=True)
class RootRuntime:
    scan_context: ScanContext
    root_id: str
    root_agent: Any
    initial_input: Any
    run_config: RunConfig
    delegate_run_config: RunConfig
    hooks: Any
    context: dict[str, Any]
    root_session: Any
    sessions_to_close: list[Any]
    root_instructions: str
    root_context: dict[str, Any]
    scope_context: dict[str, Any]
    skills: list[str]
    is_whitebox: bool
    cache_enabled: bool
    root_cache_options: Any
    delegate_cache_options: Any
    root_routing: bool
    delegate_routing: bool
    max_output_tokens: int
    model_request_timeout: float
    bounded_runtime: bool
    root_status: str | None


async def build_root_runtime(
    *,
    scan_context: ScanContext,
    coordinator: Any,
    bundle: dict[str, Any],
    scan_config: dict[str, Any],
    scan_id: str,
    max_turns: int,
    max_budget_usd: float | None,
    interactive: bool,
    is_resume: bool,
    event_sink: Any,
    root_id: str,
    sessions_to_close: list[Any],
    root_instructions_override: str | None,
    extra_system_prompt_context: dict[str, Any] | None,
    services: RootAgentServices,
) -> RootRuntime:
    """Build coordinator and delegate configuration while preserving run contracts."""
    settings = scan_context.settings
    llm_settings = scan_context.llm_settings
    resolved_model = scan_context.resolved_model
    delegate_model = scan_context.delegate_model
    delegate_reasoning_effort = scan_context.delegate_reasoning_effort
    scan_mode = scan_context.scan_mode
    targets: list[Any] = list(scan_config.get("targets") or [])
    is_whitebox = any(target.get("type") == "local_code" for target in targets)
    skills = list(scan_config.get("skills") or [])
    root_task = services.build_root_task(scan_config)
    scope_context = services.build_scope_context(scan_config)
    root_context = services.merge_root_prompt_context(scope_context, extra_system_prompt_context)
    root_instructions = services.compose_root_instructions_override(
        root_instructions_override,
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        interactive=interactive,
        system_prompt_context=root_context,
    )
    cache_enabled = bool(llm_settings.prompt_cache)
    root_cache_options = (
        services.prompt_cache_options_for_model(resolved_model) if cache_enabled else None
    )
    delegate_cache_options = (
        services.prompt_cache_options_for_model(delegate_model) if cache_enabled else None
    )
    # Stable routing keys are decoupled from explicit cache options: when
    # routing is enabled for an approved model, each role gets a stable key.
    root_routing = cache_enabled and services.prompt_cache_routing_enabled(resolved_model)
    delegate_routing = cache_enabled and services.prompt_cache_routing_enabled(delegate_model)
    initial_input: Any = (
        []
        if is_resume
        else services.build_root_initial_input(
            scan_config,
            model_name=resolved_model if root_cache_options else None,
        )
    )
    max_output_tokens = services.resolve_max_output_tokens(
        scan_mode,
        getattr(llm_settings, "max_output_tokens", None),
    )
    bounded_runtime = not interactive and coordinator.run_deadline is not None
    model_request_timeout = (
        min(llm_settings.timeout, 90 if scan_mode == "deep" else 60)
        if bounded_runtime
        else llm_settings.timeout
    )
    model_settings = services.make_model_settings(
        llm_settings.reasoning_effort,
        model_name=resolved_model,
        force_required_tool_choice=llm_settings.force_required_tool_choice,
        request_timeout=model_request_timeout,
        bounded_runtime=bounded_runtime,
        max_output_tokens=max_output_tokens,
        prompt_cache_key=(
            services.stable_prompt_cache_key(
                "coordinator",
                json.dumps(
                    {"model": resolved_model, "instructions": root_instructions},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                scan_id,
            )
            if root_routing
            else None
        ),
        prompt_cache_options=root_cache_options,
        extra_headers=llm_settings.extra_headers,
    )
    delegate_max_output_tokens = min(
        max_output_tokens,
        services.delegate_output_token_ceiling,
    )
    delegate_cache_material = json.dumps(
        {
            "model": delegate_model,
            "scan_mode": scan_mode,
            "is_whitebox": is_whitebox,
            "interactive": interactive,
            "scope_context": scope_context,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    delegate_model_settings = services.make_model_settings(
        delegate_reasoning_effort,
        model_name=delegate_model,
        force_required_tool_choice=llm_settings.force_required_tool_choice,
        request_timeout=model_request_timeout,
        bounded_runtime=bounded_runtime,
        max_output_tokens=delegate_max_output_tokens,
        prompt_cache_key=(
            services.stable_prompt_cache_key("delegates", delegate_cache_material, scan_id)
            if delegate_routing
            else None
        ),
        prompt_cache_options=delegate_cache_options,
        extra_headers=llm_settings.extra_headers,
    )
    run_config = RunConfig(
        model=resolved_model,
        model_provider=services.model_provider_factory(settings),
        model_settings=model_settings,
        sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
        trace_include_sensitive_data=False,
    )
    delegate_run_config = replace(
        run_config,
        model=delegate_model,
        model_settings=delegate_model_settings,
    )
    hooks = services.usage_hooks_factory(
        model=resolved_model,
        max_budget_usd=max_budget_usd,
        max_output_tokens=max_output_tokens,
        max_input_tokens=getattr(llm_settings, "max_input_tokens", None),
        max_turns=max_turns,
        interactive=interactive,
    )
    # Metered calls outside the agent loop (such as dedupe) reserve against
    # this scan, and the finally block clears the scan-scoped hooks.
    services.set_active_hooks(hooks)
    if interactive:
        coordinator.set_budget_extender(hooks.extend_budget)

    report_state = services.report_state_getter()
    if report_state is not None:
        report_state.run_record.update(
            {
                "engine_version": services.engine_version(),
                "prompt_bundle_hash": hashlib.sha256(root_instructions.encode("utf-8")).hexdigest(),
                "prompt_cache": {
                    "enabled": cache_enabled,
                    "routing_enabled": root_routing,
                    "routing": "stable-prompt-v2" if root_routing else None,
                    "mode": (
                        "explicit" if root_cache_options else "implicit" if cache_enabled else None
                    ),
                    "ttl": root_cache_options["ttl"] if root_cache_options else None,
                },
                "model": resolved_model,
                "reasoning_effort": llm_settings.reasoning_effort,
                "delegate_model": delegate_model,
                "delegate_reasoning_effort": delegate_reasoning_effort,
                "model_routing_policy": services.model_routing_policy(
                    resolved_model,
                    llm_settings.reasoning_effort,
                    delegate_model,
                    delegate_reasoning_effort,
                ),
                "max_output_tokens": max_output_tokens,
                "compaction_trigger_tokens": hooks.compaction_trigger_tokens,
                "compaction_target_tokens": hooks.compaction_target_tokens,
                "max_agents": coordinator.max_agents,
            }
        )
        report_state.save_run_data()

    root_agent = services.build_strix_agent(
        name="LyraShield",
        skills=skills,
        is_root=True,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        interactive=interactive,
        chat_completions_tools=scan_context.chat_completions_tools,
        system_prompt_context=root_context,
        instructions_override=root_instructions,
        model=resolved_model,
        model_settings=model_settings,
    )
    if not is_resume:
        await coordinator.register(
            root_id,
            "LyraShield",
            parent_id=None,
            task=root_task,
            skills=skills,
        )

    child_agent_builder = services.make_child_factory(
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        interactive=interactive,
        chat_completions_tools=scan_context.delegate_chat_completions_tools,
        system_prompt_context=scope_context,
        model=delegate_model,
        model_settings=delegate_model_settings,
    )
    server_conversation = getattr(settings.runtime, "server_conversation", False)

    async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await services.start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=scan_context.paths.agents_db,
                sessions_to_close=sessions_to_close,
                run_config=delegate_run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                server_conversation=server_conversation,
                model_name=delegate_model if delegate_cache_options else None,
                **kwargs,
            ),
        )

    root_runtime_context: dict[str, Any] = {
        "coordinator": coordinator,
        "sandbox_session": bundle["session"],
        "caido_client": bundle["caido_client"],
        "agent_id": root_id,
        "parent_id": None,
        "interactive": interactive,
        "spawn_child_agent": spawn_child_agent,
        "scan_targets": services.build_scan_targets(scan_config),
        "max_context_images": settings.runtime.max_context_images,
        "server_conversation": server_conversation,
    }
    root_session = services.open_agent_session(
        root_id,
        scan_context.paths.agents_db,
        server_conversation=server_conversation,
        conversation_id=coordinator.conversation_ids.get(root_id),
    )
    sessions_to_close.append(root_session)
    await coordinator.attach_runtime(root_id, session=root_session)

    if is_resume:
        await services.respawn_subagents(
            coordinator=coordinator,
            factory=child_agent_builder,
            agents_db_path=scan_context.paths.agents_db,
            sessions_to_close=sessions_to_close,
            run_config=delegate_run_config,
            max_turns=max_turns,
            interactive=interactive,
            parent_ctx=root_runtime_context,
            root_id=root_id,
            server_conversation=server_conversation,
            event_sink=event_sink,
            hooks=hooks,
        )

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
    return RootRuntime(
        scan_context=scan_context,
        root_id=root_id,
        root_agent=root_agent,
        initial_input=initial_input,
        run_config=run_config,
        delegate_run_config=delegate_run_config,
        hooks=hooks,
        context=root_runtime_context,
        root_session=root_session,
        sessions_to_close=sessions_to_close,
        root_instructions=root_instructions,
        root_context=root_context,
        scope_context=scope_context,
        skills=skills,
        is_whitebox=is_whitebox,
        cache_enabled=cache_enabled,
        root_cache_options=root_cache_options,
        delegate_cache_options=delegate_cache_options,
        root_routing=root_routing,
        delegate_routing=delegate_routing,
        max_output_tokens=max_output_tokens,
        model_request_timeout=model_request_timeout,
        bounded_runtime=bounded_runtime,
        root_status=root_status,
    )
