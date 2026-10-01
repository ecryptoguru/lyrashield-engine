# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Top-level Strix scan runner."""

from __future__ import annotations

import contextlib
import hashlib
import io
import logging
import uuid
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any

from openai import RateLimitError

from lyrashield.agents.factory import build_strix_agent, make_child_factory
from lyrashield.agents.prompt import render_system_prompt
from lyrashield.artifacts import evidence as _evidence
from lyrashield.artifacts.state import get_global_report_state
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.execution import (
    _is_content_filter_error,
    _is_output_token_truncation,
    respawn_subagents,
    run_agent_loop,
)
from lyrashield.lifecycle.execution import (
    spawn_child_agent as start_child_agent,
)
from lyrashield.lifecycle.fallback import FallbackServices, run_root_agent
from lyrashield.lifecycle.finalize import (
    FinalizeServices,
    cleanup_scan_resources,
    finish_scan_result,
)
from lyrashield.lifecycle.hooks import (
    BudgetExceededError,
    ReportUsageHooks,
    recomputed_budget_flags,
    set_active_hooks,
)
from lyrashield.lifecycle.inputs import (
    DEFAULT_MAX_TURNS,
    _sanitize_prompt_value,
    build_root_initial_input,
    build_root_task,
    build_scan_targets,
    build_scope_context,
    make_model_settings,
    prompt_cache_options_for_model,
    prompt_cache_routing_enabled,
)
from lyrashield.lifecycle.restore import restore_coordinator
from lyrashield.lifecycle.root_agent import RootAgentServices, build_root_runtime
from lyrashield.lifecycle.sandbox_bringup import bring_up_sandbox
from lyrashield.lifecycle.scan_context import create_scan_paths, resolve_scan_context
from lyrashield.lifecycle.sessions import open_agent_session
from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import (
    StrixProvider,
    configure_sdk_model_defaults,
    uses_chat_completions_tool_schema,
)
from lyrashield.runtime import session_manager
from lyrashield.telemetry.logging import set_scan_id, setup_scan_logging
from lyrashield.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    configure_spill_writer,
)
from strix.core.paths import run_dir_for, runtime_state_dir


if TYPE_CHECKING:
    from agents.memory import Session
    from agents.result import RunResultBase

    from lyrashield.policy.settings import ReasoningEffort


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]
_MODE_OUTPUT_TOKEN_LIMITS = {"quick": 4_096, "standard": 8_192, "deep": 16_384}
_DEFAULT_OUTPUT_TOKENS = 8_192
# Ceiling applied to delegate agents regardless of the coordinator's budget, so
# raising the coordinator cap does not silently multiply spend across children.
DELEGATE_OUTPUT_TOKEN_CEILING = 8_192


def _model_routing_policy(
    coordinator_model: str,
    coordinator_effort: ReasoningEffort,
    delegate_model: str,
    delegate_effort: ReasoningEffort,
) -> str:
    """Return a receipt label derived from the route that actually ran."""
    return (
        f"coordinator={coordinator_model}@{coordinator_effort};"
        f"delegate={delegate_model}@{delegate_effort};v=1"
    )


def _stable_prompt_cache_key(role: str, material: str, scan_id: str) -> str:
    """Route repeated turns together without sharing private cache across scans."""
    fingerprint = hashlib.sha256(f"{scan_id}\0{material}".encode()).hexdigest()
    # Azure Responses accepts at most 64 characters. The longest current role
    # ("coordinator") leaves 38 hexadecimal characters: 152 bits of routing
    # entropy, while retaining a recognizable product/version prefix.
    return f"lyrashield:v2:{role}:{fingerprint[:38]}"


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
    attachments: list[dict[str, Any]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    resume: bool = False,
    cleanup_on_exit: bool = True,
    artifact_state: Any | None = None,
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

    paths = create_scan_paths(
        scan_id=scan_id,
        resume=resume,
        run_dir_for=run_dir_for,
        runtime_state_dir=runtime_state_dir,
        setup_scan_logging=setup_scan_logging,
        set_scan_id=set_scan_id,
    )
    run_dir = paths.run_dir
    state_dir = paths.state_dir
    agents_path = paths.agents_path
    agents_db = paths.agents_db
    is_resume = paths.is_resume

    logger.info(
        "%s LyraShield scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    context = resolve_scan_context(
        paths=paths,
        scan_config=scan_config,
        model=model,
        load_settings=load_settings,
        configure_sdk_model_defaults=configure_sdk_model_defaults,
        uses_chat_completions_tool_schema=uses_chat_completions_tool_schema,
    )
    llm_settings = context.llm_settings
    resolved_model = context.resolved_model
    delegate_model = context.delegate_model
    delegate_reasoning_effort = context.delegate_reasoning_effort
    scan_mode = context.scan_mode
    logger.info("LLM model resolved: %s", resolved_model)
    logger.info(
        "LLM routing resolved: coordinator=%s/%s delegate=%s/%s",
        resolved_model,
        llm_settings.reasoning_effort,
        delegate_model,
        delegate_reasoning_effort,
    )
    coordinator, root_id = await restore_coordinator(
        coordinator=coordinator,
        coordinator_factory=AgentCoordinator,
        scan_mode=scan_mode,
        state_dir=state_dir,
        agents_path=agents_path,
        agents_db=agents_db,
        scan_id=scan_id,
        is_resume=is_resume,
        max_budget_usd=max_budget_usd,
        interactive=interactive,
        report_state_getter=get_global_report_state,
        recomputed_budget_flags=recomputed_budget_flags,
    )

    bundle = await bring_up_sandbox(
        scan_id=scan_id,
        image=image,
        local_sources=local_sources,
        attachments=attachments,
        scan_config=scan_config,
        create_or_reuse=session_manager.create_or_reuse,
        report_state_getter=get_global_report_state,
    )

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
    finalizer = FinalizeServices(
        get_global_report_state=get_global_report_state,
        record_supports_evidence=_evidence.record_supports_evidence_v1_1,
        export_http_exchange_evidence=_evidence.export_http_exchange_evidence,
        set_active_hooks=set_active_hooks,
        configure_spill_writer=configure_spill_writer,
        cleanup_sandbox=session_manager.cleanup,
    )

    try:
        root_runtime = await build_root_runtime(
            scan_context=context,
            coordinator=coordinator,
            bundle=bundle,
            scan_config=scan_config,
            scan_id=scan_id,
            max_turns=max_turns,
            max_budget_usd=max_budget_usd,
            interactive=interactive,
            is_resume=is_resume,
            event_sink=event_sink,
            root_id=root_id,
            sessions_to_close=sessions_to_close,
            root_instructions_override=root_instructions_override,
            extra_system_prompt_context=extra_system_prompt_context,
            services=RootAgentServices(
                build_root_task=build_root_task,
                build_scope_context=build_scope_context,
                merge_root_prompt_context=_merge_root_prompt_context,
                compose_root_instructions_override=_compose_root_instructions_override,
                resolve_max_output_tokens=resolve_max_output_tokens,
                prompt_cache_options_for_model=prompt_cache_options_for_model,
                prompt_cache_routing_enabled=prompt_cache_routing_enabled,
                stable_prompt_cache_key=_stable_prompt_cache_key,
                build_root_initial_input=build_root_initial_input,
                make_model_settings=make_model_settings,
                build_strix_agent=build_strix_agent,
                make_child_factory=make_child_factory,
                open_agent_session=open_agent_session,
                start_child_agent=start_child_agent,
                respawn_subagents=respawn_subagents,
                set_active_hooks=set_active_hooks,
                usage_hooks_factory=ReportUsageHooks,
                engine_version=_engine_version,
                model_routing_policy=_model_routing_policy,
                report_state_getter=get_global_report_state,
                model_provider_factory=lambda provider_settings: StrixProvider(
                    settings=provider_settings,
                ),
                build_scan_targets=build_scan_targets,
                delegate_output_token_ceiling=DELEGATE_OUTPUT_TOKEN_CEILING,
            ),
        )
        result = await run_root_agent(
            runtime=root_runtime,
            coordinator=coordinator,
            scan_id=scan_id,
            max_turns=max_turns,
            interactive=interactive,
            is_resume=is_resume,
            event_sink=event_sink,
            services=FallbackServices(
                run_agent_loop=run_agent_loop,
                is_output_token_truncation=_is_output_token_truncation,
                is_content_filter_error=_is_content_filter_error,
                uses_chat_completions_tool_schema=uses_chat_completions_tool_schema,
                make_model_settings=make_model_settings,
                stable_prompt_cache_key=_stable_prompt_cache_key,
                build_strix_agent=build_strix_agent,
                report_state_getter=get_global_report_state,
                delegate_output_token_ceiling=DELEGATE_OUTPUT_TOKEN_CEILING,
            ),
        )
        return await finish_scan_result(
            result=result,
            interactive=interactive,
            scan_id=scan_id,
            coordinator=coordinator,
            root_id=root_id,
            services=finalizer,
        )
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
            "Resume with 'lyrashield --resume %s' once the limit clears.",
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
        logger.exception("LyraShield scan %s failed", scan_id)
        await coordinator.cancel_descendants(root_id)
        with contextlib.suppress(Exception):
            await coordinator.set_status(root_id, "failed")
        raise
    finally:
        await cleanup_scan_resources(
            scan_id=scan_id,
            sessions_to_close=sessions_to_close,
            coordinator=coordinator,
            artifact_state=artifact_state,
            bundle=bundle,
            cleanup_on_exit=cleanup_on_exit,
            paths=paths,
            services=finalizer,
        )
