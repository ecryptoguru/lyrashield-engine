# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Run the root agent and preserve partial findings across model failures."""

from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from agents.exceptions import ModelBehaviorError

from lyrashield.policy.models import is_bounded_stream_timeout


if TYPE_CHECKING:
    from collections.abc import Callable

    from lyrashield.lifecycle.root_agent import RootRuntime


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FallbackServices:
    run_agent_loop: Callable[..., Any]
    is_output_token_truncation: Callable[[BaseException], bool]
    is_content_filter_error: Callable[[BaseException], bool]
    uses_chat_completions_tool_schema: Callable[[str, Any], bool]
    make_model_settings: Callable[..., Any]
    stable_prompt_cache_key: Callable[..., str]
    build_strix_agent: Callable[..., Any]
    report_state_getter: Callable[[], Any | None]
    delegate_output_token_ceiling: int


async def _salvage_bounded_stream_timeout(
    *,
    runtime: RootRuntime,
    coordinator: Any,
    scan_id: str,
    exc: BaseException,
    services: FallbackServices,
) -> None:
    """Settle a bounded stream-idle/provider timeout like a model-behavior stop.

    The inherited stream guard raises ``TimeoutError``; without this route a
    root turn that went silent past its configured bound failed the whole scan
    even when findings were already filed. Cancel descendants, mark the root
    stopped, and record the existing engine-stopped terminal reason so the
    reader keeps the incomplete/PARTIAL contract. The stream is already closed
    by the guard and no new model call is made here.
    """
    logger.warning(
        "Scan %s: root model stream hit its configured idle/provider timeout "
        "(exc_type=%s); salvaging partial findings.",
        scan_id,
        type(exc).__name__,
    )
    await coordinator.cancel_descendants(runtime.root_id)
    with contextlib.suppress(Exception):
        await coordinator.set_status(runtime.root_id, "stopped")
    report_state = services.report_state_getter()
    if report_state is not None:
        report_state.set_terminal_reason("engine_stopped")


async def run_root_agent(
    *,
    runtime: RootRuntime,
    coordinator: Any,
    scan_id: str,
    max_turns: int,
    interactive: bool,
    is_resume: bool,
    event_sink: Any,
    services: FallbackServices,
) -> Any | None:
    """Run the primary model and, for model-behavior errors, one delegate fallback."""
    scan_context = runtime.scan_context
    settings = scan_context.settings
    llm_settings = scan_context.llm_settings
    resolved_model = scan_context.resolved_model
    delegate_model = scan_context.delegate_model
    delegate_reasoning_effort = scan_context.delegate_reasoning_effort
    result: Any | None
    try:
        result = await services.run_agent_loop(
            agent=runtime.root_agent,
            initial_input=runtime.initial_input,
            run_config=runtime.run_config,
            context=runtime.context,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=runtime.root_id,
            interactive=interactive,
            session=runtime.root_session,
            start_parked=bool(interactive and is_resume and runtime.root_status != "running"),
            event_sink=event_sink,
            hooks=runtime.hooks,
        )
    except ModelBehaviorError as exc:
        if services.is_output_token_truncation(exc):
            # Output exhaustion is a budget boundary, not evidence that a
            # different model should retry the same investigation.
            logger.warning(
                "Scan %s: root output-token limit reached; preserving partial findings.",
                scan_id,
            )
            await coordinator.cancel_descendants(runtime.root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(runtime.root_id, "stopped")
            report_state = services.report_state_getter()
            if report_state is not None:
                report_state.set_terminal_reason("engine_stopped")
            return None
        # The root agent hit a model error. Switch directly to the delegate
        # model; retrying the coordinator would repeat the same failure.
        is_content_filter = services.is_content_filter_error(exc)
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
            await coordinator.cancel_descendants(runtime.root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(runtime.root_id, "stopped")
            report_state = services.report_state_getter()
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
        fallback_chat_completions_tools = services.uses_chat_completions_tool_schema(
            delegate_model,
            settings,
        )
        fallback_model_settings = services.make_model_settings(
            delegate_reasoning_effort,
            model_name=delegate_model,
            force_required_tool_choice=llm_settings.force_required_tool_choice,
            request_timeout=runtime.model_request_timeout,
            bounded_runtime=runtime.bounded_runtime,
            max_output_tokens=min(
                runtime.max_output_tokens,
                services.delegate_output_token_ceiling,
            ),
            prompt_cache_key=(
                services.stable_prompt_cache_key(
                    "fallback",
                    json.dumps(
                        {"model": delegate_model, "instructions": runtime.root_instructions},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    scan_id,
                )
                if runtime.delegate_routing
                else None
            ),
            prompt_cache_options=runtime.delegate_cache_options,
            extra_headers=llm_settings.extra_headers,
        )
        fallback_agent = services.build_strix_agent(
            name="LyraShield",
            skills=runtime.skills,
            is_root=True,
            scan_mode=scan_context.scan_mode,
            is_whitebox=runtime.is_whitebox,
            interactive=interactive,
            chat_completions_tools=fallback_chat_completions_tools,
            system_prompt_context=runtime.root_context,
            instructions_override=runtime.root_instructions,
            model=delegate_model,
            model_settings=fallback_model_settings,
        )
        fallback_run_config = replace(
            runtime.run_config,
            model=delegate_model,
            model_settings=fallback_model_settings,
        )
        try:
            result = await services.run_agent_loop(
                agent=fallback_agent,
                initial_input=[],
                run_config=fallback_run_config,
                context=runtime.context,
                max_turns=max_turns,
                coordinator=coordinator,
                agent_id=runtime.root_id,
                interactive=interactive,
                session=runtime.root_session,
                start_parked=bool(interactive and is_resume and runtime.root_status != "running"),
                event_sink=event_sink,
                hooks=runtime.hooks,
            )
        except ModelBehaviorError as fallback_exc:
            is_cf = services.is_content_filter_error(fallback_exc)
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
            await coordinator.cancel_descendants(runtime.root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(runtime.root_id, "stopped")
            report_state = services.report_state_getter()
            if report_state is not None:
                report_state.set_terminal_reason(terminal_reason)
            return None
        except Exception as fallback_exc:
            if not is_bounded_stream_timeout(fallback_exc):
                raise
            await _salvage_bounded_stream_timeout(
                runtime=runtime,
                coordinator=coordinator,
                scan_id=scan_id,
                exc=fallback_exc,
                services=services,
            )
            return None
    except Exception as exc:
        # A bounded stream-idle/provider timeout is a configured boundary, not
        # a crash: salvage partial findings instead of failing the scan.
        # Unrelated internal timeouts, programming errors, auth errors and
        # invalid artifacts re-raise unchanged.
        if not is_bounded_stream_timeout(exc):
            raise
        await _salvage_bounded_stream_timeout(
            runtime=runtime,
            coordinator=coordinator,
            scan_id=scan_id,
            exc=exc,
            services=services,
        )
        return None
    return result
