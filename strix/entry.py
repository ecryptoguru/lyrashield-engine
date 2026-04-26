"""Top-level scan entry point.

1. Build the per-scan ``AgentMessageBus``.
2. Bring up (or reuse) a sandbox session for ``scan_id`` via the
   :mod:`strix.runtime.session_manager`.
3. Build the root ``Agent`` via :func:`build_strix_agent` and a
   matching child factory via :func:`make_child_factory`.
4. Build the root context dict (bus + sandbox bundle + agent_factory).
5. Register the root in the bus.
6. Build the ``RunConfig`` via the factory.
7. Call ``Runner.run(...)`` and surface the result.
8. ``finally`` cleanup the sandbox session — even on cancel, the bus
   propagates ``cancel_descendants`` to every spawned child task.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from agents.memory import SQLiteSession

from strix.agents.factory import build_strix_agent, make_child_factory
from strix.config import load_settings
from strix.orchestration.bus import AgentMessageBus
from strix.orchestration.hooks import StrixOrchestrationHooks
from strix.orchestration.run_loop import run_with_continuation
from strix.run_config_factory import (
    STRIX_DEFAULT_MAX_TURNS,
    make_agent_context,
    make_run_config,
)
from strix.runtime import session_manager


if TYPE_CHECKING:
    from agents.result import RunResultBase


logger = logging.getLogger(__name__)


def _build_root_task(scan_config: dict[str, Any]) -> str:
    """Format the user-facing task for the root agent.

    Collects each target type into a labelled section, appends
    diff-scope context if active, and tacks on user_instructions. The
    structured section headers are referenced by the system prompt
    template, so the shape matters for prompt parity.
    """
    targets = scan_config.get("targets", []) or []
    diff_scope = scan_config.get("diff_scope") or {}
    user_instructions = scan_config.get("user_instructions", "") or ""

    repos: list[str] = []
    locals_: list[str] = []
    urls: list[str] = []
    ips: list[str] = []

    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype == "repository":
            url = details.get("target_repo", "")
            cloned = details.get("cloned_repo_path")
            repos.append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = details.get("target_path", "unknown")
            locals_.append(f"- {path} (available at: {workspace_path})")
        elif ttype == "web_application":
            urls.append(f"- {details.get('target_url', '')}")
        elif ttype == "ip_address":
            ips.append(f"- {details.get('target_ip', '')}")

    parts: list[str] = []
    if repos:
        parts.append("\n\nRepositories:")
        parts.extend(repos)
    if locals_:
        parts.append("\n\nLocal Codebases:")
        parts.extend(locals_)
    if urls:
        parts.append("\n\nURLs:")
        parts.extend(urls)
    if ips:
        parts.append("\n\nIP Addresses:")
        parts.extend(ips)

    if diff_scope.get("active"):
        parts.append("\n\nScope Constraints:")
        parts.append(
            "- Pull request diff-scope mode is active. Prioritize changed files "
            "and use other files only for context.",
        )
        for repo_scope in diff_scope.get("repos", []) or []:
            label = (
                repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
            )
            changed = repo_scope.get("analyzable_files_count", 0)
            deleted = repo_scope.get("deleted_files_count", 0)
            parts.append(f"- {label}: {changed} changed file(s) in primary scope")
            if deleted:
                parts.append(f"- {label}: {deleted} deleted file(s) are context-only")

    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"
    return task


def _build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    """Produce the system_prompt_context block used by the prompt template.

    The prompt template's ``system_prompt_context.authorized_targets``
    lookups expect this exact shape.
    """
    authorized: list[dict[str, str]] = []
    for target in scan_config.get("targets", []) or []:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}

        if ttype == "repository":
            value = details.get("target_repo", "")
        elif ttype == "local_code":
            value = details.get("target_path", "")
        elif ttype == "web_application":
            value = details.get("target_url", "")
        elif ttype == "ip_address":
            value = details.get("target_ip", "")
        else:
            value = target.get("original", "")

        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )

    return {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
    }


async def run_strix_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    sources_path: Path,
    tracer: Any | None = None,
    bus: AgentMessageBus | None = None,
    interactive: bool = False,
    max_turns: int = STRIX_DEFAULT_MAX_TURNS,
    model: str | None = None,
    cleanup_on_exit: bool = True,
) -> RunResultBase:
    """Run one Strix scan end-to-end against a freshly-prepared sandbox.

    Args:
        scan_config: Per-scan configuration — ``targets``,
            ``user_instructions``, ``diff_scope``, ``scan_mode``,
            ``skills``. ``is_whitebox`` is derived from ``targets``.
        scan_id: Used to key the sandbox session cache. Auto-generated
            if omitted — callers that want resume-after-crash semantics
            should pass a stable id.
        image: Docker image tag for the sandbox (e.g.
            ``"strix-sandbox:0.1.13"``).
        sources_path: Host directory mounted into ``/workspace/sources``.
        tracer: Optional Strix tracer. Stored in context for the
            telemetry hook chain. Pass ``None`` for unit tests.
        interactive: Renders the interactive-mode prompt block on the
            root agent.
        max_turns: Cap on root-agent LLM turns (default 300).
        model: Litellm model alias. ``None`` (default) reads
            :attr:`Settings.llm.model` — caller pre-validates via
            :func:`validate_environment` that it's set.
        cleanup_on_exit: When True (default), tears down the sandbox
            session in a ``finally``. Set to False for resume scenarios
            where the caller wants to preserve the container.

    Returns the SDK ``RunResult`` from ``Runner.run``. Raises if the
    sandbox bring-up fails or the run itself raises.
    """
    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    logger.info("Starting Strix scan %s", scan_id)

    resolved_model = model or load_settings().llm.model
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set STRIX_LLM env or pass model= to run_strix_scan().",
        )

    # Caller may pre-create the bus so it can hold a handle (e.g., the
    # TUI uses it to route stop / chat-input commands). Otherwise we
    # own the bus internally for the scan's lifetime.
    if bus is None:
        bus = AgentMessageBus()
    root_id = uuid.uuid4().hex[:8]

    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        sources_path=sources_path,
    )

    try:
        # Lazy: ``strix.interface`` pulls cli→tui→entry which would cycle.
        from strix.interface.utils import is_whitebox_scan

        scan_mode = str(scan_config.get("scan_mode") or "deep")
        is_whitebox = is_whitebox_scan(scan_config.get("targets") or [])
        skills = list(scan_config.get("skills") or [])
        diff_scope = scan_config.get("diff_scope") or None
        run_id = scan_config.get("run_id") or scan_id

        scope_context = _build_scope_context(scan_config)

        root_agent = build_strix_agent(
            name="strix",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            system_prompt_context=scope_context,
        )

        await bus.register(root_id, "strix", parent_id=None)

        agent_factory = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            system_prompt_context=scope_context,
        )

        context = make_agent_context(
            bus=bus,
            sandbox_session=bundle["session"],
            sandbox_client=bundle["client"],
            caido_client=bundle["caido_client"],
            agent_id=root_id,
            parent_id=None,
            tracer=tracer,
            model=resolved_model,
            max_turns=max_turns,
            is_whitebox=is_whitebox,
            interactive=interactive,
            diff_scope=diff_scope,
            run_id=run_id,
            agent_factory=agent_factory,
        )

        reasoning_effort: Literal["low", "medium", "high"] | None = (
            load_settings().llm.reasoning_effort
        )
        run_config = make_run_config(
            sandbox_session=bundle["session"],
            sandbox_client=bundle["client"],
            model=resolved_model,
            reasoning_effort=reasoning_effort,
        )

        # Native SDK session: persists conversation history to
        # ``strix_runs/<scan_id>/session.db`` so a second invocation
        # with the same ``scan_id`` resumes from where we left off.
        session_db = (
            (tracer.get_run_dir() / "session.db")
            if tracer is not None and hasattr(tracer, "get_run_dir")
            else Path.cwd() / "strix_runs" / scan_id / "session.db"
        )
        session_db.parent.mkdir(parents=True, exist_ok=True)
        session = SQLiteSession(session_id=scan_id, db_path=session_db)

        return await run_with_continuation(
            agent=root_agent,
            initial_input=_build_root_task(scan_config),
            run_config=run_config,
            context=context,
            hooks=StrixOrchestrationHooks(),
            max_turns=max_turns,
            bus=bus,
            agent_id=root_id,
            interactive=interactive,
            session=session,
        )
    except BaseException:
        # Cancel any descendant tasks the root spawned before unwinding.
        # cancel_descendants is idempotent and handles the empty-tree case.
        await bus.cancel_descendants(root_id)
        raise
    finally:
        if cleanup_on_exit:
            await session_manager.cleanup(scan_id)
