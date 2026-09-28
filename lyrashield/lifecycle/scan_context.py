# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Immutable per-scan paths and model routing context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScanPaths:
    scan_id: str
    run_dir: Path
    state_dir: Path
    agents_path: Path
    agents_db: Path
    is_resume: bool
    teardown_logging: Callable[[], None]


@dataclass(frozen=True, slots=True)
class ScanContext:
    paths: ScanPaths
    settings: Any
    llm_settings: Any
    resolved_model: str
    delegate_model: str
    delegate_reasoning_effort: Any
    chat_completions_tools: bool
    delegate_chat_completions_tools: bool
    scan_mode: str


def create_scan_paths(
    *,
    scan_id: str,
    resume: bool,
    run_dir_for: Callable[[str], Path],
    runtime_state_dir: Callable[[Path], Path],
    setup_scan_logging: Callable[[Path], Callable[[], None]],
    set_scan_id: Callable[[str], None],
) -> ScanPaths:
    """Create scan state directories and configure scan-scoped logging."""
    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)
    return ScanPaths(
        scan_id=scan_id,
        run_dir=run_dir,
        state_dir=state_dir,
        agents_path=state_dir / "agents.json",
        agents_db=state_dir / "agents.db",
        is_resume=resume,
        teardown_logging=teardown_logging,
    )


def resolve_scan_context(
    *,
    paths: ScanPaths,
    scan_config: dict[str, Any],
    model: str | None,
    load_settings: Callable[[], Any],
    configure_sdk_model_defaults: Callable[[Any], None],
    uses_chat_completions_tool_schema: Callable[[str, Any], bool],
) -> ScanContext:
    """Resolve the configured models and per-scan routing capabilities."""
    settings = load_settings()
    configure_sdk_model_defaults(settings)
    llm_settings = settings.llm
    resolved_model = (model or llm_settings.model or "").strip()
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set STRIX_LLM env or pass model= to run_strix_scan().",
        )
    delegate_model = str(getattr(llm_settings, "delegate_model", None) or resolved_model).strip()
    delegate_reasoning_effort = getattr(
        llm_settings,
        "delegate_reasoning_effort",
        llm_settings.reasoning_effort,
    )
    return ScanContext(
        paths=paths,
        settings=settings,
        llm_settings=llm_settings,
        resolved_model=resolved_model,
        delegate_model=delegate_model,
        delegate_reasoning_effort=delegate_reasoning_effort,
        chat_completions_tools=uses_chat_completions_tool_schema(resolved_model, settings),
        delegate_chat_completions_tools=uses_chat_completions_tool_schema(delegate_model, settings),
        scan_mode=str(scan_config.get("scan_mode") or "deep"),
    )


def build_scan_context(
    *,
    scan_id: str,
    scan_config: dict[str, Any],
    model: str | None,
    resume: bool,
    run_dir_for: Callable[[str], Path],
    runtime_state_dir: Callable[[Path], Path],
    setup_scan_logging: Callable[[Path], Callable[[], None]],
    set_scan_id: Callable[[str], None],
    load_settings: Callable[[], Any],
    configure_sdk_model_defaults: Callable[[Any], None],
    uses_chat_completions_tool_schema: Callable[[str, Any], bool],
) -> ScanContext:
    """Convenience composition used by focused tests and simple callers."""
    paths = create_scan_paths(
        scan_id=scan_id,
        resume=resume,
        run_dir_for=run_dir_for,
        runtime_state_dir=runtime_state_dir,
        setup_scan_logging=setup_scan_logging,
        set_scan_id=set_scan_id,
    )
    return resolve_scan_context(
        paths=paths,
        scan_config=scan_config,
        model=model,
        load_settings=load_settings,
        configure_sdk_model_defaults=configure_sdk_model_defaults,
        uses_chat_completions_tool_schema=uses_chat_completions_tool_schema,
    )
