# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import asyncio
import atexit
import contextlib
import logging
import re
import signal
import sys
import threading
import time
from typing import Any, cast

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from lyrashield.artifacts.state import ReportState, set_global_report_state
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceeded
from lyrashield.lifecycle.inputs import DEFAULT_MAX_TURNS
from lyrashield.lifecycle.runner import run_strix_scan
from lyrashield.runtime import session_manager
from strix.config import load_settings

from .utils import (
    build_live_stats_text,
    format_vulnerability_report,
)


logger = logging.getLogger(__name__)
_SAFE_PROVIDER_ERROR_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _noninteractive_failure_label(exc: Exception) -> str:
    label = type(exc).__name__
    module = type(exc).__module__
    if label == "APIError" and module.startswith("docker."):
        label = "DockerAPIError"
    elif label == "APIError" and module.startswith("openai."):
        label = "ProviderAPIError"
    body = getattr(exc, "body", None)
    if not isinstance(body, dict):
        return label
    body = cast("dict[str, Any]", body)
    for key in ("code", "type", "param"):
        component = body.get(key)
        if isinstance(component, str) and _SAFE_PROVIDER_ERROR_COMPONENT.fullmatch(component):
            return f"{label}.{component}"
    return label


def _resolve_sandbox_image() -> str:
    image = load_settings().runtime.image
    if not image:
        raise RuntimeError(
            "strix_image is not configured. Set it in ~/.strix/cli-config.json.",
        )
    return image


async def run_cli(args: Any) -> None:
    console = Console()
    non_interactive = bool(getattr(args, "non_interactive", False))

    start_text = Text()
    start_text.append("Penetration test initiated", style="bold #22c55e")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    results_text = Text()
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(f"strix_runs/{args.run_name}", style="#60a5fa")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("Vulnerabilities will be displayed in real-time.", style="dim")

    startup_panel = Panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n",
            results_text,
            note_text,
        ),
        title="[bold white]LYRASHIELD",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )

    if not non_interactive:
        console.print("\n")
        console.print(startup_panel)
        console.print()

    scan_mode = getattr(args, "scan_mode", "deep")

    scan_config: dict[str, Any] = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scan_mode": scan_mode,
        "non_interactive": bool(getattr(args, "non_interactive", False)),
        "local_sources": getattr(args, "local_sources", None) or [],
        "attachments": getattr(args, "attachments", None) or [],
        "scope_mode": getattr(args, "scope_mode", "auto"),
        "diff_base": getattr(args, "diff_base", None),
        "diff_head": getattr(args, "diff_head", None),
        "repository_revision": getattr(args, "repository_revision", None),
        "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
    }

    report_state = ReportState(args.run_name)
    if getattr(args, "resume", None):
        report_state.hydrate_from_run_dir()
    report_state.set_scan_config(scan_config)
    report_state.save_run_data()

    def display_vulnerability(report: dict[str, Any]) -> None:
        report_id = report.get("id", "unknown")

        if non_interactive:
            logger.info(
                "Finding recorded: id=%s severity=%s",
                report_id,
                report.get("severity", "unknown"),
            )
            return

        vuln_text = format_vulnerability_report(report)

        vuln_panel = Panel(
            vuln_text,
            title=f"[bold red]{report_id.upper()}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    report_state.vulnerability_found_callback = display_vulnerability

    def cleanup_on_exit() -> None:
        report_state.cleanup()

    def signal_handler(_signum: int, _frame: Any) -> None:
        report_state.cleanup(status="interrupted")
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_report_state(report_state)

    for warm_model, warm_usage in getattr(args, "warm_up_usages", []) or []:
        report_state.record_sdk_usage(
            agent_id="warmup", agent_name="warmup", model=warm_model, usage=warm_usage
        )

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("Penetration test in progress", style="bold #22c55e")
        status_text.append("\n\n")

        stats_text = build_live_stats_text(report_state)
        if stats_text:
            status_text.append(stats_text)

        return Panel(
            status_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )

    async def execute_scan() -> None:
        logger.info(
            "CLI launching scan: run_name=%s targets=%d interactive=%s",
            args.run_name,
            len(scan_config.get("targets") or []),
            bool(getattr(args, "interactive", False)),
        )
        runtime_seconds = getattr(args, "runtime_budget_seconds", None)
        if runtime_seconds is not None and not non_interactive:
            raise ValueError("runtime budget is supported only for non-interactive scans")
        deadline = (
            RunDeadline.start(runtime_seconds) if non_interactive and runtime_seconds else None
        )
        coordinator = AgentCoordinator() if deadline is not None else None
        if coordinator is not None:
            coordinator.run_deadline = deadline
        run = run_strix_scan(
            scan_config=scan_config,
            scan_id=args.run_name,
            image=_resolve_sandbox_image(),
            local_sources=getattr(args, "local_sources", None) or [],
            attachments=getattr(args, "attachments", None) or [],
            interactive=bool(getattr(args, "interactive", False)),
            max_budget_usd=getattr(args, "max_budget_usd", None),
            max_turns=getattr(args, "max_turns", DEFAULT_MAX_TURNS),
            resume=bool(getattr(args, "resume", None)),
            artifact_state=report_state,
            coordinator=coordinator,
        )
        if deadline is None:
            await run
        else:

            async def notify_wrap() -> None:
                await asyncio.sleep(deadline.until_wrap_seconds())
                if coordinator is None:
                    return
                for (
                    agent_id,
                    status,
                    _parent,
                    _name,
                    _metadata,
                ) in await coordinator.agents_with_metadata():
                    if status in {"running", "waiting"}:
                        await coordinator.send(
                            agent_id,
                            {
                                "from": "system",
                                "type": "runtime_wrap",
                                "content": (
                                    "Runtime wrap-up: stop new work, collect existing reports, "
                                    "record unresolved coverage, and finish truthfully."
                                ),
                            },
                            interrupt=False,
                        )

            wrap_task = asyncio.create_task(notify_wrap())
            scan_timeout = asyncio.timeout(deadline.remaining_seconds())
            try:
                async with scan_timeout:
                    await run
            except (TimeoutError, RunDeadlineExceeded) as exc:
                # Only the deadline itself is salvageable. Two cases reach here:
                # the asyncio timeout context actually expired, or the lifecycle
                # refused a model start past the deadline (RunDeadlineExceeded).
                # An internal TimeoutError that escaped the run while the
                # context had NOT expired is a real failure and must not be
                # relabelled as a bounded partial result.
                if not (scan_timeout.expired() or isinstance(exc, RunDeadlineExceeded)):
                    raise
                # The hard runtime deadline fired. Record the reason so the
                # worker can keep the findings already filed and report a
                # truthful bounded result.
                report_state.set_terminal_reason("runtime_deadline")
                logger.warning("Scan runtime deadline reached; salvaging partial results")
            finally:
                wrap_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await wrap_task

    try:
        if non_interactive:
            try:
                await execute_scan()
            finally:
                with contextlib.suppress(Exception):
                    # This outer cleanup is the last owner to run before the worker
                    # reads run.json. Persist its outcome (idempotent: a confirmed
                    # removal or recorded failure from the lifecycle cleanup passes
                    # through unchanged) so the worker can fail closed when a
                    # sandbox is stranded.
                    cleanup_outcome = await session_manager.cleanup(args.run_name)
                    report_state.set_cleanup_outcome(cleanup_outcome)
        else:
            console.print()
            with Live(
                create_live_status(), console=console, refresh_per_second=2, transient=False
            ) as live:
                stop_updates = threading.Event()

                def update_status() -> None:
                    while not stop_updates.is_set():
                        try:
                            live.update(create_live_status())
                            time.sleep(2)
                        except Exception:
                            break

                update_thread = threading.Thread(target=update_status, daemon=True)
                update_thread.start()

                try:
                    await execute_scan()
                finally:
                    stop_updates.set()
                    update_thread.join(timeout=1)
                    with contextlib.suppress(Exception):
                        await session_manager.cleanup(args.run_name)

    except Exception as e:
        if non_interactive:
            # Do not persist the exception text or traceback; engine failures may
            # contain target-derived content in non-interactive worker runs.
            logger.error(  # noqa: TRY400
                "Non-interactive scan failed: %s",
                _noninteractive_failure_label(e),
            )
        else:
            console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if report_state.final_scan_result and not non_interactive:
        console.print()

        final_report_text = Text()
        final_report_text.append("Penetration test summary", style="bold #60a5fa")

        final_report_panel = Panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                report_state.final_scan_result,
            ),
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="#60a5fa",
            padding=(1, 2),
        )

        console.print(final_report_panel)
        console.print()
