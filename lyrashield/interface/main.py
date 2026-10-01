#!/usr/bin/env python3
# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""
Strix Agent Interface
"""

import argparse
import asyncio
import logging
import shutil
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.artifacts.state import (
    ReportState,
    get_global_report_state,
    initial_run_record,
    sanitize_attachments,
    sanitize_local_sources,
    sanitize_targets_info,
    set_global_report_state,
    validate_run_record,
)
from lyrashield.artifacts.writer import (
    write_resume_record,
    write_run_record,
)
from lyrashield.interface.arg_parser import parse_arguments
from lyrashield.interface.cli import run_cli
from lyrashield.interface.environment_gate import validate_environment
from lyrashield.interface.image_pull import (
    _normalize_digest,  # noqa: F401
    _verify_image_digest,  # noqa: F401
    process_pull_line,  # noqa: F401
    pull_docker_image,
)
from lyrashield.interface.resume_state import _load_resume_state  # noqa: F401
from lyrashield.interface.tui import run_tui
from lyrashield.interface.utils import (
    _is_full_git_commit_sha,
    build_final_stats_text,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    is_whitebox_scan,
    resolve_diff_scope_context,
    validate_config_file,
)
from lyrashield.interface.warmup import warm_up_llm
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError
from lyrashield.policy import codex
from lyrashield.policy.loader import load_settings
from lyrashield.policy.settings import (
    is_chatgpt_subscription_allowed,
    is_lyrashield_product,
)
from lyrashield.telemetry import posthog, scarf
from lyrashield.telemetry.logging import configure_dependency_logging
from strix.config import apply_config_override
from strix.core.paths import run_dir_for


logger = logging.getLogger(__name__)


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.debug("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


def _persist_run_record(
    args: argparse.Namespace, *, terminal: dict[str, Any] | None = None
) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    # The first observable run.json must already be a complete versioned
    # worker contract, so build it through the same canonical constructor
    # ReportState uses — never a partial hand-rolled dict (I10).
    run_record = initial_run_record(
        args.run_name,
        auth_mode=codex.auth_mode(load_settings().llm.model),
        targets_info=sanitize_targets_info(args.targets_info),
        extra={
            "scan_mode": args.scan_mode,
            "instruction": args.instruction,
            "non_interactive": args.non_interactive,
            "local_sources": sanitize_local_sources(getattr(args, "local_sources", [])),
            "attachments": sanitize_attachments(getattr(args, "attachments", [])),
            "diff_scope": getattr(args, "diff_scope", {"active": False}),
            "scope_mode": args.scope_mode,
            "diff_base": args.diff_base,
            "diff_head": getattr(args, "diff_head", None),
            "repository_revision": getattr(args, "repository_revision", None),
        },
    )
    if terminal:
        # Terminal overrides (e.g. the no-change receipt) are applied after the
        # canonical constructor — this is the deliberate end-state written by
        # the engine itself, not caller-supplied forgery of required fields.
        run_record.update(terminal)
    # Validate the pre-scan contract before writing, so an incomplete record
    # never reaches the run directory (I10/C3).
    validate_run_record(run_record)
    write_run_record(run_dir, run_record)
    # Preserve the unsanitized execution fields needed for resume in a private
    # file that is not part of the public worker contract (comment #5).
    write_resume_record(
        run_dir,
        targets_info=args.targets_info,
        local_sources=getattr(args, "local_sources", []),
        attachments=getattr(args, "attachments", []),
    )


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") == "completed"

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

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

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    view_text = Text()
    view_text.append("\n")
    view_text.append("View", style="dim")
    view_text.append("    ")
    view_text.append(f"lyrashield view {args.run_name}", style="#22c55e")
    panel_parts.extend(["\n", view_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"lyrashield --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]LYRASHIELD",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print("[#60a5fa]https://lyrashieldai.com[/]")
    console.print()
    # Upstream shows an update notice here; LyraShield Engine ships as reviewed
    # releases, so the upstream version check would suggest the wrong package.


def main(
    *,
    entry_monotonic: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    # Auto-load the engine .env if present; explicit shell exports still win.
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    except Exception:
        logger.debug("Could not load .env file; continuing without it", exc_info=True)

    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # `lyrashield view [<run>]` is a viewer-only subcommand, dispatched before the
    # scan argument parser (which requires a target) and before any scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "view":
        from lyrashield.interface.viewer.cli import run_view

        run_view(sys.argv[2:])
        return

    # `lyrashield auth …` manages model-subscription sign-in and exits; it needs no
    # target, Docker, or scan setup. It is enabled unless the operator sets
    # `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0`.
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        if is_lyrashield_product() and not is_chatgpt_subscription_allowed():
            Console().print(
                "[bold red]LyraShield does not support ChatGPT subscription authentication.[/]"
            )
            sys.exit(1)
        from lyrashield.interface.auth_cli import run_auth

        sys.exit(run_auth(sys.argv[2:]))

    # Provider checks are target-free deployment gates, not scans, so skip Docker.
    if len(sys.argv) > 1 and sys.argv[1] == "provider-contract":
        from lyrashield.interface.provider_contract_cli import run_provider_contract

        sys.exit(run_provider_contract(sys.argv[2:]))

    # Triage is an additive artifact command, not a target scan. It deliberately
    # bypasses Docker and never touches the deterministic vulnerabilities output.
    if len(sys.argv) > 1 and sys.argv[1] == "ai-security-triage":
        from lyrashield.triage.cli import run_triage_cli

        sys.exit(run_triage_cli(sys.argv[2:]))

    args = parse_arguments()

    if args.config:
        apply_config_override(validate_config_file(args.config))

    # The non-interactive runtime allowance starts as early as the owned scan
    # entry permits: image pull, repository clone and diff-scope resolution
    # all consume the same deadline the lifecycle enforces. Interpreter and
    # import time before main() cannot be included — the worker's own timer
    # starts at process spawn and already accounts for it.
    args.run_deadline = None
    runtime_seconds = getattr(args, "runtime_budget_seconds", None)
    if getattr(args, "non_interactive", False) and runtime_seconds is not None:
        args.run_deadline = RunDeadline.start(
            runtime_seconds,
            clock=monotonic,
            started_at=entry_monotonic if entry_monotonic is not None else monotonic(),
        )
    deadline = args.run_deadline

    validate_environment()
    check_docker_installed()

    # Non-interactive worker runs must not make an unmetered warm-up request or
    # persist provider credentials under the container home directory.
    warm_up_usages: list[tuple[str, Any]] = []
    args.warm_up_usages = warm_up_usages

    args.run_name = args.resume or args.run_name or generate_run_name(args.targets_info)

    deadline_exhausted = False
    try:
        pull_docker_image(deadline=deadline)

        if not args.resume:
            # --repository-revision pins the remote checkout; --diff-head asserts
            # the comparison head. When both are absent a full-SHA
            # --repository-branch is the legacy pin form. The validated diff-head
            # doubles as the checkout revision when no explicit revision is given —
            # Review Changes compares the recorded head, not a moving branch tip.
            checkout_revision = args.repository_revision or args.diff_head
            required_commits: tuple[str, ...] = ()
            if args.diff_base and _is_full_git_commit_sha(args.diff_base):
                required_commits = (args.diff_base.lower(),)

            for target_info in args.targets_info:
                if target_info["type"] == "repository":
                    repo_url = target_info["details"]["target_repo"]
                    dest_name = target_info["details"].get("workspace_subdir")
                    cloned_path = clone_repository(
                        repo_url,
                        args.run_name,
                        dest_name,
                        args.repository_branch,
                        revision=checkout_revision,
                        required_commits=required_commits,
                        deadline=deadline,
                    )
                    target_info["details"]["cloned_repo_path"] = cloned_path

            runtime = load_settings().runtime
            args.local_sources = collect_local_sources(
                args.targets_info,
                # Product Docker scans own the fresh clone and keep TMPDIR on the
                # host-visible worker root. A read-only bind avoids streaming the
                # entire Git tree through Docker's archive API before every scan.
                mount_cloned_repositories=is_lyrashield_product() and runtime.backend == "docker",
            )
            try:
                diff_scope = resolve_diff_scope_context(
                    local_sources=args.local_sources,
                    scope_mode=args.scope_mode,
                    diff_base=args.diff_base,
                    non_interactive=args.non_interactive,
                    diff_head=args.diff_head,
                )
            except ValueError as e:
                console = Console()
                error_text = Text()
                error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
                error_text.append("\n\n", style="white")
                error_text.append(str(e), style="white")

                panel = Panel(
                    error_text,
                    title="[bold white]LYRASHIELD",
                    title_align="left",
                    border_style="red",
                    padding=(1, 2),
                )
                console.print("\n")
                console.print(panel)
                console.print()
                sys.exit(1)

            args.diff_scope = diff_scope.metadata

            if diff_scope.active and diff_scope.metadata.get("no_change"):
                # Empty analyzable diff: record a durable no-change receipt and
                # stop. No sandbox, warm-up, or provider call is ever reached —
                # the run record below is the entire output of this run.
                _persist_run_record(
                    args,
                    terminal={
                        "status": "completed",
                        "phase": "completed",
                        "terminal_reason": "no_change",
                        "end_time": datetime.now(UTC).isoformat(),
                        "instruction": None,
                        "instruction_chars": len(args.instruction or ""),
                    },
                )
                console = Console()
                note_text = Text()
                note_text.append("NO ANALYZABLE CHANGES", style="bold #22c55e")
                note_text.append("\n\n", style="white")
                note_text.append(
                    "Diff-scope resolved zero analyzable files "
                    f"({diff_scope.metadata.get('no_change_reason', 'empty_diff')}). "
                    "The run was recorded as a no-change receipt; no scan was launched.\n",
                    style="white",
                )
                panel = Panel(
                    note_text,
                    title="[bold white]LYRASHIELD",
                    title_align="left",
                    border_style="#22c55e",
                    padding=(1, 2),
                )
                console.print("\n")
                console.print(panel)
                console.print()
                sys.exit(0)

            if diff_scope.instruction_block:
                if args.instruction:
                    args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
                else:
                    args.instruction = diff_scope.instruction_block

            _persist_run_record(args)
    except RunDeadlineExceededError:
        # Acquisition ran the shared allowance to zero: fall through to the
        # honest bounded terminal artifact below instead of starting a scan
        # that can only be killed mid-flight.
        deadline_exhausted = True

    if deadline is not None and deadline.remaining_seconds() <= 0:
        deadline_exhausted = True

    if deadline_exhausted:
        # The allowance was spent before model work could begin. Persist the
        # truthful stopped receipt — never a fabricated clean result — then
        # hydrate it so persisted findings and the terminal reason reach the
        # worker exit-code contract below.
        _persist_run_record(
            args,
            terminal={
                "status": "stopped",
                "phase": "stopped",
                "terminal_reason": "runtime_deadline",
                "end_time": datetime.now(UTC).isoformat(),
                "instruction": None,
                "instruction_chars": len(args.instruction or ""),
            },
        )
        exhausted_state = ReportState(args.run_name)
        exhausted_state.hydrate_from_run_dir()
        set_global_report_state(exhausted_state)

    if not args.non_interactive:
        asyncio.run(warm_up_llm(show_model_warning=False, usages=warm_up_usages))

    _telemetry_model = load_settings().llm.model
    _telemetry_scan_mode = args.scan_mode
    _telemetry_is_whitebox = is_whitebox_scan(args.targets_info)
    _telemetry_interactive = not args.non_interactive
    _telemetry_has_instructions = bool(args.instruction)
    posthog.start(
        model=_telemetry_model,
        scan_mode=_telemetry_scan_mode,
        is_whitebox=_telemetry_is_whitebox,
        interactive=_telemetry_interactive,
        has_instructions=_telemetry_has_instructions,
    )
    scarf.start(
        model=_telemetry_model,
        scan_mode=_telemetry_scan_mode,
        is_whitebox=_telemetry_is_whitebox,
        interactive=_telemetry_interactive,
        has_instructions=_telemetry_has_instructions,
    )

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            # An allowance already spent on preprocessing means no model work:
            # the bounded terminal record above is the entire run output.
            if not deadline_exhausted:
                asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception:
        exit_reason = "error"
        posthog.error("unhandled_exception")
        scarf.error("unhandled_exception")
        _exit_noninteractive_failure(non_interactive=args.non_interactive)
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            posthog.end(report_state, exit_reason=exit_reason)
            scarf.end(report_state, exit_reason=exit_reason)

    results_path = run_dir_for(args.run_name)
    if not args.non_interactive:
        display_completion_message(args, results_path)

    if args.non_interactive:
        exit_code = _non_interactive_exit_code(get_global_report_state())
        if exit_code:
            sys.exit(exit_code)


def _non_interactive_exit_code(report_state: Any | None) -> int:
    """Map an engine receipt to the worker's stable terminal contract."""
    if report_state is None:
        return 5
    if report_state.run_record.get("status") == "completed":
        return 2 if report_state.vulnerability_reports else 0
    match report_state.run_record.get("terminal_reason"):
        case "no_change":
            return 0
        case "budget_exceeded":
            return 3
        case "rate_limited":
            return 4
        case "content_filter_stopped" | "engine_stopped" | "runtime_deadline":
            # Partial scan — findings may have been collected before the
            # model stopped or the runtime deadline fired. Treat like
            # "vulnerabilities found" so the worker persists them rather than
            # failing.
            return 2 if report_state.vulnerability_reports else 5
        case _:
            return 5


def _exit_noninteractive_failure(*, non_interactive: bool) -> None:
    if not non_interactive:
        return
    # ``run_cli`` already emitted the fixed, class-only failure marker. Exit
    # without an interpreter traceback because exception messages and frames
    # may contain target-derived data.
    raise SystemExit(1) from None


if __name__ == "__main__":
    main()
