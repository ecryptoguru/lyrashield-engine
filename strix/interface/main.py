#!/usr/bin/env python3
# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""
Strix Agent Interface
"""

import argparse
import asyncio
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import (
    apply_config_override,
    codex,
    load_settings,
)
from strix.config.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    configure_sdk_model_defaults,
    is_gpt56_model,
    is_known_openai_bare_model,
    is_recommended_or_frontier_model,
)
from strix.config.settings import Settings
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.interface.cli import run_cli
from strix.interface.tui import run_tui
from strix.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    build_mount_targets_info,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    dedupe_local_targets,
    find_oversized_local_targets,
    generate_run_name,
    image_exists,
    infer_target_type,
    is_whitebox_scan,
    process_pull_line,
    read_target_list_file,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
)
from strix.report.state import get_global_report_state
from strix.report.writer import read_run_record, write_run_record
from strix.telemetry import posthog, scarf
from strix.telemetry.logging import configure_dependency_logging


HOST_GATEWAY_HOSTNAME = "host.docker.internal"
BEDROCK_MODEL_PREFIX = "bedrock/"
BEDROCK_MISSING_MODULE_ERROR = "No module named 'boto3'"
BEDROCK_EXTRA_HINT = (
    'Bedrock support is optional. Install it with: pipx install "strix-agent[bedrock]"'
)
VERTEX_MODEL_MARKER = "vertex"
VERTEX_MISSING_MODULE_ERROR = "No module named 'google"
VERTEX_EXTRA_HINT = (
    'Vertex AI support is optional. Install it with: pipx install "strix-agent[vertex]"'
)


import logging  # noqa: E402


logger = logging.getLogger(__name__)


def _reject_resolved_subscription_models(settings: Settings, console: Console) -> None:
    """Reject subscription-backed models that reached settings via `--config`.

    The product entry point (`lyrashield_adapter.cli`) rejects `chatgpt/` models
    at the environment level, but `--config` is applied afterwards. A
    subscription route bypasses the Terra/Luna gate and zeroes the metered cost
    ledger, so the worker would bill nothing for a real scan.
    """
    configured = {
        "STRIX_LLM": settings.llm.model,
        "STRIX_DELEGATE_LLM": getattr(settings.llm, "delegate_model", None),
        "STRIX_DEDUPE_MODEL": getattr(settings, "dedupe", None) and settings.dedupe.model,
    }
    for name, value in configured.items():
        if codex.subscription_model(value):
            console.print(
                f"[bold red]{name}={value} routes through a ChatGPT subscription, "
                "which is not supported for LyraShield scans.[/] Configure a GPT-5.6 "
                "Terra or Luna API deployment instead."
            )
            sys.exit(1)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars: list[str] = []
    missing_optional_vars: list[str] = []

    settings = load_settings()

    # `--config` is applied after the product entry point's env-level gate, so a
    # config file could still name a subscription-backed model. Re-check the
    # resolved settings here, where every source (env, JSON, --config) has been
    # merged. Enforced for every entry point so `strix.interface.main.main()`
    # cannot bypass the product boundary.
    _reject_resolved_subscription_models(settings, console)

    if codex.subscription_model(settings.llm.model):
        if not codex.is_authenticated():
            console.print(
                f"[red]STRIX_LLM={settings.llm.model} uses your ChatGPT subscription, "
                "but you're not signed in.[/] Run [cyan]strix auth login chatgpt[/] first."
            )
            sys.exit(1)
        logger.info("Environment OK (ChatGPT subscription)")
        return

    if not settings.llm.model:
        missing_required_vars.append("STRIX_LLM or LYRASHIELD_LLM")
    elif (
        not is_gpt56_model(settings.llm.model)
        or (settings.llm.delegate_model and not is_gpt56_model(settings.llm.delegate_model))
        or (settings.dedupe.model and not is_gpt56_model(settings.dedupe.model))
    ):
        error_text = Text(
            "LyraShield scans require a GPT-5.6 Terra or Luna deployment",
            style="bold red",
        )
        console.print("\n")
        console.print(
            Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            ),
        )
        console.print()
        sys.exit(1)

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var in {"STRIX_LLM or LYRASHIELD_LLM", "STRIX_LLM"}:
                error_text.append("• ", style="white")
                error_text.append("STRIX_LLM / LYRASHIELD_LLM", style="bold cyan")
                error_text.append(
                    " - GPT-5.6 Terra or Luna deployment name\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the configured GPT-5.6 endpoint\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Base URL for the configured GPT-5.6 endpoint\n",
                        style="white",
                    )
                elif var in {"STRIX_REASONING_EFFORT", "LYRASHIELD_REASONING_EFFORT"}:
                    error_text.append("• ", style="white")
                    error_text.append(
                        "STRIX_REASONING_EFFORT / LYRASHIELD_REASONING_EFFORT",
                        style="bold cyan",
                    )
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append(
            "export STRIX_LLM='openai/gpt-5.6-luna'  # or LYRASHIELD_LLM\n",
            style="dim white",
        )

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# credential for the configured GPT-5.6 endpoint\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='https://your-gpt-5-6-endpoint.example'\n",
                        style="dim white",
                    )
                elif var in {"STRIX_REASONING_EFFORT", "LYRASHIELD_REASONING_EFFORT"}:
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'  # or LYRASHIELD_REASONING_EFFORT\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.error("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.error("Docker CLI not found in PATH")
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
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


def _exception_messages(exc: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        messages.append(str(current))
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
    return tuple(messages)


def _provider_import_hint(exc: BaseException, model: str) -> str | None:
    """Return an install hint when *exc* is a missing provider dependency.

    Bedrock and Vertex AI ship as optional extras: Bedrock needs ``boto3`` and
    Vertex AI needs ``google-auth``. When either is absent, litellm may raise an
    ``ImportError``/``ModuleNotFoundError`` directly or wrap it in a connection
    error. Map the missing module back to the matching extra so the user knows
    what to install. Returns ``None`` for any unrelated error.
    """
    model_name = model.lower()
    messages = _exception_messages(exc)
    if any(
        BEDROCK_MISSING_MODULE_ERROR in message for message in messages
    ) and model_name.startswith(BEDROCK_MODEL_PREFIX):
        return BEDROCK_EXTRA_HINT
    if (
        any(VERTEX_MISSING_MODULE_ERROR in message for message in messages)
        and VERTEX_MODEL_MARKER in model_name
    ):
        return VERTEX_EXTRA_HINT
    return None


def _subscription_error_hint(exc: BaseException) -> str | None:
    """Return an actionable hint for a known ChatGPT-subscription error, or None."""
    if not codex.subscription_model(load_settings().llm.model):
        return None
    joined = " ".join(_exception_messages(exc)).lower()
    if "not supported when using codex with a chatgpt account" in joined:
        return (
            "This model isn't available on your ChatGPT subscription. "
            "Set STRIX_LLM to a model your plan includes (e.g. chatgpt/gpt-5.4)."
        )
    if (
        "error code: 401" in joined
        or "http 401" in joined
        or "unauthorized" in joined
        or "invalid_grant" in joined
    ):
        return (
            "Your ChatGPT sign-in has expired or was revoked. Sign in again:\n"
            "  strix auth login chatgpt"
        )
    return None


async def warm_up_llm(
    show_model_warning: bool = True,
    *,
    usages: list[tuple[str, Any]] | None = None,
) -> None:
    """Warm up the configured LLM and optional dedupe model.

    If ``usages`` is supplied, each model's ``response.usage`` is appended as
    ``(model_name, usage)`` so the CLI/TUI can record warm-up tokens in the run
    ledger. Non-interactive runs skip warm-up and leave the list empty.
    """
    console = Console()
    logger.info("Warming up LLM connection")

    raw_model = ""
    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm
        raw_model = (llm.model or "").strip()

        if (
            raw_model
            and "/" not in raw_model
            and not is_known_openai_bare_model(raw_model)
            and not llm.api_base
        ):
            warn_text = Text()
            warn_text.append("UNKNOWN MODEL NAME", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " is not a known OpenAI model. Bare names route to OpenAI by default.\n"
                "If you meant a non-OpenAI provider, use the '",
                style="white",
            )
            warn_text.append("<provider>/<model>", style="bold cyan")
            warn_text.append(
                "' form, e.g. 'anthropic/claude-opus-4-7', 'deepseek/deepseek-v4-pro'.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]STRIX",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )
            sys.exit(1)

        if show_model_warning and raw_model and not is_recommended_or_frontier_model(raw_model):
            warn_text = Text()
            warn_text.append("MODEL QUALITY WARNING", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " is not a recommended frontier model for Strix.\nSecurity scans work best with:\n",
                style="white",
            )
            for recommended_model in RECOMMENDED_MODEL_NAMES:
                warn_text.append(f"• {recommended_model}\n", style="bold cyan")
            warn_text.append(
                "\nYou can continue, but weaker models may miss vulnerabilities "
                "or produce lower-quality findings.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]STRIX",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )

        model = StrixProvider(settings=settings).get_model(raw_model)
        response = await asyncio.wait_for(
            model.get_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=ModelSettings(),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ),
            timeout=llm.timeout,
        )
        if usages is not None and getattr(response, "usage", None) is not None:
            usages.append((raw_model, response.usage))
        logger.info("LLM warm-up succeeded for model %s", (llm.model or "").strip())

        if settings.dedupe.model:
            from strix.report.dedupe import dedupe_extra_args

            dedupe_model = settings.dedupe.model.strip()
            raw_model = dedupe_model
            deduper = StrixProvider().get_model(dedupe_model)
            # Match the runtime path: send the dedupe key/endpoint per call so a
            # separate-provider dedupe model authenticates during warm-up too.
            deduper_extra = dedupe_extra_args(settings.dedupe)
            deduper_settings = ModelSettings(extra_args=deduper_extra or None)
            response = await asyncio.wait_for(
                deduper.get_response(
                    system_instructions="You are a helpful assistant.",
                    input="Reply with just 'OK'.",
                    model_settings=deduper_settings,
                    tools=[],
                    output_schema=None,
                    handoffs=[],
                    tracing=ModelTracing.DISABLED,
                    previous_response_id=None,
                    conversation_id=None,
                    prompt=None,
                ),
                timeout=llm.timeout,
            )
            if usages is not None and getattr(response, "usage", None) is not None:
                usages.append((dedupe_model, response.usage))
            logger.info("LLM warm-up succeeded for dedupe model %s", dedupe_model)

    except Exception as e:
        logger.exception("LLM warm-up failed")
        error_text = Text()
        sub_hint = _subscription_error_hint(e)
        if sub_hint is not None:
            # The model/backend answered with a clear, actionable rejection —
            # show that instead of a generic "connection failed".
            border_style = "yellow"
            error_text.append("MODEL NOT AVAILABLE ON SUBSCRIPTION", style="bold yellow")
            error_text.append("\n\n", style="white")
            error_text.append(f"{sub_hint}\n", style="white")
            error_text.append(f"\nDetails: {e}", style="dim white")
        else:
            border_style = "red"
            error_text.append("LLM CONNECTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(
                "Could not establish connection to the language model.\n", style="white"
            )
            error_text.append("Please check your configuration and try again.\n", style="white")
            hint = _provider_import_hint(e, raw_model)
            if hint is not None:
                error_text.append(f"\n{hint}\n", style="bold yellow")
            error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style=border_style,
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("lyrashield-engine")
    except Exception:
        return "unknown"


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def _safe_run_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) or ".." in value:
        raise argparse.ArgumentTypeError("run name must be a safe 1-128 character identifier")
    return value


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  strix --target https://example.com

  # GitHub repository analysis
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # Local code analysis
  strix --target ./my-project

  # Large local repository (bind-mounted read-only instead of copied)
  strix --mount ./huge-monorepo

  # Domain penetration test
  strix --target example.com

  # IP address penetration test
  strix --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Targets from a file, one target per non-empty, non-comment line
  strix --target-list ./targets.txt

  # Custom instructions (inline)
  strix --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="Disabled in LyraShield Engine: self-update would replace this "
        "controlled derivative with the upstream distribution. Upgrade via a "
        "reviewed LyraShield Engine release instead.",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans. "
        "Fresh runs require at least one of --target, --target-list, or --mount.",
    )
    parser.add_argument(
        "--target-list",
        type=str,
        action="append",
        metavar="PATH",
        help="Path to a file containing targets, one per non-empty, non-comment line. "
        "Can be specified multiple times and combined with --target.",
    )
    parser.add_argument(
        "--mount",
        type=str,
        action="append",
        metavar="PATH",
        help="Bind-mount a local directory into the sandbox (read-only) instead of "
        "copying it file-by-file. Use this for large repositories that are too big to "
        "stream into the container. Can be specified multiple times.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "Scope mode for code targets: "
            "'auto' enables PR diff-scope in CI/headless runs, "
            "'diff' forces changed-files scope, "
            "'full' disables diff-scope."
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "Target branch or commit to compare against (e.g., origin/main). "
            "Defaults to the repository's default branch."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.strix/cli-config.json",
    )

    parser.add_argument(
        "--max-budget-usd",
        type=_positive_budget,
        default=None,
        help="Maximum LLM cost in USD (> 0). The scan stops cleanly when this limit is reached.",
    )

    parser.add_argument(
        "--run-name",
        type=_safe_run_name,
        help="Stable run identifier supplied by an orchestrator.",
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help=(
            "Resume a prior scan by its run name (the dir under ./strix_runs/). "
            "Picks up the root + every non-terminal subagent's full LLM history "
            "and agent topology. Skips fresh run-name generation."
        ),
    )

    args = parser.parse_args()

    if args.update:
        # Upstream self-update fetches usestrix/strix release artifacts (or the
        # strix-agent package), which would replace this controlled derivative
        # with the upstream distribution. Upgrades ship as reviewed LyraShield
        # Engine releases instead.
        Console().print(
            "[bold red]Self-update is disabled in LyraShield Engine.[/] "
            "Upgrade by installing a reviewed LyraShield Engine release."
        )
        sys.exit(1)

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.user_explicit_instruction = args.instruction if args.resume else None

    if args.resume:
        if args.run_name:
            parser.error("Cannot combine --resume with --run-name")
        if args.target or args.target_list or args.mount:
            parser.error(
                "Cannot combine --resume with --target/--target-list/--mount. "
                "--resume picks up where the prior run left off, including the "
                "original target list."
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}: missing {agents_path}. The run was "
                f"persisted but never reached its first agent snapshot — "
                f"there's nothing to resume from. Pick a fresh --run-name "
                f"or remove --resume to start over with the same targets."
            )
    else:
        if not args.target and not args.target_list and not args.mount:
            parser.error(
                "the following arguments are required: -t/--target, --target-list, or --mount "
                "(or use --resume <run_name> to continue a prior scan)"
            )
        target_strs: list[str] = cast("list[str]", args.target or [])
        target_list_paths: list[str] = cast("list[str]", args.target_list or [])
        mount_paths: list[str] = cast("list[str]", args.mount or [])
        targets_info: list[dict[str, Any]] = []
        targets: list[str] = list(target_strs)
        for target_list_path in target_list_paths:
            try:
                targets.extend(read_target_list_file(target_list_path))
            except ValueError as e:
                parser.error(str(e))

        for target in targets:
            try:
                target_type, target_dict = infer_target_type(target)

                if target_type == "local_code":
                    display_target = target_dict.get("target_path", target)
                else:
                    display_target = target

                targets_info.append(
                    {"type": target_type, "details": target_dict, "original": display_target}
                )
            except ValueError:
                parser.error(f"Invalid target '{target}'")

        try:
            targets_info.extend(build_mount_targets_info(mount_paths))
        except ValueError as e:
            parser.error(str(e))

        targets_info = dedupe_local_targets(targets_info)
        args.targets_info = targets_info

        assign_workspace_subdirs(targets_info)
        rewrite_localhost_targets(targets_info, HOST_GATEWAY_HOSTNAME)

        max_local_copy_mb = load_settings().runtime.max_local_copy_mb
        max_copy_bytes = max_local_copy_mb * 1024 * 1024
        oversized = find_oversized_local_targets(targets_info, max_copy_bytes)
        if oversized:
            details = "; ".join(
                f"{path} ({size / (1024 * 1024):.0f} MB)" for path, size in oversized
            )
            parser.error(
                f"Local target too large to stream into the sandbox: {details}. "
                f"The limit is {max_local_copy_mb} MB "
                "(set STRIX_MAX_LOCAL_COPY_MB to change it). Re-run with "
                "--mount <path> to bind-mount the directory instead of copying it."
            )

    return args


def _persist_run_record(args: argparse.Namespace) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "auth_mode": codex.auth_mode(load_settings().llm.model),
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
    }
    write_run_record(run_dir, run_record)


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        parser.error(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}: run.json unreadable: {exc}")

    raw_targets_info: Any = state.get("targets_info") or []
    if not isinstance(raw_targets_info, list):
        parser.error(f"--resume {args.resume}: run.json targets_info is not a list")
    raw_targets_info = cast("list[Any]", raw_targets_info)

    targets_info: list[dict[str, Any]] = [
        cast("dict[str, Any]", raw) for raw in raw_targets_info if isinstance(raw, dict)
    ]

    if not targets_info:
        parser.error(f"--resume {args.resume}: run.json has no targets_info")

    for target in targets_info:
        details_raw: Any = target.get("details")
        details: dict[str, Any] = (
            cast("dict[str, Any]", details_raw) if isinstance(details_raw, dict) else {}
        )
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not isinstance(cloned, str) or not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )

    args.targets_info = targets_info

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode


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
    view_text.append("         ")
    view_text.append(f"strix view {args.run_name}", style="#22c55e")
    panel_parts.extend(["\n", view_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"strix --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]STRIX",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print(
        "[#60a5fa]strix.ai[/]  [dim]·[/]  "
        "[#60a5fa]docs.strix.ai[/]  [dim]·[/]  "
        "[#60a5fa]discord.gg/strix-ai[/]"
    )
    console.print()
    # Upstream shows an update notice here; LyraShield Engine ships as reviewed
    # releases, so the upstream version check would suggest the wrong package.


def _normalize_digest(value: str) -> str:
    """Return the bare hex digest, removing repo prefix and ``sha256:``."""
    normalized = value.strip().lower()
    if "@" in normalized:
        normalized = normalized.rsplit("@", 1)[-1]
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    return normalized


def _verify_image_digest(client: Any, image: str, expected_digest: str) -> None:
    """Verify a pulled image matches an expected SHA256 digest if one is supplied."""
    try:
        pulled = client.images.get(image)
    except ImageNotFound as e:
        raise RuntimeError(f"Pulled image {image} not found for digest verification") from e

    expected = _normalize_digest(expected_digest)
    if not expected:
        raise RuntimeError(
            f"Image digest value for {image} is empty or malformed: {expected_digest!r}"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError(
            f"Image digest value for {image} is not a 64-character "
            f"SHA-256 hex string: {expected_digest!r}"
        )

    digests = pulled.attrs.get("RepoDigests") or []
    for digest_ref in digests:
        actual = _normalize_digest(str(digest_ref))
        if actual and actual == expected:
            logger.info("Image digest verified for %s", image)
            return

    raise RuntimeError(
        f"Image digest verification failed for {image}: expected {expected_digest}, found {digests}"
    )


def pull_docker_image() -> None:
    """Pull the configured sandbox image, optionally verifying ``STRIX_IMAGE_DIGEST``.

    If ``STRIX_IMAGE_DIGEST`` is set, the pulled image's ``RepoDigests`` must
    contain the expected value. The function exits on pull or verification failure.
    """
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image
    expected_digest = os.environ.get("STRIX_IMAGE_DIGEST", "").strip()

    needs_pull = not image_exists(client, image)
    if not needs_pull and expected_digest:
        try:
            _verify_image_digest(client, image, expected_digest)
        except RuntimeError:
            logger.warning("Local image %s digest does not match; re-pulling", image)
            needs_pull = True
        else:
            logger.debug("Docker image already present locally and digest verified: %s", image)
            return

    if not needs_pull:
        logger.debug("Docker image already present locally: %s", image)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]Pulling image[/] {image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

            if expected_digest:
                _verify_image_digest(client, image, expected_digest)

        except (DockerException, RuntimeError) as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def main() -> None:
    # Auto-load the engine .env if present; explicit shell exports still win.
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    except Exception:
        logger.debug("Could not load .env file; continuing without it", exc_info=True)

    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # `strix view [<run>]` is a viewer-only subcommand, dispatched before the
    # scan argument parser (which requires a target) and before any scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "view":
        from strix.viewer.cli import run_view

        run_view(sys.argv[2:])
        return

    # `strix auth …` manages model-subscription sign-in and exits; it needs no
    # target, Docker, or scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        from strix.interface.auth_cli import run_auth

        sys.exit(run_auth(sys.argv[2:]))

    # Provider checks are target-free deployment gates, not scans, so skip Docker.
    if len(sys.argv) > 1 and sys.argv[1] == "provider-contract":
        from strix.interface.provider_contract_cli import run_provider_contract

        sys.exit(run_provider_contract(sys.argv[2:]))

    args = parse_arguments()

    if args.config:
        apply_config_override(validate_config_file(args.config))

    validate_environment()
    check_docker_installed()
    pull_docker_image()

    # Non-interactive worker runs must not make an unmetered warm-up request or
    # persist provider credentials under the container home directory.
    warm_up_usages: list[tuple[str, Any]] = []
    args.warm_up_usages = warm_up_usages
    if not args.non_interactive:
        asyncio.run(warm_up_llm(show_model_warning=False, usages=warm_up_usages))

    args.run_name = args.resume or args.run_name or generate_run_name(args.targets_info)

    if not args.resume:
        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)
        try:
            diff_scope = resolve_diff_scope_context(
                local_sources=args.local_sources,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
            )
        except ValueError as e:
            console = Console()
            error_text = Text()
            error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(str(e), style="white")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print("\n")
            console.print(panel)
            console.print()
            sys.exit(1)

        args.diff_scope = diff_scope.metadata
        if diff_scope.instruction_block:
            if args.instruction:
                args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
            else:
                args.instruction = diff_scope.instruction_block

        _persist_run_record(args)

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
        case "budget_exceeded":
            return 3
        case "rate_limited":
            return 4
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
