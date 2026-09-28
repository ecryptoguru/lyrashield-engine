"""Model and environment admission checks for scan entrypoints."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.policy import codex
from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import is_gpt6_supported_provider


if TYPE_CHECKING:
    from lyrashield.policy.settings import Settings


logger = logging.getLogger(__name__)


def _reject_resolved_subscription_models(settings: Settings, console: Console) -> None:
    """Reject subscription-backed models that reached settings via `--config`.

    The product entry point (`lyrashield_adapter.cli`) admits `chatgpt/gpt-6-*`
    models at the environment level only for the main model, but `--config` is
    applied afterwards. A subscription route records zero metered cost, so it
    stays confined to ``STRIX_LLM`` — delegate and dedupe models must use a
    metered GPT-6 API route.
    """
    configured = {
        "STRIX_LLM": settings.llm.model,
        "STRIX_DELEGATE_LLM": getattr(settings.llm, "delegate_model", None),
        "STRIX_DEDUPE_MODEL": getattr(settings, "dedupe", None) and settings.dedupe.model,
    }
    for name, value in configured.items():
        if not codex.subscription_model(value):
            continue
        if name == "STRIX_LLM" and settings.product.allow_chatgpt_subscription:
            continue
        console.print(
            f"[bold red]{name}={value} routes through a ChatGPT subscription, "
            "which is not supported for LyraShield scans.[/] Configure a GPT-6 "
            "Sol or Luna API deployment instead."
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

    if not settings.llm.model:
        missing_required_vars.append("STRIX_LLM or LYRASHIELD_LLM")
    elif (
        (
            not codex.subscription_model(settings.llm.model)
            and not is_gpt6_supported_provider(settings.llm.model)
        )
        or (
            settings.llm.delegate_model
            and not is_gpt6_supported_provider(settings.llm.delegate_model)
        )
        or (settings.dedupe.model and not is_gpt6_supported_provider(settings.dedupe.model))
    ):
        error_text = Text(
            "LyraShield scans require a GPT-6 Sol or Luna deployment from a supported provider",
            style="bold red",
        )
        console.print("\n")
        console.print(
            Panel(
                error_text,
                title="[bold white]LYRASHIELD",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            ),
        )
        console.print()
        sys.exit(1)

    if codex.subscription_model(settings.llm.model):
        if not settings.product.allow_chatgpt_subscription:
            console.print(
                f"[bold red]STRIX_LLM={settings.llm.model} routes through a ChatGPT "
                "subscription, which is not supported for LyraShield scans.[/] "
                "Set LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=1 or configure a GPT-6 "
                "Sol or Luna API deployment instead."
            )
            sys.exit(1)
        normalized_subscription_route = (settings.llm.model or "").strip().lower().replace("_", "-")
        if normalized_subscription_route not in {"chatgpt/gpt-6-sol", "chatgpt/gpt-6-luna"}:
            console.print(
                f"[bold red]STRIX_LLM={settings.llm.model} is not a GPT-6 Sol or "
                "Luna deployment.[/] Subscription scans require a "
                "chatgpt/gpt-6-sol or chatgpt/gpt-6-luna route."
            )
            sys.exit(1)
        if not codex.is_authenticated():
            console.print(
                f"[red]STRIX_LLM={settings.llm.model} uses your ChatGPT subscription, "
                "but you're not signed in.[/] Run [cyan]lyrashield auth login chatgpt[/] first."
            )
            sys.exit(1)
        logger.info("Environment OK (ChatGPT subscription)")
        return

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
                    " - GPT-6 Sol or Luna deployment name\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the configured GPT-6 endpoint\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Base URL for the configured GPT-6 endpoint\n",
                        style="white",
                    )
                elif var in {"STRIX_REASONING_EFFORT", "LYRASHIELD_REASONING_EFFORT"}:
                    error_text.append("• ", style="white")
                    error_text.append(
                        "STRIX_REASONING_EFFORT / LYRASHIELD_REASONING_EFFORT",
                        style="bold cyan",
                    )
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh, "
                        "max (default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append(
            "export LYRASHIELD_LLM='openai/gpt-6-luna'\n",
            style="dim white",
        )

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# credential for the configured GPT-6 endpoint\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='https://your-gpt-6-endpoint.example'\n",
                        style="dim white",
                    )
                elif var in {"STRIX_REASONING_EFFORT", "LYRASHIELD_REASONING_EFFORT"}:
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'  # or LYRASHIELD_REASONING_EFFORT\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.debug("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )
