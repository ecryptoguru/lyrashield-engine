"""LLM startup warm-up and connection error guidance."""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

from agents.models.interface import ModelTracing
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy import codex
from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    configure_sdk_model_defaults,
    is_known_openai_bare_model,
    is_recommended_or_frontier_model,
)


logger = logging.getLogger(__name__)


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


def _subscription_error_hint(exc: BaseException) -> str | None:
    """Return an actionable hint for a known ChatGPT-subscription error, or None."""
    if not codex.subscription_model(load_settings().llm.model):
        return None
    joined = " ".join(_exception_messages(exc)).lower()
    if "not supported when using codex with a chatgpt account" in joined:
        return (
            "This model isn't available on your ChatGPT subscription. "
            "Set STRIX_LLM to a model your plan includes (e.g. chatgpt/gpt-6-luna)."
        )
    if (
        "error code: 401" in joined
        or "http 401" in joined
        or "unauthorized" in joined
        or "invalid_grant" in joined
    ):
        return (
            "Your ChatGPT sign-in has expired or was revoked. Sign in again:\n"
            "  lyrashield auth login chatgpt"
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
                "' form, e.g. 'openai/gpt-6-luna'.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]LYRASHIELD",
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
                " is not a recommended frontier model for LyraShield.\n"
                "Security scans work best with:\n",
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
                    title="[bold white]LYRASHIELD",
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
                model_settings=make_model_settings(
                    None,
                    model_name=raw_model,
                    request_timeout=llm.timeout,
                    extra_headers=llm.extra_headers,
                ),
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
            from lyrashield.artifacts.dedupe import resolve_dedupe_model

            dedupe_model = settings.dedupe.model.strip()
            raw_model = dedupe_model
            # Credentials ride on the dedupe model's own provider, matching the
            # runtime path — a separate-provider dedupe model authenticates
            # during warm-up too without clobbering the main model's globals.
            deduper = resolve_dedupe_model(settings.dedupe, dedupe_model, settings=settings)
            # A dedicated dedupe model may route to another provider, which must
            # never receive the main endpoint's headers; it has its own
            # DEDUPE_LLM_EXTRA_HEADERS.
            deduper_settings = make_model_settings(
                None,
                model_name=dedupe_model,
                request_timeout=llm.timeout,
                extra_headers=settings.dedupe.extra_headers,
            )
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
        logger.debug("LLM warm-up failed", exc_info=True)
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
            error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style=border_style,
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
