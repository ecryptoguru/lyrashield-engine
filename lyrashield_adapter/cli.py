"""Product boundary for the upstream Strix CLI."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, cast, get_args, get_origin


if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping

    from agents.tool import Tool

from pydantic import AliasChoices, BaseModel

from lyrashield.policy import loader as _lyra_loader  # noqa: F401
from lyrashield.policy.settings import (
    PRODUCT_BOUNDARY_ENV_VAR,
    Settings,
    is_chatgpt_subscription_allowed,
)


try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # type: ignore[assignment]


# ``chatgpt/<model>`` routes inference through a ChatGPT subscription
# (``strix/config/codex.py``), which bypasses the Terra/Luna deployment gate and
# records the run with zero metered cost. LyraShield scans are metered per token,
# so the product entry point refuses subscription-backed models outright.
_SUBSCRIPTION_PREFIX = "chatgpt/"


def _build_env_aliases() -> dict[str, str]:
    """Derive LYRASHIELD_* -> upstream env mappings from the Settings schema.

    This keeps the adapter in sync with the ``_lyra()`` pydantic aliasing in
    ``strix.config.settings`` instead of maintaining a parallel hard-coded list.
    """
    aliases: dict[str, str] = {}

    def _walk(model: type[BaseModel]) -> None:
        for finfo in model.model_fields.values():
            ann = finfo.annotation
            origin = get_origin(ann)
            if origin is not None:
                for arg in get_args(ann):
                    if isinstance(arg, type) and issubclass(arg, BaseModel):
                        _walk(arg)
            elif isinstance(ann, type) and issubclass(ann, BaseModel):
                _walk(ann)

            va = finfo.validation_alias
            if not isinstance(va, AliasChoices):
                continue
            choices = [c for c in va.choices if isinstance(c, str)]
            if not choices:
                continue
            product: str | None = None
            upstream: str | None = None
            for c in choices:
                if c.upper().startswith("LYRASHIELD_"):
                    product = c
                elif upstream is None:
                    upstream = c
            if product and upstream:
                aliases[product] = upstream

    _walk(Settings)
    return aliases


ENV_ALIASES = _build_env_aliases()


_STALE_EMPTY_ENV_VARS = ("LLM_API_KEY", "LLM_API_BASE", "LLM_API_VERSION")


_MODEL_ENV_VARS_UPSTREAM = ("STRIX_LLM", "STRIX_DELEGATE_LLM", "STRIX_DEDUPE_MODEL")
_MODEL_ENV_VARS_PRODUCT = tuple(
    product for product, upstream in ENV_ALIASES.items() if upstream in _MODEL_ENV_VARS_UPSTREAM
)
_MODEL_ENV_VARS = _MODEL_ENV_VARS_UPSTREAM + _MODEL_ENV_VARS_PRODUCT


# Marks the process as running behind the product entry point. ``--config`` is
# applied after this module hands off to the upstream CLI and can set a model
# the env gate below never saw, so ``validate_environment`` re-checks the
# resolved settings when this flag is present. The bare ``strix`` dev CLI does
# not set it and keeps upstream behavior. Imported lazily in
# ``prepare_environment`` to keep ``--version`` free of the strix import cost.


def prepare_environment(
    environ: MutableMapping[str, str] | None = None,
) -> MutableMapping[str, str]:
    env = environ if environ is not None else os.environ
    # Remove stale empty generic LLM env vars that would shadow Azure-specific
    # aliases via pydantic AliasChoices priority (first match wins, even if empty).
    for name in _STALE_EMPTY_ENV_VARS:
        if env.get(name, "").strip() == "":
            env.pop(name, None)
    for product_name, upstream_name in ENV_ALIASES.items():
        if upstream_name not in env and product_name in env:
            env[upstream_name] = env[product_name]
    env["STRIX_TELEMETRY"] = "0"
    # Self-update would replace this controlled derivative with the upstream
    # distribution; the update check also makes network calls during scans.
    env["STRIX_NO_UPDATE_CHECK"] = "1"
    env[PRODUCT_BOUNDARY_ENV_VAR] = "1"
    _reject_subscription_models(env)
    _reject_unsupported_gpt56_providers(env)
    return env


def _reject_subscription_models(env: MutableMapping[str, str]) -> None:
    if is_chatgpt_subscription_allowed(env):
        return
    for name in _MODEL_ENV_VARS:
        value = env.get(name, "").strip()
        if value.lower().startswith(_SUBSCRIPTION_PREFIX):
            msg = (
                f"{name}={value} routes through a ChatGPT subscription, which is "
                "not supported for LyraShield scans. Configure a GPT-5.6 Terra or "
                "Luna API deployment instead."
            )
            raise SystemExit(msg)


def _reject_unsupported_gpt56_providers(env: MutableMapping[str, str]) -> None:
    """Fail fast if a model env var names a GPT-5.6 deployment from an unsupported provider.

    LiteLLM's cost map currently only lists ``openai``, ``azure``, and
    ``bedrock_mantle`` for ``gpt-5.6-*``. The Azure alias ``azure_ai`` and the
    ChatGPT subscription route ``chatgpt/`` are also allowed.
    """
    from lyrashield.policy.models import (  # noqa: PLC0415
        is_gpt56_model,
        is_gpt56_supported_provider,
    )

    for name in _MODEL_ENV_VARS:
        value = env.get(name, "").strip()
        if not value:
            continue
        if is_gpt56_supported_provider(value):
            continue
        if is_gpt56_model(value):
            msg = (
                f"{name}={value} is a GPT-5.6 Terra/Luna deployment, but its "
                "provider is not currently supported by LyraShield. Supported "
                "providers are openai, azure, azure_ai, bedrock_mantle, and "
                "chatgpt (with `lyrashield auth login chatgpt`)."
            )
            raise SystemExit(msg)


def get_version() -> str:
    try:
        return version("lyrashield-engine")
    except PackageNotFoundError:
        return "unknown"


def _register_lyrashield_skills() -> None:
    from strix.skills import register_skill_dir  # noqa: PLC0415

    register_skill_dir(Path(__file__).resolve().parents[1] / "lyrashield" / "skills")


# Product tool overrides, mapped as override name -> (module, attribute). The
# modules are imported only when an override is actually resolved (the scan
# path), so non-scan subcommands (auth, view, provider-contract) never pay
# for the product toolset imports at CLI startup.
_TOOL_OVERRIDE_SPECS: dict[str, tuple[str, str]] = {
    "agent_finish": ("lyrashield.tools.agents_graph.tools", "agent_finish"),
    "create_agent": ("lyrashield.tools.agents_graph.tools", "create_agent"),
    "send_message_to_agent": ("lyrashield.tools.agents_graph.tools", "send_message_to_agent"),
    "stop_agent": ("lyrashield.tools.agents_graph.tools", "stop_agent"),
    "view_agent_graph": ("lyrashield.tools.agents_graph.tools", "view_agent_graph"),
    "wait_for_agents": ("lyrashield.tools.agents_graph.tools", "wait_for_agents"),
    "web_search": ("lyrashield.tools.web_search.tool", "web_search"),
    "respond_to_user": ("lyrashield.tools.respond.tool", "respond_to_user"),
    "list_requests": ("lyrashield.tools.proxy.tools", "list_requests"),
    "view_request": ("lyrashield.tools.proxy.tools", "view_request"),
    "repeat_request": ("lyrashield.tools.proxy.tools", "repeat_request"),
    "list_sitemap": ("lyrashield.tools.proxy.tools", "list_sitemap"),
    "view_sitemap_entry": ("lyrashield.tools.proxy.tools", "view_sitemap_entry"),
    "scope_rules": ("lyrashield.tools.proxy.tools", "scope_rules"),
    "create_vulnerability_report": (
        "lyrashield.tools.reporting.tool",
        "create_vulnerability_report",
    ),
    "create_dependency_report": (
        "lyrashield.tools.reporting.tool",
        "create_dependency_report",
    ),
    "list_reports": ("lyrashield.tools.reporting.tool", "list_reports"),
    "get_report": ("lyrashield.tools.reporting.tool", "get_report"),
    "create_todo": ("lyrashield.tools.todo.tools", "create_todo"),
    "list_todos": ("lyrashield.tools.todo.tools", "list_todos"),
    "update_todo": ("lyrashield.tools.todo.tools", "update_todo"),
    "mark_todo_done": ("lyrashield.tools.todo.tools", "mark_todo_done"),
    "mark_todo_pending": ("lyrashield.tools.todo.tools", "mark_todo_pending"),
    "delete_todo": ("lyrashield.tools.todo.tools", "delete_todo"),
}


def _register_lyrashield_tool_overrides() -> None:
    from importlib import import_module  # noqa: PLC0415

    from lyrashield.agents.overrides import (  # noqa: PLC0415
        register_tool_override_loader,
    )

    def _loader(module_name: str, attr: str) -> Callable[[], Tool]:
        def _load() -> Tool:
            return cast("Tool", getattr(import_module(module_name), attr))

        return _load

    for name, (module_name, attr) in _TOOL_OVERRIDE_SPECS.items():
        register_tool_override_loader(name, _loader(module_name, attr))


def _register_lyrashield_model_policy() -> None:
    from lyrashield.agents.overrides import (  # noqa: PLC0415
        register_model_policy_loader,
    )

    def _load() -> Callable[..., object]:
        from lyrashield.policy.models import (  # noqa: PLC0415
            model_supports_programmatic_tool_calling,
        )

        return model_supports_programmatic_tool_calling

    register_model_policy_loader("model_supports_programmatic_tool_calling", _load)


def _run_upstream() -> None:
    from lyrashield.interface.main import main as product_main  # noqa: PLC0415

    product_main()


def main() -> None:
    if sys.argv[1:] in (["--version"], ["-v"]):
        print(f"lyrashield {get_version()}")  # noqa: T201
        return
    if load_dotenv is not None:
        # Caller-supplied env vars must win over a local .env file.
        load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
    prepare_environment()
    _register_lyrashield_skills()
    _register_lyrashield_tool_overrides()
    _register_lyrashield_model_policy()
    _run_upstream()


if __name__ == "__main__":
    main()
