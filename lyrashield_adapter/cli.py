"""Product boundary for the upstream Strix CLI."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, get_args, get_origin


if TYPE_CHECKING:
    from collections.abc import MutableMapping

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


def _register_lyrashield_tool_overrides() -> None:
    from lyrashield.tools.proxy.tools import (  # noqa: PLC0415
        list_requests,
        list_sitemap,
        repeat_request,
        scope_rules,
        view_request,
        view_sitemap_entry,
    )
    from lyrashield.tools.reporting.tool import (  # noqa: PLC0415
        create_dependency_report,
        create_vulnerability_report,
        get_report,
        list_reports,
    )
    from lyrashield.tools.respond.tool import (  # noqa: PLC0415
        respond_to_user as lyra_respond_to_user,
    )
    from lyrashield.tools.todo.tools import (  # noqa: PLC0415
        create_todo,
        delete_todo,
        list_todos,
        mark_todo_done,
        mark_todo_pending,
        update_todo,
    )
    from lyrashield.tools.web_search.tool import (  # noqa: PLC0415
        web_search as lyra_web_search,
    )
    from strix.agents.factory import register_tool_override  # noqa: PLC0415

    register_tool_override("web_search", lyra_web_search)
    register_tool_override("respond_to_user", lyra_respond_to_user)

    register_tool_override("list_requests", list_requests)
    register_tool_override("view_request", view_request)
    register_tool_override("repeat_request", repeat_request)
    register_tool_override("list_sitemap", list_sitemap)
    register_tool_override("view_sitemap_entry", view_sitemap_entry)
    register_tool_override("scope_rules", scope_rules)
    register_tool_override("create_vulnerability_report", create_vulnerability_report)
    register_tool_override("create_dependency_report", create_dependency_report)
    register_tool_override("list_reports", list_reports)
    register_tool_override("get_report", get_report)
    register_tool_override("create_todo", create_todo)
    register_tool_override("list_todos", list_todos)
    register_tool_override("update_todo", update_todo)
    register_tool_override("mark_todo_done", mark_todo_done)
    register_tool_override("mark_todo_pending", mark_todo_pending)
    register_tool_override("delete_todo", delete_todo)


def _register_lyrashield_model_policy() -> None:
    from lyrashield.policy.models import (  # noqa: PLC0415
        model_supports_programmatic_tool_calling,
    )
    from strix.agents.factory import register_model_policy  # noqa: PLC0415

    register_model_policy(
        "model_supports_programmatic_tool_calling",
        model_supports_programmatic_tool_calling,
    )


def _run_upstream() -> None:
    from strix.interface.main import main as upstream_main  # noqa: PLC0415

    upstream_main()


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
