"""Product boundary for the upstream Strix CLI."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # type: ignore[assignment, misc]


if TYPE_CHECKING:
    from collections.abc import MutableMapping


# ``chatgpt/<model>`` routes inference through a ChatGPT subscription
# (``strix/config/codex.py``), which bypasses the Terra/Luna deployment gate and
# records the run with zero metered cost. LyraShield scans are metered per token,
# so the product entry point refuses subscription-backed models outright.
_SUBSCRIPTION_PREFIX = "chatgpt/"
_MODEL_ENV_VARS = ("STRIX_LLM", "STRIX_DELEGATE_LLM", "STRIX_DEDUPE_MODEL")

# Marks the process as running behind the product entry point. ``--config`` is
# applied after this module hands off to the upstream CLI and can set a model
# the env gate below never saw, so ``validate_environment`` re-checks the
# resolved settings when this flag is present. The bare ``strix`` dev CLI does
# not set it and keeps upstream behavior. Imported lazily in
# ``prepare_environment`` to keep ``--version`` free of the strix import cost.


ENV_ALIASES = {
    "LYRASHIELD_LLM": "STRIX_LLM",
    "LYRASHIELD_DELEGATE_LLM": "STRIX_DELEGATE_LLM",
    "LYRASHIELD_IMAGE": "STRIX_IMAGE",
    "LYRASHIELD_RUNTIME_BACKEND": "STRIX_RUNTIME_BACKEND",
    "LYRASHIELD_MAX_LOCAL_COPY_MB": "STRIX_MAX_LOCAL_COPY_MB",
    "LYRASHIELD_MAX_CONTEXT_IMAGES": "STRIX_MAX_CONTEXT_IMAGES",
    "LYRASHIELD_REASONING_EFFORT": "STRIX_REASONING_EFFORT",
    "LYRASHIELD_DELEGATE_REASONING_EFFORT": "STRIX_DELEGATE_REASONING_EFFORT",
    "LYRASHIELD_FORCE_REQUIRED_TOOL_CHOICE": "STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    "LYRASHIELD_LLM_TIMEOUT": "LLM_TIMEOUT",
    "LYRASHIELD_TELEMETRY": "STRIX_TELEMETRY",
}


_STALE_EMPTY_ENV_VARS = ("LLM_API_KEY", "LLM_API_BASE", "LLM_API_VERSION")


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
    from strix.config.settings import PRODUCT_BOUNDARY_ENV_VAR  # noqa: PLC0415

    env[PRODUCT_BOUNDARY_ENV_VAR] = "1"
    _reject_subscription_models(env)
    return env


def _reject_subscription_models(env: MutableMapping[str, str]) -> None:
    for name in _MODEL_ENV_VARS:
        value = env.get(name, "").strip()
        if value.lower().startswith(_SUBSCRIPTION_PREFIX):
            msg = (
                f"{name}={value} routes through a ChatGPT subscription, which is "
                "not supported for LyraShield scans. Configure a GPT-5.6 Terra or "
                "Luna API deployment instead."
            )
            raise SystemExit(msg)


def get_version() -> str:
    try:
        return version("lyrashield-engine")
    except PackageNotFoundError:
        return "unknown"


def _run_upstream() -> None:
    from strix.interface.main import main as upstream_main  # noqa: PLC0415

    upstream_main()


def main() -> None:
    if load_dotenv:
        load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)
    prepare_environment()
    if sys.argv[1:] in (["--version"], ["-v"]):
        print(f"lyrashield {get_version()}")  # noqa: T201
        return
    _run_upstream()


if __name__ == "__main__":
    main()
