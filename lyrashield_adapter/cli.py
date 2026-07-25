"""Product boundary for the upstream Strix CLI."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import MutableMapping


# ``chatgpt/<model>`` routes inference through a ChatGPT subscription
# (``strix/config/codex.py``), which bypasses the Terra/Luna deployment gate and
# records the run with zero metered cost. LyraShield scans are metered per token,
# so the product entry point refuses subscription-backed models outright.
_SUBSCRIPTION_PREFIX = "chatgpt/"
_MODEL_ENV_VARS = ("STRIX_LLM", "STRIX_DELEGATE_LLM", "STRIX_DEDUPE_MODEL")


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


def prepare_environment(
    environ: MutableMapping[str, str] | None = None,
) -> MutableMapping[str, str]:
    env = environ if environ is not None else os.environ
    for product_name, upstream_name in ENV_ALIASES.items():
        if upstream_name not in env and product_name in env:
            env[upstream_name] = env[product_name]
    env["STRIX_TELEMETRY"] = "0"
    # Self-update would replace this controlled derivative with the upstream
    # distribution; the update check also makes network calls during scans.
    env["STRIX_NO_UPDATE_CHECK"] = "1"
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
    prepare_environment()
    if sys.argv[1:] in (["--version"], ["-v"]):
        print(f"lyrashield {get_version()}")  # noqa: T201
        return
    _run_upstream()


if __name__ == "__main__":
    main()
