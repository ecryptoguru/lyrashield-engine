"""Product boundary for the upstream Strix CLI."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import MutableMapping


ENV_ALIASES = {
    "LYRASHIELD_LLM": "STRIX_LLM",
    "LYRASHIELD_DELEGATE_LLM": "STRIX_DELEGATE_LLM",
    "LYRASHIELD_IMAGE": "STRIX_IMAGE",
    "LYRASHIELD_RUNTIME_BACKEND": "STRIX_RUNTIME_BACKEND",
    "LYRASHIELD_MAX_LOCAL_COPY_MB": "STRIX_MAX_LOCAL_COPY_MB",
    "LYRASHIELD_REASONING_EFFORT": "STRIX_REASONING_EFFORT",
    "LYRASHIELD_DELEGATE_REASONING_EFFORT": "STRIX_DELEGATE_REASONING_EFFORT",
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
    return env


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
