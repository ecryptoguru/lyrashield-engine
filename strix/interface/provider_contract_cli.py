"""CLI for bounded provider capability release gates."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from strix.config import apply_config_override, load_settings
from strix.interface.utils import validate_config_file
from strix.provider_contract import probe_provider_contract


if TYPE_CHECKING:
    from collections.abc import Sequence


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= parsed <= 128:
        raise argparse.ArgumentTypeError("must be between 1 and 128")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lyrashield provider-contract",
        description="Run a bounded, static provider capability probe.",
    )
    parser.add_argument("--config", type=Path, help="Optional CLI JSON config path")
    parser.add_argument("--max-output-tokens", type=_positive_int, default=64)
    parser.add_argument("--timeout-seconds", type=_positive_float, default=None)
    parser.add_argument("--require-programmatic-tool-calling", action="store_true")
    parser.add_argument("--require-previous-response-id", action="store_true")
    return parser


def run_provider_contract(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(list(argv))
    if args.config is not None:
        apply_config_override(validate_config_file(str(args.config)))
    try:
        result = asyncio.run(
            probe_provider_contract(
                load_settings(),
                max_output_tokens=args.max_output_tokens,
                timeout_seconds=args.timeout_seconds,
            )
        )
    except (RuntimeError, ValueError) as exc:
        print(f"provider-contract: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    print(json.dumps(result.as_dict(), sort_keys=True))  # noqa: T201
    return int(
        not result.meets_requirements(
            require_programmatic_tool_calling=args.require_programmatic_tool_calling,
            require_previous_response_id=args.require_previous_response_id,
        )
    )
