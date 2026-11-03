"""CLI boundary for bounded AI-security triage artifacts."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from lyrashield.artifacts.financial_io import FinancialDirectory
from lyrashield.artifacts.finite_budget import active_journal, protected_run
from lyrashield.artifacts.state import (
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from lyrashield.lifecycle.hooks import get_active_hooks, set_active_hooks
from lyrashield.policy.loader import load_settings
from lyrashield.triage.service import (
    TRIAGE_OUTPUT_SCHEMA_VERSION,
    TriageInput,
    invalid_input_artifact,
    run_triage,
    triage_cache_key,
    write_artifact,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an additive bounded AI-security triage artifact"
    )
    parser.add_argument(
        "--input", required=True, type=Path, help="Versioned deterministic candidate JSON"
    )
    parser.add_argument("--output", required=True, type=Path, help="Output ai-security-triage.json")
    parser.add_argument(
        "--cache-dir", type=Path, help="Private cache directory for redacted artifacts"
    )
    parser.add_argument("--enabled", action="store_true", help="Allow paid-scan triage execution")
    parser.add_argument(
        "--max-budget-usd",
        type=_positive_budget,
        help="Remaining protected scan budget available to triage",
    )
    return parser.parse_args(argv)


def _positive_budget(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("budget must be a number") from error
    if not (parsed > 0 and parsed < 1_000):
        raise argparse.ArgumentTypeError("budget must be greater than 0 and less than 1000")
    return parsed


def _luna_model_route() -> str:
    settings = load_settings()
    configured = (settings.llm.delegate_model, settings.llm.model)
    for route in configured:
        if route and route.strip().lower().endswith("gpt-6-luna"):
            return route.strip()
    return os.environ.get("LYRASHIELD_LUNA_LLM", "").strip() or "unconfigured"


def _read_cached(path: Path, *, cache_key: str) -> dict[str, object] | None:
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(cached, dict):
        return None
    if (
        cached.get("schemaVersion") != TRIAGE_OUTPUT_SCHEMA_VERSION
        or cached.get("cacheKey") != cache_key
        or cached.get("status") != "COMPLETED"
    ):
        return None
    return cached


def run_triage_cli(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    model_route = _luna_model_route()
    try:
        raw_input = args.input.read_text(encoding="utf-8")
    except OSError:
        write_artifact(args.output, invalid_input_artifact("", model_route=model_route))
        return 2
    try:
        triage_input = TriageInput.model_validate_json(raw_input)
    except ValidationError:
        write_artifact(args.output, invalid_input_artifact(raw_input, model_route=model_route))
        return 2

    cache_key = triage_cache_key(triage_input, model_route=model_route)
    cache_path = args.cache_dir / f"{cache_key}.json" if args.cache_dir else None
    if args.enabled and cache_path is not None:
        cached = _read_cached(cache_path, cache_key=cache_key)
        if cached is not None:
            write_artifact(args.output, dict(cached))
            return 0

    owner = None
    borrowed = None
    previous_state, previous_hooks = get_global_report_state(), get_active_hooks()
    workspace = args.input.absolute().parent
    candidate = ReportState(workspace.name) if args.enabled else None
    run_dir = candidate.get_run_dir(create=False, cwd=workspace) if candidate is not None else None
    existing = run_dir is not None and protected_run(run_dir)
    if (
        candidate is not None
        and run_dir is not None
        and (args.max_budget_usd is not None or existing)
    ):
        owner = candidate
        owner._run_dir = run_dir
        # Hydration is read-only after checking/creating financial parents without
        # traversing aliases. This is the worker's actual main scan output layout.
        directory = FinancialDirectory(owner._run_dir, create=True)
        directory.close()
        owner.hydrate_from_run_dir()
        existing = protected_run(owner._run_dir, owner.run_record)
        borrowed = active_journal(owner._run_dir)
        owner.enable_finite_budget(
            None if existing else owner.get_total_llm_cost() + float(args.max_budget_usd)
        )
        set_global_report_state(owner)
        set_active_hooks(None)
    try:
        artifact = asyncio.run(
            run_triage(
                triage_input,
                model_route=model_route,
                enabled=bool(args.enabled),
                max_budget_usd=args.max_budget_usd,
                checkpoint=lambda progress: write_artifact(args.output, progress),
                report_state=owner,
            )
        )
    finally:
        if owner is not None:
            set_global_report_state(previous_state)
            set_active_hooks(previous_hooks)
            if owner._finite_budget is not None and owner._finite_budget is not borrowed:
                owner._finite_budget.close()
    write_artifact(args.output, artifact)
    if cache_path is not None and artifact["status"] == "COMPLETED":
        write_artifact(cache_path, artifact)
    return 0
