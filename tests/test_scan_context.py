from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.lifecycle.scan_context import build_scan_context


if TYPE_CHECKING:
    from pathlib import Path


def _settings(*, delegate_model: str | None = None) -> Any:
    return types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="azure_ai/gpt-6-sol",
            delegate_model=delegate_model,
            reasoning_effort="medium",
            delegate_reasoning_effort="high",
        ),
    )


def test_build_scan_context_resolves_paths_and_models(tmp_path: Path) -> None:
    calls: list[str] = []
    settings = _settings()

    context = build_scan_context(
        scan_id="scan-context",
        scan_config={"scan_mode": "standard"},
        model=None,
        resume=True,
        run_dir_for=lambda scan_id: tmp_path / scan_id,
        runtime_state_dir=lambda run_dir: run_dir / "state",
        setup_scan_logging=lambda _run_dir: lambda: calls.append("teardown"),
        set_scan_id=lambda scan_id: calls.append(f"scan-id:{scan_id}"),
        load_settings=lambda: settings,
        configure_sdk_model_defaults=lambda value: calls.append(f"configure:{value is settings}"),
        uses_chat_completions_tool_schema=lambda name, _settings: name.endswith("gpt-6-sol"),
    )

    assert context.paths.scan_id == "scan-context"
    assert context.paths.run_dir == tmp_path / "scan-context"
    assert context.paths.state_dir == tmp_path / "scan-context" / "state"
    assert context.paths.agents_path == context.paths.state_dir / "agents.json"
    assert context.paths.agents_db == context.paths.state_dir / "agents.db"
    assert context.paths.is_resume is True
    assert context.settings is settings
    assert context.llm_settings is settings.llm
    assert context.resolved_model == "azure_ai/gpt-6-sol"
    assert context.delegate_model == context.resolved_model
    assert context.delegate_reasoning_effort == "high"
    assert context.chat_completions_tools is True
    assert context.delegate_chat_completions_tools is True
    assert context.scan_mode == "standard"
    assert calls == ["scan-id:scan-context", "configure:True"]
    context.paths.teardown_logging()
    assert calls[-1] == "teardown"


def test_build_scan_context_fails_before_model_routing_when_unconfigured(tmp_path: Path) -> None:
    events: list[str] = []
    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(model="", reasoning_effort="medium"),
    )

    with pytest.raises(RuntimeError, match="No LLM model configured"):
        build_scan_context(
            scan_id="scan-no-model",
            scan_config={},
            model=None,
            resume=False,
            run_dir_for=lambda scan_id: tmp_path / scan_id,
            runtime_state_dir=lambda run_dir: run_dir / "state",
            setup_scan_logging=lambda _run_dir: lambda: None,
            set_scan_id=lambda _scan_id: None,
            load_settings=lambda: settings,
            configure_sdk_model_defaults=lambda _settings: None,
            uses_chat_completions_tool_schema=lambda *_args: events.append("route") or False,
        )

    assert not events
