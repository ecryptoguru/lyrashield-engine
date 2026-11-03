"""Specialist turn guidance remains advisory beneath the hard ceiling."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from lyrashield.lifecycle import execution
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.hooks import ReportUsageHooks
from lyrashield.policy.loader import _read_json_overrides
from lyrashield.policy.settings import RuntimeSettings, Settings


def test_largest_selected_skill_limit_is_clamped_to_hard_ceiling() -> None:
    settings = RuntimeSettings(
        subagent_turn_limits={"vulnerabilities/xss": 30, "vulnerabilities/sql_injection": 80}
    )
    assert settings.skill_turn_limit(["xss", "vulnerabilities/sql_injection"], hard_limit=50) == 50
    assert settings.skill_turn_limit(["xss"], hard_limit=50) == 30
    assert settings.skill_turn_limit(["unconfigured"], hard_limit=50) is None


@pytest.mark.parametrize(
    "mapping",
    [
        {"xss": 10},
        {"../xss": 10},
        {"vulnerabilities/xss": 0},
        {"vulnerabilities/xss": True},
        {"vulnerabilities/xss": "20"},
    ],
)
def test_soft_limit_mapping_requires_qualified_names_and_positive_integers(mapping: dict) -> None:
    with pytest.raises(ValidationError):
        RuntimeSettings(subagent_turn_limits=mapping)


def test_soft_limit_warns_without_stopping_or_extending_hard_limit() -> None:
    hooks = ReportUsageHooks(model="test", max_turns=50)
    context = SimpleNamespace(
        context={"agent_id": "child", "parent_id": "root", "advisory_turn_limit": 20}
    )
    items = []
    hooks._maybe_warn_soft_turn_limit(context, items, turns_used=20)
    assert len(items) == 1
    assert "[SYSTEM-NOTICE]" in items[0]["content"]
    assert "advisory" in items[0]["content"].lower()
    assert "hard" in items[0]["content"].lower()
    assert hooks._max_turns == 50


@pytest.mark.asyncio
async def test_child_runner_receives_selected_limit_without_changing_hard_cap(
    tmp_path, monkeypatch
) -> None:

    coordinator = AgentCoordinator()
    await coordinator.register("child", "child", "root")
    runtime = RuntimeSettings(subagent_turn_limits={"vulnerabilities/xss": 20})
    monkeypatch.setattr(execution, "load_settings", lambda: SimpleNamespace(runtime=runtime))
    loop = AsyncMock()
    monkeypatch.setattr(execution, "run_agent_loop", loop)
    sessions = []
    try:
        await execution._start_child_runner(
            parent_ctx={"agent_id": "root"},
            coordinator=coordinator,
            agents_db_path=tmp_path / "agents.db",
            sessions_to_close=sessions,
            run_config=MagicMock(),
            max_turns=50,
            interactive=False,
            child_agent=MagicMock(),
            child_id="child",
            name="child",
            parent_id="root",
            task="bounded test",
            initial_input=[],
            skills=["xss"],
        )
        await coordinator.runtimes["child"].task
        assert loop.await_args.kwargs["context"]["advisory_turn_limit"] == 20
        assert loop.await_args.kwargs["max_turns"] == 50
    finally:
        for session in sessions:
            session.close()


def test_environment_mapping_is_parsed_and_root_is_not_warned(monkeypatch) -> None:
    monkeypatch.setenv("LYRASHIELD_SUBAGENT_TURN_LIMITS", '{"vulnerabilities/xss":20}')
    assert RuntimeSettings().subagent_turn_limits == {"vulnerabilities/xss": 20}
    hooks = ReportUsageHooks(model="test", max_turns=50)
    items = []
    hooks._maybe_warn_soft_turn_limit(
        SimpleNamespace(context={"parent_id": None, "advisory_turn_limit": 20}),
        items,
        turns_used=20,
    )
    assert items == []


@pytest.mark.asyncio
async def test_soft_warning_is_injected_on_actual_model_start(monkeypatch) -> None:
    hooks = ReportUsageHooks(model="test", max_turns=50)
    coordinator = AgentCoordinator()
    await coordinator.register("child", "child", "root")
    coordinator.model_start_counts["child"] = 19
    context = SimpleNamespace(
        context={
            "agent_id": "child",
            "parent_id": "root",
            "advisory_turn_limit": 20,
            "coordinator": coordinator,
        }
    )
    monkeypatch.setattr(hooks_module, "_compact_input_items", lambda *_args: (10, 10))
    items = []
    await hooks.on_llm_start(context, SimpleNamespace(name="child", model="test"), None, items)
    assert any("Specialist advisory" in item["content"] for item in items)
    assert coordinator.model_start_counts["child"] == 20


def test_persisted_environment_mapping_restores_from_config_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("LYRASHIELD_SUBAGENT_TURN_LIMITS", raising=False)
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"env": {"LYRASHIELD_SUBAGENT_TURN_LIMITS": '{"vulnerabilities/xss":20}'}})
    )
    restored = Settings(**_read_json_overrides(config))
    assert restored.runtime.subagent_turn_limits == {"vulnerabilities/xss": 20}
