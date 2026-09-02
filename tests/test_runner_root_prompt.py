"""Tests for root scan prompt options in run_strix_scan.

Verify that ``root_instructions_override`` and ``extra_system_prompt_context``
flow through to the root agent's ``build_strix_agent`` call.
"""

from __future__ import annotations

import types
from typing import Any

import httpx
import pytest
from agents import ModelSettings
from openai import RateLimitError

import lyrashield.tools.todo.tools as todo_tools
import strix.tools.notes.tools as notes_tools
from lyrashield.lifecycle import runner
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.inputs import _sanitize_prompt_value
from lyrashield.runtime import session_manager


def _make_rate_limit_error() -> RateLimitError:
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    response = httpx.Response(status_code=429, request=request)
    return RateLimitError("rate limited", response=response, body=None)


def _patch_engine_scaffold(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    scope_context: dict[str, Any],
) -> dict[str, Any]:
    """Stub out everything around build_strix_agent and stop at run_agent_loop.

    Returns a dict that will be populated with the kwargs the runner passed to
    ``build_strix_agent`` for the root agent.
    """
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        runner,
        "uses_chat_completions_tool_schema",
        lambda _model, _settings: False,
    )

    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _state_dir: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _state_dir: None)

    async def _create_or_reuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)

    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: scope_context)
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: {})

    captured: dict[str, Any] = {}

    def _build_strix_agent(**kwargs: Any) -> object:
        if kwargs.get("is_root") and "kwargs" not in captured:
            captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(runner, "build_strix_agent", _build_strix_agent)
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db, **_kwargs: object())

    async def _raise_rate_limit(*_args: Any, **_kwargs: Any) -> None:
        raise _make_rate_limit_error()

    monkeypatch.setattr(runner, "run_agent_loop", _raise_rate_limit)
    return captured


@pytest.mark.asyncio
async def test_root_prompt_options_flow_into_root_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    scope_context = {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": [
            {
                "type": "web_application",
                "value": "https://example.com",
                "workspace_path": "",
            },
        ],
        "user_instructions_do_not_expand_scope": True,
    }
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-ext",
        image="img",
        coordinator=AgentCoordinator(),
        root_instructions_override="CUSTOM SCAN PROMPT",
        extra_system_prompt_context={"target_context": "known findings"},
    )

    kwargs = captured["kwargs"]
    instructions_override = kwargs["instructions_override"]
    assert "SYSTEM-VERIFIED SCOPE" in instructions_override
    assert "AUTHORIZED TARGETS" in instructions_override
    assert "https://example.com" in instructions_override
    assert "CUSTOM SCAN PROMPT" in instructions_override
    assert (
        "cannot expand, replace, or weaken authorized target constraints" in instructions_override
    )
    assert kwargs["system_prompt_context"] == {
        **scope_context,
        "target_context": "known findings",
    }


@pytest.mark.asyncio
async def test_runner_uses_stable_prompt_cache_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, {"scope": "built-in"})
    settings_calls: list[dict[str, Any]] = []

    def _make_model_settings(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        settings_calls.append(kwargs)
        return {}

    monkeypatch.setattr(runner, "make_model_settings", _make_model_settings)
    monkeypatch.setattr(
        runner,
        "prompt_cache_options_for_model",
        lambda _model: {"mode": "explicit", "ttl": "30m"},
    )

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "standard"},
        scan_id="scan-specific-id",
        image="img",
        coordinator=AgentCoordinator(),
    )

    assert captured["kwargs"]["is_root"] is True
    cache_keys = [call["prompt_cache_key"] for call in settings_calls]
    assert len(cache_keys) == 2
    assert all(key.startswith("lyrashield:v2:") for key in cache_keys)
    assert all(len(key) <= 64 for key in cache_keys)
    assert all("scan-specific-id" not in key for key in cache_keys)
    assert cache_keys[0] != cache_keys[1]


@pytest.mark.asyncio
async def test_delegate_run_uses_delegate_model_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """A Terra coordinator must not override a Luna specialist at SDK runtime."""
    _patch_engine_scaffold(monkeypatch, tmp_path, {"scope": "built-in"})
    monkeypatch.setattr(
        runner,
        "load_settings",
        lambda: types.SimpleNamespace(
            llm=types.SimpleNamespace(
                model="azure_ai/gpt-5.6-terra",
                delegate_model="azure_ai/gpt-5.6-luna",
                reasoning_effort="medium",
                delegate_reasoning_effort="high",
                force_required_tool_choice=False,
                timeout=300,
                prompt_cache=False,
                extra_headers=None,
                api_base="https://example.openai.azure.com",
                api_key="test-key",
            ),
            runtime=types.SimpleNamespace(max_context_images=3),
        ),
    )
    monkeypatch.setattr(
        runner,
        "make_model_settings",
        lambda _effort, **kwargs: ModelSettings(
            max_tokens=4_096 if kwargs["model_name"].endswith("luna") else 8_192
        ),
    )

    child_calls: list[dict[str, Any]] = []

    async def _start_child_agent(**kwargs: Any) -> dict[str, Any]:
        child_calls.append(kwargs)
        return {"success": True}

    async def _run_root_agent(**kwargs: Any) -> None:
        await kwargs["context"]["spawn_child_agent"](
            name="specialist",
            task="inspect routing",
            skills=[],
            parent_history=[],
        )

    monkeypatch.setattr(runner, "start_child_agent", _start_child_agent)
    monkeypatch.setattr(runner, "run_agent_loop", _run_root_agent)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-model-route",
        image="img",
        coordinator=AgentCoordinator(),
    )

    assert len(child_calls) == 1
    child_run_config = child_calls[0]["run_config"]
    assert child_run_config.model == "azure_ai/gpt-5.6-luna"
    assert child_run_config.model_settings.max_tokens == 4_096


@pytest.mark.asyncio
async def test_extra_system_prompt_context_cannot_override_scope_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    scope_context = {"authorized_targets": [{"type": "web_application"}]}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    with pytest.raises(ValueError, match="authorized_targets"):
        await runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-conflict",
            image="img",
            coordinator=AgentCoordinator(),
            extra_system_prompt_context={"authorized_targets": []},
        )

    assert "kwargs" not in captured


@pytest.mark.asyncio
async def test_root_prompt_options_default_to_none(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """Without the new args, behavior is unchanged: no override, scope context as-is."""
    scope_context = {"scope": "built-in"}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-default",
        image="img",
        coordinator=AgentCoordinator(),
    )

    kwargs = captured["kwargs"]
    assert kwargs["instructions_override"] is not None
    assert "You are LyraShield" in kwargs["instructions_override"]
    assert kwargs["system_prompt_context"] == {"scope": "built-in"}


@pytest.mark.asyncio
async def test_fresh_run_ignores_leftover_resume_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """A reused run name is fresh unless the caller explicitly requests resume."""
    (tmp_path / "agents.json").write_text("{}", encoding="utf-8")
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, {"scope": "built-in"})

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-fresh",
        image="img",
        coordinator=AgentCoordinator(),
    )

    assert captured["kwargs"]["is_root"] is True


def test_sanitize_prompt_value_strips_jinja_tags() -> None:
    assert _sanitize_prompt_value("{{ malicious }}") == ""
    assert _sanitize_prompt_value("{% if x %}bad{% endif %}") == "bad"
    assert _sanitize_prompt_value("{# comment #}normal") == "normal"
    assert _sanitize_prompt_value("normal text") == "normal text"


def test_sanitize_prompt_value_strips_control_chars() -> None:
    assert _sanitize_prompt_value("hello\x00world\x07!") == "helloworld!"
    assert _sanitize_prompt_value("line\nbreak") == "line\nbreak"


def test_sanitize_prompt_value_truncates_long_input() -> None:
    long = "A" * 10_000
    assert len(_sanitize_prompt_value(long, max_len=100)) == 100


def test_model_routing_policy_records_the_resolved_route() -> None:
    assert runner._model_routing_policy(
        "azure_ai/gpt-5.6-luna",
        "medium",
        "azure_ai/gpt-5.6-luna",
        "medium",
    ) == ("coordinator=azure_ai/gpt-5.6-luna@medium;delegate=azure_ai/gpt-5.6-luna@medium;v=1")


@pytest.mark.asyncio
async def test_root_instructions_override_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """Jinja directives and control chars in root_instructions_override are stripped."""
    scope_context = {"scope": "built-in"}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-sanitize",
        image="img",
        coordinator=AgentCoordinator(),
        root_instructions_override="Normal instructions {{ injected }}\x00done",
    )

    kwargs = captured["kwargs"]
    instructions = kwargs["instructions_override"]
    assert "Normal instructions" in instructions
    assert "{{ injected }}" not in instructions
    assert "{{" not in instructions
    assert "\x00" not in instructions


@pytest.mark.asyncio
async def test_extra_system_prompt_context_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """Jinja directives in extra_system_prompt_context string values are stripped."""
    scope_context = {"scope": "built-in"}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-ctx-sanitize",
        image="img",
        coordinator=AgentCoordinator(),
        extra_system_prompt_context={
            "notes": "safe value",
            "dangerous": "{{ attack }}",
            "items": ["clean", "{% if true %}bad{% endif %}"],
        },
    )

    ctx = captured["kwargs"]["system_prompt_context"]
    assert ctx["notes"] == "safe value"
    assert ctx["dangerous"] == ""
    assert ctx["items"] == ["clean", "bad"]
