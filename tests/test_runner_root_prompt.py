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
from agents.exceptions import ModelBehaviorError
from openai import RateLimitError

import lyrashield.tools.todo.tools as todo_tools
import strix.tools.notes.tools as notes_tools
from lyrashield.lifecycle import runner
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.inputs import _sanitize_prompt_value, make_model_settings
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
    # Stable keys now follow the routing gate, not the explicit-options flag.
    monkeypatch.setattr(runner, "prompt_cache_routing_enabled", lambda _model: True)

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


def _has_cache_breakpoint(initial_input: Any) -> bool:
    """Return whether an agent input carries an explicit cache breakpoint part."""
    if not isinstance(initial_input, list):
        return False
    for message in initial_input:
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        if any(isinstance(part, dict) and part.get("prompt_cache_breakpoint") for part in content):
            return True
    return False


def _gpt56_llm_settings(*, prompt_cache: bool = True) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="azure_ai/gpt-5.6-terra",
            delegate_model="azure_ai/gpt-5.6-luna",
            reasoning_effort="medium",
            delegate_reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=prompt_cache,
            extra_headers=None,
            api_base="https://example.openai.azure.com",
            api_key="test-key",
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cache_enabled", [False, True])
@pytest.mark.parametrize("routing_on", [False, True])
@pytest.mark.parametrize("explicit_on", [False, True])
async def test_prompt_cache_policy_matrix_across_construction_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    cache_enabled: bool,
    routing_on: bool,
    explicit_on: bool,
) -> None:
    """Stable keys follow routing; options and breakpoints follow explicit mode.

    Coordinator, delegate, and fallback model-settings construction must all
    honor the same policy matrix:

    | Routing | Explicit | Stable key | Cache options | Content breakpoint |
    | Off     | Off      | No         | None          | No                 |
    | On      | Off      | Yes        | None          | No                 |
    | Off     | On       | No         | Explicit 30m  | Yes                |
    | On      | On       | Yes        | Explicit 30m  | Yes                |
    """
    _patch_engine_scaffold(monkeypatch, tmp_path, {"scope": "built-in"})
    if routing_on:
        monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    else:
        monkeypatch.delenv("LYRASHIELD_PROMPT_CACHE_ROUTING", raising=False)
    if explicit_on:
        monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", "1")
    else:
        monkeypatch.delenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", raising=False)
    monkeypatch.setattr(
        runner,
        "load_settings",
        lambda: _gpt56_llm_settings(prompt_cache=cache_enabled),
    )

    settings_calls: list[dict[str, Any]] = []
    wire_payloads: list[dict[str, Any]] = []

    def _make_model_settings(*args: Any, **kwargs: Any) -> ModelSettings:
        settings_calls.append(kwargs)
        settings = make_model_settings(*args, **kwargs)
        wire_payloads.append(settings.to_json_dict())
        return settings

    monkeypatch.setattr(runner, "make_model_settings", _make_model_settings)

    record = types.SimpleNamespace(
        run_record={},
        save_run_data=lambda: None,
        set_cleanup_outcome=lambda _outcome: None,
        set_terminal_reason=lambda _reason: None,
    )
    monkeypatch.setattr(runner, "get_global_report_state", lambda: record)

    loop_calls: list[dict[str, Any]] = []

    async def _run_agent_loop(*_args: Any, **kwargs: Any) -> Any:
        loop_calls.append(kwargs)
        if len(loop_calls) == 1:
            # Drive the fallback path so its ModelSettings get built too.
            raise ModelBehaviorError("coordinator failed")
        return types.SimpleNamespace(final_output='{"scan_completed": true}')

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)

    await runner.run_strix_scan(
        scan_config={
            "targets": [
                {
                    "type": "repository",
                    "details": {
                        "target_repo": "https://repo.example.com/a.git",
                        "cloned_repo_path": "/workspace/a",
                        "workspace_subdir": "a",
                    },
                },
            ],
            "scan_mode": "deep",
        },
        scan_id="scan-matrix",
        image="img",
        coordinator=AgentCoordinator(),
    )

    # Coordinator, delegates, and the model-error fallback each build their own
    # ModelSettings; all three must emit the same cache posture.
    assert len(settings_calls) == 3
    effective_routing = cache_enabled and routing_on
    expected_options = {"mode": "explicit", "ttl": "30m"} if cache_enabled and explicit_on else None
    for call in settings_calls:
        assert (call["prompt_cache_key"] is not None) is effective_routing
        assert call["prompt_cache_options"] == expected_options
        assert call["prompt_cache"] is cache_enabled
    for wire in wire_payloads:
        assert ((wire["extra_args"] or {}).get("prompt_cache_key") is not None) is effective_routing
        assert wire["prompt_cache_options"] == expected_options
    if effective_routing:
        roles = [call["prompt_cache_key"].split(":")[2] for call in settings_calls]
        assert roles == ["coordinator", "delegates", "fallback"]

    assert record.run_record["prompt_cache"] == {
        "enabled": cache_enabled,
        "routing_enabled": effective_routing,
        "routing": "stable-prompt-v2" if effective_routing else None,
        "mode": "explicit" if expected_options else "implicit" if cache_enabled else None,
        "ttl": "30m" if expected_options else None,
    }


@pytest.mark.asyncio
async def test_stable_prompt_cache_keys_exclude_scan_material(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """Cache keys are digests: no raw target, workspace, instructions, or IDs."""
    scope_context = {
        "authorized_targets": [
            {
                "type": "repository",
                "value": "https://sensitive-target.example.com",
                "workspace_path": "/workspace/private-subdir",
            },
        ],
    }
    _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    monkeypatch.delenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", raising=False)
    monkeypatch.setattr(runner, "load_settings", _gpt56_llm_settings)

    settings_calls: list[dict[str, Any]] = []

    def _make_model_settings(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        settings_calls.append(kwargs)
        return {}

    monkeypatch.setattr(runner, "make_model_settings", _make_model_settings)

    seen: dict[str, Any] = {}

    def _open_session(root_id: Any, _db: Any, **_kwargs: Any) -> object:
        seen["root_id"] = root_id
        return object()

    monkeypatch.setattr(runner, "open_agent_session", _open_session)

    loop_calls = 0

    async def _run_agent_loop(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal loop_calls
        loop_calls += 1
        if loop_calls == 1:
            raise ModelBehaviorError("coordinator failed")
        return types.SimpleNamespace(final_output='{"scan_completed": true}')

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)

    await runner.run_strix_scan(
        scan_config={
            "targets": [
                {
                    "type": "repository",
                    "details": {
                        "target_repo": "https://sensitive-target.example.com",
                        "workspace_subdir": "private-subdir",
                    },
                },
            ],
            "user_instructions": "RAW-INSTRUCTION-MARKER",
            "scan_mode": "deep",
        },
        scan_id="scan-SENSITIVE-ID",
        image="img",
        coordinator=AgentCoordinator(),
        root_instructions_override="OVERRIDE-MARKER-123",
    )

    forbidden = [
        "https://sensitive-target.example.com",
        "private-subdir",
        "RAW-INSTRUCTION-MARKER",
        "OVERRIDE-MARKER-123",
        "scan-SENSITIVE-ID",
        str(seen["root_id"]),
    ]
    keys = [call["prompt_cache_key"] for call in settings_calls]
    assert len(keys) == 3
    for key in keys:
        assert key is not None
        assert key.startswith("lyrashield:v2:")
        digest = key.rsplit(":", 1)[-1]
        assert all(char in "0123456789abcdef" for char in digest)
        for material in forbidden:
            assert material not in key


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
