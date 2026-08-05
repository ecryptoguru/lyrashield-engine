# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for content-filter detection, session sanitization, and retry recovery.

Covers the four-layer fix for Azure content-filter blocks that crash DEEP scans:
- Layer 1: ``_is_content_filter_error`` detection + ``_run_cycle`` retry
- Layer 2: ``sanitize_session_secrets`` rewrites tool outputs / messages
- Layer 3: proactive ``redact_secrets`` in exec_command output
- Layer 4: root-agent retry without prompt-cache gate
"""

from __future__ import annotations

import types
from typing import Any, cast

import pytest
from agents import RunConfig, Runner
from agents.exceptions import ModelBehaviorError
from agents.memory import SQLiteSession

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.config import codex
from strix.core import execution, runner
from strix.core.agents import AgentCoordinator
from strix.core.sessions import sanitize_session_secrets
from strix.report.state import ReportState, get_global_report_state, set_global_report_state
from strix.runtime import session_manager


# ---------------------------------------------------------------------------
# Layer 1: _is_content_filter_error
# ---------------------------------------------------------------------------


def test_is_content_filter_error_detects_incomplete() -> None:
    exc = ModelBehaviorError(
        "Responses stream ended with terminal event `response.incomplete`. "
        "status=incomplete; incomplete_details=IncompleteDetails(reason='content_filter')."
    )
    assert execution._is_content_filter_error(exc) is True


def test_is_content_filter_error_detects_response_failed_with_content_filter() -> None:
    """``response.failed`` with a content_filter context marker is content-filter.

    Azure's content filter can reject a retried response with ``response.failed``
    instead of ``response.incomplete``. We treat it as content-filter only when
    the error text also contains a filter-specific marker.
    """
    exc = ModelBehaviorError(
        "Responses stream ended with terminal event `response.failed`. "
        "status=failed; content_filter triggered."
    )
    assert execution._is_content_filter_error(exc) is True


def test_is_content_filter_error_detects_response_failed_with_content_policy() -> None:
    """``response.failed`` with a content_policy marker is content-filter."""
    exc = ModelBehaviorError(
        "Responses stream ended with terminal event `response.failed`. "
        "status=failed; content_policy_violation."
    )
    assert execution._is_content_filter_error(exc) is True


def test_is_content_filter_error_ignores_response_failed_without_filter_context() -> None:
    """``response.failed`` without a filter-specific marker is NOT content-filter.

    Azure can emit ``response.failed`` for non-content-filter reasons (server
    errors, rate limits). These should not trigger session sanitization.
    """
    exc = ModelBehaviorError(
        "Responses stream ended with terminal event `response.failed`. status=failed."
    )
    assert execution._is_content_filter_error(exc) is False


def test_is_content_filter_error_detects_guardrail() -> None:
    guardrail = codex.CodexContentGuardrailError("gpt-5.6-terra")
    assert execution._is_content_filter_error(guardrail) is True


def test_is_content_filter_error_ignores_unrelated_model_error() -> None:
    exc = ModelBehaviorError("Model did not produce a final response!")
    assert execution._is_content_filter_error(exc) is False


def test_is_content_filter_error_ignores_malformed_json() -> None:
    exc = ModelBehaviorError("The model produced malformed JSON in a tool call.")
    assert execution._is_content_filter_error(exc) is False


def test_content_filter_error_is_not_transient() -> None:
    """Content-filter errors have their own retry path, not the transient path."""
    exc = ModelBehaviorError(
        "Responses stream ended with terminal event `response.incomplete`. "
        "status=incomplete; incomplete_details=IncompleteDetails(reason='content_filter')."
    )
    assert execution._is_content_filter_error(exc) is True
    assert execution._is_transient_model_error(exc) is False


def test_response_failed_with_content_filter_is_not_transient() -> None:
    """``response.failed`` with content_filter context is not transient."""
    exc = ModelBehaviorError(
        "Responses stream ended with terminal event `response.failed`. "
        "status=failed; content_filter triggered."
    )
    assert execution._is_content_filter_error(exc) is True
    assert execution._is_transient_model_error(exc) is False


# ---------------------------------------------------------------------------
# Layer 2: sanitize_session_secrets
# ---------------------------------------------------------------------------


def _tool_output_item(call_id: str, output: Any) -> dict[str, Any]:
    """Build a function_call_output session item."""
    return {
        "type": "function_call_output",
        "call_id": call_id,
        "output": output,
    }


def _message_output_item(content: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a message_output session item."""
    return {
        "type": "message_output",
        "content": content,
    }


_PEM_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAtest1234567890abcdef\n"
    "-----END RSA PRIVATE KEY-----"
)


@pytest.mark.asyncio
async def test_sanitize_session_redacts_private_key_in_string_output(
    tmp_path: Any,
) -> None:
    session = SQLiteSession("agent1", tmp_path / "test.db")
    await session.add_items(
        [
            _tool_output_item("call_1", f"File contents:\n{_PEM_KEY}\nend"),
        ]
    )

    sanitized = await sanitize_session_secrets(session)

    assert sanitized is True
    items = await session.get_items()
    output = items[0]["output"]
    assert "MIIEowIBAAKCAQEAtest1234567890abcdef" not in output
    assert "[PRIVATE_KEY]" in output
    session.close()


@pytest.mark.asyncio
async def test_sanitize_session_redacts_private_key_in_block_output(
    tmp_path: Any,
) -> None:
    session = SQLiteSession("agent2", tmp_path / "test.db")
    await session.add_items(
        [
            _tool_output_item(
                "call_2",
                [
                    {"type": "input_text", "text": f"Found key:\n{_PEM_KEY}"},
                ],
            ),
        ]
    )

    sanitized = await sanitize_session_secrets(session)

    assert sanitized is True
    items = await session.get_items()
    block = items[0]["output"][0]
    assert "MIIEowIBAAKCAQEAtest1234567890abcdef" not in block["text"]
    assert "[PRIVATE_KEY]" in block["text"]
    session.close()


@pytest.mark.asyncio
async def test_sanitize_session_redacts_api_key_in_message_output(
    tmp_path: Any,
) -> None:
    session = SQLiteSession("agent3", tmp_path / "test.db")
    await session.add_items(
        [
            _message_output_item(
                [
                    {"type": "output_text", "text": "The api_key=sk-1234567890abcdef is exposed"},
                ]
            ),
        ]
    )

    sanitized = await sanitize_session_secrets(session)

    assert sanitized is True
    items = await session.get_items()
    block = items[0]["content"][0]
    assert "sk-1234567890abcdef" not in block["text"]
    assert "[SECRET]" in block["text"]
    session.close()


@pytest.mark.asyncio
async def test_sanitize_session_no_change_returns_false(tmp_path: Any) -> None:
    session = SQLiteSession("agent4", tmp_path / "test.db")
    await session.add_items(
        [
            _tool_output_item("call_3", "function login(user) { return true; }"),
        ]
    )

    sanitized = await sanitize_session_secrets(session)

    assert sanitized is False
    items = await session.get_items()
    assert items[0]["output"] == "function login(user) { return true; }"
    session.close()


@pytest.mark.asyncio
async def test_sanitize_session_preserves_non_text_blocks(tmp_path: Any) -> None:
    session = SQLiteSession("agent5", tmp_path / "test.db")
    await session.add_items(
        [
            _tool_output_item(
                "call_4",
                [
                    {"type": "input_image", "image_url": "https://example.com/img.png"},
                    {"type": "input_text", "text": f"api_key=sk-secret123\n{_PEM_KEY}"},
                ],
            ),
        ]
    )

    sanitized = await sanitize_session_secrets(session)

    assert sanitized is True
    items = await session.get_items()
    blocks = items[0]["output"]
    # Image block preserved unchanged
    assert blocks[0] == {"type": "input_image", "image_url": "https://example.com/img.png"}
    # Text block redacted
    assert "sk-secret123" not in blocks[1]["text"]
    assert "[SECRET]" in blocks[1]["text"]
    assert "[PRIVATE_KEY]" in blocks[1]["text"]
    session.close()


# ---------------------------------------------------------------------------
# Layer 1 + 2 integration: _run_cycle retries with sanitized session
# ---------------------------------------------------------------------------


class _FakeStream:
    def __init__(self, exc: BaseException | None = None) -> None:
        self._exc = exc
        self._events: list[Any] = []
        self.run_loop_exception: BaseException | None = None

    async def stream_events(self) -> Any:
        if self._exc is not None:
            raise self._exc
        for event in self._events:
            yield event


def _content_filter_error() -> ModelBehaviorError:
    return ModelBehaviorError(
        "Responses stream ended with terminal event `response.incomplete`. "
        "status=incomplete; incomplete_details=IncompleteDetails(reason='content_filter')."
    )


async def _run_cycle_with_session(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
    session: SQLiteSession,
) -> tuple[Any, int, AgentCoordinator]:
    calls = {"n": 0}

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStream:
        stream = streams[calls["n"]]
        calls["n"] += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    result = await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=5,
        session=session,
        interactive=False,
        event_sink=None,
        hooks=None,
    )
    return result, calls["n"], coordinator


@pytest.mark.asyncio
async def test_run_cycle_retries_content_filter_with_sanitized_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """A content_filter error triggers session sanitization and a retry."""
    session = SQLiteSession("root", tmp_path / "retry.db")
    await session.add_items(
        [
            _tool_output_item("call_1", f"cat output:\n{_PEM_KEY}"),
        ]
    )

    streams = [_FakeStream(exc=_content_filter_error()), _FakeStream()]
    result, attempts, _coord = await _run_cycle_with_session(monkeypatch, streams, session)

    assert result is streams[1]
    assert attempts == 2  # First attempt raised, second succeeded

    # Session should now have the redacted output
    items = await session.get_items()
    assert "[PRIVATE_KEY]" in items[0]["output"]
    assert "MIIEowIBAAKCAQEAtest1234567890abcdef" not in items[0]["output"]
    session.close()


@pytest.mark.asyncio
async def test_run_cycle_gives_up_after_max_content_filter_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """After _MAX_CONTENT_FILTER_RETRIES, the error propagates (root, non-interactive).

    Mocks ``sanitize_session_secrets`` to always return True so the retry
    counter increments on every attempt (real sanitization would find nothing
    after the first pass, falling through before the limit is reached).
    """
    session = SQLiteSession("root", tmp_path / "max.db")
    await session.add_items(
        [
            _tool_output_item("call_1", f"api_key=sk-secret123\n{_PEM_KEY}"),
        ]
    )

    async def _always_sanitized(_session: Any) -> bool:
        return True

    monkeypatch.setattr(execution, "sanitize_session_secrets", _always_sanitized)

    # Need _MAX + 1 streams: _MAX retries that continue, then one that hits
    # the limit check (content_filter_retries >= _MAX) and falls through.
    streams = [
        _FakeStream(exc=_content_filter_error())
        for _ in range(execution._MAX_CONTENT_FILTER_RETRIES + 1)
    ]
    with pytest.raises(ModelBehaviorError):
        await _run_cycle_with_session(monkeypatch, streams, session)
    session.close()


@pytest.mark.asyncio
async def test_run_cycle_retries_content_filter_even_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """Content-filter errors retry even when sanitization finds no secrets.

    The content filter may trigger on the model's response (security analysis)
    rather than on input secrets. In that case, sanitization finds nothing to
    redact, but we still retry — the model may generate a different response.
    """
    session = SQLiteSession("root", tmp_path / "clean.db")
    await session.add_items(
        [
            _tool_output_item("call_1", "function login(user) { return true; }"),
        ]
    )

    streams = [_FakeStream(exc=_content_filter_error()), _FakeStream()]
    result, attempts, _coord = await _run_cycle_with_session(monkeypatch, streams, session)

    assert result is streams[1]
    assert attempts == 2  # First attempt raised content_filter, second succeeded
    session.close()


# ---------------------------------------------------------------------------
# Layer 4: runner.py delegate model fallback cascade
# ---------------------------------------------------------------------------


def _content_filter_model_error() -> ModelBehaviorError:
    return ModelBehaviorError(
        "Responses stream ended with terminal event `response.incomplete`. "
        "status=incomplete; incomplete_details=IncompleteDetails(reason='content_filter')."
    )


@pytest.mark.asyncio
async def test_runner_falls_back_to_delegate_model_on_content_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """When the coordinator model hits content_filter once, the scan switches
    directly to the delegate model for the root agent (no coordinator retry)."""
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            delegate_model="openai/gpt-4o-mini",
            reasoning_effort="high",
            delegate_reasoning_effort="medium",
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
        runner, "uses_chat_completions_tool_schema", lambda _model, _settings: False
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
    monkeypatch.setattr(runner, "build_root_initial_input", lambda _config, **_kw: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_kw: {})
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kw: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kw: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db, **_kw: object())

    call_count = {"n": 0}

    async def _run_agent_loop(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise _content_filter_model_error()
        return types.SimpleNamespace(final_output='{"scan_completed": true}')

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)

    coordinator = AgentCoordinator()
    result = await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-fallback-test",
        image="img",
        coordinator=coordinator,
    )

    assert result is not None
    assert call_count["n"] == 2  # One coordinator failure + one delegate success


@pytest.mark.asyncio
async def test_runner_salvages_when_delegate_also_hits_content_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """When both the coordinator and the delegate fallback hit content_filter,
    the scan salvages partial findings and returns None with
    ``content_filter_stopped`` as the terminal reason."""
    report_state = ReportState(run_name="scan-salvage-test")
    set_global_report_state(report_state)
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            delegate_model="openai/gpt-4o-mini",
            reasoning_effort="high",
            delegate_reasoning_effort="medium",
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
        runner, "uses_chat_completions_tool_schema", lambda _model, _settings: False
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
    monkeypatch.setattr(runner, "build_root_initial_input", lambda _config, **_kw: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_kw: {})
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kw: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kw: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db, **_kw: object())

    call_count = {"n": 0}

    async def _run_agent_loop(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        # Both the coordinator and the delegate fallback hit content_filter
        raise _content_filter_model_error()

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)

    coordinator = AgentCoordinator()
    result = await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-salvage-test",
        image="img",
        coordinator=coordinator,
    )

    assert result is None  # Salvaged, not a normal completion
    assert call_count["n"] == 2  # One coordinator failure + one delegate failure
    final_report_state = get_global_report_state()
    assert final_report_state is not None
    assert final_report_state.run_record.get("terminal_reason") == "content_filter_stopped"
    set_global_report_state(None)


@pytest.mark.asyncio
async def test_runner_salvages_when_delegate_hits_non_content_filter_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """When the coordinator hits content_filter and the delegate fallback hits
    a non-content-filter ModelBehaviorError, the scan still salvages partial
    findings with ``engine_stopped`` as the terminal reason."""
    report_state = ReportState(run_name="scan-engine-stopped-test")
    set_global_report_state(report_state)
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            delegate_model="openai/gpt-4o-mini",
            reasoning_effort="high",
            delegate_reasoning_effort="medium",
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
        runner, "uses_chat_completions_tool_schema", lambda _model, _settings: False
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
    monkeypatch.setattr(runner, "build_root_initial_input", lambda _config, **_kw: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_kw: {})
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kw: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kw: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db, **_kw: object())

    call_count = {"n": 0}

    async def _run_agent_loop(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Coordinator hits content_filter
            raise _content_filter_model_error()
        # Delegate hits a non-content-filter ModelBehaviorError
        raise ModelBehaviorError("Max turns exceeded")

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)

    coordinator = AgentCoordinator()
    result = await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-engine-stopped-test",
        image="img",
        coordinator=coordinator,
    )

    assert result is None  # Salvaged, not a normal completion
    assert call_count["n"] == 2  # One coordinator failure + one delegate failure
    final_report_state = get_global_report_state()
    assert final_report_state is not None
    assert final_report_state.run_record.get("terminal_reason") == "engine_stopped"
    set_global_report_state(None)
