"""Tests for the shell tool adapters in the agent factory."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import CustomTool, FunctionTool

from strix.agents import factory
from strix.config import load_settings


def _capturing_exec_tool(captured: dict[str, str]) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    return FunctionTool(
        name="exec_command",
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


@pytest.mark.asyncio
async def test_wrap_exec_command_defaults_shell_to_bash() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "source /tmp/env"}))

    assert result == "ok"
    parsed = json.loads(captured["raw_input"])
    assert parsed["cmd"] == "source /tmp/env"
    assert parsed["shell"] == "bash"
    expected_cap = load_settings().context.tool_output_max_tokens
    assert parsed["max_output_tokens"] == expected_cap


@pytest.mark.asyncio
async def test_wrap_exec_command_preserves_smaller_explicit_output_cap() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "echo hi", "max_output_tokens": 42})
    )

    assert json.loads(captured["raw_input"])["max_output_tokens"] == 42


@pytest.mark.asyncio
async def test_wrap_exec_command_clamps_oversized_explicit_output_cap() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))
    ceiling = load_settings().context.tool_output_max_tokens

    await wrapped.on_invoke_tool(
        cast("Any", None),
        json.dumps({"cmd": "echo hi", "max_output_tokens": ceiling * 100}),
    )

    assert json.loads(captured["raw_input"])["max_output_tokens"] == ceiling


@pytest.mark.asyncio
@pytest.mark.parametrize("shell", ["/bin/zsh", ""])
async def test_wrap_exec_command_preserves_explicit_shell(shell: str) -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "echo test", "shell": shell})
    )

    assert json.loads(captured["raw_input"])["shell"] == shell


@pytest.mark.asyncio
async def test_responses_filesystem_custom_tool_output_is_bounded() -> None:
    async def invoke(_ctx: Any, _inp: str) -> str:
        return "line\n" * 50_000

    toolset = SimpleNamespace(
        read_file=CustomTool(name="read_file", description="read", on_invoke_tool=invoke)
    )
    factory._configure_filesystem_tools(toolset, chat_completions=False)

    assert isinstance(toolset.read_file, CustomTool)
    result = await toolset.read_file.on_invoke_tool(cast("Any", None), "{}")

    assert "truncated" in result
    assert len(result) < len("line\n" * 50_000)


@pytest.mark.asyncio
async def test_chat_completions_filesystem_custom_tool_becomes_function_tool() -> None:
    async def invoke(_ctx: Any, _inp: str) -> str:
        return "ok"

    toolset = SimpleNamespace(
        read_file=CustomTool(name="read_file", description="read", on_invoke_tool=invoke)
    )
    factory._configure_filesystem_tools(toolset, chat_completions=True)

    assert isinstance(toolset.read_file, FunctionTool)


def test_function_tools_are_result_bounded() -> None:
    agent = factory.build_strix_agent(is_root=True)
    by_name = {t.name: t for t in agent.tools}

    assert getattr(by_name["think"], "_strix_bounded", False) is True


# --- Layer 3: proactive secret redaction in shell tool output ---


def _secret_returning_exec_tool(return_value: str) -> FunctionTool:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return return_value

    return FunctionTool(
        name="exec_command",
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


@pytest.mark.asyncio
async def test_wrap_exec_command_redacts_private_key_in_output() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAtest1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    wrapped = factory._wrap_exec_command(
        _secret_returning_exec_tool(f"cat config/key.pem\n{pem}\nend")
    )

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "cat key.pem"}))

    assert "MIIEowIBAAKCAQEAtest1234567890abcdef" not in result
    assert "[PRIVATE_KEY]" in result
    assert "cat config/key.pem" in result  # non-secret content preserved


@pytest.mark.asyncio
async def test_wrap_exec_command_redacts_api_key_in_output() -> None:
    wrapped = factory._wrap_exec_command(
        _secret_returning_exec_tool("api_key=sk_live_1234567890abcdef")
    )

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "env"}))

    assert "sk_live_1234567890abcdef" not in result
    assert "[SECRET]" in result


@pytest.mark.asyncio
async def test_wrap_exec_command_preserves_normal_code_output() -> None:
    code = "function login(user, pass) { return authenticate(user, pass); }"
    wrapped = factory._wrap_exec_command(_secret_returning_exec_tool(code))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "cat auth.ts"}))

    assert result == code  # no secrets → no redaction → unchanged


@pytest.mark.asyncio
async def test_wrap_write_stdin_redacts_secrets_in_output() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAtest1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return f"output: {pem}"

    tool = FunctionTool(
        name="write_stdin",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )
    wrapped = factory._wrap_write_stdin(tool)

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"chars": "test"}))

    assert "MIIEowIBAAKCAQEAtest1234567890abcdef" not in result
    assert "[PRIVATE_KEY]" in result
