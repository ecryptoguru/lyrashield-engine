# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Build SandboxAgents for root + child Strix runs."""

from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import re
from typing import TYPE_CHECKING, Any, cast

from agents.agent import ToolsToFinalOutputResult
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Filesystem, Shell
from agents.sandbox.errors import InvalidManifestPathError
from agents.tool import (
    ApplyPatchTool,
    CustomTool,
    FunctionTool,
    ProgrammaticToolCallingTool,
    ShellTool,
    Tool,
    ToolCaller,
)
from pydantic import ValidationError

from lyrashield.agents import overrides as _product_overrides
from lyrashield.agents.prompt import render_system_prompt
from lyrashield.tools.finish.tool import finish_scan
from lyrashield.tools.output_store import bound_and_store, bound_text
from lyrashield.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from lyrashield.tools.reporting.tool import (
    create_dependency_report,
    create_vulnerability_report,
    get_report,
    list_reports,
)
from lyrashield.tools.respond.tool import respond_to_user
from lyrashield.tools.todo.tools import (
    create_todo,
    delete_todo,
    list_todos,
    mark_todo_done,
    mark_todo_pending,
    update_todo,
)
from lyrashield.tools.web_search.tool import web_search
from lyrashield.utils.redaction import redact_secrets
from strix.config import load_settings
from strix.tools.agents_graph.tools import (
    agent_finish,
    create_agent,
    send_message_to_agent,
    stop_agent,
    view_agent_graph,
    wait_for_agents,
)
from strix.tools.load_skill.tool import load_skill
from strix.tools.notes.tools import (
    create_note,
    delete_note,
    get_note,
    list_notes,
    update_note,
)
from strix.tools.thinking.tool import think


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from agents import RunContextWrapper
    from agents.model_settings import ModelSettings
    from agents.tool import FunctionToolResult


logger = logging.getLogger(__name__)


_CUSTOM_TOOL_INPUT_FIELD_BY_NAME = {
    "apply_patch": "patch",
}
_DEFAULT_CUSTOM_TOOL_INPUT_FIELD = "input"

# Allowed callers for tools when programmatic tool calling is enabled.
_PROGRAMMATIC_ALLOWED_CALLERS: list[ToolCaller] = cast(
    "list[ToolCaller]",
    ["direct", "programmatic"],
)


def _custom_tool_input_field(tool: CustomTool) -> str:
    return _CUSTOM_TOOL_INPUT_FIELD_BY_NAME.get(tool.name, _DEFAULT_CUSTOM_TOOL_INPUT_FIELD)


def _raw_input_schema(tool: CustomTool) -> dict[str, Any]:
    input_field = _custom_tool_input_field(tool)
    return {
        "type": "object",
        "properties": {
            input_field: {
                "type": "string",
                "description": (
                    f"Complete `{tool.name}` payload. Follow the tool description exactly."
                ),
            },
        },
        "required": [input_field],
        "additionalProperties": False,
    }


def _extract_custom_input(tool: CustomTool, raw_input: str | dict[str, Any]) -> str:
    if isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            return ""
    else:
        parsed = raw_input
    value = parsed.get(_custom_tool_input_field(tool))
    return value if isinstance(value, str) else ""


def _tool_output_limits() -> tuple[int, int]:
    context = load_settings().context
    return context.tool_output_max_lines, context.tool_output_max_bytes


async def _bound_result(result: Any) -> Any:
    if not isinstance(result, str):
        return result
    max_lines, max_bytes = _tool_output_limits()
    return await bound_and_store(result, max_lines=max_lines, max_bytes=max_bytes)


def _format_tool_error(exc: Exception) -> str:
    message = str(exc) or exc.__class__.__name__
    max_lines, max_bytes = _tool_output_limits()
    return bound_text(message, max_lines=max_lines, max_bytes=max_bytes)


def _with_bounded_result(tool: FunctionTool) -> FunctionTool:
    """Cap a tool's result size before it enters history (idempotent)."""
    if getattr(tool, "_strix_bounded", False):
        return tool
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        return await _bound_result(await invoke_tool(ctx, raw_input))

    tool.on_invoke_tool = invoke
    tool._strix_bounded = True  # type: ignore[attr-defined]
    return tool


def _function_tool_with_error_result(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            return await _bound_result(await invoke_tool(ctx, raw_input))
        except Exception as exc:  # noqa: BLE001 - tool errors should be model-visible results.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    tool.on_invoke_tool = invoke
    return tool


def _custom_tool_as_function_tool(tool: CustomTool) -> FunctionTool:
    async def invoke(ctx: Any, raw_input: str) -> Any:
        custom_input = _extract_custom_input(tool, raw_input)
        if not custom_input:
            return f"`{_custom_tool_input_field(tool)}` must be a non-empty string."
        try:
            return await _bound_result(await tool.on_invoke_tool(ctx, custom_input))
        except Exception as exc:  # noqa: BLE001 - matches SDK CustomTool error-as-result behavior.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    needs_approval = tool.runtime_needs_approval()
    function_needs_approval: bool | Callable[[Any, dict[str, Any], str], Awaitable[bool]]
    if callable(needs_approval):

        async def approve(ctx: Any, args: dict[str, Any], call_id: str) -> bool:
            result = needs_approval(ctx, _extract_custom_input(tool, args), call_id)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)

        function_needs_approval = approve
    else:
        function_needs_approval = needs_approval

    return FunctionTool(
        name=tool.name,
        description=(
            f"{tool.description}\n\n"
            f"Pass the complete `{tool.name}` payload in `{_custom_tool_input_field(tool)}`."
        ),
        params_json_schema=_raw_input_schema(tool),
        on_invoke_tool=invoke,
        strict_json_schema=False,
        needs_approval=function_needs_approval,
    )


def _bound_custom_tool(tool: CustomTool) -> CustomTool:
    """Bound a native ``CustomTool`` result in place (Responses path)."""
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        return await _bound_result(await invoke_tool(ctx, raw_input))

    tool.on_invoke_tool = invoke
    return tool


def _configure_filesystem_tools(
    toolset: Any, *, chat_completions: bool = False, programmatic: bool = False
) -> None:
    for name, tool in cast("dict[str, Any]", vars(toolset)).items():
        wrapped = tool
        if chat_completions and isinstance(tool, CustomTool):
            wrapped = _custom_tool_as_function_tool(tool)
        elif chat_completions and isinstance(tool, FunctionTool):
            wrapped = _function_tool_with_error_result(tool)
        elif isinstance(tool, CustomTool):
            wrapped = _bound_custom_tool(tool)
        elif isinstance(tool, FunctionTool):
            wrapped = _with_bounded_result(tool)
        if isinstance(wrapped, (FunctionTool, CustomTool, ShellTool, ApplyPatchTool)):
            wrapped.allowed_callers = _PROGRAMMATIC_ALLOWED_CALLERS if programmatic else None
        setattr(toolset, name, wrapped)


def _make_filesystem_configurator(*, chat_completions: bool, programmatic: bool) -> Any:
    def configure(toolset: Any) -> None:
        _configure_filesystem_tools(
            toolset,
            chat_completions=chat_completions,
            programmatic=programmatic,
        )

    return configure


_CHARS_ESCAPE_RE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0abtnvfr\\])")
_CHARS_ESCAPE_MAP = {
    "\\\\": "\\",
    "\\n": "\n",
    "\\t": "\t",
    "\\r": "\r",
    "\\0": "\x00",
    "\\a": "\x07",
    "\\b": "\x08",
    "\\v": "\x0b",
    "\\f": "\x0c",
}


def _decode_chars_escape(s: str) -> str:
    if "\\" not in s:
        return s

    def sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _CHARS_ESCAPE_MAP:
            return _CHARS_ESCAPE_MAP[token]
        if token.startswith(("\\u", "\\x")):
            return chr(int(token[2:], 16))
        return token

    return _CHARS_ESCAPE_RE.sub(sub, s)


def _format_validation_error(tool_name: str, exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = err.get("msg", "invalid")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return f"{tool_name}: invalid arguments — " + "; ".join(parts)


def _apply_shell_output_cap(parsed: dict[str, Any]) -> None:
    """Clamp the SDK shell tools' ``max_output_tokens`` to the configured
    ceiling; a smaller explicit value is respected."""
    ceiling = load_settings().context.tool_output_max_tokens
    requested = parsed.get("max_output_tokens")
    parsed["max_output_tokens"] = (
        ceiling if not isinstance(requested, int) or requested > ceiling else requested
    )


def _redact_tool_output(result: Any, tool_name: str) -> Any:
    """Redact secrets in tool output before it enters the model context.

    Proactively redacts PEM keys, API keys, JWTs, and passwords to prevent
    Azure content-filter blocks on sensitive material without hiding
    vulnerability-relevant code patterns (function names, SQL, auth logic).
    """
    if not isinstance(result, str):
        return result
    redacted = redact_secrets(result)
    if redacted != result:
        logger.debug(
            "%s output redacted %d -> %d chars",
            tool_name,
            len(result),
            len(redacted),
        )
        return redacted
    return result


def _wrap_exec_command(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            if "shell" not in parsed:
                parsed["shell"] = "bash"
            _apply_shell_output_cap(parsed)
            raw_input = json.dumps(parsed)
        try:
            result = await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)
        except InvalidManifestPathError as exc:
            rel = exc.context.get("rel", "?")
            return (
                "exec_command: workdir must be a path inside /workspace "
                "(or omitted to use the turn's cwd). "
                f"Got: {rel!r}."
            )
        return _redact_tool_output(result, tool.name)

    tool.on_invoke_tool = invoke
    return tool


def _wrap_write_stdin(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            if isinstance(parsed.get("chars"), str):
                parsed["chars"] = _decode_chars_escape(parsed["chars"])
            _apply_shell_output_cap(parsed)
            raw_input = json.dumps(parsed)
        try:
            result = await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)
        return _redact_tool_output(result, tool.name)

    tool.on_invoke_tool = invoke
    return tool


def _configure_shell_tools(toolset: Any, *, chat_completions: bool, programmatic: bool) -> None:
    for name, tool in cast("dict[str, Any]", vars(toolset)).items():
        if not isinstance(tool, FunctionTool):
            continue
        wrapped = tool
        if tool.name == "exec_command":
            wrapped = _wrap_exec_command(wrapped)
        elif tool.name == "write_stdin":
            wrapped = _wrap_write_stdin(wrapped)
        if chat_completions:
            wrapped = _function_tool_with_error_result(wrapped)
        wrapped.allowed_callers = _PROGRAMMATIC_ALLOWED_CALLERS if programmatic else None
        setattr(toolset, name, wrapped)


def _make_shell_configurator(*, chat_completions: bool, programmatic: bool) -> Any:
    def configure(toolset: Any) -> None:
        _configure_shell_tools(
            toolset,
            chat_completions=chat_completions,
            programmatic=programmatic,
        )

    return configure


# Tools that hand control away by parking the agent rather than ending the scan.
_PARKING_TOOLS: frozenset[str] = frozenset({"respond_to_user", "wait_for_agents"})


def _lifecycle_tool_completed(tool_name: str, output: Any) -> bool:
    if tool_name == "agent_finish":
        completion_key = "agent_completed"
    elif tool_name == "finish_scan":
        completion_key = "scan_completed"
    else:
        return False

    if not isinstance(output, str):
        return False
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return False
    if not isinstance(parsed, dict):
        return False
    parsed_dict = cast("dict[str, Any]", parsed)
    return bool(parsed_dict.get("success") and parsed_dict.get(completion_key))


def _wait_tool_parked(tool_name: str, output: Any) -> bool:
    if tool_name not in _PARKING_TOOLS or not isinstance(output, str):
        return False
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return False
    if not isinstance(parsed, dict):
        return False
    parsed_dict = cast("dict[str, Any]", parsed)
    return bool(parsed_dict.get("success") and parsed_dict.get("wait_outcome") == "waiting")


def _finish_tool_use_behavior(
    ctx: RunContextWrapper[Any],
    tool_results: list[FunctionToolResult],
) -> ToolsToFinalOutputResult:
    """Stop only after a lifecycle tool reports successful completion."""
    if isinstance(ctx.context, dict):
        context = cast("dict[str, Any]", ctx.context)
        interactive = bool(context.get("interactive", False))
    else:
        interactive = False
    for tool_result in tool_results:
        if _lifecycle_tool_completed(tool_result.tool.name, tool_result.output):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
        if interactive and _wait_tool_parked(tool_result.tool.name, tool_result.output):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


def _set_tools_programmatic_callers(tools: list[Tool], *, enabled: bool) -> None:
    """Set callers on per-agent tool copies without leaking a prior agent's policy."""
    for tool in tools:
        if isinstance(tool, ProgrammaticToolCallingTool):
            continue
        if isinstance(tool, (FunctionTool, CustomTool, ShellTool, ApplyPatchTool)):
            tool.allowed_callers = _PROGRAMMATIC_ALLOWED_CALLERS if enabled else None


def _materialize_tool(tool: Tool) -> Tool:
    """Return a per-agent copy of a registry/toolset tool singleton.

    ``allowed_callers`` policy and result-bounding wrappers mutate the tool
    object they touch; applying them to the shared singletons would silently
    reconfigure every already-running agent built from the same registry.
    Dataclass copy keeps the (stateless) invoke functions shared.
    """
    if isinstance(tool, (FunctionTool, CustomTool, ShellTool, ApplyPatchTool)):
        return dataclasses.replace(tool)
    return tool


_BASE_TOOLS: tuple[Tool, ...] = (
    think,
    web_search,
    load_skill,
    create_todo,
    list_todos,
    update_todo,
    mark_todo_done,
    mark_todo_pending,
    delete_todo,
    create_note,
    list_notes,
    get_note,
    update_note,
    delete_note,
    create_vulnerability_report,
    create_dependency_report,
    list_requests,
    view_request,
    repeat_request,
    list_sitemap,
    view_sitemap_entry,
    scope_rules,
    send_message_to_agent,
    wait_for_agents,
)

# Scan-wide finding review is coordinator-only. Specialists file their own
# evidence and return; carrying these schemas on every leaf wastes context and
# contradicts the system-prompt contract.
_REPORT_REVIEW_TOOLS: tuple[Tool, ...] = (list_reports, get_report)


_ROOT_ORCHESTRATION_TOOLS: tuple[Tool, ...] = (
    view_agent_graph,
    create_agent,
    stop_agent,
)


# Extra tools registered for scan agents. Mirrors
# ``strix.runtime.backends.register_backend``: register before the first
# ``build_strix_agent`` call and every agent (root + children) gets them.
_EXTRA_TOOLS: list[Tool] = []

# Product overrides for base tools. A name mapped here replaces any tool
# with the same name in the assembled tool list.
_TOOL_OVERRIDES: dict[str, Tool] = {}


def _ensure_unique_tool_names(tools: Sequence[Tool]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for tool in tools:
        if tool.name in seen:
            duplicates.add(tool.name)
        seen.add(tool.name)
    if duplicates:
        msg = f"Agent tools must have unique names: {sorted(duplicates)}"
        raise ValueError(msg)


def register_agent_tools(*tools: Tool) -> None:
    """Register tools for every scan agent built afterwards.

    Tools are added to both root and child agents, after the base set and
    before the lifecycle tool (``finish_scan`` / ``agent_finish``). Duplicate
    tool objects are ignored so repeated imports don't double-register.
    """
    new_tools: list[Tool] = []
    for tool in tools:
        if tool not in _EXTRA_TOOLS and tool not in new_tools:
            new_tools.append(tool)

    _ensure_unique_tool_names(
        [
            *_BASE_TOOLS,
            *_REPORT_REVIEW_TOOLS,
            *_ROOT_ORCHESTRATION_TOOLS,
            *_EXTRA_TOOLS,
            *new_tools,
            finish_scan,
            agent_finish,
        ]
    )

    for tool in new_tools:
        _EXTRA_TOOLS.append(tool)
        logger.info("Registered extra agent tool: %s", getattr(tool, "name", tool))


def registered_agent_tools() -> tuple[Tool, ...]:
    """Return the currently registered scan-agent tools."""
    return tuple(_EXTRA_TOOLS)


def register_tool_override(name: str, tool: Tool) -> None:
    """Override a base tool by name across all agents built afterwards.

    If ``tool.name`` differs from ``name``, ``tool.name`` is used as the
    override key. This allows a product-specific implementation to replace
    an upstream base tool without editing the base toolset.
    """
    key = tool.name
    if key != name:
        logger.warning(
            "Tool override key %r differs from tool.name %r; using %r",
            name,
            key,
            key,
        )
    _TOOL_OVERRIDES[key] = tool
    logger.info("Registered tool override: %s", key)


def resolve_product_overrides() -> None:
    """Materialize registrations the product entry point deferred.

    The entry point queues loader callables (see ``lyrashield.agents.overrides``)
    instead of importing the product tool modules at CLI startup; resolving
    runs those loaders, performing the deferred imports. Safe to call
    repeatedly: draining empties the queues and already-resolved names are
    skipped, so this is also the recovery path when a registration lands
    after this module was first imported.
    """
    for name, load in _product_overrides.drain_tool_override_loaders().items():
        if name not in _TOOL_OVERRIDES:
            register_tool_override(name, load())
    for policy_name, policy_load in _product_overrides.drain_model_policy_loaders().items():
        if policy_name not in _MODEL_POLICY:
            register_model_policy(policy_name, policy_load())


def _apply_tool_overrides(tools: list[Tool]) -> list[Tool]:
    """Replace any tool whose name is registered as an override."""
    resolve_product_overrides()
    if not _TOOL_OVERRIDES:
        return tools
    updated: list[Tool] = []
    replaced: set[str] = set()
    for tool in tools:
        if tool.name in _TOOL_OVERRIDES:
            updated.append(_TOOL_OVERRIDES[tool.name])
            replaced.add(tool.name)
        else:
            updated.append(tool)
    for key, tool in _TOOL_OVERRIDES.items():
        if key not in replaced:
            updated.append(tool)
    return updated


_MODEL_POLICY: dict[str, Callable[..., Any]] = {}


def register_model_policy(name: str, fn: Callable[..., Any]) -> None:
    """Register a product-specific model-policy helper used by the agent factory.

    This is a neutral seam: upstream `strix.agents.factory` exposes no product
    model names, and the adapter binds the product helpers before calling the
    upstream entry point.
    """
    _MODEL_POLICY[name] = fn


def _model_policy(name: str, *args: Any, default: Any = False, **kwargs: Any) -> Any:
    if name not in _MODEL_POLICY:
        resolve_product_overrides()
    if name in _MODEL_POLICY:
        return _MODEL_POLICY[name](*args, **kwargs)
    return default


def model_supports_programmatic_tool_calling(model_name: str | None) -> bool:
    """Return whether the resolved model is known to support programmatic tool calling.

    The default is False. The product adapter can register a policy helper to
    enable this for specific model families.
    """
    return bool(_model_policy("model_supports_programmatic_tool_calling", model_name))


def build_strix_agent(
    *,
    name: str = "strix",
    skills: list[str] | None = None,
    is_root: bool,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    extra_tools: Sequence[Tool] | None = None,
    instructions_override: str | None = None,
    model: str | None = None,
    model_settings: ModelSettings | None = None,
) -> SandboxAgent[Any]:
    """Build a SandboxAgent for either root or child use.

    Args:
        chat_completions_tools: Wrap SDK custom tools as function tools
            when the selected backend cannot accept Responses custom tools.
        extra_tools: Additional tools for this scan agent only, on top of any
            registered via ``register_agent_tools``.
        instructions_override: Use this verbatim as the system prompt instead
            of rendering the built-in scan prompt.
    """
    if instructions_override is not None:
        instructions = instructions_override
    else:
        instructions = render_system_prompt(
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            interactive=interactive,
            system_prompt_context=system_prompt_context,
        )

    agent_tools = [*_EXTRA_TOOLS, *(extra_tools or [])]
    if interactive:
        # Yielding to the user is only meaningful when one is attached.
        agent_tools.append(respond_to_user)
    if is_root:
        tools: list[Tool] = [
            *_BASE_TOOLS,
            *_REPORT_REVIEW_TOOLS,
            *_ROOT_ORCHESTRATION_TOOLS,
            *agent_tools,
            finish_scan,
        ]
    else:
        tools = [*_BASE_TOOLS, *agent_tools, agent_finish]

    tools = _apply_tool_overrides(tools)
    # Materialize per-agent copies before any policy or wrapper mutates them,
    # so building one agent can never reconfigure another agent's tools.
    tools = [_materialize_tool(tool) for tool in tools]

    use_programmatic = (
        not chat_completions_tools
        and model is not None
        and model_supports_programmatic_tool_calling(model)
    )
    _set_tools_programmatic_callers(tools, enabled=use_programmatic)
    if use_programmatic:
        tools.append(ProgrammaticToolCallingTool())

    _ensure_unique_tool_names(tools)
    tools = [
        _with_bounded_result(tool) if isinstance(tool, FunctionTool) else tool for tool in tools
    ]

    logger.info(
        "Built %s agent '%s' (skills=%d, tools=%d, scan_mode=%s, whitebox=%s, programmatic=%s)",
        "root" if is_root else "child",
        name,
        len(skills or []),
        len(tools),
        scan_mode,
        is_whitebox,
        use_programmatic,
    )

    agent_model_options: dict[str, Any] = {}
    if model is not None:
        agent_model_options["model"] = model
    if model_settings is not None:
        agent_model_options["model_settings"] = model_settings

    return SandboxAgent(
        name=name,
        instructions=instructions,
        tools=tools,
        tool_use_behavior=_finish_tool_use_behavior,
        **agent_model_options,
        capabilities=[
            Filesystem(
                configure_tools=_make_filesystem_configurator(
                    chat_completions=chat_completions_tools,
                    programmatic=use_programmatic,
                ),
            ),
            Shell(
                configure_tools=_make_shell_configurator(
                    chat_completions=chat_completions_tools,
                    programmatic=use_programmatic,
                ),
            ),
        ],
    )


def make_child_factory(
    *,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    model: str | None = None,
    model_settings: ModelSettings | None = None,
) -> Any:
    """Return the runner-owned builder used by ``spawn_child_agent``.

    Run-level arguments (``scan_mode``, ``is_whitebox``, etc.) are
    captured in a closure so each child inherits scan-level configuration
    without the graph tool knowing about runner internals.
    """

    def _factory(*, name: str, skills: list[str]) -> SandboxAgent[Any]:
        return build_strix_agent(
            name=name,
            skills=skills,
            is_root=False,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=system_prompt_context,
            model=model,
            model_settings=model_settings,
        )

    return _factory


# Materialize anything the product entry point registered before this module
# was first imported. The loaders' target modules are already imported by this
# module's own top-level imports, so resolving here adds no import cost; the
# call is idempotent, and later registrations are picked up by
# ``resolve_product_overrides`` at build time.
resolve_product_overrides()
