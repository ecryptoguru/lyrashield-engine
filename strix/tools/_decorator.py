"""strix_tool — function_tool factory with Strix defaults.

Every tool in the migrated harness should be decorated with ``@strix_tool``
instead of bare ``@function_tool`` so the team's defaults stay consistent
without per-tool boilerplate. Override per call when needed.

Defaults:
    - ``timeout``: 120s (matches the legacy tool server's
      ``STRIX_SANDBOX_EXECUTION_TIMEOUT``).
    - ``timeout_behavior``: ``"error_as_result"`` for idempotent tools.
      Critical sandbox tools (terminal, browser, python) should pass
      ``timeout_behavior="raise_exception"`` explicitly so the SDK can fail
      the run rather than letting the model retry the same hung call (C20).

The SDK auto-threads sync function bodies via ``asyncio.to_thread``
(``tool.py:1820-1829``), so libtmux / IPython / blocking httpx code can be
written as plain ``def`` and the decorator will not block the event loop.

References:
    - PLAYBOOK.md §2.6
    - AUDIT_R3.md C20 (per-tool timeout_behavior discrimination)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from agents import function_tool
from agents.tool import FunctionTool


_ToolFn = Callable[..., Any]
_ToolBehavior = Literal["error_as_result", "raise_exception"]


def strix_tool(
    *,
    timeout: float = 120.0,
    timeout_behavior: _ToolBehavior = "error_as_result",
    name_override: str | None = None,
    description_override: str | None = None,
) -> Callable[[_ToolFn], FunctionTool]:
    """Wrap ``agents.function_tool`` with Strix defaults.

    The SDK's ``FunctionTool`` requires ``async def`` for ``timeout_seconds``
    to apply (sync handlers cannot be cleanly cancelled). All Strix tools are
    ``async def``; sync libraries (libtmux, IPython) get wrapped in
    ``asyncio.to_thread`` inside the async tool body.

    Usage::

        @strix_tool()
        async def my_tool(ctx: RunContextWrapper, x: int) -> str: ...

        @strix_tool(timeout=300, timeout_behavior="raise_exception")
        async def critical_tool(ctx: RunContextWrapper, ...) -> str: ...
    """
    return function_tool(
        timeout=timeout,
        timeout_behavior=timeout_behavior,
        name_override=name_override,
        description_override=description_override,
    )
