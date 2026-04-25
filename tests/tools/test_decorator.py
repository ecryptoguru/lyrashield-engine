"""Phase 0 smoke tests for the strix_tool decorator factory.

The SDK's ``FunctionTool`` only honors ``timeout_seconds`` for ``async``
handlers (verified at ``agents.tool._validate_function_tool_timeout_config``):
sync function bodies cannot be cleanly cancelled, so the SDK refuses to
attach a timeout to them. Every Strix tool is therefore an ``async def``;
sync libraries (libtmux, IPython) get wrapped in ``asyncio.to_thread``
inside the async tool body.
"""

from __future__ import annotations

import pytest
from agents.tool import FunctionTool

from strix.tools._decorator import strix_tool


def test_strix_tool_returns_function_tool() -> None:
    @strix_tool()
    async def my_tool(x: int) -> str:
        """Do a thing."""
        return str(x)

    assert isinstance(my_tool, FunctionTool)


def test_strix_tool_default_timeout_is_120s() -> None:
    @strix_tool()
    async def my_tool(x: int) -> str:
        """Do a thing."""
        return str(x)

    assert my_tool.timeout_seconds == 120.0


def test_strix_tool_default_timeout_behavior_is_error_as_result() -> None:
    @strix_tool()
    async def my_tool(x: int) -> str:
        """Do a thing."""
        return str(x)

    assert my_tool.timeout_behavior == "error_as_result"


def test_strix_tool_timeout_override() -> None:
    @strix_tool(timeout=300)
    async def my_tool(x: int) -> str:
        """Do a thing."""
        return str(x)

    assert my_tool.timeout_seconds == 300.0


def test_strix_tool_critical_tool_can_raise() -> None:
    """C20 (AUDIT_R3): critical tools opt into raise_exception."""

    @strix_tool(timeout=30, timeout_behavior="raise_exception")
    async def critical_tool(x: int) -> str:
        """Do a critical thing."""
        return str(x)

    assert critical_tool.timeout_behavior == "raise_exception"


def test_strix_tool_sync_handlers_rejected_by_sdk() -> None:
    """SDK explicitly rejects timeout on sync handlers; documenting the constraint."""
    with pytest.raises(ValueError, match="async @function_tool"):

        @strix_tool()
        def my_sync_tool(x: int) -> str:
            """Sync tools can't have a timeout in the SDK."""
            return str(x)
