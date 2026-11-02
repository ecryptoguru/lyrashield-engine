"""Reject malformed function arguments before executing any owned tool."""

from __future__ import annotations

import json
from typing import Any


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def describe_malformed_arguments(tool_name: str, arguments: str) -> str | None:
    """Give safe recovery guidance without reflecting argument contents."""
    try:
        parsed = json.loads(arguments, parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError):
        parsed = None
    if isinstance(parsed, dict):
        return None
    return (
        f"{tool_name}: the tool call was not executed because its arguments were "
        "truncated or otherwise not a valid JSON object. "
        "Re-issue the call with complete, valid JSON arguments."
    )
