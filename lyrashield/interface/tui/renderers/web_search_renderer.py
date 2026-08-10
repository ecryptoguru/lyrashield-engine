# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""TUI renderer for the web_search tool."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class WebSearchRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "web_search"
    css_classes: ClassVar[list[str]] = ["tool-call", "web-search-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "completed")
        result = tool_data.get("result")

        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                result = None

        text = Text()
        text.append("Search", style="bold #f59e0b")

        query = args.get("query") or args.get("search_query") or ""
        if query:
            text.append(" ")
            text.append(str(query), style="dim")

        if isinstance(result, dict):
            if result.get("success") is False:
                message = str(result.get("message") or "Search failed")
                text.append("\n  ")
                text.append(message, style="red")
            else:
                content = str(result.get("content") or "").strip()
                if content:
                    text.append("\n  ")
                    text.append(content[:500], style="dim")
                else:
                    text.append("\n  ")
                    text.append("No results returned", style="dim")
        elif not result:
            text.append("\n  ")
            text.append("Searching...", style="dim")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)
