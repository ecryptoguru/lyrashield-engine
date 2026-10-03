"""Shared Pygments colors for the Textual tool renderers."""

from functools import cache
from typing import Any

from pygments.styles import get_style_by_name


@cache
def _style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def token_color(token_type: Any) -> str | None:
    colors = _style_colors()
    while token_type:
        if token_type in colors:
            return colors[token_type]
        token_type = token_type.parent
    return None
