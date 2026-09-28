"""Security and bounds checks for terminal-output rendering."""

from __future__ import annotations

from rich.text import Text

from lyrashield.interface.tui.renderers.shell_renderer import (
    MAX_LINE_LENGTH,
    MAX_OUTPUT_LINES,
    ExecCommandRenderer,
    _clean_output,
    _format_output,
)


def test_terminal_output_ansi_and_rich_markup_remain_plain_text() -> None:
    raw = "\x1b[31mred\x1b[0m [bold red]do not style[/]"

    cleaned = _clean_output(raw)
    rendered = ExecCommandRenderer.render(
        {"status": "completed", "args": {}, "result": {"content": raw}}
    ).content

    assert cleaned == "red [bold red]do not style[/]"
    assert isinstance(rendered, Text)
    assert rendered.plain.endswith(cleaned)
    assert not any("bold" in str(span.style) or "red" in str(span.style) for span in rendered.spans)


def test_terminal_output_is_bounded_by_lines_and_line_length() -> None:
    lines = ["x" * (MAX_LINE_LENGTH + 20) for _ in range(MAX_OUTPUT_LINES + 5)]

    rendered = _format_output("\n".join(lines))
    rendered_lines = rendered.plain.splitlines()

    assert len(rendered_lines) == MAX_OUTPUT_LINES
    assert all(len(line) <= MAX_LINE_LENGTH + 2 for line in rendered_lines)
    assert "lines truncated" in rendered.plain
