"""Local web viewer for Strix runs.

Serves a prebuilt single-page app that renders a run (live or finished) read
directly from the run's on-disk files. No cloud dependency, no file picker.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable
    from http.server import ThreadingHTTPServer
    from pathlib import Path


def serve(
    run_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
    steer_handler: Callable[[str, str], bool] | None = None,
) -> tuple[ThreadingHTTPServer, str, str]:
    """Start the viewer without importing its server during package initialization."""
    from strix.interface.viewer.server import serve as serve_viewer  # noqa: PLC0415

    return serve_viewer(
        run_dir,
        host=host,
        port=port,
        open_browser=open_browser,
        steer_handler=steer_handler,
    )


__all__ = ["serve"]
