"""Product TUI must use the same runtime registry as the product runner."""

from lyrashield.interface.tui import app
from lyrashield.runtime import session_manager


def test_tui_cleanup_targets_product_runtime_sessions() -> None:
    assert app.session_manager is session_manager
