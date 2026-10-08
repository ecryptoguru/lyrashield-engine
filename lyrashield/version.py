"""Single source of truth for the engine's own package version.

The distribution is named ``lyrashield-engine`` in ``pyproject.toml``. Looking
up any other identifier raises ``PackageNotFoundError`` in every environment that
installed this project, which silently degrades the SARIF
``tool.driver.version`` field and the TUI header.

``engine_version`` never raises: a frozen PyInstaller build or a source checkout
that was never installed has no distribution metadata at all, and a version
string is informational rather than load-bearing.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


DISTRIBUTION_NAME = "lyrashield-engine"


def engine_version() -> str | None:
    """Return the installed engine version, or ``None`` when metadata is absent."""
    try:
        return version(DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return None
    except Exception:  # noqa: BLE001 - metadata backends can fail in frozen builds
        return None
