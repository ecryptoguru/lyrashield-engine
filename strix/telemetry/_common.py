from __future__ import annotations

import logging
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4


logger = logging.getLogger(__name__)

SESSION_ID: str = uuid4().hex[:16]

# (connect, read) seconds. Telemetry is a beacon, never something a user waits
# on, and these calls sit on the shutdown path: an endpoint that is blackholed by
# a firewall stalls in connect, so the cap has to be short enough that quitting
# still feels immediate.
SEND_TIMEOUT: tuple[float, float] = (2.0, 3.0)

_first_run_cached: bool | None = None


class TelemetryReportState(Protocol):
    """Report data consumed by telemetry without importing report state."""

    posthog_scan_ended_sent: bool
    scarf_scan_ended_sent: bool
    scan_ended_exit_reason: str | None
    vulnerability_reports: list[dict[str, Any]]
    start_time: str
    end_time: str | None
    run_record: dict[str, Any]

    def get_total_llm_usage(self) -> dict[str, Any]: ...


def get_version() -> str:
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        logger.debug("strix-agent version lookup failed", exc_info=True)
        return "unknown"


def is_first_run() -> bool:
    global _first_run_cached  # noqa: PLW0603
    if _first_run_cached is not None:
        return _first_run_cached
    marker = Path.home() / ".strix" / ".seen"
    if marker.exists():
        _first_run_cached = False
        return False
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110
    _first_run_cached = True
    return True


def base_props() -> dict[str, Any]:
    return {
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "strix_version": get_version(),
    }
