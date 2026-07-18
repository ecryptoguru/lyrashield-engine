"""Non-interactive CLI behavior stays free of Rich live rendering."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix.interface import cli


@pytest.mark.asyncio
async def test_non_interactive_scan_bypasses_live_display() -> None:
    args = SimpleNamespace(
        run_name="scan-test",
        targets_info=[{"original": "example.test"}],
        instruction=None,
        diff_scope={"active": False},
        local_sources=[],
        scope_mode="auto",
        diff_base=None,
        user_explicit_instruction=None,
        scan_mode="quick",
        non_interactive=True,
        interactive=False,
        max_budget_usd=1.0,
    )
    report_state = MagicMock()
    report_state.final_scan_result = None

    with (
        patch.object(cli, "ReportState", return_value=report_state),
        patch.object(cli, "set_global_report_state"),
        patch.object(cli, "_resolve_sandbox_image", return_value="sandbox@sha256:test"),
        patch.object(cli, "run_strix_scan", new=AsyncMock()) as run_scan,
        patch.object(cli.session_manager, "cleanup", new=AsyncMock()) as cleanup,
        patch.object(cli, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli.atexit, "register"),
        patch.object(cli.signal, "signal"),
    ):
        await cli.run_cli(args)

    run_scan.assert_awaited_once()
    cleanup.assert_awaited_once_with("scan-test")
