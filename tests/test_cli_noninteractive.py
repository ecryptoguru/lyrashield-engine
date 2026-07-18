"""Non-interactive CLI behavior stays free of Rich live rendering."""

from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix.interface import cli


main_module = import_module("strix.interface.main")


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


@pytest.mark.parametrize(
    ("record", "findings", "expected"),
    [
        ({"status": "completed"}, [], 0),
        ({"status": "completed"}, [{"id": "finding-1"}], 2),
        ({"status": "stopped", "terminal_reason": "budget_exceeded"}, [], 3),
        ({"status": "stopped", "terminal_reason": "rate_limited"}, [], 4),
        ({"status": "stopped", "terminal_reason": "incomplete"}, [], 5),
    ],
)
def test_non_interactive_exit_code_requires_a_completed_receipt(
    record: dict[str, str], findings: list[dict[str, str]], expected: int
) -> None:
    report_state = SimpleNamespace(run_record=record, vulnerability_reports=findings)
    assert main_module._non_interactive_exit_code(report_state) == expected
