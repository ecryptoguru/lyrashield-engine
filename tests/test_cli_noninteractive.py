"""Non-interactive CLI behavior stays free of Rich live rendering."""

from __future__ import annotations

import asyncio
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lyrashield.interface import cli
from lyrashield.lifecycle.deadline import RunDeadlineExceeded


main_module = import_module("lyrashield.interface.main")


class _ProviderFailureError(RuntimeError):
    def __init__(self, body: object) -> None:
        super().__init__("target-derived detail")
        self.body = body


def test_noninteractive_failure_label_includes_only_a_safe_provider_code() -> None:
    failure = _ProviderFailureError(
        {
            "code": "context_length_exceeded",
            "type": "invalid_request_error",
            "param": "input",
            "message": "target-derived detail",
        }
    )

    assert (
        cli._noninteractive_failure_label(failure)
        == "_ProviderFailureError.context_length_exceeded"
    )


@pytest.mark.parametrize(
    "body",
    [
        {"code": "unsafe value with spaces"},
        {"code": "x" * 65},
        {"message": "target-derived detail"},
        "not-a-mapping",
    ],
)
def test_noninteractive_failure_label_rejects_unbounded_provider_details(body: object) -> None:
    assert cli._noninteractive_failure_label(_ProviderFailureError(body)) == "_ProviderFailureError"


@pytest.mark.parametrize(
    ("module", "expected"),
    [
        ("docker.errors", "DockerAPIError"),
        ("openai._exceptions", "ProviderAPIError"),
    ],
)
def test_noninteractive_failure_label_disambiguates_api_error_source(
    module: str, expected: str
) -> None:
    failure_type = type("APIError", (RuntimeError,), {"__module__": module})

    assert cli._noninteractive_failure_label(failure_type("bounded failure")) == expected


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
        runtime_budget_seconds=100.0,
    )
    report_state = MagicMock()
    report_state.final_scan_result = None

    with (
        patch.object(cli, "ReportState", return_value=report_state),
        patch.object(cli, "set_global_report_state"),
        patch.object(cli, "_resolve_sandbox_image", return_value="sandbox@sha256:test"),
        patch.object(cli, "run_strix_scan", new=AsyncMock()) as run_scan,
        patch.object(
            cli.session_manager, "cleanup", new=AsyncMock(return_value="removed")
        ) as cleanup,
        patch.object(cli, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli.atexit, "register"),
        patch.object(cli.signal, "signal"),
    ):
        await cli.run_cli(args)

    run_scan.assert_awaited_once()
    assert run_scan.call_args.kwargs["coordinator"].run_deadline.remaining_seconds() > 0
    cleanup.assert_awaited_once_with("scan-test")
    assert report_state.set_cleanup_outcome.call_args.args == ("removed",)
    report_state.hydrate_from_run_dir.assert_not_called()


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


def test_non_interactive_unhandled_failure_exits_without_a_traceback() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main_module._exit_noninteractive_failure(non_interactive=True)

    assert exc_info.value.code == 1
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True


def test_interactive_unhandled_failure_remains_raisable() -> None:
    assert main_module._exit_noninteractive_failure(non_interactive=False) is None


@pytest.mark.parametrize(
    ("record", "findings", "expected"),
    [
        ({"status": "stopped", "terminal_reason": "runtime_deadline"}, [], 5),
        (
            {"status": "stopped", "terminal_reason": "runtime_deadline"},
            [{"id": "finding-1"}],
            2,
        ),
        ({"status": "stopped", "terminal_reason": "engine_stopped"}, [], 5),
    ],
)
def test_runtime_deadline_exit_code_matches_the_partial_contract(
    record: dict[str, str], findings: list[dict[str, str]], expected: int
) -> None:
    report_state = SimpleNamespace(run_record=record, vulnerability_reports=findings)
    assert main_module._non_interactive_exit_code(report_state) == expected


@pytest.mark.asyncio
async def test_runtime_deadline_salvages_instead_of_failing() -> None:
    """The hard deadline records runtime_deadline and does not raise out."""
    args = SimpleNamespace(
        run_name="scan-deadline",
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
        # A tiny allowance: the run body never finishes before the deadline.
        runtime_budget_seconds=0.01,
    )
    report_state = MagicMock()
    report_state.final_scan_result = None

    async def _never_finishes(*_args: object, **_kwargs: object) -> None:
        await asyncio.sleep(5)

    with (
        patch.object(cli, "ReportState", return_value=report_state),
        patch.object(cli, "set_global_report_state"),
        patch.object(cli, "_resolve_sandbox_image", return_value="sandbox@sha256:test"),
        patch.object(cli, "run_strix_scan", new=_never_finishes),
        patch.object(cli.session_manager, "cleanup", new=AsyncMock(return_value="removed")),
        patch.object(cli, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli.atexit, "register"),
        patch.object(cli.signal, "signal"),
    ):
        await cli.run_cli(args)

    report_state.set_terminal_reason.assert_called_once_with("runtime_deadline")


@pytest.mark.asyncio
async def test_a_non_deadline_failure_still_propagates() -> None:
    """A genuine error must not be swallowed by the deadline handler."""
    args = SimpleNamespace(
        run_name="scan-error",
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
        runtime_budget_seconds=100.0,
    )
    report_state = MagicMock()
    report_state.final_scan_result = None

    async def _raises(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("engine blew up")

    with (
        patch.object(cli, "ReportState", return_value=report_state),
        patch.object(cli, "set_global_report_state"),
        patch.object(cli, "_resolve_sandbox_image", return_value="sandbox@sha256:test"),
        patch.object(cli, "run_strix_scan", new=_raises),
        patch.object(cli.session_manager, "cleanup", new=AsyncMock(return_value="removed")),
        patch.object(cli, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli.atexit, "register"),
        patch.object(cli.signal, "signal"),
        pytest.raises(RuntimeError, match="engine blew up"),
    ):
        await cli.run_cli(args)

    report_state.set_terminal_reason.assert_not_called()


@pytest.mark.asyncio
async def test_a_lifecycle_deadline_refusal_is_salvaged() -> None:
    """RunDeadlineExceeded is the dedicated deadline signal and must salvage.

    The lifecycle raises this type from ``on_llm_start`` when a model start is
    attempted past the deadline. It is distinguishable from an internal
    TimeoutError, so it salvages without waiting for the asyncio context to
    expire.
    """
    args = SimpleNamespace(
        run_name="scan-lifecycle-deadline",
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
        runtime_budget_seconds=100.0,
    )
    report_state = MagicMock()
    report_state.final_scan_result = None

    async def _deadline_refusal(*_args: object, **_kwargs: object) -> None:
        raise RunDeadlineExceeded("scan runtime deadline reached")

    with (
        patch.object(cli, "ReportState", return_value=report_state),
        patch.object(cli, "set_global_report_state"),
        patch.object(cli, "_resolve_sandbox_image", return_value="sandbox@sha256:test"),
        patch.object(cli, "run_strix_scan", new=_deadline_refusal),
        patch.object(cli.session_manager, "cleanup", new=AsyncMock(return_value="removed")),
        patch.object(cli, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli.atexit, "register"),
        patch.object(cli.signal, "signal"),
    ):
        await cli.run_cli(args)

    report_state.set_terminal_reason.assert_called_once_with("runtime_deadline")


@pytest.mark.asyncio
async def test_an_internal_timeout_is_not_relabeled_as_a_deadline() -> None:
    """A TimeoutError raised while time remains is a real failure, not a deadline.

    An internal ``asyncio.wait_for``, a provider call timeout or a tool timeout
    that escapes the run must NOT be reported as a bounded partial result. Only
    the hard deadline is salvageable.
    """
    args = SimpleNamespace(
        run_name="scan-internal-timeout",
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
        # Plenty of time left: the deadline is nowhere near expiring.
        runtime_budget_seconds=100.0,
    )
    report_state = MagicMock()
    report_state.final_scan_result = None

    async def _internal_timeout(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError("an internal wait_for expired")

    with (
        patch.object(cli, "ReportState", return_value=report_state),
        patch.object(cli, "set_global_report_state"),
        patch.object(cli, "_resolve_sandbox_image", return_value="sandbox@sha256:test"),
        patch.object(cli, "run_strix_scan", new=_internal_timeout),
        patch.object(cli.session_manager, "cleanup", new=AsyncMock(return_value="removed")),
        patch.object(cli, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli.atexit, "register"),
        patch.object(cli.signal, "signal"),
        pytest.raises(TimeoutError, match="an internal wait_for expired"),
    ):
        await cli.run_cli(args)

    report_state.set_terminal_reason.assert_not_called()
