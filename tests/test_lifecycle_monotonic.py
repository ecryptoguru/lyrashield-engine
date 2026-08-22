"""Monotonic cleanup, receipt persistence, and fail-closed lifecycle (C3, I6,
I10, I11, I22)."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from lyrashield.agents.factory import _lifecycle_tool_completed
from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import (
    REQUIRED_RUN_RECORD_FIELDS,
    RUN_RECORD_SCHEMA_VERSION,
    ReportState,
    initial_run_record,
    validate_run_record,
)
from lyrashield.runtime import session_manager
from lyrashield.tools.finish.tool import _do_finish
from lyrashield.tools.reporting import tool as reporting_tool


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _clean_session_tracking():
    session_manager._SESSION_CACHE.clear()
    session_manager._CLEANUP_RECEIPTS.clear()
    session_manager._CACHE_LOCK = __import__("asyncio").Lock()
    session_manager._CREATION_LOCK = __import__("asyncio").Lock()
    yield
    session_manager._SESSION_CACHE.clear()
    session_manager._CLEANUP_RECEIPTS.clear()


def _cached_session(scan_id: str, *, delete_raises: bool = False) -> MagicMock:
    client = MagicMock()
    if delete_raises:
        client.delete = AsyncMock(side_effect=RuntimeError("docker daemon gone"))
    else:
        client.delete = AsyncMock()
    session_manager._SESSION_CACHE[scan_id] = {
        "client": client,
        "session": MagicMock(),
        "caido_client": None,
        "egress_policy_dir": None,
    }
    return client


@pytest.mark.asyncio
async def test_failed_delete_stays_failed_and_retryable_until_real_deletion() -> None:
    _cached_session("scan-1", delete_raises=True)
    assert await session_manager.cleanup("scan-1") == session_manager.CLEANUP_FAILED
    # Session stays cached with its handles for the retry.
    assert "scan-1" in session_manager._SESSION_CACHE
    # A cache-miss-looking retry (receipt path) cannot rewrite failure.
    _cached_session("scan-1", delete_raises=True)
    session_manager._SESSION_CACHE.pop("scan-1", None)
    assert await session_manager.cleanup("scan-1") == session_manager.CLEANUP_FAILED

    # A real deletion transitions failure to removed exactly once, retaining
    # attempt history.
    _cached_session("scan-1", delete_raises=False)
    assert await session_manager.cleanup("scan-1") == session_manager.CLEANUP_REMOVED
    assert await session_manager.cleanup("scan-1") == session_manager.CLEANUP_REMOVED
    receipt = session_manager._CLEANUP_RECEIPTS["scan-1"]
    assert receipt["status"] == session_manager.CLEANUP_REMOVED
    assert receipt["attempts"] >= 2
    assert receipt.get("last_error")


@pytest.mark.asyncio
async def test_cleanup_not_found_for_unknown_scan() -> None:
    assert await session_manager.cleanup("never-created") == session_manager.CLEANUP_NOT_FOUND


def test_cleanup_outcome_receipt_is_monotonic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    state = ReportState(run_name="receipt-run")

    state.set_cleanup_outcome(session_manager.CLEANUP_FAILED, last_error="boom")
    assert state.run_record["cleanup"] == {
        "status": "failed",
        "sandbox_removed": False,
        "last_error": "boom",
    }

    # A cache miss (not_found) cannot erase the recorded failure.
    state.set_cleanup_outcome(session_manager.CLEANUP_NOT_FOUND)
    assert state.run_record["cleanup"]["status"] == session_manager.CLEANUP_FAILED

    # Confirmed removal transitions and keeps the last_error for audit.
    state.set_cleanup_outcome(session_manager.CLEANUP_REMOVED)
    assert state.run_record["cleanup"]["sandbox_removed"] is True
    assert state.run_record["cleanup"]["last_error"] == "boom"

    # Removed is terminal.
    state.set_cleanup_outcome(session_manager.CLEANUP_FAILED)
    assert state.run_record["cleanup"]["status"] == session_manager.CLEANUP_REMOVED


def test_first_run_json_write_is_complete_versioned_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I10: intercept the very first run.json replacement and validate the
    full worker contract before any consumer can observe it."""
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    captured: list[dict[str, Any]] = []
    real_write = state_module.write_run_record

    def capturing_write(run_dir: Path, record: dict[str, Any]) -> None:
        if not captured:
            validate_run_record(record)
        real_write(run_dir, record)
        captured.append(dict(record))

    monkeypatch.setattr(state_module, "write_run_record", capturing_write)
    state = ReportState(run_name="first-write")
    state.add_vulnerability_report(title="Test finding", severity="high", description="desc")

    on_disk = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == RUN_RECORD_SCHEMA_VERSION
    for field in REQUIRED_RUN_RECORD_FIELDS:
        assert field in on_disk, field
    assert captured[0] == on_disk


def test_receipt_persisted_true_on_disk_and_reverted_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    state = ReportState(run_name="receipt-truth")

    state.save_run_data()
    on_disk = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert on_disk["receipt_persisted"] is True
    assert state.receipt_persisted is True

    # Force the next write to fail: memory must stop claiming disk success.
    def failing_write(_run_dir: Path, _record: dict[str, Any]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(state_module, "write_run_record", failing_write)
    state.save_run_data()
    assert state.receipt_persisted is False
    assert state.run_record["receipt_persisted"] is False


def test_validate_run_record_rejects_incomplete_record() -> None:
    with pytest.raises(RuntimeError, match="missing fields"):
        validate_run_record({"schema_version": RUN_RECORD_SCHEMA_VERSION})
    with pytest.raises(RuntimeError, match="unsupported schema_version"):
        validate_run_record(dict.fromkeys(REQUIRED_RUN_RECORD_FIELDS) | {"schema_version": "0.9"})


def test_initial_run_record_is_canonical_for_both_owners() -> None:
    record = initial_run_record("cli-run", auth_mode="byok", extra={"scan_mode": "deep"})
    validate_run_record(record)
    assert record["run_id"] == "cli-run"
    assert record["scan_mode"] == "deep"


def test_finish_scan_fails_closed_without_report_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I22: no report state means no completion, and the factory's completion
    detector (success + scan_completed) cannot translate the error."""
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: None)
    result = _do_finish(
        parent_id=None,
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
    )
    assert result["success"] is False
    assert result["scan_completed"] is False

    assert not _lifecycle_tool_completed("finish_scan", json.dumps(result))


def test_finish_scan_fails_closed_when_receipt_not_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    report_state = ReportState(run_name="receipt-finish")
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: report_state)
    monkeypatch.setattr(
        state_module, "write_run_record", lambda _d, _r: (_ for _ in ()).throw(OSError("disk full"))
    )

    result = _do_finish(
        parent_id=None,
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
    )
    assert result["success"] is False
    assert result["scan_completed"] is False


def test_reporting_tools_fail_closed_without_report_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I6: dynamic and dependency findings return terminal errors."""
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: None)

    dynamic = asyncio.run(
        reporting_tool._do_create(
            title="RCE",
            description="d",
            impact="i",
            target="https://t.example",
            technical_analysis="ta",
            poc_description="p",
            poc_script_code="print('poc')",
            remediation_steps="r",
            evidence="e",
            assumptions="a",
            fix_effort="low",
            cvss_breakdown={
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "H",
                "integrity": "H",
                "availability": "H",
            },
            endpoint=None,
            method=None,
            cve=None,
            cwe=None,
            code_locations=None,
        )
    )
    assert dynamic["success"] is False
    assert "not persisted" in dynamic["error"]

    dependency = asyncio.run(
        reporting_tool._do_create_dependency(
            title="Vulnerable dep",
            description="d",
            target="https://t.example",
            cve="CVE-2026-1234",
            package_name="left-pad",
            installed_version="1.0.0",
            impact="i",
            remediation_steps="r",
            assumptions="a",
            package_ecosystem="npm",
            fixed_version="1.0.1",
            cwe=None,
            advisory_cvss=9.8,
            technical_analysis=None,
            fix_effort="low",
        )
    )
    assert dependency["success"] is False
    assert "not persisted" in dependency["error"]
