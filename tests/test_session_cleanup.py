"""Sandbox session cleanup outcomes (C3): explicit, monotonic, retryable."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from lyrashield.runtime import session_manager


@pytest.fixture(autouse=True)
def _clean_tracking():
    session_manager._SESSION_CACHE.clear()
    session_manager._CLEANUP_RECEIPTS.clear()
    yield
    session_manager._SESSION_CACHE.clear()
    session_manager._CLEANUP_RECEIPTS.clear()


@pytest.mark.asyncio
async def test_cleanup_reports_sandbox_delete_failure() -> None:
    scan_id = "cleanup-failure"
    client = SimpleNamespace(
        delete=AsyncMock(side_effect=RuntimeError("daemon unavailable")),
        docker_client=MagicMock(),
    )
    session_manager._SESSION_CACHE[scan_id] = {
        "client": client,
        "session": object(),
        "caido_client": None,
    }

    assert await session_manager.cleanup(scan_id) == session_manager.CLEANUP_FAILED
    # The session stays cached with its handles so a retry can succeed.
    assert scan_id in session_manager._SESSION_CACHE
    receipt = session_manager._CLEANUP_RECEIPTS[scan_id]
    assert receipt["status"] == "failed"
    assert "daemon unavailable" in str(receipt.get("last_error"))


@pytest.mark.asyncio
async def test_cleanup_reports_sandbox_delete_success() -> None:
    scan_id = "cleanup-success"
    client = SimpleNamespace(delete=AsyncMock(return_value=object()), docker_client=MagicMock())
    session_manager._SESSION_CACHE[scan_id] = {
        "client": client,
        "session": object(),
        "caido_client": None,
    }

    assert await session_manager.cleanup(scan_id) == session_manager.CLEANUP_REMOVED
    assert scan_id not in session_manager._SESSION_CACHE
    assert session_manager._CLEANUP_RECEIPTS[scan_id]["status"] == "removed"
