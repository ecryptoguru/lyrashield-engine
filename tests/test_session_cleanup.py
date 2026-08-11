from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from lyrashield.runtime import session_manager


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

    assert await session_manager.cleanup(scan_id) is False
    assert scan_id not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_cleanup_reports_sandbox_delete_success() -> None:
    scan_id = "cleanup-success"
    client = SimpleNamespace(delete=AsyncMock(return_value=object()), docker_client=MagicMock())
    session_manager._SESSION_CACHE[scan_id] = {
        "client": client,
        "session": object(),
        "caido_client": None,
    }

    assert await session_manager.cleanup(scan_id) is True
    assert scan_id not in session_manager._SESSION_CACHE
