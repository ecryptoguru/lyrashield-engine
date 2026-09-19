"""Sandbox session cleanup outcomes (C3): explicit, monotonic, retryable.

Also pins the startup-ownership contract: every exit from
``create_or_reuse`` — validation failure, backend failure, cancellation —
leaves no leaked staging/policy/grant dirs and no undeleted sandbox.
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from lyrashield.runtime import session_manager


@pytest.fixture(autouse=True)
def _clean_tracking(monkeypatch: pytest.MonkeyPatch):
    # Module locks bind to the loop that first contends them; give each test
    # (pytest-asyncio creates a loop per test) fresh locks and clean maps.
    original_cache_lock = session_manager._CACHE_LOCK
    original_creation_lock = session_manager._CREATION_LOCK
    session_manager._SESSION_CACHE.clear()
    session_manager._CLEANUP_RECEIPTS.clear()
    session_manager._CACHE_LOCK = asyncio.Lock()
    session_manager._CREATION_LOCK = asyncio.Lock()
    monkeypatch.delenv("STRIX_TARGET_RELAY_URL", raising=False)
    monkeypatch.delenv("STRIX_TARGET_RELAY_GRANT", raising=False)
    yield
    session_manager._SESSION_CACHE.clear()
    session_manager._CLEANUP_RECEIPTS.clear()
    session_manager._CACHE_LOCK = original_cache_lock
    session_manager._CREATION_LOCK = original_creation_lock


def _stub_startup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    bootstrap: Any = None,
    backend: Any = None,
    environment: Any = None,
) -> SimpleNamespace:
    """Mock the ``create_or_reuse`` allocation/startup seam; return handles."""
    client = SimpleNamespace(
        delete=AsyncMock(),
        docker_client=SimpleNamespace(close=Mock()),
    )
    session = SimpleNamespace(
        resolve_exposed_port=AsyncMock(
            return_value=SimpleNamespace(tls=False, host="127.0.0.1", port=8080)
        )
    )
    if backend is None:
        backend = AsyncMock(return_value=(client, session))
    if bootstrap is None:
        bootstrap = AsyncMock(return_value=SimpleNamespace(aclose=AsyncMock()))
    replacements = {
        "build_session_entries": Mock(return_value=({}, [], ["/mock/staging"], [])),
        "derive_authorized_target_hosts": Mock(return_value=set()),
        "write_egress_policy": Mock(return_value=({}, "/mock/policy")),
        "load_settings": Mock(
            return_value=SimpleNamespace(runtime=SimpleNamespace(backend="docker"))
        ),
        "get_backend": Mock(return_value=backend),
        "get_sandbox_container_ip": Mock(return_value=None),
        "resolve_sandbox_endpoint": Mock(return_value=("127.0.0.1", 8080)),
        "bootstrap_caido": bootstrap,
        # This suite exercises lifecycle ownership, not capability probing;
        # the fake backend/session would otherwise report exec=absent and
        # fail preflight before the behavior under test is reached.
        "probe_session_capabilities": Mock(
            return_value={"preflight": {"degradations": [], "failures": []}}
        ),
    }
    if environment is not None:
        replacements["build_sandbox_environment"] = Mock(return_value=environment)
    for name, replacement in replacements.items():
        monkeypatch.setattr(session_manager, name, replacement)
    rmtree = Mock()
    monkeypatch.setattr(session_manager.shutil, "rmtree", rmtree)
    return SimpleNamespace(client=client, session=session, backend=backend, rmtree=rmtree)


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


@pytest.mark.asyncio
async def test_cancelled_startup_deletes_created_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """bootstrap_caido raising CancelledError must still delete the sandbox."""
    mocks = _stub_startup(
        monkeypatch,
        bootstrap=AsyncMock(side_effect=asyncio.CancelledError()),
        environment={},
    )
    with pytest.raises(asyncio.CancelledError):
        await session_manager.create_or_reuse(
            "cancelled-startup", image="fixture-image", local_sources=[]
        )
    mocks.client.delete.assert_awaited_once_with(mocks.session)
    mocks.rmtree.assert_any_call("/mock/policy", ignore_errors=True)
    mocks.rmtree.assert_any_call("/mock/staging", ignore_errors=True)
    assert "cancelled-startup" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_task_cancellation_during_bootstrap_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real task.cancel() mid-startup runs bounded cleanup, then propagates."""
    mocks = _stub_startup(monkeypatch, environment={})
    bootstrap_started = asyncio.Event()

    async def hanging_bootstrap(*_args: Any, **_kwargs: Any) -> None:
        bootstrap_started.set()
        await asyncio.Event().wait()  # hangs until the task is cancelled

    monkeypatch.setattr(session_manager, "bootstrap_caido", hanging_bootstrap)

    task = asyncio.ensure_future(
        session_manager.create_or_reuse("real-cancel", image="img", local_sources=[])
    )
    await bootstrap_started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The shielded delete still completed before the cancellation propagated.
    mocks.client.delete.assert_awaited_once_with(mocks.session)
    mocks.rmtree.assert_any_call("/mock/policy", ignore_errors=True)
    assert "real-cancel" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_invalid_relay_grant_allocates_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A malformed relay grant fails validation before any allocation."""
    mocks = _stub_startup(monkeypatch, environment={})
    monkeypatch.setenv("STRIX_TARGET_RELAY_URL", "https://relay.example")
    monkeypatch.setenv("STRIX_TARGET_RELAY_GRANT", "lrg1.bad grant;$(id)")
    with (
        caplog.at_level(logging.DEBUG, logger="lyrashield.runtime.session_manager"),
        pytest.raises(RuntimeError, match="invalid wire format"),
    ):
        await session_manager.create_or_reuse("bad-grant", image="fixture-image", local_sources=[])
    # Validation ran before any staging/policy/grant allocation existed.
    session_manager.build_session_entries.assert_not_called()
    session_manager.write_egress_policy.assert_not_called()
    mocks.client.delete.assert_not_called()
    mocks.rmtree.assert_not_called()
    assert "bad-grant" not in session_manager._SESSION_CACHE
    # The raw grant must never reach logs.
    assert "lrg1.bad grant" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "build_session_entries",
        "derive_authorized_target_hosts",
        "write_egress_policy",
        "build_sandbox_environment",
        "load_settings",
        "get_backend",
        "backend",
        "resolve_exposed_port",
        "bootstrap_caido",
    ],
)
async def test_startup_faults_never_leak_owned_resources(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """Fault injection at every allocation boundary cleans what it owns."""
    mocks = _stub_startup(monkeypatch, environment={})
    boom = RuntimeError(f"boom:{fault}")
    if fault == "backend":
        session_manager.get_backend.return_value = AsyncMock(side_effect=boom)
    elif fault == "resolve_exposed_port":
        mocks.session.resolve_exposed_port = AsyncMock(side_effect=boom)
    else:
        getattr(session_manager, fault).side_effect = boom

    scan_id = f"fault-{fault}"
    with pytest.raises(RuntimeError, match=f"boom:{fault}"):
        await session_manager.create_or_reuse(scan_id, image="img", local_sources=[])

    # A created sandbox is always deleted; a never-created one needs no delete.
    if fault in {"resolve_exposed_port", "bootstrap_caido"}:
        mocks.client.delete.assert_awaited_once_with(mocks.session)
    else:
        mocks.client.delete.assert_not_called()
    # Staging dirs are removed once allocated; a staging fault allocated none.
    if fault == "build_session_entries":
        mocks.rmtree.assert_not_called()
    else:
        mocks.rmtree.assert_any_call("/mock/staging", ignore_errors=True)
    # The policy dir only exists once write_egress_policy has run.
    if fault not in {
        "build_session_entries",
        "derive_authorized_target_hosts",
        "write_egress_policy",
    }:
        mocks.rmtree.assert_any_call("/mock/policy", ignore_errors=True)
    assert scan_id not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_repeated_cancelled_startups_each_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation is retryable: each attempt cleans its own sandbox."""
    mocks = _stub_startup(
        monkeypatch,
        bootstrap=AsyncMock(side_effect=asyncio.CancelledError()),
        environment={},
    )
    for _ in range(2):
        with pytest.raises(asyncio.CancelledError):
            await session_manager.create_or_reuse("repeat-cancel", image="img", local_sources=[])
    assert mocks.client.delete.await_count == 2
    assert "repeat-cancel" not in session_manager._SESSION_CACHE
    # Successful deletes record no failure receipt.
    assert session_manager._CLEANUP_RECEIPTS.get("repeat-cancel") is None


@pytest.mark.asyncio
async def test_failed_startup_delete_failure_stays_reapable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed startup delete keeps ownership metadata for the reaper."""
    mocks = _stub_startup(
        monkeypatch,
        bootstrap=AsyncMock(side_effect=RuntimeError("caido down")),
        environment={},
    )
    mocks.client.delete.side_effect = RuntimeError("daemon gone")

    with pytest.raises(RuntimeError, match="caido down"):
        await session_manager.create_or_reuse("stranded", image="img", local_sources=[])

    # Ownership metadata is retained; deletion was never claimed.
    bundle = session_manager._SESSION_CACHE["stranded"]
    assert bundle["session"] is mocks.session
    assert bundle["startup_error"]
    assert bundle["egress_policy_dir"] == "/mock/policy"
    receipt = session_manager._CLEANUP_RECEIPTS["stranded"]
    assert receipt["status"] == "failed"
    assert "daemon gone" in str(receipt["last_error"])
    # Host dirs stay owned by the stranded bundle for the reaper to remove.
    assert not any(call.args[0] == "/mock/policy" for call in mocks.rmtree.call_args_list)

    # The existing reaper recovers it once the daemon returns.
    mocks.client.delete.side_effect = None
    assert await session_manager.cleanup("stranded") == session_manager.CLEANUP_REMOVED
    assert "stranded" not in session_manager._SESSION_CACHE
    assert session_manager._CLEANUP_RECEIPTS["stranded"]["status"] == "removed"


@pytest.mark.asyncio
async def test_next_create_reaps_stranded_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry create first reaps the stranded sandbox, then starts fresh."""
    mocks = _stub_startup(
        monkeypatch,
        bootstrap=AsyncMock(side_effect=RuntimeError("caido down")),
        environment={},
    )
    mocks.client.delete.side_effect = RuntimeError("daemon gone")
    with pytest.raises(RuntimeError, match="caido down"):
        await session_manager.create_or_reuse("retry-scan", image="img", local_sources=[])

    # While the daemon is still gone, a retry fails closed — no second sandbox.
    with pytest.raises(RuntimeError, match="still stranded"):
        await session_manager.create_or_reuse("retry-scan", image="img", local_sources=[])
    assert mocks.backend.await_count == 1

    # Once deletion succeeds, the same call creates a fresh session.
    mocks.client.delete.side_effect = None
    session_manager.bootstrap_caido.side_effect = None
    session_manager.bootstrap_caido.return_value = SimpleNamespace(aclose=AsyncMock())
    bundle = await session_manager.create_or_reuse("retry-scan", image="img", local_sources=[])
    assert "startup_error" not in bundle
    assert mocks.backend.await_count == 2
    assert session_manager._CLEANUP_RECEIPTS["retry-scan"]["status"] == "removed"


@pytest.mark.asyncio
async def test_concurrent_same_scan_creation_shares_one_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mocks = _stub_startup(monkeypatch, environment={})
    bundles = await asyncio.gather(
        *(
            session_manager.create_or_reuse("shared", image="img", local_sources=[])
            for _ in range(4)
        )
    )
    assert all(bundle is bundles[0] for bundle in bundles)
    assert mocks.backend.await_count == 1


@pytest.mark.asyncio
async def test_relay_grant_never_reaches_agent_env_or_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The raw grant only reaches the bridge mount — never env or logs."""
    grant = "lrg1.payload.signature"
    monkeypatch.setenv("STRIX_TARGET_RELAY_URL", "https://relay.example")
    monkeypatch.setenv("STRIX_TARGET_RELAY_GRANT", grant)
    # Real environment builder so the relay branch actually engages.
    mocks = _stub_startup(
        monkeypatch,
        bootstrap=AsyncMock(side_effect=asyncio.CancelledError()),
    )
    write_upstream = Mock(
        return_value=(
            {
                "source": "/mock/upstream",
                "target": "/run/lyrashield-relay/upstream",
                "read_only": True,
            },
            "/mock/relay",
        )
    )
    monkeypatch.setattr(session_manager, "write_relay_upstream", write_upstream)
    captured: dict[str, Any] = {}

    async def backend_spy(**kwargs: Any) -> tuple[Any, Any]:
        captured.update(kwargs)
        return mocks.client, mocks.session

    session_manager.get_backend.return_value = backend_spy

    with (
        caplog.at_level(logging.DEBUG, logger="lyrashield.runtime.session_manager"),
        pytest.raises(asyncio.CancelledError),
    ):
        await session_manager.create_or_reuse("relay-cancel", image="img", local_sources=[])

    mocks.client.delete.assert_awaited_once_with(mocks.session)
    mocks.rmtree.assert_any_call("/mock/policy", ignore_errors=True)
    mocks.rmtree.assert_any_call("/mock/relay", ignore_errors=True)
    # The grant-bearing URL went only to the bridge upstream mount.
    write_upstream.assert_called_once_with(f"https://{grant}@relay.example")
    env_values = captured["manifest"].environment.value
    assert all(grant not in str(value) for value in env_values.values())
    assert "STRIX_TARGET_RELAY" in env_values
    assert grant not in caplog.text
