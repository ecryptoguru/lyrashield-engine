"""Docker transport discovery must remain responsive and own late results."""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from agents.sandbox.manifest import Manifest

from lyrashield.runtime import backends
from lyrashield.runtime import docker_client as docker_runtime
from lyrashield.runtime.docker_client import StrixDockerSandboxClient


@pytest.mark.asyncio
async def test_docker_discovery_keeps_event_loop_responsive(monkeypatch) -> None:
    discovering = threading.Event()
    finished = threading.Event()
    ticks_during_discovery: list[bool] = []
    transport = SimpleNamespace(close=Mock())

    def discover():
        discovering.set()
        time.sleep(0.06)
        discovering.clear()
        return transport

    async def heartbeat():
        while not finished.is_set():
            ticks_during_discovery.append(discovering.is_set())
            await asyncio.sleep(0.005)

    session = SimpleNamespace(start=AsyncMock())
    monkeypatch.setattr("docker.from_env", discover)
    monkeypatch.setattr(StrixDockerSandboxClient, "create", AsyncMock(return_value=session))
    ticker = asyncio.create_task(heartbeat())
    try:
        client, started = await backends.docker_backend(
            image="fixture", manifest=Manifest(), exposed_ports=()
        )
    finally:
        finished.set()
        await ticker

    assert any(ticks_during_discovery), "Docker discovery blocked the event loop"
    assert client.docker_client is transport
    assert started is session
    session.start.assert_awaited_once()
    transport.close.assert_not_called()


@pytest.mark.asyncio
async def test_cancelled_discovery_closes_late_transport_without_creating_sandbox(
    monkeypatch,
) -> None:
    discovering = threading.Event()
    release_discovery = threading.Event()
    closed = threading.Event()
    close_threads: list[int] = []
    caller_thread = threading.get_ident()

    def close():
        close_threads.append(threading.get_ident())
        closed.set()

    transport = SimpleNamespace(close=Mock(side_effect=close))

    def discover():
        discovering.set()
        release_discovery.wait(timeout=0.3)
        return transport

    create = AsyncMock()
    monkeypatch.setattr("docker.from_env", discover)
    monkeypatch.setattr(StrixDockerSandboxClient, "create", create)
    task = asyncio.create_task(
        backends.docker_backend(image="fixture", manifest=Manifest(), exposed_ports=())
    )
    try:
        assert await asyncio.to_thread(discovering.wait, 1)
        task.cancel()
        done, _pending = await asyncio.wait({task}, timeout=0.05)
        assert task in done, "cancellation waited for blocking Docker discovery"
        with pytest.raises(asyncio.CancelledError):
            task.result()
        transport.close.assert_not_called()
        create.assert_not_awaited()
    finally:
        release_discovery.set()
        await asyncio.gather(task, return_exceptions=True)

    assert await asyncio.to_thread(closed.wait, 1), "late Docker transport was leaked"
    transport.close.assert_called_once()
    assert len(close_threads) == 1
    assert close_threads[0] != caller_thread
    create.assert_not_awaited()


@pytest.mark.asyncio
async def test_container_creation_never_uses_synchronous_image_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = Mock()
    transport.containers.create.return_value = SimpleNamespace(short_id="verified")
    client = StrixDockerSandboxClient(transport)
    client.strix_bind_mounts = []
    image_exists = Mock(side_effect=AssertionError("synchronous Docker inspect"))
    monkeypatch.setattr(StrixDockerSandboxClient, "image_exists", image_exists)
    monkeypatch.setattr(docker_runtime, "network_capabilities_enabled", lambda: False)
    monkeypatch.setattr(docker_runtime, "host_gateway_enabled", lambda: False)
    monkeypatch.setattr(docker_runtime, "_apply_sandbox_network", lambda _kwargs: None)
    monkeypatch.setattr(docker_runtime, "_apply_resource_limits", lambda _kwargs: None)
    monkeypatch.setattr(docker_runtime, "_apply_log_limits", lambda _kwargs: None)
    monkeypatch.setattr(docker_runtime, "_apply_run_labels", lambda _kwargs: None)
    monkeypatch.setattr(docker_runtime, "_assert_sandbox_network_admission", lambda *_args: None)

    container = await client._create_container("verified-image")

    assert container.short_id == "verified"
    image_exists.assert_not_called()
    transport.images.pull.assert_not_called()
