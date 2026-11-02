"""Native macOS control-plane routing must retain sandbox network isolation."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from agents.sandbox.errors import ExposedPortUnavailableError
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import DockerSandboxClient

from lyrashield.runtime import backends, session_manager
from lyrashield.runtime import docker_client as runtime
from lyrashield.runtime.docker_control_plane import DockerControlPlaneTunnel


NETWORK = "owned-internal"


@pytest.fixture(autouse=True)
def configured_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", NETWORK)
    monkeypatch.setenv("STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES", "0")
    monkeypatch.setenv("STRIX_SANDBOX_ALLOW_HOST_GATEWAY", "0")


def transport(base_url: str = "http+docker://localhost") -> Any:
    container = SimpleNamespace(
        short_id="owned",
        attrs={
            "HostConfig": {"NetworkMode": NETWORK},
            "NetworkSettings": {"Networks": {NETWORK: {"IPAddress": "172.21.0.2"}}},
        },
        reload=Mock(),
        remove=Mock(),
    )

    def create(**kwargs: Any) -> Any:
        container.attrs["HostConfig"]["PortBindings"] = {
            key: [{"HostIp": value[0], "HostPort": ""}]
            for key, value in kwargs.get("ports", {}).items()
        }
        return container

    return SimpleNamespace(
        api=SimpleNamespace(base_url=base_url),
        containers=SimpleNamespace(create=Mock(side_effect=create)),
        networks=SimpleNamespace(
            get=lambda _name: SimpleNamespace(
                attrs={
                    "Internal": True,
                    "Driver": "bridge",
                    "Options": {"com.docker.network.bridge.enable_icc": "false"},
                }
            )
        ),
        container=container,
    )


def session(client: Any, ports: Any) -> Any:
    client.container.attrs["NetworkSettings"]["Ports"] = ports
    result = runtime.LyraShieldDockerSandboxSession(
        docker_client=client,
        container=client.container,
        state=SimpleNamespace(
            exposed_ports=(48080,), workspace_root_ready=False, container_id="owned"
        ),
    )
    result.sandbox_network = NETWORK
    return result


@pytest.mark.asyncio
async def test_darwin_create_retains_internal_network_without_published_ports(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport()
    client = runtime.StrixDockerSandboxClient(daemon)
    client.strix_bind_mounts = [
        {"source": "/local/source", "target": "/workspace/source", "read_only": True}
    ]
    await client._create_container("qualified", exposed_ports=(48080,))
    request = daemon.containers.create.call_args.kwargs
    assert "ports" not in request
    assert request["network"] == NETWORK
    assert request["mounts"][0]["ReadOnly"] is True
    assert not request.get("privileged")
    assert not request.get("devices")
    assert not request.get("cap_add")
    assert not request.get("extra_hosts")


@pytest.mark.asyncio
async def test_restored_session_owns_reuses_and_closes_tunnel_on_delete(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport()
    sandbox = session(daemon, {})  # Recreated state has no serialized listener.
    first = await sandbox.resolve_exposed_port(48080)
    second = await sandbox.resolve_exposed_port(48080)
    assert first is second
    assert first.host == "127.0.0.1"
    assert 1 <= first.port <= 65535
    owned_tunnel = sandbox._control_plane_tunnel
    wrapper = SimpleNamespace(_inner=sandbox)
    daemon.containers.get = lambda _id: SimpleNamespace(kill=Mock())
    monkeypatch.setattr(DockerSandboxClient, "delete", AsyncMock(return_value=wrapper))
    await runtime.StrixDockerSandboxClient(daemon).delete(wrapper)
    assert owned_tunnel._closed
    assert not owned_tunnel._server.is_serving()


@pytest.mark.asyncio
async def test_delete_owns_tunnel_created_by_concurrent_resolution(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport()
    sandbox = session(daemon, {})
    wrapper = SimpleNamespace(_inner=sandbox)
    daemon.containers.get = lambda _id: SimpleNamespace(kill=Mock())
    monkeypatch.setattr(DockerSandboxClient, "delete", AsyncMock(return_value=wrapper))
    entered = asyncio.Event()
    release = asyncio.Event()
    create = DockerControlPlaneTunnel.create

    async def delayed_create(*args):
        entered.set()
        await release.wait()
        return await create(*args)

    monkeypatch.setattr(DockerControlPlaneTunnel, "create", delayed_create)
    resolving = asyncio.create_task(sandbox.resolve_exposed_port(48080))
    await entered.wait()
    deleting = asyncio.create_task(runtime.StrixDockerSandboxClient(daemon).delete(wrapper))
    await asyncio.sleep(0)
    release.set()
    try:
        await asyncio.gather(resolving, deleting)
        assert not sandbox._control_plane_tunnel._server.is_serving()
        with pytest.raises(ExposedPortUnavailableError):
            await sandbox.resolve_exposed_port(48080)
    finally:
        release.set()
        await asyncio.gather(resolving, deleting, return_exceptions=True)
        await sandbox._control_plane_tunnel.aclose()


@pytest.mark.parametrize("base_url", ["http+docker://localhost", "https://remote:2376"])
@pytest.mark.asyncio
async def test_linux_keeps_bridge_transport_without_publication(monkeypatch, base_url) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")
    daemon = transport(base_url)
    await runtime.StrixDockerSandboxClient(daemon)._create_container(
        "qualified", exposed_ports=(48080,)
    )
    assert "ports" not in daemon.containers.create.call_args.kwargs
    endpoint = await session(daemon, {})._resolve_exposed_port(48080)
    assert (endpoint.host, endpoint.port) == ("172.21.0.2", 48080)


@pytest.mark.asyncio
async def test_remote_linux_missing_bridge_never_resolves_worker_loopback(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")
    daemon = transport("https://remote:2376")
    daemon.container.attrs["NetworkSettings"]["Networks"] = {NETWORK: {}}
    with pytest.raises(ExposedPortUnavailableError):
        await session(
            daemon, {"48080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "59123"}]}
        )._resolve_exposed_port(48080)


@pytest.mark.parametrize(
    "base_url",
    ["http://remote:2375", "https://remote:2376", "http://127.0.0.1:2375", "http+docker://ssh", ""],
)
@pytest.mark.asyncio
async def test_darwin_remote_or_unknown_transport_fails_before_create(
    monkeypatch, base_url
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport(base_url)
    with pytest.raises(RuntimeError, match="local Unix socket"):
        await runtime.StrixDockerSandboxClient(daemon)._create_container(
            "qualified", exposed_ports=(48080,)
        )
    daemon.containers.create.assert_not_called()


@pytest.mark.asyncio
async def test_unsupported_remote_admission_closes_acquired_transport(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport("https://remote:2376")
    daemon.close = Mock()
    monkeypatch.setattr("lyrashield.runtime.docker_connection.connect_docker", lambda: daemon)

    with pytest.raises(RuntimeError, match="local Unix socket"):
        await backends.docker_backend(
            image="qualified", manifest=Manifest(), exposed_ports=(48080,)
        )

    daemon.containers.create.assert_not_called()
    daemon.close.assert_called_once()


@pytest.mark.asyncio
async def test_darwin_refuses_to_publish_unowned_ports(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport()
    with pytest.raises(RuntimeError, match="48080"):
        await runtime.StrixDockerSandboxClient(daemon)._create_container(
            "qualified", exposed_ports=(48080, 8080)
        )
    daemon.containers.create.assert_not_called()


@pytest.mark.asyncio
async def test_tunnel_creation_failure_uses_owned_startup_cleanup(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport()
    daemon.close = Mock()
    sandbox = session(daemon, {})

    async def delete(owned_session: Any) -> None:
        assert owned_session is sandbox
        daemon.container.remove(force=True)

    owner = SimpleNamespace(docker_client=daemon, delete=delete)

    async def backend(**_kwargs: Any) -> tuple[Any, Any]:
        return owner, sandbox

    bootstrap = AsyncMock()
    monkeypatch.setattr(
        "lyrashield.runtime.docker_control_plane.DockerControlPlaneTunnel.create",
        AsyncMock(side_effect=OSError("listener unavailable")),
    )
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", bootstrap)
    scan_id = "desktop-mapping-failure-cleanup"

    with pytest.raises(OSError, match="listener unavailable"):
        await session_manager.create_or_reuse(scan_id, image="qualified", local_sources=[])

    daemon.container.remove.assert_called_once_with(force=True)
    daemon.close.assert_called_once()
    bootstrap.assert_not_awaited()
    assert scan_id not in session_manager._SESSION_CACHE


@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.asyncio
async def test_bootstrap_failure_or_cancel_closes_session_listener(monkeypatch, cancel):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    daemon = transport()
    daemon.close = Mock()
    daemon.containers.get = lambda _id: daemon.container
    daemon.container.kill = Mock()
    sandbox = session(daemon, {})
    owner = runtime.StrixDockerSandboxClient(daemon)
    wrapper = SimpleNamespace(_inner=sandbox, resolve_exposed_port=sandbox.resolve_exposed_port)
    entered = asyncio.Event()

    async def backend(**_kwargs):
        return owner, wrapper

    async def bootstrap(*_args, **_kwargs):
        entered.set()
        if cancel:
            await asyncio.Event().wait()
        raise RuntimeError("bootstrap unavailable")

    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", bootstrap)
    monkeypatch.setattr(DockerSandboxClient, "delete", AsyncMock(return_value=wrapper))
    scan_id = f"desktop-bootstrap-cleanup-{cancel}"
    task = asyncio.create_task(
        session_manager.create_or_reuse(scan_id, image="qualified", local_sources=[])
    )
    await asyncio.wait_for(entered.wait(), 1)
    endpoint = sandbox._control_plane_tunnel.endpoint
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else RuntimeError):
        await task
    with pytest.raises(OSError):
        await asyncio.open_connection(endpoint.host, endpoint.port)
    assert sandbox._control_plane_tunnel._closed
    assert not sandbox._control_plane_tunnel._tasks
    assert scan_id not in session_manager._SESSION_CACHE
    daemon.close.assert_called_once()
