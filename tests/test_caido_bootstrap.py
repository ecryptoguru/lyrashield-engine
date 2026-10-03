"""Tests for Caido bootstrap."""

from __future__ import annotations

from typing import Any

import pytest

from lyrashield.runtime import caido_bootstrap


class _FakeProject:
    def __init__(self, name: str) -> None:
        self.name = name
        self.id = "project-id"


class _FakeProjectManager:
    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []

    async def create(self, options: Any) -> _FakeProject:
        self.created.append({"name": options.name, "temporary": options.temporary})
        return _FakeProject(options.name)

    async def select(self, project_id: str) -> None:
        self.selected = project_id


class _FakeClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        self.project = _FakeProjectManager()
        self.close_count = 0

    async def connect(self) -> None:
        return None

    async def aclose(self) -> None:
        self.close_count = getattr(self, "close_count", 0) + 1


class _FakeTokenAuth:
    def __init__(self, token: str) -> None:
        self.token = token


@pytest.mark.asyncio
async def test_bootstrap_caido_uses_per_scan_project_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(caido_bootstrap, "Client", _FakeClient)
    monkeypatch.setattr(caido_bootstrap, "TokenAuthOptions", _FakeTokenAuth)

    async def _fake_login(*_args: Any, **_kwargs: Any) -> str:
        return "guest-token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _fake_login)

    class _FakeSession:
        pass

    client = await caido_bootstrap.bootstrap_caido(
        _FakeSession(),  # type: ignore[arg-type]
        scan_id="scan-12345678-uuid",
        host_url="http://localhost:48080",
        container_url="http://127.0.0.1:48080",
    )

    assert client.project.created
    assert client.project.created[0]["name"].startswith("sandbox-scan-123")
    assert client.project.created[0]["name"] == "sandbox-scan-123"
    assert client.project.created[0]["temporary"] is True


@pytest.mark.asyncio
async def test_bootstrap_transfers_client_before_connect_and_leaves_cleanup_to_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registered: list[_FakeClient] = []

    class ConnectingClient(_FakeClient):
        async def connect(self) -> None:
            assert registered == [self]
            raise RuntimeError("connect failed")

    monkeypatch.setattr(caido_bootstrap, "Client", ConnectingClient)
    monkeypatch.setattr(caido_bootstrap, "TokenAuthOptions", _FakeTokenAuth)

    async def _fake_login(*_args: Any, **_kwargs: Any) -> str:
        return "guest-token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _fake_login)

    class _FakeSession:
        pass

    with pytest.raises(RuntimeError, match="connect failed"):
        await caido_bootstrap.bootstrap_caido(
            _FakeSession(),  # type: ignore[arg-type]
            scan_id="scan-ownership",
            host_url="http://localhost:48080",
            container_url="http://127.0.0.1:48080",
            on_client_created=registered.append,
        )

    assert len(registered) == 1
    assert registered[0].close_count == 0
    await registered[0].aclose()
    assert registered[0].close_count == 1


@pytest.mark.asyncio
async def test_bootstrap_closes_client_on_connect_failure_without_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ConnectingClient(_FakeClient):
        async def connect(self) -> None:
            raise RuntimeError("connect failed")

    monkeypatch.setattr(caido_bootstrap, "Client", ConnectingClient)
    monkeypatch.setattr(caido_bootstrap, "TokenAuthOptions", _FakeTokenAuth)

    async def _fake_login(*_args: Any, **_kwargs: Any) -> str:
        return "guest-token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _fake_login)

    class _FakeSession:
        pass

    clients: list[ConnectingClient] = []

    def make_client(*args: Any, **kwargs: Any) -> ConnectingClient:
        client = ConnectingClient(*args, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(caido_bootstrap, "Client", make_client)
    with pytest.raises(RuntimeError, match="connect failed"):
        await caido_bootstrap.bootstrap_caido(
            _FakeSession(),  # type: ignore[arg-type]
            scan_id="scan-local-cleanup",
            host_url="http://localhost:48080",
            container_url="http://127.0.0.1:48080",
        )

    assert len(clients) == 1
    assert clients[0].close_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift", [None, "disabled", "different_port", "narrow_scope", "socks", "plugin"]
)
async def test_target_relay_upstream_requires_exact_readback(drift: str | None) -> None:
    class Graphql:
        configured: dict[str, Any]

        async def mutation(self, _query: str, variables: dict[str, Any]) -> dict[str, Any]:
            self.configured = {"id": "proxy-id", **variables["input"]}
            return {"createUpstreamProxyHttp": {"proxy": {"id": "proxy-id"}}}

        async def query(self, _query: str) -> dict[str, Any]:
            if drift == "disabled":
                self.configured["enabled"] = False
            elif drift == "different_port":
                self.configured["connection"]["port"] = 1234
            elif drift == "narrow_scope":
                self.configured["allowlist"] = ["one.example"]
            return {
                "upstreamProxiesHttp": [self.configured],
                "upstreamProxiesSocks": [{"enabled": drift == "socks"}],
                "upstreamPlugins": [{"enabled": drift == "plugin"}],
            }

    class Client:
        graphql = Graphql()

    if drift:
        with pytest.raises(RuntimeError, match="verification failed"):
            await caido_bootstrap.configure_target_relay(Client())  # type: ignore[arg-type]
    else:
        await caido_bootstrap.configure_target_relay(Client())  # type: ignore[arg-type]
        assert Client.graphql.configured["connection"] == {
            "host": "127.0.0.1",
            "port": 48081,
            "isTLS": False,
        }
