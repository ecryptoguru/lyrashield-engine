"""StrixDockerSandboxClient.delete() best-effort teardown.

delete() kills the sandbox container before delegating to the SDK's delete().
The kill is meant to be best-effort, but the ``contextlib.suppress`` around it
must cover the case where the docker daemon socket is already gone: then
``containers.get()`` -> ``inspect_container`` raises requests'
``ConnectionError``, which is a *sibling* of ``docker.errors.APIError`` under
``requests.RequestException`` (not a subclass), so an APIError-only suppress
would let it escape and surface a traceback on every teardown.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agents.sandbox.sandboxes.docker import DockerSandboxClient
from docker import errors as docker_errors
from requests.exceptions import ConnectionError as RequestsConnectionError

from lyrashield.runtime.docker_client import StrixDockerSandboxClient, _apply_resource_limits


def _client_with_kill_error(exc: Exception) -> StrixDockerSandboxClient:
    """A StrixDockerSandboxClient whose containers.get(...).kill() raises ``exc``."""
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    docker_client = MagicMock()
    docker_client.containers.get.side_effect = exc
    client.docker_client = docker_client
    return client


def _session() -> object:
    # delete() reads session._inner.state.container_id
    return SimpleNamespace(_inner=SimpleNamespace(state=SimpleNamespace(container_id="abc123")))


@pytest.mark.parametrize(
    "exc",
    [
        RequestsConnectionError("Connection aborted", FileNotFoundError(2, "No such file")),
        docker_errors.NotFound("gone"),
        docker_errors.APIError("unhappy"),
    ],
)
@pytest.mark.asyncio
async def test_delete_swallows_best_effort_kill_errors(exc):
    """A torn-down socket (ConnectionError) or a gone/unhappy container
    (NotFound/APIError) during the kill must not propagate; delete() still
    delegates to the SDK's delete()."""
    client = _client_with_kill_error(exc)
    session = _session()

    with patch.object(
        DockerSandboxClient, "delete", new=AsyncMock(return_value=session)
    ) as super_delete:
        result = await client.delete(session)

    assert result is session
    super_delete.assert_awaited_once()  # teardown proceeded despite the kill error


@pytest.mark.asyncio
async def test_delete_does_not_swallow_unrelated_errors():
    """A programming error (e.g. ValueError) is not part of best-effort kill and
    must still propagate."""
    client = _client_with_kill_error(ValueError("boom"))
    with pytest.raises(ValueError):
        await client.delete(_session())


@pytest.mark.asyncio
async def test_delete_noop_without_container_id():
    """No container_id -> no kill attempt, just delegate."""
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    client.docker_client = MagicMock()
    session = SimpleNamespace(_inner=SimpleNamespace(state=SimpleNamespace(container_id=None)))

    with patch.object(
        DockerSandboxClient, "delete", new=AsyncMock(return_value=session)
    ) as super_delete:
        await client.delete(session)

    client.docker_client.containers.get.assert_not_called()
    super_delete.assert_awaited_once()


# --- Default-on sandbox resource caps (founder-pinned defaults) ---


def test_resource_limits_default_on_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for knob in (
        "STRIX_SANDBOX_MEM_LIMIT",
        "STRIX_SANDBOX_SHM_SIZE",
        "STRIX_SANDBOX_CPUS",
        "STRIX_SANDBOX_PIDS_LIMIT",
    ):
        monkeypatch.delenv(knob, raising=False)

    create_kwargs: dict[str, Any] = {}
    _apply_resource_limits(create_kwargs)

    assert create_kwargs["mem_limit"] == "2g"
    assert create_kwargs["shm_size"] == "512m"
    assert create_kwargs["nano_cpus"] == 2_000_000_000
    assert create_kwargs["pids_limit"] == 512


def test_resource_limits_env_overrides_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MEM_LIMIT", "4g")
    monkeypatch.setenv("STRIX_SANDBOX_SHM_SIZE", "1g")
    monkeypatch.setenv("STRIX_SANDBOX_CPUS", "1.5")
    monkeypatch.setenv("STRIX_SANDBOX_PIDS_LIMIT", "256")

    create_kwargs: dict[str, Any] = {}
    _apply_resource_limits(create_kwargs)

    assert create_kwargs["mem_limit"] == "4g"
    assert create_kwargs["shm_size"] == "1g"
    assert create_kwargs["nano_cpus"] == 1_500_000_000
    assert create_kwargs["pids_limit"] == 256


def test_resource_limits_explicit_opt_out_restores_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value in ("0", "off", "none", "unlimited"):
        monkeypatch.setenv("STRIX_SANDBOX_MEM_LIMIT", value)
        monkeypatch.setenv("STRIX_SANDBOX_CPUS", value)
        monkeypatch.setenv("STRIX_SANDBOX_PIDS_LIMIT", value)
        monkeypatch.setenv("STRIX_SANDBOX_SHM_SIZE", value)

        create_kwargs: dict[str, Any] = {}
        _apply_resource_limits(create_kwargs)

        assert "mem_limit" not in create_kwargs, value
        assert "nano_cpus" not in create_kwargs, value
        assert "pids_limit" not in create_kwargs, value
        assert "shm_size" not in create_kwargs, value


def test_resource_limits_unparseable_value_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_CPUS", "not-a-number")
    monkeypatch.setenv("STRIX_SANDBOX_PIDS_LIMIT", "also-not-a-number")
    monkeypatch.delenv("STRIX_SANDBOX_MEM_LIMIT", raising=False)

    create_kwargs: dict[str, Any] = {}
    _apply_resource_limits(create_kwargs)

    # Never falls back to unbounded on a bad value.
    assert create_kwargs["nano_cpus"] == 2_000_000_000
    assert create_kwargs["pids_limit"] == 512
    assert create_kwargs["mem_limit"] == "2g"
