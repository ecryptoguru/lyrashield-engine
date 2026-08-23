"""Sandbox network admission binds to the container's actual network mode (I13)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from docker import errors as docker_errors

from lyrashield.runtime.docker_client import _assert_sandbox_network_admission


def _container(network_mode: str, *, attached_networks: dict[str, Any] | None = None) -> MagicMock:
    container = MagicMock()
    attrs: dict[str, Any] = {"HostConfig": {"NetworkMode": network_mode}}
    if attached_networks is not None:
        attrs["NetworkSettings"] = {"Networks": attached_networks}
    container.attrs = attrs
    return container


def _docker_client(
    _network_name: str = "lyrashield-sandbox", *, internal: bool = True
) -> MagicMock:
    """Mock docker client whose networks.get returns a network with the given Internal flag."""
    client = MagicMock()
    network = MagicMock()
    network.attrs = {"Internal": internal}
    network.internal = internal
    client.networks.get.return_value = network
    return client


def _docker_client_missing(_network_name: str = "lyrashield-sandbox") -> MagicMock:
    """Mock docker client whose networks.get raises NotFound."""
    client = MagicMock()
    client.networks.get.side_effect = docker_errors.NotFound("network not found")
    return client


def test_missing_network_configuration_fails_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)
    with pytest.raises(RuntimeError, match="STRIX_DOCKER_SANDBOX_NETWORK is not set"):
        _assert_sandbox_network_admission(_container("bridge"), _docker_client())


@pytest.mark.parametrize("mode", ["default", "bridge", "host"])
def test_denied_network_modes_fail_admission(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", mode)
    with pytest.raises(RuntimeError, match="not a deny-by-default sandbox network"):
        _assert_sandbox_network_admission(_container(mode), _docker_client(mode))


def test_attached_mode_must_match_configured_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    with pytest.raises(RuntimeError, match="does not match the configured sandbox network"):
        _assert_sandbox_network_admission(_container("bridge"), _docker_client())


def test_configured_network_attachment_admits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    _assert_sandbox_network_admission(
        _container(
            "lyrashield-sandbox",
            attached_networks={"lyrashield-sandbox": {"EndpointID": "abc"}},
        ),
        _docker_client("lyrashield-sandbox"),
    )


def test_extra_network_attachment_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """E1: a container attached to the configured network plus an extra
    network (e.g. bridge) has an unauthorized egress path and must be
    rejected."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    container = _container(
        "lyrashield-sandbox",
        attached_networks={
            "lyrashield-sandbox": {"EndpointID": "abc"},
            "bridge": {"EndpointID": "xyz"},
        },
    )
    with pytest.raises(RuntimeError, match="attached to networks besides"):
        _assert_sandbox_network_admission(container, _docker_client("lyrashield-sandbox"))


def test_network_mode_matches_but_actual_attachment_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E1: NetworkMode claims the expected network but NetworkSettings.Networks
    does not contain it — admission must fail."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    container = _container(
        "lyrashield-sandbox",
        attached_networks={"bridge": {"EndpointID": "xyz"}},  # wrong network
    )
    with pytest.raises(RuntimeError, match="not attached to the configured network"):
        _assert_sandbox_network_admission(container, _docker_client("lyrashield-sandbox"))


def test_admission_reads_immutable_container_fact(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lying environment must not admit a container on the default bridge."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    container: Any = _container("default")
    with pytest.raises(RuntimeError, match="does not match"):
        _assert_sandbox_network_admission(container, _docker_client())


def test_named_but_non_internal_network_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A network that exists by name but is NOT internal must fail admission."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    client = _docker_client("lyrashield-sandbox", internal=False)
    with pytest.raises(RuntimeError, match="not internal"):
        _assert_sandbox_network_admission(_container("lyrashield-sandbox"), client)


def test_network_lookup_failure_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """When docker network inspect fails (NotFound), admission must fail."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    client = _docker_client_missing("lyrashield-sandbox")
    with pytest.raises(RuntimeError, match=r"network.*not found|lookup.*fail"):
        _assert_sandbox_network_admission(_container("lyrashield-sandbox"), client)


def test_network_inspect_error_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """When docker network inspect raises a generic API error, admission must fail."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    client = MagicMock()
    client.networks.get.side_effect = docker_errors.APIError("daemon unavailable")
    with pytest.raises(RuntimeError, match=r"network.*inspect|lookup.*fail"):
        _assert_sandbox_network_admission(_container("lyrashield-sandbox"), client)
