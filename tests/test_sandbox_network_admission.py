"""Sandbox network admission binds to the container's actual network mode (I13)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from lyrashield.runtime.docker_client import _assert_sandbox_network_admission


def _container(network_mode: str) -> MagicMock:
    container = MagicMock()
    container.attrs = {"HostConfig": {"NetworkMode": network_mode}}
    return container


def test_missing_network_configuration_fails_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)
    with pytest.raises(RuntimeError, match="STRIX_DOCKER_SANDBOX_NETWORK is not set"):
        _assert_sandbox_network_admission(_container("bridge"))


@pytest.mark.parametrize("mode", ["default", "bridge", "host"])
def test_denied_network_modes_fail_admission(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", mode)
    with pytest.raises(RuntimeError, match="not a deny-by-default sandbox network"):
        _assert_sandbox_network_admission(_container(mode))


def test_attached_mode_must_match_configured_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    with pytest.raises(RuntimeError, match="does not match the configured sandbox network"):
        _assert_sandbox_network_admission(_container("bridge"))


def test_configured_network_attachment_admits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    _assert_sandbox_network_admission(_container("lyrashield-sandbox"))


def test_admission_reads_immutable_container_fact(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lying environment must not admit a container on the default bridge."""
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "lyrashield-sandbox")
    container: Any = _container("default")
    with pytest.raises(RuntimeError, match="does not match"):
        _assert_sandbox_network_admission(container)
