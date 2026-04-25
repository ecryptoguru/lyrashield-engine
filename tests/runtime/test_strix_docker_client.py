"""Phase 0 smoke tests for StrixDockerSandboxClient.

These tests do NOT require Docker. They mock the Docker SDK client (passed
to the constructor) and verify our subclass injects the right kwargs into
``containers.create``. Live container tests are part of Phase 0 manual
smoke (TESTING_STRATEGY.md §9).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import docker.errors  # type: ignore[import-untyped,unused-ignore]
import pytest

from strix.runtime.strix_docker_client import StrixDockerSandboxClient


@pytest.fixture
def fake_docker() -> MagicMock:
    """Stand-in for the Docker SDK client passed to the subclass."""
    fake = MagicMock()
    fake.images.get.return_value = MagicMock()  # image_exists -> True
    fake.images.pull = MagicMock()
    fake.containers.create.return_value = MagicMock(name="container")
    return fake


def _create_kwargs(fake: MagicMock) -> dict[str, Any]:
    result: dict[str, Any] = fake.containers.create.call_args.kwargs
    return result


def test_subclass_injects_net_admin_and_net_raw(fake_docker: MagicMock) -> None:
    client = StrixDockerSandboxClient(docker_client=fake_docker)
    asyncio.run(
        client._create_container("strix-image:latest", manifest=None, exposed_ports=()),
    )
    kwargs = _create_kwargs(fake_docker)
    assert "NET_ADMIN" in kwargs["cap_add"]
    assert "NET_RAW" in kwargs["cap_add"]


def test_subclass_injects_host_gateway(fake_docker: MagicMock) -> None:
    client = StrixDockerSandboxClient(docker_client=fake_docker)
    asyncio.run(
        client._create_container("strix-image:latest", manifest=None, exposed_ports=()),
    )
    kwargs = _create_kwargs(fake_docker)
    assert kwargs["extra_hosts"]["host.docker.internal"] == "host-gateway"


def test_subclass_preserves_image_and_command(fake_docker: MagicMock) -> None:
    client = StrixDockerSandboxClient(docker_client=fake_docker)
    asyncio.run(
        client._create_container("custom:tag", manifest=None, exposed_ports=()),
    )
    kwargs = _create_kwargs(fake_docker)
    assert kwargs["image"] == "custom:tag"
    assert kwargs["entrypoint"] == ["tail"]
    assert kwargs["command"] == ["-f", "/dev/null"]
    assert kwargs["detach"] is True


def test_subclass_emits_ports_dict_for_exposed_ports(fake_docker: MagicMock) -> None:
    client = StrixDockerSandboxClient(docker_client=fake_docker)
    asyncio.run(
        client._create_container(
            "strix-image:latest",
            manifest=None,
            exposed_ports=(48081, 48080),
        ),
    )
    kwargs = _create_kwargs(fake_docker)
    assert "48081/tcp" in kwargs["ports"]
    assert "48080/tcp" in kwargs["ports"]


def test_caps_appended_not_duplicated(fake_docker: MagicMock) -> None:
    """Idempotent injection: calling twice doesn't add duplicate caps."""
    client = StrixDockerSandboxClient(docker_client=fake_docker)
    asyncio.run(
        client._create_container("img:latest", manifest=None, exposed_ports=()),
    )
    kwargs = _create_kwargs(fake_docker)
    assert kwargs["cap_add"].count("NET_ADMIN") == 1
    assert kwargs["cap_add"].count("NET_RAW") == 1


def test_pulls_image_when_missing(fake_docker: MagicMock) -> None:
    """If image_exists returns False on first check, pull is invoked."""
    # First call raises ImageNotFound, second succeeds.
    fake_docker.images.get.side_effect = [
        docker.errors.ImageNotFound("not found"),
        MagicMock(),
    ]
    client = StrixDockerSandboxClient(docker_client=fake_docker)
    asyncio.run(
        client._create_container("registry.io/strix:tag", manifest=None, exposed_ports=()),
    )
    fake_docker.images.pull.assert_called_once()
