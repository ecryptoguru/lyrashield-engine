"""LyraShield-owned sandbox backend selection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.runtime.backends import SandboxBackend
from strix.runtime.backends import get_backend as get_upstream_backend


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


async def docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Start a Docker session through the LyraShield adapter."""
    import docker  # noqa: PLC0415
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions  # noqa: PLC0415

    from lyrashield.runtime.docker_client import (  # noqa: PLC0415
        StrixDockerSandboxClient,
        assert_sdk_docker_compatibility,
    )

    assert_sdk_docker_compatibility()
    client = StrixDockerSandboxClient(docker.from_env())
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


def get_backend(name: str) -> SandboxBackend:
    """Return product Docker behavior, delegating custom backends upstream."""
    return docker_backend if name == "docker" else get_upstream_backend(name)
