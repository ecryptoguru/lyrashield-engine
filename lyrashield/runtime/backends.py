"""LyraShield-owned sandbox backend selection."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from strix.runtime.backends import SandboxBackend
from strix.runtime.backends import get_backend as get_upstream_backend


logger = logging.getLogger(__name__)
_pending_transport_closures: set[asyncio.Future[Any]] = set()


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
    from agents.sandbox.types import User  # noqa: PLC0415

    from lyrashield.runtime.docker_client import (  # noqa: PLC0415
        StrixDockerSandboxClient,
        assert_sdk_docker_compatibility,
    )

    assert_sdk_docker_compatibility()
    loop = asyncio.get_running_loop()
    discovery = loop.run_in_executor(None, docker.from_env)
    try:
        transport = await asyncio.shield(discovery)
    except asyncio.CancelledError:
        # Docker SDK environment discovery can block on client setup. Shield its
        # thread future so cancellation returns promptly, then close any late
        # client from a worker thread once discovery completes.
        def close_late_transport(future: asyncio.Future[Any]) -> None:
            try:
                late_transport = future.result()
            except Exception:
                return
            close = getattr(late_transport, "close", None)
            if not callable(close):
                return
            cleanup = loop.run_in_executor(None, close)
            _pending_transport_closures.add(cleanup)

            def finish_close(done: asyncio.Future[Any]) -> None:
                _pending_transport_closures.discard(done)
                try:
                    done.result()
                except Exception:
                    logger.warning("late Docker transport close failed after cancellation")

            cleanup.add_done_callback(finish_close)

        discovery.add_done_callback(close_late_transport)
        raise

    client = StrixDockerSandboxClient(transport)
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    if not any(user.name == "pentester" for user in manifest.users):
        # The shared agent factory pins run_as to this SDK manifest identity.
        # Copy the caller's manifest rather than mutating a shared template.
        manifest = manifest.model_copy(update={"users": [*manifest.users, User(name="pentester")]})
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


def get_backend(name: str) -> SandboxBackend:
    """Return product Docker behavior, delegating custom backends upstream."""
    return docker_backend if name == "docker" else get_upstream_backend(name)
