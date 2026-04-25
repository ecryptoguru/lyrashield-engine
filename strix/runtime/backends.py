"""Sandbox backend registry — runtime-agnostic session bring-up.

A *backend* is an async callable that takes an image tag + an SDK
:class:`Manifest` + the ports to expose, and returns the matching
``(client, session)`` pair. The caller owns lifecycle from there
(``await client.delete(session)``).

This keeps :mod:`strix.runtime.session_manager` free of any
backend-specific imports — switching to Daytona / K8s / Modal /
whatever is one new factory function plus one registry entry.

Selection is driven by ``STRIX_RUNTIME_BACKEND`` (default: ``"docker"``).
Unknown values raise :class:`ValueError` rather than silently falling
back, so typos fail loudly.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


# A backend brings up a fresh session and returns the (client, session)
# pair. The client is whatever object exposes ``await client.delete(session)``
# for cleanup — typically an ``agents.sandbox.client.BaseSandboxClient``
# subclass, but the protocol is duck-typed so non-SDK backends could
# also plug in if they implement the same interface.
SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]


async def _docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
) -> tuple[Any, Any]:
    """Bring up a session backed by the local Docker daemon.

    Uses :class:`StrixDockerSandboxClient` to inject NET_ADMIN /
    NET_RAW caps + ``host.docker.internal`` host-gateway. Imports
    ``docker`` lazily so deployments that target a non-Docker
    backend don't need the docker-py library installed.
    """
    import docker
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient

    client = StrixDockerSandboxClient(docker.from_env())
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    return client, session


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
}


def get_backend(name: str) -> SandboxBackend:
    """Return the backend factory for ``name`` or raise.

    Args:
        name: Backend identifier (e.g. ``"docker"``). Match is exact;
            no fallback. Unknown values raise so config typos surface
            immediately instead of silently picking a default.
    """
    backend = _BACKENDS.get(name)
    if backend is None:
        supported = ", ".join(sorted(_BACKENDS))
        raise ValueError(
            f"Unknown STRIX_RUNTIME_BACKEND: {name!r} (supported: {supported})",
        )
    return backend


def register_backend(name: str, backend: SandboxBackend) -> None:
    """Register a custom backend under ``name``.

    Intended for downstream users who ship their own runtime — register
    before any ``session_manager.create_or_reuse`` call. Re-registering
    an existing name overwrites the prior entry.
    """
    _BACKENDS[name] = backend


def supported_backends() -> list[str]:
    """Snapshot of registered backend names. Useful for ``--help`` text."""
    return sorted(_BACKENDS)
