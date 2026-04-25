"""Per-scan sandbox session lifecycle.

One session per scan, reused across every agent in that scan's tree.

The bundle returned by :func:`create_or_reuse` is what the per-agent
context dict reads from in ``run_config_factory.make_agent_context`` —
``client``, ``session``, ``tool_server_host_port``, ``caido_host_port``,
and ``bearer`` for authenticating to the in-container FastAPI tool server.

Cache strategy: a module-level dict keyed by ``scan_id``. The same scan
issuing multiple ``create_or_reuse`` calls (e.g., resume after a crash
on the host side) gets the same bundle back. ``cleanup`` is best-effort
— a leaked container is preferable to a stuck cleanup that prevents the
next scan from starting.
"""

from __future__ import annotations

import logging
import secrets
import socket
from typing import TYPE_CHECKING, Any

import docker
from agents.sandbox.entries import LocalDir
from agents.sandbox.manifest import Environment, Manifest
from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

from strix.runtime.strix_docker_client import StrixDockerSandboxClient


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


# In-container ports (must match the image's tool server + Caido sidecar
# binds). Defined here as a single source of truth for both the
# capability and the manifest env vars.
_CONTAINER_TOOL_SERVER_PORT = 48081
_CONTAINER_CAIDO_PORT = 48080


# Per-scan session cache. Module-level so a scan that bounces through
# multiple host-side processes (e.g., re-imports the module) doesn't
# spin up a second container — though in practice we expect one
# Strix process per scan.
_SESSION_CACHE: dict[str, dict[str, Any]] = {}


def _alloc_loopback_port() -> int:
    """Reserve a free 127.0.0.1 port via ephemeral socket bind.

    Used only as a fallback when the SDK doesn't return a resolved
    host port (older SDK versions before ``_resolve_exposed_port``
    existed). Modern path uses the SDK's resolution.
    """
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    sources_path: Path,
    execution_timeout: int = 120,
) -> dict[str, Any]:
    """Return the existing bundle for ``scan_id`` or create a new one.

    Args:
        scan_id: Caller-provided scan identifier (used as cache key).
        image: Docker image tag (e.g. ``"strix-sandbox:0.1.13"``).
        sources_path: Host directory mounted into the container's
            ``/workspace/sources`` so the agent can read user code.
        execution_timeout: ``STRIX_SANDBOX_EXECUTION_TIMEOUT`` env var
            inside the container — caps how long the in-container tool
            server waits for a tool to finish before responding 504.
            Defaults to 120s, matching the legacy harness.

    Returns the bundle dict containing ``client``, ``session``,
    ``tool_server_host_port``, ``caido_host_port``, and ``bearer``.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    bearer = secrets.token_urlsafe(32)

    # Caido runs as an in-container sidecar on _CONTAINER_CAIDO_PORT and
    # all HTTP(S) traffic from shelled-out tools (curl, Python requests,
    # etc.) needs to flow through it — set the conventional env vars so
    # standard libraries pick them up automatically.
    caido_proxy_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries={"sources": LocalDir(src=sources_path)},
        environment=Environment(
            value={
                "TOOL_SERVER_TOKEN": bearer,
                "TOOL_SERVER_PORT": str(_CONTAINER_TOOL_SERVER_PORT),
                "STRIX_SANDBOX_EXECUTION_TIMEOUT": str(execution_timeout),
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": caido_proxy_url,
                "https_proxy": caido_proxy_url,
                "ALL_PROXY": caido_proxy_url,
            },
        ),
    )

    # The SDK's DockerSandboxClient requires a docker.DockerClient
    # instance at construction time (since openai-agents 0.14.x).
    # ``docker.from_env()`` reads DOCKER_HOST etc. from the environment.
    client = StrixDockerSandboxClient(docker.from_env())
    options = DockerSandboxClientOptions(
        image=image,
        exposed_ports=(_CONTAINER_TOOL_SERVER_PORT, _CONTAINER_CAIDO_PORT),
    )

    logger.info(
        "Creating sandbox session for scan %s (image=%s, exec_timeout=%ds)",
        scan_id,
        image,
        execution_timeout,
    )
    session = await client.create(options=options, manifest=manifest)

    tool_server_endpoint = await session._resolve_exposed_port(
        _CONTAINER_TOOL_SERVER_PORT,
    )
    caido_endpoint = await session._resolve_exposed_port(_CONTAINER_CAIDO_PORT)

    bundle = {
        "client": client,
        "session": session,
        "tool_server_host_port": tool_server_endpoint.port,
        "caido_host_port": caido_endpoint.port,
        "bearer": bearer,
    }
    _SESSION_CACHE[scan_id] = bundle
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )


def cached_scan_ids() -> list[str]:
    """Snapshot of currently-cached scan ids. Used by the TUI / CLI."""
    return list(_SESSION_CACHE.keys())


def _reset_cache_for_tests() -> None:
    """Test helper — clears the module cache between unit tests."""
    _SESSION_CACHE.clear()
