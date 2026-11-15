"""LyraShield-owned sandbox backend selection."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

from strix.runtime.backends import SandboxBackend
from strix.runtime.backends import get_backend as get_upstream_backend


logger = logging.getLogger(__name__)
_pending_transport_closures: set[asyncio.Future[Any]] = set()
_pending_cleanup_deletions: set[asyncio.Task[Any]] = set()
# Bound for the startup-failure cleanup await so a hung backend delete or
# transport close cannot strand a failed or cancelled startup.
_STARTUP_CLEANUP_TIMEOUT = 30.0


def _observe_cleanup_deletion(task: asyncio.Task[Any]) -> None:
    _pending_cleanup_deletions.discard(task)
    try:
        task.result()
    except asyncio.CancelledError:
        logger.warning("Sandbox startup cleanup deletion was cancelled")
    except BaseException as cleanup_error:
        logger.warning(
            "Sandbox startup cleanup deletion failed after handoff: %s: %s",
            type(cleanup_error).__name__,
            cleanup_error,
        )


async def _cleanup_unstarted_sandbox(client: Any, session: Any, transport: Any) -> None:
    """Release a created-but-unstarted sandbox and its transport.

    Bounded and best-effort: the original startup failure is always re-raised
    by the caller, and cleanup failure is logged, never hidden, never raised.
    """
    try:
        # Retain a strong reference until the deletion completes; a timeout or
        # caller cancellation must not orphan the task nor swallow its error.
        delete = asyncio.ensure_future(client.delete(session))
        _pending_cleanup_deletions.add(delete)
        delete.add_done_callback(_observe_cleanup_deletion)
        await asyncio.wait_for(asyncio.shield(delete), _STARTUP_CLEANUP_TIMEOUT)
    except TimeoutError:
        logger.warning(
            "Sandbox startup cleanup deletion exceeded %.1fs; it continues in background",
            _STARTUP_CLEANUP_TIMEOUT,
        )
    except BaseException as cleanup_error:
        logger.warning(
            "Sandbox startup cleanup could not delete the created sandbox: %s: %s",
            type(cleanup_error).__name__,
            cleanup_error,
        )
    try:
        transport.close()
    except BaseException as cleanup_error:
        logger.warning(
            "Sandbox startup cleanup could not close the Docker transport: %s: %s",
            type(cleanup_error).__name__,
            cleanup_error,
        )


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
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions  # noqa: PLC0415
    from agents.sandbox.types import User  # noqa: PLC0415

    from lyrashield.runtime import docker_connection  # noqa: PLC0415
    from lyrashield.runtime.docker_client import (  # noqa: PLC0415
        StrixDockerSandboxClient,
        assert_sdk_docker_compatibility,
    )

    assert_sdk_docker_compatibility()
    loop = asyncio.get_running_loop()
    discovery = loop.run_in_executor(None, docker_connection.connect_docker)
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
    try:
        session = await client.create(options=options, manifest=manifest)
    except BaseException:
        # No session handle has reached the startup owner yet. Partially
        # allocated containers are outside the SDK's create() handle
        # contract; the host-side reaper owns those. Close the transport.
        with contextlib.suppress(Exception):
            transport.close()
        raise
    try:
        await session.start()
    except BaseException:
        # Startup did not complete, so no handle reaches the runtime owner:
        # this backend still owns the created container and the transport and
        # must release them here.
        await _cleanup_unstarted_sandbox(client, session, transport)
        raise
    return client, session


def get_backend(name: str) -> SandboxBackend:
    """Return product Docker behavior, delegating custom backends upstream."""
    if name == "docker":
        return docker_backend
    if name == "controller":
        from lyrashield.runtime.controller_backend import controller_backend  # noqa: PLC0415

        return controller_backend
    return get_upstream_backend(name)
