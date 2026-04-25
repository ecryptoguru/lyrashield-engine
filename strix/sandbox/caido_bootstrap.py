"""Caido client bootstrap.

Caido CLI runs as an in-container sidecar. We connect from the host to
its mapped port, fetch a guest token (the CLI runs with
``--allow-guests``), then create + select a temporary project so the
SDK has a project context to operate on.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp
from caido_sdk_client import Client, TokenAuthOptions
from caido_sdk_client.types import CreateProjectOptions


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_QUERY = "mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"


async def _login_as_guest(url: str, *, attempts: int = 5) -> str:
    """POST ``loginAsGuest`` mutation; return the access token.

    Retries up to ``attempts`` times with exponential-ish backoff, mirroring
    what the legacy bash entrypoint did. The Caido sidecar may not be ready
    on the first poke even after its TCP port accepts connections.
    """
    last_err: Exception | None = None
    async with aiohttp.ClientSession() as session:
        for i in range(1, attempts + 1):
            try:
                async with session.post(
                    f"{url}/graphql",
                    json={"query": _LOGIN_AS_GUEST_QUERY},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as response:
                    response.raise_for_status()
                    payload: dict[str, Any] = await response.json()
                    token = (
                        payload.get("data", {})
                        .get("loginAsGuest", {})
                        .get("token", {})
                        .get("accessToken")
                    )
                    if token:
                        return str(token)
                    last_err = RuntimeError(f"loginAsGuest returned no token: {payload}")
            except (aiohttp.ClientError, TimeoutError, RuntimeError) as exc:
                last_err = exc
                logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, exc)
            await asyncio.sleep(min(2.0 * i, 8.0))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


async def bootstrap_caido_client(host_port: int) -> Client:
    """Connect to the in-container Caido sidecar and select a fresh project.

    Args:
        host_port: Resolved host port that maps to the container's Caido
            GraphQL listener.

    Returns:
        A connected :class:`caido_sdk_client.Client` ready to use.
    """
    url = f"http://127.0.0.1:{host_port}"
    logger.info("Bootstrapping Caido client at %s", url)

    access_token = await _login_as_guest(url)
    client = Client(url, auth=TokenAuthOptions(token=access_token))
    await client.connect()

    project = await client.project.create(
        CreateProjectOptions(name="sandbox", temporary=True),
    )
    await client.project.select(project.id)
    logger.info("Caido project selected: %s", project.id)
    return client
