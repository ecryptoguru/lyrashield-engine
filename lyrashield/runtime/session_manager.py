# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import shutil
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import EnvEntry, Environment, EnvValue, Manifest
from agents.sandbox.workspace_paths import SandboxPathGrant

from lyrashield.runtime.backends import get_backend
from lyrashield.runtime.caido_bootstrap import bootstrap_caido
from lyrashield.runtime.docker_client import host_gateway_enabled
from lyrashield.runtime.local_dir_staging import stage_symlink_safe_dir
from lyrashield.tools.proxy import caido_api
from strix.config import load_settings


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_LOCK = asyncio.Lock()

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"


def build_sandbox_environment(
    container_caido_url: str,
) -> dict[str, str | EnvValue | EnvEntry]:
    environment: dict[str, str | EnvValue | EnvEntry] = {
        "PYTHONUNBUFFERED": "1",
        "http_proxy": container_caido_url,
        "https_proxy": container_caido_url,
        "ALL_PROXY": container_caido_url,
        "NO_PROXY": "localhost,127.0.0.1",
    }
    if host_gateway_enabled():
        environment["HOST_GATEWAY"] = "host.docker.internal"
    return environment


def resolve_sandbox_endpoint(
    host: str,
    port: int,
    *,
    in_container: bool | None = None,
    container_ip: str | None = None,
) -> tuple[str, int]:
    """Return a sandbox endpoint reachable from this process."""
    if in_container is None:
        in_container = Path("/.dockerenv").exists()
    if in_container and container_ip and host in {"127.0.0.1", "::1", "localhost"}:
        return container_ip, _CONTAINER_CAIDO_PORT
    return host, port


def get_sandbox_container_ip(client: Any, session: Any) -> str | None:
    """Read the sandbox bridge address when the Docker backend exposes one."""
    docker_client = getattr(client, "docker_client", None)
    container_id = getattr(getattr(session, "_inner", session), "container_id", None)
    if docker_client is None or not container_id:
        return None
    try:
        container = docker_client.containers.get(container_id)
        networks = cast(
            "dict[str, Any]",
            container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {},
        )
        for network in networks.values():
            if not isinstance(network, dict):
                continue
            network = cast("dict[str, Any]", network)
            ip = network.get("IPAddress")
            if isinstance(ip, str) and ip:
                return ip
    except Exception:
        logger.debug("Could not resolve sandbox container IP", exc_info=True)
    return None


def build_session_entries(
    local_sources: list[dict[str, Any]],
) -> tuple[
    dict[str | Path, BaseEntry], list[dict[str, Any]], list[Path], tuple[SandboxPathGrant, ...]
]:
    """Split local sources into copied manifest entries and host bind mounts.

    Sources flagged ``mount`` are bind-mounted read-only at
    ``/workspace/<workspace_subdir>`` (not added to the manifest, so the SDK
    does not stream them in file-by-file). Every other source becomes a
    ``LocalDir`` entry copied into the container as before. Trees containing
    symlinks (which the SDK's ``LocalDir`` walker refuses outright) are first
    staged into a symlink-safe temp copy; those temp dirs are returned so the
    caller can remove them once the upload completes.

    ``extra_path_grants`` is a tuple of ``SandboxPathGrant`` objects that tell
    the SDK's LocalDir walker which absolute host paths are allowed outside the
    workspace root. This is required by openai-agents >= 0.18.0, which rejects
    source paths not under the manifest base directory unless explicitly granted.
    """
    entries: dict[str | Path, BaseEntry] = {}
    bind_mounts: list[dict[str, Any]] = []
    staged_dirs: list[Path] = []
    grants: set[str] = set()
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        if src.get("mount"):
            bind_mounts.append(
                {
                    "source": str(resolved),
                    "target": f"{_WORKSPACE_ROOT}/{ws_subdir}",
                    "read_only": True,
                }
            )
            grants.add(str(resolved))
        else:
            upload_path, staged = stage_symlink_safe_dir(resolved)
            if staged is not None:
                staged_dirs.append(staged)
            entries[ws_subdir] = LocalDir(src=upload_path)
            grants.add(str(upload_path))
    extra_path_grants = tuple(SandboxPathGrant(path=p) for p in sorted(grants))
    return entries, bind_mounts, staged_dirs, extra_path_grants


def _hosts_from_target_value(value: str) -> set[str]:
    """Parse a comma-separated URL/host/IP target value into bare hosts."""
    hosts: set[str] = set()
    for raw_piece in value.split(","):
        piece = raw_piece.strip()
        if not piece:
            continue
        if "://" in piece:
            host = urlparse(piece).hostname or ""
        else:
            # Bare host/IP, possibly with :port or /CIDR suffix.
            host = piece.split("/")[0]
            if ":" in host and not host.startswith("["):
                host = host.rsplit(":", 1)[0].strip("[]")
        if host:
            hosts.add(host.lower().rstrip("."))
    return hosts


def derive_authorized_target_hosts(targets: list[dict[str, Any]] | None) -> set[str]:
    """Extract network-reachable authorized target hosts from ``targets_info``.

    Only URL and IP targets produce egress hosts; repositories and local
    source trees are not network destinations for the replay path.
    """
    hosts: set[str] = set()
    for target in targets or []:
        ttype = str(target.get("type") or "")
        details = target.get("details")
        if not isinstance(details, dict):
            continue
        if ttype == "web_application":
            value_keys = ("target_url",)
        elif ttype == "ip_address":
            value_keys = ("target_ip",)
        else:
            continue
        for key in value_keys:
            hosts |= _hosts_from_target_value(str(details.get(key) or ""))
    return hosts


def derive_default_scope_allowlist(hosts: set[str]) -> list[str]:
    """Caido allowlist patterns covering each authorized host and subdomains."""
    patterns: list[str] = []
    for host in sorted(hosts):
        patterns.append(host)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            patterns.append(f"*.{host}")
    return patterns


async def _create_default_scope(
    caido_client: Any,
    *,
    scan_id: str,
    authorized_hosts: set[str],
) -> tuple[str | None, list[str] | None]:
    """Create the default authorized-targets Caido scope before the agent starts.

    Returns ``(scope_id, allowlist)``; ``(None, None)`` when there are no
    network targets OR when scope creation fails. A creation failure is logged
    but non-fatal: the scope focuses the agent's proxy view, while the replay
    egress guard is the enforced control and stays active regardless. On
    failure both values are None so a caller never sees an allowlist without
    its scope id.
    """
    if not authorized_hosts:
        return None, None
    allowlist = derive_default_scope_allowlist(authorized_hosts)
    try:
        scope = await caido_api.scope_create(
            caido_client,
            name="authorized-targets",
            allowlist=allowlist,
        )
    except Exception:
        logger.exception(
            "Failed to create default Caido scope for scan %s; replay egress guard remains active",
            scan_id,
        )
        return None, None
    scope_id = str(getattr(scope, "id", "") or "") or None
    logger.info(
        "Default Caido scope for scan %s created (id=%s, allowlist=%s)",
        scan_id,
        scope_id,
        allowlist,
    )
    return scope_id, allowlist


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    targets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in, or
    bind-mounted read-only when the entry is flagged ``mount``.

    When ``targets`` carries the scan's authorized network targets, a default
    Caido scope derived from them is created before the agent starts, and the
    authorized hosts are registered with the replay egress guard so
    private-range traffic is only permitted toward explicitly authorized
    internal targets.
    """
    async with _CACHE_LOCK:
        cached = _SESSION_CACHE.get(scan_id)
        if cached is not None:
            logger.info("Reusing existing sandbox session for scan %s", scan_id)
            return cached

    entries, bind_mounts, staged_dirs, extra_path_grants = build_session_entries(local_sources)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(value=build_sandbox_environment(container_caido_url)),
        extra_path_grants=extra_path_grants,
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    client: Any | None = None
    session: Any | None = None
    caido_client: Any | None = None
    try:
        client, session = await backend(
            image=image,
            manifest=manifest,
            exposed_ports=(_CONTAINER_CAIDO_PORT,),
            bind_mounts=bind_mounts,
        )

        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
        scheme = "https" if caido_endpoint.tls else "http"
        sandbox_host, sandbox_port = resolve_sandbox_endpoint(
            caido_endpoint.host,
            caido_endpoint.port,
            container_ip=get_sandbox_container_ip(client, session),
        )
        host_caido_url = f"{scheme}://{sandbox_host}:{sandbox_port}"
        logger.debug("Caido host endpoint resolved: %s", host_caido_url)

        caido_client = await bootstrap_caido(
            session,
            scan_id=scan_id,
            host_url=host_caido_url,
            container_url=container_caido_url,
        )

        authorized_hosts = derive_authorized_target_hosts(targets)
        caido_api.set_authorized_target_hosts(authorized_hosts)
        default_scope_id, default_scope_allowlist = await _create_default_scope(
            caido_client,
            scan_id=scan_id,
            authorized_hosts=authorized_hosts,
        )
    except Exception:
        if caido_client is not None:
            with contextlib.suppress(Exception):
                await caido_client.aclose()
        if client is not None and session is not None:
            with contextlib.suppress(Exception):
                await client.delete(session)
        if client is not None:
            with contextlib.suppress(Exception):
                docker_client = getattr(client, "docker_client", None)
                if docker_client is not None:
                    docker_client.close()
        raise
    finally:
        for staged in staged_dirs:
            shutil.rmtree(staged, ignore_errors=True)

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
        "default_scope_id": default_scope_id,
        "default_scope_allowlist": default_scope_allowlist,
        "authorized_hosts": sorted(authorized_hosts),
    }
    async with _CACHE_LOCK:
        _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> bool:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Cleanup remains non-fatal for scan results, but the return value makes a
    stranded container observable to the receipt and worker event paths.
    """
    async with _CACHE_LOCK:
        bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return True

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    client = bundle["client"]
    sandbox_removed = True
    try:
        await client.delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        sandbox_removed = False
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )

    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        try:
            docker_client.close()
        except Exception:
            logger.debug("cleanup(%s): docker_client.close() raised", scan_id, exc_info=True)
    return sandbox_removed
