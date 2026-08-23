# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import shutil
import tempfile
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

# Read-only mount target for the per-run replay egress policy consumed by the
# guarded ``caido_api`` module inside the sandbox.
_EGRESS_POLICY_TARGET = "/run/lyrashield-egress/policy.json"


_SESSION_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_LOCK = asyncio.Lock()
# ponytail: one global creation lock serializes all sandbox creations; per-ID
# locks only if measured throughput ever needs them.
_CREATION_LOCK = asyncio.Lock()

# Durable cleanup receipts: the last known cleanup outcome per scan ID. A
# recorded failure stays failed (and retryable) until a real deletion
# succeeds — a later cache miss can never rewrite it to success.
_CLEANUP_RECEIPTS: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"

# Cleanup outcomes (C3): explicit instead of ambiguous booleans.
CLEANUP_REMOVED = "removed"
CLEANUP_FAILED = "failed"
CLEANUP_NOT_FOUND = "not_found"


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


def write_egress_policy(
    scan_id: str,
    authorized_hosts: set[str],
    *,
    allow_private_egress: bool = False,
) -> tuple[dict[str, Any], str]:
    """Write the run-scoped replay egress policy for ``scan_id``.

    Returns ``(bind_mount_spec, host_dir)`` where the spec mounts the policy
    read-only at :data:`_EGRESS_POLICY_TARGET`. The trusted host creates the
    policy before launch; the sandbox agent can read it but — via the
    read-only mount plus the guard's mount check — cannot replace it with its
    own authorization.
    """
    host_dir = tempfile.mkdtemp(prefix=f"lyrashield-egress-{scan_id}-")
    policy_path = Path(host_dir) / "policy.json"
    payload = {
        "version": 1,
        "scan_id": scan_id,
        "authorized_hosts": sorted(authorized_hosts),
        "allow_private_egress": allow_private_egress,
    }
    policy_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    policy_path.chmod(0o444)
    mount = {
        "source": str(policy_path),
        "target": _EGRESS_POLICY_TARGET,
        "read_only": True,
    }
    return mount, host_dir


async def create_or_reuse(  # noqa: PLR0915
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

    When ``targets`` carries the scan's authorized network targets, the hosts
    are written to a per-run read-only egress policy mounted into the
    container, and a default Caido scope derived from them is created before
    the agent starts, so private-range replay is only permitted toward
    explicitly authorized internal targets. The whole check-create-insert
    sequence runs under one lock, so concurrent calls for the same scan ID
    share exactly one tracked session.
    """
    async with _CREATION_LOCK:
        async with _CACHE_LOCK:
            cached = _SESSION_CACHE.get(scan_id)
        if cached is not None:
            logger.info("Reusing existing sandbox session for scan %s", scan_id)
            return cached

        entries, bind_mounts, staged_dirs, extra_path_grants = build_session_entries(local_sources)

        authorized_hosts = derive_authorized_target_hosts(targets)
        policy_mount, policy_host_dir = write_egress_policy(scan_id, authorized_hosts)
        bind_mounts.append(policy_mount)

        # Caido runs as an in-container sidecar; HTTP(S) traffic from any
        # process started via ``session.exec`` (the SDK's Shell tool, etc.)
        # picks up these env vars automatically. ``NO_PROXY`` keeps the
        # agent-browser CDP daemon's localhost traffic from looping back
        # through Caido. These variables steer clients toward the proxy; the
        # enforced egress controls are the network policy admission check and
        # the replay guard's policy file.
        container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
        environment = build_sandbox_environment(container_caido_url)
        environment["LYRASHIELD_EGRESS_POLICY"] = _EGRESS_POLICY_TARGET
        environment["STRIX_RUN_ID"] = scan_id
        manifest = Manifest(
            entries=entries,
            environment=Environment(value=environment),
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
            shutil.rmtree(policy_host_dir, ignore_errors=True)
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
            "egress_policy_dir": policy_host_dir,
        }
        async with _CACHE_LOCK:
            _SESSION_CACHE[scan_id] = bundle
        logger.info("Sandbox session for scan %s ready and cached", scan_id)
        return bundle


async def cleanup(scan_id: str) -> str:
    """Tear down ``scan_id``'s container and report an explicit outcome.

    Returns :data:`CLEANUP_REMOVED` when the sandbox is confirmed deleted,
    :data:`CLEANUP_FAILED` when deletion raised (the session stays cached so a
    retry has the handles it needs), or :data:`CLEANUP_NOT_FOUND` when nothing
    is tracked for the ID. Outcomes are monotonic: a recorded failure cannot
    be replaced by success through a later cache miss, and a confirmed removal
    is terminal. Cleanup remains non-fatal for scan results, but the receipt
    makes a stranded container observable to the run record and worker.

    Cleanup holds ``_CREATION_LOCK`` so a same-ID create cannot race: the
    create/cleanup pair is serialized per scan ID through the same lock.
    """
    async with _CREATION_LOCK:
        async with _CACHE_LOCK:
            bundle = _SESSION_CACHE.get(scan_id)
        if bundle is None:
            receipt = _CLEANUP_RECEIPTS.get(scan_id)
            if receipt is not None:
                return str(receipt["status"])
            logger.debug("cleanup(%s): no cached session", scan_id)
            return CLEANUP_NOT_FOUND

        caido_client = bundle.get("caido_client")
        if caido_client is not None:
            try:
                await caido_client.aclose()
            except Exception:
                logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

        client = bundle["client"]
        try:
            await client.delete(bundle["session"])
            logger.info("Cleaned up sandbox session for scan %s", scan_id)
        except Exception as exc:
            logger.exception(
                "cleanup(%s): client.delete raised; container may need manual reaping",
                scan_id,
            )
            _record_cleanup_receipt(scan_id, CLEANUP_FAILED, last_error=str(exc))
            return CLEANUP_FAILED

        async with _CACHE_LOCK:
            _SESSION_CACHE.pop(scan_id, None)
        docker_client = getattr(client, "docker_client", None)
        if docker_client is not None:
            try:
                docker_client.close()
            except Exception:
                logger.debug("cleanup(%s): docker_client.close() raised", scan_id, exc_info=True)
        policy_dir = bundle.get("egress_policy_dir")
        if policy_dir:
            shutil.rmtree(policy_dir, ignore_errors=True)
        _record_cleanup_receipt(scan_id, CLEANUP_REMOVED)
        return CLEANUP_REMOVED


def _record_cleanup_receipt(scan_id: str, status: str, *, last_error: str | None = None) -> None:
    prior = _CLEANUP_RECEIPTS.get(scan_id) or {}
    receipt: dict[str, Any] = {
        "status": status,
        "attempts": _int_or_zero(prior.get("attempts")) + 1,
    }
    if last_error is not None:
        receipt["last_error"] = last_error
    elif prior.get("last_error"):
        # Retain the prior attempt's error for auditability.
        receipt["last_error"] = prior["last_error"]
    _CLEANUP_RECEIPTS[scan_id] = receipt


def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
