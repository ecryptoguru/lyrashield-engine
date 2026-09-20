# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import EnvEntry, Environment, EnvValue, Manifest
from agents.sandbox.workspace_paths import SandboxPathGrant

from lyrashield.runtime.attachments import public_manifest, stage_attachments
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
_RELAY_UPSTREAM_TARGET = "/run/lyrashield-relay/upstream"


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

# Accepted wire format for the signed relay grant (proxy userinfo); anything
# else is rejected before it can reach a mount, log line, or shell.
_RELAY_GRANT_RE = re.compile(r"lrg1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Per-step bound (seconds) for shielded startup-cleanup awaits: a hung
# backend delete/close must not strand a failed or cancelled startup.
_CLEANUP_STEP_TIMEOUT = 30.0


def _sanitize_startup_error(exc: BaseException) -> str:
    """Bounded, secret-free description of a startup/cleanup failure."""
    message = f"{type(exc).__name__}: {exc}"
    return _RELAY_GRANT_RE.sub("lrg1.<redacted>", message)[:500]


async def _bounded_cleanup_step(awaitable: Any, *, scan_id: str, step: str) -> None:
    """Await one startup-cleanup step shielded and time-bounded.

    The step runs on a task whose handle is retained until it reaches a
    terminal state: cancellation delivered to the caller while a delete or
    close is in flight can never orphan that work, and a timed-out step is
    cancelled and drained instead of becoming untracked background cleanup.
    """
    task = asyncio.ensure_future(awaitable)
    try:
        await asyncio.wait_for(asyncio.shield(task), _CLEANUP_STEP_TIMEOUT)
    except asyncio.CancelledError:
        # The wait — not the shielded step — was cancelled. Keep the handle
        # and drain within the same bound so the step still completes
        # before the cancellation propagates.
        if not task.done():
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(asyncio.shield(task), _CLEANUP_STEP_TIMEOUT)
            if not task.done():
                logger.debug(
                    "Startup cleanup(%s): %s still pending after re-cancellation drain",
                    scan_id,
                    step,
                )
        raise
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if task.done() and not task.cancelled():
            # Retrieve the outcome so a failed step is never reported as an
            # unretrieved task exception.
            task.exception()


async def _reap_stranded_bundle(scan_id: str, bundle: dict[str, Any]) -> bool:
    """Retry deletion of a sandbox stranded by a failed startup.

    Returns True when the delete is confirmed and the bundle's host dirs
    are removed; False when deletion fails again — the bundle stays cached
    and the failed receipt is refreshed so the reaper keeps observing (and
    can keep retrying) the stranded sandbox. Cancellation propagates.
    """
    client = bundle["client"]
    try:
        await _bounded_cleanup_step(
            client.delete(bundle["session"]), scan_id=scan_id, step="sandbox delete"
        )
    except Exception as exc:
        _record_cleanup_receipt(scan_id, CLEANUP_FAILED, last_error=_sanitize_startup_error(exc))
        return False
    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        with contextlib.suppress(Exception):
            docker_client.close()
    for key in ("egress_policy_dir", "relay_upstream_dir", "attachments_dir"):
        path = bundle.get(key)
        if path:
            shutil.rmtree(path, ignore_errors=True)
    _record_cleanup_receipt(scan_id, CLEANUP_REMOVED)
    return True


def _target_relay_proxy_url() -> str | None:
    """Relay URL with the scan grant embedded as proxy userinfo.

    The local TLS inspection bridge extracts the signed grant from userinfo
    and attaches it to each inspectable request. Returns None when the worker
    did not pass relay configuration; repo scans keep the Caido proxy.
    """
    relay_url = os.environ.get("STRIX_TARGET_RELAY_URL", "").strip()
    grant = os.environ.get("STRIX_TARGET_RELAY_GRANT", "").strip()
    if not relay_url and not grant:
        return None
    if not relay_url or not grant:
        raise RuntimeError("Target relay URL and grant must both be configured")
    # Tokens become proxy userinfo and shell startup configuration. Accept only
    # the product's signed base64url wire format, never shell/URL metacharacters.
    if not _RELAY_GRANT_RE.fullmatch(grant):
        raise RuntimeError("Target relay grant has an invalid wire format")
    try:
        parsed = urlparse(relay_url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        raise RuntimeError("STRIX_TARGET_RELAY_URL must be an http(s) origin") from None
    if (
        parsed.scheme not in ("http", "https")
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[A-Za-z0-9.:-]+", host)
    ):
        raise RuntimeError("STRIX_TARGET_RELAY_URL must be an http(s) origin")
    if parsed.scheme == "http" and host not in ("127.0.0.1", "::1"):
        raise RuntimeError("STRIX_TARGET_RELAY_URL requires HTTPS outside loopback")
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme}://{grant}@{netloc}"


def build_sandbox_environment(
    container_caido_url: str,
) -> dict[str, str | EnvValue | EnvEntry]:
    # Keep capture and replay on Caido. Relay sessions configure Caido's own
    # upstream to the local TLS bridge before any agent executes; every request
    # then reaches the scoped relay in inspectable form.
    relay_proxy = _target_relay_proxy_url()
    proxy_url = container_caido_url
    environment: dict[str, str | EnvValue | EnvEntry] = {
        "PYTHONUNBUFFERED": "1",
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        "NO_PROXY": "localhost,127.0.0.1",
        "AGENT_BROWSER_PROXY": proxy_url,
    }
    if relay_proxy:
        environment["STRIX_TARGET_RELAY"] = "1"
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
    try:
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
    except Exception:
        # A failure partway through the list must not leak already-staged
        # symlink-safe copies; the caller never receives them.
        for staged in staged_dirs:
            shutil.rmtree(staged, ignore_errors=True)
        raise
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


def write_relay_upstream(relay_proxy: str) -> tuple[dict[str, Any], str]:
    """Mount the grant for the bridge's root-only startup, never agent env."""
    host_dir = tempfile.mkdtemp(prefix="lyrashield-relay-")
    upstream = Path(host_dir) / "upstream"
    upstream.write_text(relay_proxy, encoding="ascii")
    upstream.chmod(0o400)
    return {"source": str(upstream), "target": _RELAY_UPSTREAM_TARGET, "read_only": True}, host_dir


async def create_or_reuse(  # noqa: PLR0912, PLR0915
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    targets: list[dict[str, Any]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in, or
    bind-mounted read-only when the entry is flagged ``mount``.

    ``attachments`` are validated supporting-file entries (see
    :mod:`lyrashield.runtime.attachments`); their staged originals are
    bind-mounted read-only under ``/input/attachments``, separate from
    ``/workspace`` source. They are untrusted input evidence: they never
    contribute to ``authorized_hosts``, the egress policy, scope, or any
    other authorization input — those derive only from ``targets``.

    When ``targets`` carries the scan's authorized network targets, the hosts
    are written to a per-run read-only egress policy mounted into the
    container, and a default Caido scope derived from them is created before
    the agent starts, so private-range replay is only permitted toward
    explicitly authorized internal targets. The whole check-create-insert
    sequence runs under one lock, so concurrent calls for the same scan ID
    share exactly one tracked session.

    Startup owns every resource it allocates: any failure or cancellation
    after the sandbox is created deletes it under a bounded, shielded wait
    and removes the host-side staging/policy/relay dirs before the original
    exception propagates. When a delete cannot be confirmed the handles
    stay cached under a ``startup_error`` marker with a failed cleanup
    receipt, so :func:`cleanup` (or a later create) can retry the reaping —
    deletion is never claimed without confirmation.
    """
    async with _CREATION_LOCK:
        async with _CACHE_LOCK:
            cached = _SESSION_CACHE.get(scan_id)
        if cached is not None:
            if not cached.get("startup_error"):
                logger.info("Reusing existing sandbox session for scan %s", scan_id)
                return cached
            # A previous startup created a sandbox whose deletion could not
            # be confirmed. Retry that delete under this same lock (the
            # serialization cleanup() uses) before allowing a fresh create;
            # if it still fails, fail closed and leave the stranded record
            # for the reaper rather than silently starting a second sandbox.
            if not await _reap_stranded_bundle(scan_id, cached):
                raise RuntimeError(
                    f"Sandbox for scan {scan_id} is still stranded; "
                    "startup cannot proceed until its deletion succeeds"
                )
            async with _CACHE_LOCK:
                _SESSION_CACHE.pop(scan_id, None)

        # Validate relay configuration before any host allocation so a
        # malformed grant or URL cannot leak staged, policy, or grant dirs.
        relay_proxy = _target_relay_proxy_url()

        # Resource handles owned by this create, initialized before the
        # allocation block so the single lifecycle scope below can clean up
        # every partial state — including cancellation at any await.
        staged_dirs: list[Path] = []
        authorized_hosts: set[str] = set()
        policy_host_dir: str | None = None
        attachments_dir: str | None = None
        relay_dir: str | None = None
        client: Any | None = None
        session: Any | None = None
        caido_client: Any | None = None
        try:
            entries, bind_mounts, staged_dirs, extra_path_grants = build_session_entries(
                local_sources
            )

            authorized_hosts = derive_authorized_target_hosts(targets)
            policy_mount, policy_host_dir = write_egress_policy(scan_id, authorized_hosts)
            bind_mounts.append(policy_mount)

            # Attachments stage into a dedicated read-only mount; staging
            # failures (e.g. a checksum drift between validation and copy)
            # raise inside this scope so attachments_dir is cleaned up below.
            if attachments:
                attachment_mount, attachments_dir = stage_attachments(scan_id, attachments)
                bind_mounts.append(attachment_mount)

            # Caido runs as an in-container sidecar; HTTP(S) traffic from any
            # process started via ``session.exec`` (the SDK's Shell tool, etc.)
            # picks up these env vars automatically. ``NO_PROXY`` keeps the
            # agent-browser CDP daemon's localhost traffic from looping back
            # through Caido. These variables steer clients toward the proxy;
            # the enforced egress controls are the network policy admission
            # check and the replay guard's policy file.
            container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
            environment = build_sandbox_environment(container_caido_url)
            if environment.get("STRIX_TARGET_RELAY"):
                relay_mount, relay_dir = write_relay_upstream(relay_proxy or "")
                bind_mounts.append(relay_mount)
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
            client, session = await backend(
                image=image,
                manifest=manifest,
                exposed_ports=(_CONTAINER_CAIDO_PORT,),
                bind_mounts=bind_mounts,
            )
            # ``session`` is now a live sandbox handle; every later startup
            # await is covered by the owned delete in the except block.

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
                target_relay=bool(environment.get("STRIX_TARGET_RELAY")),
            )

            default_scope_id, default_scope_allowlist = await _create_default_scope(
                caido_client,
                scan_id=scan_id,
                authorized_hosts=authorized_hosts,
            )
        except BaseException as startup_error:
            # One ownership scope: everything allocated above is released
            # here — the created sandbox first (the resource the reaper
            # cannot recover without handles), then the Caido transport and
            # Docker client, then host-side policy/relay dirs. Every await
            # is bounded and shielded so a hung backend or a second
            # cancellation cannot strand cleanup; the original exception —
            # including KeyboardInterrupt/SystemExit/CancelledError — is
            # never swallowed and always re-raised. An interrupt arriving
            # *during* cleanup is deferred and re-raised chained, so it can
            # never be swallowed either.
            deferred: BaseException | None = None
            if client is not None and session is not None:
                try:
                    await _bounded_cleanup_step(
                        client.delete(session), scan_id=scan_id, step="sandbox delete"
                    )
                except BaseException as exc:
                    delete_error = _sanitize_startup_error(exc)
                    if not isinstance(exc, Exception):
                        deferred = deferred or exc
                    logger.warning(
                        "Startup cleanup for scan %s could not delete the sandbox; "
                        "handles retained for reaper retry: %s",
                        scan_id,
                        delete_error,
                    )
                    # Keep the ownership metadata the existing reaper needs:
                    # the record stays cached under a startup_error marker
                    # and a failed receipt — deletion is never claimed.
                    _record_cleanup_receipt(scan_id, CLEANUP_FAILED, last_error=delete_error)
                    async with _CACHE_LOCK:
                        _SESSION_CACHE[scan_id] = {
                            "client": client,
                            "session": session,
                            "caido_client": None,
                            "default_scope_id": None,
                            "default_scope_allowlist": None,
                            "authorized_hosts": sorted(authorized_hosts),
                            "egress_policy_dir": policy_host_dir,
                            "relay_upstream_dir": relay_dir,
                            "attachments_dir": attachments_dir,
                            "startup_error": _sanitize_startup_error(startup_error),
                        }
                    # The dirs stay owned by the stranded bundle; cleanup()
                    # removes them once a retried delete succeeds.
                    policy_host_dir = None
                    relay_dir = None
                    attachments_dir = None
                    startup_error.add_note(f"sandbox cleanup also failed: {delete_error}")
            if caido_client is not None:
                try:
                    await _bounded_cleanup_step(
                        caido_client.aclose(), scan_id=scan_id, step="caido close"
                    )
                except BaseException as exc:
                    if not isinstance(exc, Exception):
                        deferred = deferred or exc
                    logger.debug(
                        "Startup cleanup for scan %s: caido close failed",
                        scan_id,
                        exc_info=True,
                    )
            if client is not None:
                docker_client = getattr(client, "docker_client", None)
                if docker_client is not None:
                    with contextlib.suppress(Exception):
                        docker_client.close()
            if policy_host_dir is not None:
                shutil.rmtree(policy_host_dir, ignore_errors=True)
            if relay_dir is not None:
                shutil.rmtree(relay_dir, ignore_errors=True)
            if attachments_dir:
                shutil.rmtree(attachments_dir, ignore_errors=True)
            if deferred is not None and not isinstance(
                startup_error, (KeyboardInterrupt, SystemExit)
            ):
                # An interrupt arrived while cleaning up a lesser failure —
                # propagate it with the startup error chained underneath.
                raise deferred from startup_error
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
            "relay_upstream_dir": relay_dir,
            "attachments_dir": attachments_dir,
            # Provenance shape of what was actually staged (host paths removed).
            "attachment_manifest": public_manifest(list(attachments or [])),
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
        relay_dir = bundle.get("relay_upstream_dir")
        if relay_dir:
            shutil.rmtree(relay_dir, ignore_errors=True)
        attachments_dir = bundle.get("attachments_dir")
        if attachments_dir:
            shutil.rmtree(attachments_dir, ignore_errors=True)
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
