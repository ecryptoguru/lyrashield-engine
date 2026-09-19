"""Probed sandbox capability provenance and preflight evaluation.

Session setup must never claim a control it did not verify. This module
probes the capabilities the active backend actually delivered — network
isolation, read-only mounts, exposed ports, exec, resource constraints —
immediately after the session starts, then evaluates them against the
controls the run requires.

Statuses:

- ``supported`` — probed and confirmed (with evidence).
- ``absent`` — probed and found missing/contradicted.
- ``unprobed`` — the backend exposes no way to verify it. An unprobed
  capability is never claimed; when a required control rests on it the run
  records a named degradation rather than silently proceeding.

A required control whose capability is probed ``absent`` fails preflight
(:class:`SandboxPreflightError`), which surfaces inside the session
lifecycle so the half-started sandbox is torn down by the caller's normal
cleanup path.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from lyrashield.runtime.docker_client import _sandbox_network


logger = logging.getLogger(__name__)

CAPABILITY_RECORD_SCHEMA = "lyrashield-sandbox-capabilities/1.0"

STATUS_SUPPORTED = "supported"
STATUS_ABSENT = "absent"
STATUS_UNPROBED = "unprobed"


class SandboxPreflightError(RuntimeError):
    """A capability a required control depends on is probed absent."""


def _cap(status: str, detail: str, **evidence: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {"status": status, "detail": detail}
    if evidence:
        entry["evidence"] = evidence
    return entry


def _container_attrs(client: Any, session: Any) -> dict[str, Any] | None:
    """Live container attrs for the docker backend, else ``None``.

    ``None`` means the backend exposes no introspection — the capability is
    ``unprobed``, never silently assumed.
    """
    docker_client = getattr(client, "docker_client", None)
    container_id = getattr(getattr(session, "_inner", session), "container_id", None)
    if docker_client is None or not isinstance(container_id, str) or not container_id:
        return None
    try:
        container = docker_client.containers.get(container_id)
        attrs = getattr(container, "attrs", None)
    except Exception:  # introspection failure means unprobed
        logger.debug("capability probe: container inspect failed", exc_info=True)
        return None
    return attrs if isinstance(attrs, dict) else None


def _probe_exec(session: Any) -> dict[str, Any]:
    """``session.exec`` is how every agent tool reaches the sandbox."""
    if callable(getattr(session, "exec", None)):
        return _cap(STATUS_SUPPORTED, "session.exec is available")
    return _cap(STATUS_ABSENT, "session object exposes no exec entrypoint")


def _probe_ports(session: Any, caido_endpoint: Any) -> dict[str, Any]:
    """Exposed-port resolution is required to reach the in-container proxy."""
    if not callable(getattr(session, "resolve_exposed_port", None)):
        return _cap(STATUS_ABSENT, "session exposes no port resolution")
    host = getattr(caido_endpoint, "host", None)
    port = getattr(caido_endpoint, "port", None)
    if host and port:
        return _cap(
            STATUS_SUPPORTED,
            "proxy port resolved through the backend",
            resolved=f"{host}:{port}",
        )
    return _cap(STATUS_ABSENT, "proxy port resolution returned no endpoint")


def _probe_proxy_capture(caido_client: Any) -> dict[str, Any]:
    if caido_client is not None:
        return _cap(STATUS_SUPPORTED, "capture/replay client bootstrapped")
    return _cap(STATUS_ABSENT, "capture/replay client unavailable")


def _probe_network_policy(
    backend_name: str,
    client: Any,
    session: Any,
) -> dict[str, Any]:
    """Verify deny-by-default egress from immutable container/network facts."""
    if backend_name != "docker":
        return _cap(
            STATUS_UNPROBED,
            f"backend {backend_name!r} exposes no network introspection",
        )
    attrs = _container_attrs(client, session)
    if attrs is None:
        return _cap(STATUS_UNPROBED, "container attributes unavailable")
    configured = _sandbox_network()
    if not configured:
        return _cap(STATUS_ABSENT, "no deny-by-default sandbox network configured")
    host_config = cast("dict[str, Any]", attrs.get("HostConfig", {}) or {})
    mode = str(host_config.get("NetworkMode", "") or "")
    networks = cast(
        "dict[str, Any]",
        cast("dict[str, Any]", attrs.get("NetworkSettings", {}) or {}).get("Networks", {})
        or {},
    )
    evidence: dict[str, Any] = {
        "configured": configured,
        "network_mode": mode,
        "attached": sorted(str(k) for k in networks),
    }
    if mode != configured:
        return _cap(
            STATUS_ABSENT,
            f"container network mode {mode!r} does not match {configured!r}",
            **evidence,
        )
    if set(networks.keys()) != {configured}:
        return _cap(
            STATUS_ABSENT,
            "container is attached to networks besides the sandbox network",
            **evidence,
        )
    try:
        network = client.docker_client.networks.get(configured)
        internal = bool(cast("dict[str, Any]", getattr(network, "attrs", {}) or {}).get("Internal"))
    except Exception:  # introspection failure means unprobed
        return _cap(
            STATUS_UNPROBED,
            "network object inspection failed",
            **evidence,
        )
    evidence["internal"] = internal
    if not internal:
        return _cap(
            STATUS_ABSENT,
            f"network {configured!r} is not internal",
            **evidence,
        )
    return _cap(
        STATUS_SUPPORTED,
        "container is attached exclusively to an internal (deny-by-default) network",
        **evidence,
    )


def _probe_mounts(
    backend_name: str,
    client: Any,
    session: Any,
    bind_mounts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Verify every requested bind mount landed, with its read-only bit.

    The egress policy and relay grant are delivered read-only; a mount that
    silently arrived writable (or not at all) means the in-sandbox guard has
    no trustworthy policy file and must fail closed.
    """
    expected = [m for m in bind_mounts if m.get("target")]
    if backend_name != "docker":
        return _cap(
            STATUS_UNPROBED,
            f"backend {backend_name!r} exposes no mount introspection",
            expected=len(expected),
        )
    attrs = _container_attrs(client, session)
    if attrs is None:
        return _cap(
            STATUS_UNPROBED,
            "container attributes unavailable",
            expected=len(expected),
        )
    mounts = attrs.get("Mounts", [])
    by_target: dict[str, dict[str, Any]] = {}
    if isinstance(mounts, list):
        for mount in mounts:
            if isinstance(mount, dict) and mount.get("Destination"):
                by_target[str(mount["Destination"])] = mount
    missing: list[str] = []
    writable: list[str] = []
    verified: list[str] = []
    for spec in expected:
        target = str(spec["target"])
        mount = by_target.get(target)
        if mount is None:
            missing.append(target)
            continue
        wants_ro = spec.get("read_only", True)
        if wants_ro and mount.get("RW") is not False:
            writable.append(target)
            continue
        verified.append(target)
    evidence = {"verified": verified, "missing": missing, "writable": writable}
    if missing or writable:
        parts = []
        if missing:
            parts.append(f"missing: {', '.join(missing)}")
        if writable:
            parts.append(f"mounted writable: {', '.join(writable)}")
        return _cap(STATUS_ABSENT, "; ".join(parts), **evidence)
    return _cap(
        STATUS_SUPPORTED,
        f"{len(verified)} requested mount(s) verified",
        **evidence,
    )


def _probe_exec_constraints(
    backend_name: str,
    client: Any,
    session: Any,
) -> dict[str, Any]:
    """Observed resource/exec constraints (cgroup caps, caps bounding, pty)."""
    pty = getattr(session, "supports_pty", None)
    pty_observed = pty if isinstance(pty, bool) else None
    if backend_name != "docker":
        return _cap(
            STATUS_UNPROBED,
            f"backend {backend_name!r} exposes no constraint introspection",
            pty=pty_observed,
        )
    attrs = _container_attrs(client, session)
    if attrs is None:
        return _cap(
            STATUS_UNPROBED,
            "container attributes unavailable",
            pty=pty_observed,
        )
    host_config = cast("dict[str, Any]", attrs.get("HostConfig", {}) or {})
    observed = {
        "memory_bytes": host_config.get("Memory") or 0,
        "nano_cpus": host_config.get("NanoCpus") or 0,
        "pids_limit": host_config.get("PidsLimit") or 0,
        "cap_add": sorted(str(c) for c in (host_config.get("CapAdd") or []) or []),
        "security_opt": sorted(str(o) for o in (host_config.get("SecurityOpt") or []) or []),
        "pty": pty_observed,
    }
    bounded = any(
        observed[key]
        for key in ("memory_bytes", "nano_cpus", "pids_limit")
        if isinstance(observed[key], int | float)
    )
    if not bounded:
        return _cap(
            STATUS_ABSENT,
            "no cgroup resource limits observed on the container",
            **observed,
        )
    return _cap(
        STATUS_SUPPORTED,
        "resource limits observed on the running container",
        **observed,
    )


def probe_session_capabilities(
    *,
    backend_name: str,
    client: Any,
    session: Any,
    caido_client: Any,
    caido_endpoint: Any,
    bind_mounts: list[dict[str, Any]],
    authorized_hosts: list[str],
    relay_configured: bool,
) -> dict[str, Any]:
    """Probe the live session and build the run's capability record.

    Never raises: a probe that itself fails degrades to ``unprobed`` with a
    named degradation rather than crashing session setup. Preflight failures
    are recorded on the record and raised by the caller.
    """
    capabilities: dict[str, dict[str, Any]] = {}
    probes: dict[str, Callable[[], dict[str, Any]]] = {
        "exec": lambda: _probe_exec(session),
        "ports": lambda: _probe_ports(session, caido_endpoint),
        "proxy_capture": lambda: _probe_proxy_capture(caido_client),
        "network_policy": lambda: _probe_network_policy(backend_name, client, session),
        "mounts": lambda: _probe_mounts(backend_name, client, session, bind_mounts),
        "exec_constraints": lambda: _probe_exec_constraints(backend_name, client, session),
    }
    for name, probe in probes.items():
        try:
            capabilities[name] = probe()
        except Exception as exc:  # a failed probe is unprobed, not silent
            logger.exception("capability probe %s failed", name)
            capabilities[name] = _cap(
                STATUS_UNPROBED,
                f"probe raised {type(exc).__name__}",
            )
    if relay_configured:
        # The scoped relay grant rides a read-only mount into the container
        # and the bridge config was verified during proxy bootstrap; both are
        # probed above. A requested relay with an unverifiable grant mount is
        # a degradation, not a silent assumption.
        capabilities["scoped_relay"] = _cap(
            STATUS_SUPPORTED
            if capabilities.get("mounts", {}).get("status") == STATUS_SUPPORTED
            else STATUS_UNPROBED,
            "relay configured; grant mount verified via mounts probe",
        )
    record: dict[str, Any] = {
        "schema": CAPABILITY_RECORD_SCHEMA,
        "backend": backend_name,
        "probed_at": datetime.now(UTC).isoformat(),
        "authorized_hosts": sorted(authorized_hosts),
        "capabilities": capabilities,
    }
    record["preflight"] = evaluate_preflight(
        capabilities,
        authorized_hosts=authorized_hosts,
        relay_configured=relay_configured,
    )
    return record


def evaluate_preflight(
    capabilities: dict[str, dict[str, Any]],
    *,
    authorized_hosts: list[str],
    relay_configured: bool,
) -> dict[str, Any]:
    """Map probed capabilities to the controls the run requires.

    ``failures`` are required controls resting on a probed-absent
    capability — the caller must abort session setup. ``degradations`` are
    named honesty markers: work continues, but the run record shows exactly
    which guarantee could not be proven.
    """
    failures: list[dict[str, Any]] = []
    degradations: list[dict[str, Any]] = []

    def _entry(name: str, control: str) -> dict[str, Any]:
        cap = capabilities.get(name) or {}
        return {
            "capability": name,
            "control": control,
            "status": cap.get("status"),
            "detail": cap.get("detail"),
        }

    def _status(name: str) -> str:
        return str((capabilities.get(name) or {}).get("status") or STATUS_UNPROBED)

    # Required controls — probed absence fails the run outright.
    for name, control in (
        ("exec", "agent_exec"),
        ("ports", "proxy_channel"),
        ("proxy_capture", "traffic_capture"),
    ):
        if _status(name) == STATUS_ABSENT:
            failures.append(_entry(name, control))
        elif _status(name) == STATUS_UNPROBED:
            degradations.append(_entry(name, control))

    if _status("network_policy") == STATUS_ABSENT:
        failures.append(_entry("network_policy", "deny_by_default_egress"))
    elif _status("network_policy") == STATUS_UNPROBED:
        degradations.append(_entry("network_policy", "deny_by_default_egress"))

    mounts_status = _status("mounts")
    if mounts_status == STATUS_ABSENT:
        # The egress policy is delivered on a read-only mount. Without it the
        # in-sandbox replay guard fails closed — no scoped replay at all.
        if authorized_hosts:
            failures.append(_entry("mounts", "scoped_replay"))
        else:
            degradations.append(_entry("mounts", "egress_policy_delivery"))
    elif mounts_status == STATUS_UNPROBED:
        degradations.append(_entry("mounts", "egress_policy_delivery"))

    if relay_configured and mounts_status != STATUS_SUPPORTED:
        degradations.append(_entry("scoped_relay", "relay_grant_delivery"))

    if _status("exec_constraints") in (STATUS_ABSENT, STATUS_UNPROBED):
        degradations.append(_entry("exec_constraints", "resource_limits"))

    return {"degradations": degradations, "failures": failures}
