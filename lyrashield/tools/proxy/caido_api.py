"""Shared Caido proxy helpers and sandbox-importable ``caido_api`` module."""

from __future__ import annotations

import asyncio
import dataclasses
import importlib.metadata
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunparse

from caido_sdk_client import Client, TokenAuthOptions
from caido_sdk_client.types import (
    ConnectionInfoInput,
    CreateScopeOptions,
    ReplaySendOptions,
    RequestGetOptions,
    UpdateScopeOptions,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from caido_sdk_client import Client as CaidoClient


logger = logging.getLogger(__name__)

RequestPart = Literal["request", "response"]
SortBy = Literal[
    "timestamp",
    "host",
    "method",
    "path",
    "status_code",
    "response_time",
    "response_size",
    "source",
]
SortOrder = Literal["asc", "desc"]
ScopeAction = Literal["get", "list", "create", "update", "delete"]
SitemapDepth = Literal["DIRECT", "ALL"]
_SITEMAP_PAGE_SIZE = 30

_DEFAULT_CAIDO_URL = "http://127.0.0.1:48080"

# Replay egress blocklist. Link-local IPv4/IPv6 covers cloud metadata services
# (AWS/GCP/Azure IMDS at 169.254.169.254). Cloud metadata hostnames are
# unconditionally blocked; private-target opt-in never overrides them.
# Host gateway access has a separate explicit operator opt-in.
_LINK_LOCAL_NETWORKS: tuple[ipaddress.IPv4Network, ipaddress.IPv6Network] = (
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv6Network("fe80::/10"),
)
# Addresses that cannot be valid unicast replay destinations. These denials
# apply before private-target policy, since unspecified/multicast/reserved
# addresses can resolve local or broadcast routes despite an authorized host.
_NON_ROUTABLE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("ff00::/8"),
)
# Private-range guard for REPLAY traffic only (the Caido GraphQL endpoint
# itself legitimately lives on loopback). Without this, an agent could pivot
# from an authorized public target into RFC1918/loopback internal space.
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
)
_PRIVATE_EGRESS_OPT_IN_ENV = "STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS"
_EGRESS_POLICY_ENV = "LYRASHIELD_EGRESS_POLICY"
_EGRESS_POLICY_TRUST_RW_ENV = "LYRASHIELD_EGRESS_POLICY_TRUST_RW"
_DEFAULT_EGRESS_POLICY_PATH = "/run/lyrashield-egress/policy.json"


@dataclasses.dataclass(frozen=True)
class EgressPolicy:
    """Run-scoped replay egress authorization.

    ``authorized_hosts`` and ``allow_private_egress`` come from a policy file
    the trusted host wrote before launch and bind-mounted read-only into the
    sandbox. The agent can point ``LYRASHIELD_EGRESS_POLICY`` at a file it
    controls, but that file lives on a writable mount, so the read-only-mount
    check in :func:`load_egress_policy` rejects it and the guard fails closed.
    """

    authorized_hosts: frozenset[str] = frozenset()
    allow_private_egress: bool = False


_FAIL_CLOSED_POLICY = EgressPolicy()

_SUPPORTED_POLICY_VERSIONS = frozenset({1})


def _in_container() -> bool:
    return Path("/.dockerenv").exists()


def _path_on_readonly_mount(path: str) -> bool:
    """True when ``path`` sits on a mount the runtime user cannot write.

    Parses ``/proc/self/mountinfo`` and checks the options of the deepest
    mount point containing ``path``. The agent has no ``CAP_SYS_ADMIN``, so it
    cannot remount or re-bind a writable path as read-only.
    """
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    target = os.path.realpath(path)
    best_prefix_len = -1
    best_readonly = False
    for line in lines:
        parts = line.split()
        # Fields: id parent major:minor root mountpoint mount-options ...
        if len(parts) < 6:
            continue
        mount_point = os.path.realpath(parts[4])
        if (target == mount_point or target.startswith(mount_point.rstrip("/") + "/")) and (
            len(mount_point) > best_prefix_len
        ):
            best_prefix_len = len(mount_point)
            best_readonly = "ro" in parts[5].split(",")
    return best_readonly


def _egress_policy_path() -> str | None:
    override = os.environ.get(_EGRESS_POLICY_ENV, "").strip()
    if override:
        return override
    if Path(_DEFAULT_EGRESS_POLICY_PATH).is_file():
        return _DEFAULT_EGRESS_POLICY_PATH
    return None


def load_egress_policy() -> EgressPolicy | None:
    """Load the run-scoped egress policy, or ``None`` when no policy exists.

    ``None`` keeps the legacy host-side behavior (no authorized hosts; the
    ``STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS`` opt-in is honored). When a policy
    file exists but is not on a read-only mount — tampered, agent-supplied, or
    a misconfigured launch — the fail-closed policy is returned and the env
    opt-in is ignored: inside the sandbox the policy file is the only
    authority on private-range egress.
    """
    path = _egress_policy_path()
    if path is None:
        return None
    trusted_mount = _path_on_readonly_mount(path)
    trusted_host_side = not _in_container() and os.environ.get(
        _EGRESS_POLICY_TRUST_RW_ENV, ""
    ).strip().lower() in {"1", "true", "yes"}
    if not (trusted_mount or trusted_host_side):
        return _FAIL_CLOSED_POLICY
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _FAIL_CLOSED_POLICY
    if not isinstance(raw, dict):
        return _FAIL_CLOSED_POLICY
    # Validate version: must be present and supported.
    version = raw.get("version")
    if not isinstance(version, int) or version not in _SUPPORTED_POLICY_VERSIONS:
        return _FAIL_CLOSED_POLICY
    # Validate scan_id: must be present and match the current run when
    # STRIX_RUN_ID is set (inside the container). A wrong-run policy is
    # treated as malformed — the agent must not replay toward another run's
    # authorized hosts.
    scan_id = raw.get("scan_id")
    if not isinstance(scan_id, str) or not scan_id:
        return _FAIL_CLOSED_POLICY
    expected_run_id = os.environ.get("STRIX_RUN_ID", "").strip()
    if expected_run_id and scan_id != expected_run_id:
        return _FAIL_CLOSED_POLICY
    hosts_raw = raw.get("authorized_hosts")
    if not isinstance(hosts_raw, list) or not all(isinstance(h, str) for h in hosts_raw):
        return _FAIL_CLOSED_POLICY
    allow_private = raw.get("allow_private_egress", False)
    return EgressPolicy(
        authorized_hosts=frozenset(h.lower().rstrip(".") for h in hosts_raw if h),
        allow_private_egress=allow_private is True,
    )


def _same_authorized_host(left: str, right: str) -> bool:
    if left == right:
        return True
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return False


def _private_range_block_reason(
    hostname: str, *, resolved_ips: list[str] | None = None
) -> str | None:
    """Return a block reason when replay targets private space it may not reach."""
    policy = load_egress_policy()
    if policy is not None:
        allow_private = policy.allow_private_egress
    elif _in_container():
        # Inside the sandbox, a missing policy means no authorization — the
        # mutable env opt-in is NOT honored. The per-run policy file is the
        # only authority on private-range egress inside the container.
        allow_private = False
    else:
        # Host-side legacy behavior: no policy file, env opt-in is honored.
        allow_private = os.environ.get(_PRIVATE_EGRESS_OPT_IN_ENV, "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
    if allow_private:
        return None
    hostname = hostname.lower().rstrip(".")
    try:
        hostname_ip = _normalized_ip(hostname)
    except ValueError:
        hostname_ip = None
    authorized_private_literal = (
        policy is not None
        and hostname_ip is not None
        and any(_same_authorized_host(hostname, allowed) for allowed in policy.authorized_hosts)
    )
    for raw in resolved_ips if resolved_ips is not None else _resolve_hostname_ips(hostname):
        try:
            ip = _normalized_ip(raw)
        except ValueError:
            continue
        if any(ip in net for net in _PRIVATE_NETWORKS):
            # Target-domain authorization does not authorize a DNS answer in
            # loopback or private space. An explicitly listed private IP
            # remains usable as a literal target; hostname indirection needs
            # the separate trusted allow_private_egress policy bit.
            if authorized_private_literal and ip == hostname_ip:
                continue
            return (
                f"private-range address {ip} (not an authorized target; the "
                "scan's read-only egress policy file controls this)"
            )
    return None


def _host_resolves_private(hostname: str, *, resolved_ips: list[str] | None = None) -> bool:
    """True when the host is a private-range IP or resolves into one."""
    for raw in resolved_ips if resolved_ips is not None else _resolve_hostname_ips(hostname):
        try:
            ip = _normalized_ip(raw)
        except ValueError:
            continue
        if any(ip in net for net in _PRIVATE_NETWORKS):
            return True
    return False


def _host_in_authorized_scope(hostname: str, authorized_hosts: frozenset[str]) -> bool:
    """Match a replay destination against the recorded authorized host set.

    Mirrors the default Caido scope allowlist: a bare host admits itself and
    its subdomains (``*.host``); an IP literal admits only itself — IP scope
    never widens to a name.
    """
    hostname = hostname.lower().rstrip(".")
    for allowed in authorized_hosts:
        if _same_authorized_host(hostname, allowed):
            return True
        try:
            ipaddress.ip_address(allowed)
            continue
        except ValueError:
            pass
        if hostname.endswith(f".{allowed}"):
            return True
    return False


def _authorized_scope_block_reason(
    hostname: str, *, resolved_ips: list[str] | None = None
) -> str | None:
    """Deny replay destinations outside the recorded authorized host set.

    Only applies when a trusted (or fail-closed) egress policy exists —
    without a recorded scope there is nothing to violate and the legacy
    blocklists still apply. ``allow_private_egress`` widens scope to
    private-range destinations, never to arbitrary public hosts.
    """
    policy = load_egress_policy()
    if policy is None:
        return None
    if _host_in_authorized_scope(hostname, policy.authorized_hosts):
        return None
    if policy.allow_private_egress and _host_resolves_private(hostname, resolved_ips=resolved_ips):
        return None
    return (
        f"host {hostname!r} is outside the recorded authorized scope "
        "(the run's egress policy authorizes only its own target hosts)"
    )


# --- Per-request scope decision ledger ---------------------------------------
#
# Every replay admission decision (admitted/denied) is recorded in-process.
# Denials are scope-violation evidence: a bounded entry list plus a dropped
# counter (the ledger must never grow without bound). Admissions are counted
# per host only — the request itself already lives in the proxy project.
# ``ReportState`` drains this ledger into run.json (schema 1.1); inside the
# sandbox the denial log line is the durable trace.
_SCOPE_VIOLATION_LIMIT = 200
_SCOPE_HOST_LEDGER_LIMIT = 1_000

_scope_ledger_lock = threading.Lock()
_scope_ledger: dict[str, Any] = {
    "violations": [],
    "dropped": 0,
    "admitted_hosts": {},
}


def _evidence_url(url: str) -> str:
    """URL shape for evidence: scheme/host/path only — never credentials or query."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return ""
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme}://{netloc}{parsed.path or '/'}"[:512]


def _record_scope_decision(
    url: str,
    *,
    method: str,
    admitted: bool,
    rule: str,
    reason: str | None = None,
) -> None:
    """Record one replay admission decision (bounded, process-local)."""
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    with _scope_ledger_lock:
        violations: list[dict[str, Any]] = _scope_ledger["violations"]
        admitted_hosts: dict[str, int] = _scope_ledger["admitted_hosts"]
        if admitted:
            if host and (len(admitted_hosts) < _SCOPE_HOST_LEDGER_LIMIT or host in admitted_hosts):
                admitted_hosts[host] = admitted_hosts.get(host, 0) + 1
            return
        if len(violations) < _SCOPE_VIOLATION_LIMIT:
            violations.append(
                {
                    "at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                    "method": method.upper()[:16],
                    "host": host,
                    "url": _evidence_url(url),
                    "rule": rule,
                    "reason": (reason or "")[:500],
                }
            )
        else:
            _scope_ledger["dropped"] += 1
    logger.warning(
        "scope-violation: replay %s %s denied (%s: %s)",
        method.upper(),
        host or "<unparseable>",
        rule,
        reason,
    )


def get_scope_decisions() -> dict[str, Any]:
    """Snapshot the scope-decision ledger without mutating it."""
    with _scope_ledger_lock:
        return {
            "violations": [dict(v) for v in _scope_ledger["violations"]],
            "dropped": _scope_ledger["dropped"],
            "admitted_hosts": dict(_scope_ledger["admitted_hosts"]),
        }


def clear_scope_decisions() -> None:
    """Reset the ledger — called once per fresh sandbox session."""
    with _scope_ledger_lock:
        _scope_ledger["violations"].clear()
        _scope_ledger["dropped"] = 0
        _scope_ledger["admitted_hosts"].clear()


_BLOCKED_METADATA_HOSTS = frozenset(
    {"metadata.google.internal", "metadata.google.internal.", "metadata.google", "metadata.google."}
)
# Cloud metadata IPs not covered by link-local ranges.
# Alibaba IMDS: 100.100.100.200; AWS IPv6 IMDS: fd00:ec2::254.
_BLOCKED_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
_CLIENT_CACHE: dict[str, Client] = {}
_CLIENT_LOCK = asyncio.Lock()
_REQ_FIELD_MAP: dict[SortBy, tuple[str, str]] = {
    "timestamp": ("req", "created_at"),
    "host": ("req", "host"),
    "method": ("req", "method"),
    "path": ("req", "path"),
    "source": ("req", "source"),
    "status_code": ("resp", "code"),
    "response_time": ("resp", "roundtrip"),
    "response_size": ("resp", "length"),
}


def _host_gateway_allowed() -> bool:
    return os.environ.get("STRIX_SANDBOX_ALLOW_HOST_GATEWAY", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _replay_denial(url: str, *, resolved_ips: list[str] | None = None) -> tuple[str, str] | None:
    """Return ``(reason, rule)`` for a denied replay request, else ``None``."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return (f"non-HTTP scheme {parsed.scheme!r}", "non_http_scheme")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return None
    if hostname in _BLOCKED_METADATA_HOSTS:
        return (f"cloud metadata host {hostname!r}", "cloud_metadata")
    if not _host_gateway_allowed() and hostname in {
        "host.docker.internal",
        "host.docker.internal.",
    }:
        return (
            "host.docker.internal (set STRIX_SANDBOX_ALLOW_HOST_GATEWAY=1 to allow)",
            "host_gateway",
        )
    if resolved_ips is None:
        resolved_ips = _resolve_hostname_ips(hostname)
    # Hard denials precede all authorization and private-range opt-ins,
    # including DNS aliases and IPv4-mapped IPv6 forms.
    for raw in resolved_ips:
        denial = _ip_denial(_normalized_ip(raw))
        if denial is not None:
            return denial
    # Private-range guard also resolves DNS names, so a hostname that points
    # into RFC1918/loopback space is caught the same way as a literal IP.
    private_reason = _private_range_block_reason(hostname, resolved_ips=resolved_ips)
    if private_reason is not None:
        return (private_reason, "private_range")
    scope_reason = _authorized_scope_block_reason(hostname, resolved_ips=resolved_ips)
    if scope_reason is not None:
        return (scope_reason, "outside_authorized_scope")
    return None


def caido_url() -> str:
    return os.environ.get("STRIX_CAIDO_URL", _DEFAULT_CAIDO_URL).rstrip("/")


def _resolve_hostname_ips(hostname: str) -> list[str]:
    """Return the IP address(es) for a hostname, or the literal IP if one is given."""
    try:
        return [str(ipaddress.ip_address(hostname))]
    except ValueError:
        pass
    try:
        addrs = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    ips: list[str] = []
    for family, *_rest, sockaddr in addrs:
        raw = cast("str", sockaddr[0])
        ips.append(_strip_ipv6_scope(raw, family))
    return ips


def _strip_ipv6_scope(raw_ip: str, family: int) -> str:
    if family == socket.AF_INET6 and "%" in raw_ip:
        return raw_ip.split("%", 1)[0]
    return raw_ip


def _normalized_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Apply IPv4 policy to mapped IPv6; interface scopes never change policy."""
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    return (ip.ipv4_mapped or ip) if isinstance(ip, ipaddress.IPv6Address) else ip


def _ip_denial(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[str, str] | None:
    if ip in _BLOCKED_METADATA_IPS:
        return (f"cloud metadata IP {ip}", "cloud_metadata")
    if any(ip in net for net in _LINK_LOCAL_NETWORKS):
        return (f"link-local address {ip}", "link_local")
    if any(ip in net for net in _NON_ROUTABLE_NETWORKS):
        return (f"non-routable address {ip}", "non_routable_destination")
    return None


def _check_ip_against_blocklist(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    denial = _ip_denial(_normalized_ip(str(ip)))
    if denial is not None:
        raise ValueError(f"Caido URL points to {denial[0]}")


def _validate_caido_url_host(url: str) -> None:
    """Block cloud-metadata and link-local hosts for the Caido GraphQL URL.

    Resolves hostnames before checking IPs so DNS-based metadata aliases (e.g.
    ``xip.io`` hosts pointing to ``169.254.169.254``) are caught as well.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"Invalid Caido URL scheme: {parsed.scheme!r}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError(f"Invalid Caido URL, missing hostname: {url}")
    if hostname in _BLOCKED_METADATA_HOSTS:
        raise ValueError(f"Caido URL points to cloud metadata host: {hostname!r}")
    for raw in _resolve_hostname_ips(hostname):
        try:
            ip = _normalized_ip(raw)
        except ValueError:
            continue
        _check_ip_against_blocklist(ip)


def _graphql_url() -> str:
    base_url = caido_url()
    parsed = urlparse(base_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid Caido URL: {base_url}")
    _validate_caido_url_host(base_url)
    return f"{base_url}/graphql"


def _login_as_guest() -> str:
    body = json.dumps({"query": "mutation { loginAsGuest { token { accessToken } } }"}).encode(
        "utf-8"
    )
    req = urllib.request.Request(  # noqa: S310
        _graphql_url(),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310
        payload = json.loads(resp.read())
    return str(payload["data"]["loginAsGuest"]["token"]["accessToken"])


async def _new_client() -> Client:
    token = await asyncio.to_thread(_login_as_guest)
    client = Client(caido_url(), auth=TokenAuthOptions(token=token))
    await client.connect()
    return client


async def get_client() -> Client:
    """Return the shared Caido client, creating it under a lock if needed.

    The lock prevents two concurrent callers from each building a client and
    racing ``connect()`` on the same transport ("Transport is already
    connected").
    """
    async with _CLIENT_LOCK:
        client = _CLIENT_CACHE.get("default")
        if client is None:
            client = await _new_client()
            _CLIENT_CACHE["default"] = client
        return client


async def call_with_client[T](fn: Callable[[Client], Awaitable[T]]) -> T:
    """Run ``fn`` against the shared client, serialized through ``_CLIENT_LOCK``.

    The Caido GraphQL transport is not safe for concurrent use: two in-flight
    requests race and raise "Transport is already connected". Serializing every
    proxy call through the lock prevents that.
    """
    async with _CLIENT_LOCK:
        client = _CLIENT_CACHE.get("default")
        if client is None:
            client = await _new_client()
            _CLIENT_CACHE["default"] = client
        return await fn(client)


async def close_client() -> None:
    async with _CLIENT_LOCK:
        client = _CLIENT_CACHE.pop("default", None)
    if client is None:
        return
    await client.aclose()


async def list_requests_with_client(
    client: CaidoClient,
    *,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> Any:
    builder = client.request.list().first(first)
    if httpql_filter:
        builder = builder.filter(httpql_filter)
    if after:
        builder = builder.after(after)
    if scope_id:
        builder = builder.scope(scope_id)
    target, field = _REQ_FIELD_MAP[sort_by]
    # The SDK overloads expect literal ``target``/``field`` pairs; the map is
    # already validated at runtime, so getattr avoids an unresolvable overload.
    sort_method = getattr(builder, "descending" if sort_order == "desc" else "ascending")
    builder = sort_method(target, field)
    return await builder.execute()


async def get_request_with_client(
    client: CaidoClient,
    request_id: str,
    *,
    part: RequestPart = "request",
) -> Any:
    # The Caido SDK's generated pydantic model marks Request.raw and
    # Response.raw as required strings even though the GraphQL fragment
    # makes them conditional via `@include(if: $includeRequestRaw)`.
    # Passing False for either causes pydantic validation to fail with
    # "Field required" on the missing raw field. Always request both —
    # the caller picks which one to surface via ``part``.
    opts = RequestGetOptions(request_raw=True, response_raw=True)
    return await client.request.get(request_id, opts)


_FRAMING_HEADERS = frozenset({"content-length", "transfer-encoding"})
_INVALID_HEADER_RE = re.compile(r"[\r\n\x00]")


def _default_replay_user_agent() -> str:
    """Default replay User-Agent identifying the LyraShield product.

    The ``lyrashield-engine`` dist may not be installed where this module runs
    standalone inside the sandbox, so an absent package falls back to
    ``unknown`` rather than failing the replay.
    """
    try:
        engine_version = importlib.metadata.version("lyrashield-engine")
    except importlib.metadata.PackageNotFoundError:
        engine_version = "unknown"
    return f"LyraShield/{engine_version} (+https://lyrashieldai.com)"


def _replay_connection(url: str) -> ConnectionInfoInput:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    is_tls = parsed.scheme.lower() == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_tls else 80)
    return ConnectionInfoInput(host=host, port=port, is_tls=is_tls)


def _normalized_origin(url: str) -> tuple[str, str, int]:
    """Normalize scheme, hostname and effective port for credential boundaries."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password:
        raise ValueError("Replay URL must have a valid HTTP origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Replay URL has an invalid origin port") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    try:
        normalized_host = str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            normalized_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Replay URL has an invalid origin hostname") from exc
    return scheme, normalized_host, port


def _authority_url(authority: str, *, scheme: str) -> str:
    """Validate an HTTP Host/CONNECT authority and return a scope-check URL."""
    value = authority.strip()
    if (
        not value
        or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
        or any(char in value for char in "@/?#,\\\\")
    ):
        raise ValueError("Replay request contains an invalid HTTP authority")
    try:
        parsed = urlsplit(f"{scheme}://{value}/")
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Replay request contains an invalid HTTP authority") from exc
    if (
        parsed.scheme != scheme
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Replay request contains an invalid HTTP authority")
    return f"{scheme}://{value}/"


def _request_authority_urls(
    raw: bytes, *, connection: ConnectionInfoInput
) -> list[tuple[str, str]]:
    """Return raw Host and absolute-form authorities for final scope checks."""
    components = parse_raw_request(raw)
    request_parts = components["request_line"].split(" ")
    if len(request_parts) != 3 or not all(request_parts):
        raise ValueError("Replay request has an invalid request line")
    method, target, _version = request_parts
    scheme = "https" if connection.is_tls else "http"
    host_values = []
    for line in components["header_lines"]:
        name, colon, value = line.partition(":")
        if colon and name.strip().lower() == "host":
            host_values.append(value.strip())
    if len(host_values) > 1:
        raise ValueError("Replay request contains multiple Host headers")

    authorities: list[tuple[str, str]] = []
    if host_values:
        authorities.append(("Host header", _authority_url(host_values[0], scheme=scheme)))
    if target.lower().startswith(("http://", "https://")):
        try:
            parsed_target = urlsplit(target)
            _normalized_origin(target)
        except ValueError as exc:
            raise ValueError("Replay request has an invalid absolute-form authority") from exc
        if parsed_target.fragment:
            raise ValueError("Replay absolute-form target cannot contain a fragment")
        authorities.append(("absolute-form target", target))
    elif method.upper() == "CONNECT":
        authorities.append(("CONNECT target", _authority_url(target, scheme=scheme)))
    return authorities


def _request_origin_set(
    transport_url: str,
    *,
    header_lines: list[str],
    absolute_target: str | None,
    scheme: str,
) -> set[tuple[str, str, int]]:
    origins = {_normalized_origin(transport_url)}
    for line in header_lines:
        name, colon, value = line.partition(":")
        if colon and name.strip().lower() == "host":
            origins.add(_normalized_origin(_authority_url(value, scheme=scheme)))
    if absolute_target is not None:
        origins.add(_normalized_origin(absolute_target))
    return origins


def build_raw_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> tuple[ConnectionInfoInput, bytes]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    denial = _replay_denial(url)
    if denial is not None:
        block_reason, rule = denial
        _record_scope_decision(url, method=method, admitted=False, rule=rule, reason=block_reason)
        raise ValueError(f"URL is blocked ({block_reason}): {url}")
    _record_scope_decision(url, method=method, admitted=True, rule="admitted")
    connection = _replay_connection(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    final_headers = {**headers}
    if not any(name.lower() == "host" for name in final_headers):
        final_headers["Host"] = parsed.netloc
    # Header names are case-insensitive: a caller-supplied User-Agent in any
    # case wins; only an absent one gets the LyraShield default.
    if not any(name.lower() == "user-agent" for name in final_headers):
        final_headers["User-Agent"] = _default_replay_user_agent()
    for k, v in final_headers.items():
        if _INVALID_HEADER_RE.search(k) or _INVALID_HEADER_RE.search(v):
            raise ValueError(f"Header contains forbidden characters: {k!r}: {v!r}")
    # Framing headers inherited from the captured request describe the ORIGINAL
    # body; once the body is modified for replay they are stale. We always send a
    # plain (non-chunked) body with an explicit Content-Length, so drop any
    # inherited Content-Length AND Transfer-Encoding (case-insensitively) and
    # recompute the length from the body actually being sent. This keeps the two
    # framing mechanisms from conflicting (RFC 7230 3.3.3: a leftover
    # Transfer-Encoding would make the target ignore Content-Length and try to
    # parse the body as chunked), so the replay is never desynced.
    final_headers = {k: v for k, v in final_headers.items() if k.lower() not in _FRAMING_HEADERS}
    if body:
        final_headers["Content-Length"] = str(len(body.encode("utf-8")))

    lines = [f"{method.upper()} {path} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in final_headers.items())
    raw = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")
    return connection, raw


_RESPONSE_BODY_MAX_CHARS = 8192


def parse_raw_response(raw_bytes: bytes | None) -> dict[str, Any] | None:
    """Parse a raw HTTP response into the same shape ``list_requests`` emits.

    Returns ``None`` when ``raw_bytes`` is missing or unparseable. On
    success returns ``{status_code, length, headers, body, body_truncated}``
    where ``body`` is decoded as UTF-8 (replacement chars on invalid
    bytes) and clipped at :data:`_RESPONSE_BODY_MAX_CHARS`.
    """
    if not raw_bytes:
        return None
    try:
        head, _, body_bytes = raw_bytes.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        if not lines:
            return None
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            return None
        status_code = int(status_parts[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        body_text = body_bytes.decode("utf-8", errors="replace")
        body_truncated = len(body_text) > _RESPONSE_BODY_MAX_CHARS
        if body_truncated:
            body_text = body_text[:_RESPONSE_BODY_MAX_CHARS]
        return {
            "status_code": status_code,
            "length": len(body_bytes),
            "headers": headers,
            "body": body_text,
            "body_truncated": body_truncated,
        }
    except Exception:  # noqa: BLE001 - tolerate any malformed raw bytes; None signals "unparseable" to the caller.
        return None


def parse_raw_request(raw_content: str | bytes) -> dict[str, Any]:
    """Preserve body bytes and header lines; reject non-UTF-8 request heads."""
    raw = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
    separators = [sep for sep in (b"\r\n\r\n", b"\n\n") if sep in raw]
    separator = min(separators, key=raw.index) if separators else b"\r\n\r\n"
    head, delimiter, body = raw.partition(separator)
    if not delimiter:
        raise ValueError("Request has no head/body separator")
    try:
        head_text = head.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Replay request head must use UTF-8; binary bodies are supported") from exc
    line_ending = "\r\n" if separator == b"\r\n\r\n" else "\n"
    lines = head_text.split(line_ending)
    request_line = lines[0].split(" ")
    if len(request_line) < 2:
        raise ValueError("Invalid request line format")
    method, url_path = request_line[0], request_line[1]

    parsed_headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            if _INVALID_HEADER_RE.search(key) or _INVALID_HEADER_RE.search(value):
                raise ValueError("Captured header contains forbidden characters")
            parsed_headers[key.strip()] = value.strip()

    return {
        "method": method,
        "url_path": url_path,
        "headers": parsed_headers,
        "body": body.decode("utf-8") if isinstance(raw_content, str) else body,
        "request_line": lines[0],
        "header_lines": lines[1:],
        "line_ending": line_ending,
    }


def full_url_from_components(
    original: Any,
    components: dict[str, Any],
    modifications: dict[str, Any],
) -> str:
    if "url" in modifications:
        return str(modifications["url"])
    # Captured Host/absolute-form authority are HTTP bytes, not dial metadata.
    # Only an explicit URL patch may change the captured transport destination.
    scheme = "https" if original.is_tls else "http"
    target = str(components["url_path"])
    if target.lower().startswith(("http://", "https://")):
        parsed = urlsplit(target)
        path = parsed.path
        if parsed.query or "?" in target.split("#", 1)[0]:
            path += f"?{parsed.query}"
        target = path
    elif target == "*":
        target = "/"  # Admission URL only; the emitted OPTIONS target stays '*'.
    host_header = str(original.host)
    # An unbracketed IPv6 capture host has no explicit port.
    if host_header.count(":") > 1 and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    port = getattr(original, "port", None)
    if port and port != (443 if original.is_tls else 80):
        host_header = f"{host_header}:{port}"
    return f"{scheme}://{host_header}{target}"


def _replace_header_lines(lines: list[str], replacements: dict[str, str]) -> list[str]:
    for name, value in replacements.items():
        if _INVALID_HEADER_RE.search(name) or _INVALID_HEADER_RE.search(value):
            raise ValueError(f"Header contains forbidden characters: {name!r}: {value!r}")
        updated = []
        found = False
        for line in lines:
            key, _, _value = line.partition(":")
            if key.strip().lower() != name.lower():
                updated.append(line)
            elif not found:
                updated.append(f"{key}: {value}")
                found = True
        if not found:
            updated.append(f"{name}: {value}")
        lines = updated
    return lines


def _patch_cookie_lines(lines: list[str], cookies: dict[str, str]) -> list[str]:
    """Cookie header names ignore case; cookie names remain case-sensitive."""
    for key, value in cookies.items():
        if _INVALID_HEADER_RE.search(key) or _INVALID_HEADER_RE.search(value):
            raise ValueError("Cookie contains forbidden header characters")
    missing = dict(cookies)
    last_cookie = None
    for i, line in enumerate(lines):
        name, colon, value = line.partition(":")
        if name.strip().lower() != "cookie":
            continue
        last_cookie = i
        parts = value.split(";")
        for j, part in enumerate(parts):
            prefix, equals, _old_value = part.partition("=")
            key = prefix.strip()
            if equals and key in cookies:
                parts[j] = f"{prefix}={cookies[key]}"
                missing.pop(key, None)
        lines[i] = name + colon + ";".join(parts)
    if missing:
        added = "; ".join(f"{key}={value}" for key, value in missing.items())
        if last_cookie is None:
            lines.append(f"Cookie: {added}")
        else:
            lines[last_cookie] += f"; {added}"
    return lines


def apply_modifications(
    components: dict[str, Any],
    modifications: dict[str, Any],
    full_url: str,
) -> dict[str, Any]:
    header_lines = list(
        components.get(
            "header_lines", [f"{key}: {value}" for key, value in components["headers"].items()]
        )
    )
    body = components["body"]
    final_url = full_url

    if modifications.get("params"):
        parsed = urlparse(final_url)
        replacements = dict(modifications["params"])
        query_parts = []
        for part in parsed.query.split("&") if parsed.query else []:
            pairs = parse_qsl(part, keep_blank_values=True)
            key = pairs[0][0] if pairs else None
            if key not in modifications["params"]:
                query_parts.append(part)
            elif key is not None and key in replacements:
                query_parts.append(urlencode({key: replacements.pop(key)}, doseq=True))
        if replacements:
            query_parts.append(urlencode(replacements, doseq=True))
        final_url = urlunparse(parsed._replace(query="&".join(query_parts)))
    if "headers" in modifications:
        header_lines = _replace_header_lines(header_lines, modifications["headers"])
    if "body" in modifications:
        body = modifications["body"]
    if "cookies" in modifications:
        header_lines = _patch_cookie_lines(header_lines, modifications["cookies"])

    return {
        "method": components["method"],
        "url": final_url,
        "headers": {
            line.partition(":")[0].strip(): line.partition(":")[2].strip()
            for line in header_lines
            if ":" in line
        },
        "header_lines": header_lines,
        "body": body,
    }


def build_replay_request(
    original: Any, modifications: dict[str, Any]
) -> tuple[ConnectionInfoInput, bytes]:
    """Patch a capture without normalizing untouched bytes or binary bodies."""
    components = parse_raw_request(original.raw)
    captured_url = full_url_from_components(original, components, {})
    full_url = full_url_from_components(original, components, modifications)
    modified = apply_modifications(components, modifications, full_url)
    connection = _replay_connection(modified["url"])
    original_scheme = "https" if original.is_tls else "http"
    original_absolute = (
        components["url_path"]
        if str(components["url_path"]).lower().startswith(("http://", "https://"))
        else None
    )
    final_absolute = original_absolute if "url" not in modifications else None
    original_origins = _request_origin_set(
        captured_url,
        header_lines=components["header_lines"],
        absolute_target=original_absolute,
        scheme=original_scheme,
    )
    final_origins = _request_origin_set(
        modified["url"],
        header_lines=modified["header_lines"],
        absolute_target=final_absolute,
        scheme="https" if connection.is_tls else "http",
    )
    if original_origins != final_origins:
        explicit_headers = {
            name.lower() for name in modifications.get("headers", {}) if isinstance(name, str)
        }
        credential_headers = {"cookie", "authorization", "proxy-authorization"}
        if "cookies" in modifications and "cookie" not in explicit_headers:
            # A cookie patch normally merges into the captured Cookie header.
            # Across origins, rebuild it solely from explicitly supplied
            # cookies so a partial patch cannot carry an old session token.
            modified["header_lines"] = [
                line
                for line in modified["header_lines"]
                if line.partition(":")[0].strip().lower() != "cookie"
            ]
            modified["header_lines"].extend(_patch_cookie_lines([], modifications["cookies"]))
            explicit_headers.add("cookie")
        modified["header_lines"] = [
            line
            for line in modified["header_lines"]
            if line.partition(":")[0].strip().lower() not in credential_headers
            or line.partition(":")[0].strip().lower() in explicit_headers
        ]
    request_line = components["request_line"]
    if modified["url"] != full_url or "url" in modifications:
        preserve_absolute_form = "url" not in modifications and components[
            "url_path"
        ].lower().startswith(("http://", "https://"))
        parsed = urlsplit(modified["url"])
        target = parsed.path or ("" if preserve_absolute_form else "/")
        if parsed.query or "?" in modified["url"].split("#", 1)[0]:
            target += f"?{parsed.query}"
        if preserve_absolute_form:
            original_target = components["url_path"]
            original_scheme = original_target.split(":", 1)[0]
            target = f"{original_scheme}://{urlsplit(original_target).netloc}{target}"
        method, _target, version = request_line.split(" ", 2)
        request_line = f"{method} {target} {version}"
    lines = modified["header_lines"]
    if (
        "url" in modifications
        and urlsplit(captured_url).netloc != urlsplit(modified["url"]).netloc
        and not any(key.lower() == "host" for key in modifications.get("headers", {}))
    ):
        lines = _replace_header_lines(lines, {"Host": urlsplit(modified["url"]).netloc})
    body = modified["body"]
    if isinstance(body, str):
        body = body.encode("utf-8")
    if not isinstance(body, bytes):
        raise TypeError("Replay body must be a string or bytes")
    original_body = components["body"]
    if isinstance(original_body, str):
        original_body = original_body.encode("utf-8")
    if body != original_body:
        lines = [
            line for line in lines if line.partition(":")[0].strip().lower() not in _FRAMING_HEADERS
        ]
        if body:
            lines.append(f"Content-Length: {len(body)}")
    newline = components["line_ending"]
    head = newline.join([request_line, *lines]) + newline * 2
    return connection, head.encode("utf-8") + body


_REPLAY_SEND_TIMEOUT_SECONDS = 30.0


async def _replay_uses_target_relay(client: CaidoClient) -> bool:
    """Allow only direct pinned dialing or the fixed, verified target relay."""
    state = await client.graphql.query(
        "{ upstreamProxiesHttp { id enabled connection { host port isTLS } allowlist denylist } "
        "upstreamProxiesSocks { enabled } upstreamPlugins { enabled } }"
    )
    keys = ("upstreamProxiesHttp", "upstreamProxiesSocks", "upstreamPlugins")
    if not isinstance(state, dict) or not all(isinstance(state.get(key), list) for key in keys):
        raise ValueError("Replay upstream state could not be verified")
    if any(item.get("enabled") for key in keys[1:] for item in state[key]):
        raise ValueError("Replay upstream must use the verified target relay")
    enabled = [item for item in state[keys[0]] if item.get("enabled")]
    if not enabled:
        return False
    expected = {
        "enabled": True,
        "connection": {"host": "127.0.0.1", "port": 48081, "isTLS": False},
        "allowlist": ["*"],
        "denylist": [],
    }
    if (
        len(enabled) != 1
        or not enabled[0].get("id")
        or {key: value for key, value in enabled[0].items() if key != "id"} != expected
    ):
        raise ValueError("Replay upstream must use the verified target relay")
    return True


async def replay_send_raw(
    client: CaidoClient,
    *,
    raw: bytes,
    connection: ConnectionInfoInput,
) -> dict[str, Any]:
    uses_relay = await _replay_uses_target_relay(client)
    host = connection.host
    authority = f"[{host}]" if ":" in host else host
    url = f"{'https' if connection.is_tls else 'http'}://{authority}:{connection.port}/"
    method = raw.split(b" ", 1)[0].decode("ascii", errors="replace")
    try:
        request_authorities = _request_authority_urls(raw, connection=connection)
    except ValueError as exc:
        _record_scope_decision(
            url, method=method, admitted=False, rule="invalid_request_authority", reason=str(exc)
        )
        raise
    resolved_ips = _resolve_hostname_ips(host)
    denial = _replay_denial(url, resolved_ips=resolved_ips)
    if denial is not None:
        reason, rule = denial
        _record_scope_decision(url, method=method, admitted=False, rule=rule, reason=reason)
        raise ValueError(f"Replay URL is blocked ({reason})")
    _record_scope_decision(url, method=method, admitted=True, rule="connection_authorized")
    for source, authority_url in request_authorities:
        authority_host = urlsplit(authority_url).hostname or ""
        authority_ips = resolved_ips if _same_authorized_host(authority_host, host) else None
        denial = _replay_denial(authority_url, resolved_ips=authority_ips)
        if denial is not None:
            reason, rule = denial
            _record_scope_decision(
                authority_url,
                method=method,
                admitted=False,
                rule=rule,
                reason=f"{source}: {reason}",
            )
            raise ValueError(f"Replay {source} is blocked ({reason})")
        _record_scope_decision(
            authority_url, method=method, admitted=True, rule="authority_authorized"
        )
    if connection.sni:
        sni_authority = f"[{connection.sni}]" if ":" in connection.sni else connection.sni
        sni_url = f"{'https' if connection.is_tls else 'http'}://{sni_authority}:{connection.port}/"
        denial = _replay_denial(sni_url)
        if denial is not None:
            reason, rule = denial
            _record_scope_decision(sni_url, method=method, admitted=False, rule=rule, reason=reason)
            raise ValueError(f"Replay TLS server name is blocked ({reason})")
        _record_scope_decision(sni_url, method=method, admitted=True, rule="tls_name_authorized")
    if not uses_relay:
        if not resolved_ips:
            _record_scope_decision(
                url,
                method=method,
                admitted=False,
                rule="dns_unresolved",
                reason="No connection IP resolved",
            )
            raise ValueError("Replay hostname did not resolve to a connection IP")
        # Use the exact DNS snapshot checked above for the socket destination;
        # keep captured Host bytes and TLS SNI tied to the original authority.
        connection = dataclasses.replace(
            connection,
            host=str(_normalized_ip(resolved_ips[0])),
            sni=(connection.sni or host) if connection.is_tls else connection.sni,
        )
    started = time.time()
    # Create an empty replay session, then dispatch via ``send()``.
    # Passing ``CreateReplaySessionFromRaw`` here would also seed a stored
    # entry on the server side, leading the caller to observe two history
    # rows per call (one without response from the create-step seed, one
    # with response from the actual send). The empty-create + send flow
    # produces exactly one dispatched request.
    session = await client.replay.sessions.create()
    try:
        result = await asyncio.wait_for(
            client.replay.send(
                session.id,
                ReplaySendOptions(raw=raw, connection=connection),
            ),
            timeout=_REPLAY_SEND_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "session_id": str(session.id),
            "status": "ERROR",
            "error": (
                f"Caido replay dispatch did not complete within "
                f"{_REPLAY_SEND_TIMEOUT_SECONDS:.0f}s — the target may be "
                "unroutable from the sandbox, or Caido's outbound HTTP client "
                "is stalled; check the target host/port and retry"
            ),
            "elapsed_ms": elapsed_ms,
            "response_raw": None,
        }
    elapsed_ms = int((time.time() - started) * 1000)
    response = getattr(result.entry, "response", None)
    response_raw = getattr(response, "raw", None) if response is not None else None
    return {
        "session_id": str(session.id),
        "status": result.status,
        "error": result.error,
        "elapsed_ms": elapsed_ms,
        "response_raw": response_raw,
    }


async def scope_list(client: CaidoClient) -> Any:
    return await client.scope.list()


async def scope_get(client: CaidoClient, scope_id: str) -> Any:
    return await client.scope.get(scope_id)


async def scope_create(
    client: CaidoClient,
    *,
    name: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> Any:
    return await client.scope.create(
        CreateScopeOptions(
            name=name,
            allowlist=list(allowlist or []),
            denylist=list(denylist or []),
        ),
    )


async def scope_update(
    client: CaidoClient,
    scope_id: str,
    *,
    name: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> Any:
    return await client.scope.update(
        scope_id,
        UpdateScopeOptions(
            name=name,
            allowlist=list(allowlist or []),
            denylist=list(denylist or []),
        ),
    )


async def scope_delete(client: CaidoClient, scope_id: str) -> None:
    await client.scope.delete(scope_id)


async def list_requests(
    *,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> Any:
    return await call_with_client(
        lambda client: list_requests_with_client(
            client,
            httpql_filter=httpql_filter,
            first=first,
            after=after,
            sort_by=sort_by,
            sort_order=sort_order,
            scope_id=scope_id,
        )
    )


async def view_request(request_id: str, *, part: RequestPart = "request") -> Any:
    return await call_with_client(
        lambda client: get_request_with_client(client, request_id, part=part)
    )


async def repeat_request(
    request_id: str,
    *,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mods = modifications or {}

    async def _run(client: CaidoClient) -> dict[str, Any]:
        result = await get_request_with_client(client, request_id, part="request")
        if result is None or result.request.raw is None:
            raise ValueError(f"Request {request_id} not found")

        original = result.request
        connection, raw = build_replay_request(original, mods)
        return await replay_send_raw(client, raw=raw, connection=connection)

    return await call_with_client(_run)


async def scope_rules(
    action: ScopeAction,
    *,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> Any:
    async def _run(client: CaidoClient) -> Any:
        return await _scope_rules_with_client(
            client,
            action,
            allowlist=allowlist,
            denylist=denylist,
            scope_id=scope_id,
            scope_name=scope_name,
        )

    return await call_with_client(_run)


async def _scope_rules_with_client(
    client: CaidoClient,
    action: ScopeAction,
    *,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> Any:
    if action == "list":
        result = await scope_list(client)
    elif action == "get":
        if not scope_id:
            raise ValueError("scope_id required for get")
        result = await scope_get(client, scope_id)
    elif action == "create":
        if not scope_name:
            raise ValueError("scope_name required for create")
        result = await scope_create(
            client,
            name=scope_name,
            allowlist=allowlist,
            denylist=denylist,
        )
    elif action == "update":
        if not scope_id or not scope_name:
            raise ValueError("scope_id and scope_name required for update")
        result = await scope_update(
            client,
            scope_id,
            name=scope_name,
            allowlist=allowlist,
            denylist=denylist,
        )
    elif action == "delete":
        if not scope_id:
            raise ValueError("scope_id required for delete")
        await scope_delete(client, scope_id)
        result = {"deleted": scope_id}
    else:
        raise ValueError(f"Unknown action: {action}")
    return result


_SITEMAP_ROOTS_QUERY = """
query GetSitemapRoots($scopeId: ID) {
    sitemapRootEntries(scopeId: $scopeId) {
        edges { node {
            id kind label hasDescendants
            metadata { ... on SitemapEntryMetadataDomain { isTls port } }
            request { method path response { statusCode } }
        } }
        count { value }
    }
}
"""

_SITEMAP_DESCENDANTS_QUERY = """
query GetSitemapDescendants($parentId: ID!, $depth: SitemapDescendantsDepth!) {
    sitemapDescendantEntries(parentId: $parentId, depth: $depth) {
        edges { node {
            id kind label hasDescendants
            request { method path response { statusCode } }
        } }
        count { value }
    }
}
"""

_SITEMAP_ENTRY_QUERY = """
query GetSitemapEntry($id: ID!) {
    sitemapEntry(id: $id) {
        id kind label hasDescendants
        metadata { ... on SitemapEntryMetadataDomain { isTls port } }
        request { method path response { statusCode length roundtripTime } }
        requests(first: 30, order: {by: CREATED_AT, ordering: DESC}) {
            edges { node { method path response { statusCode length } } }
            count { value }
        }
    }
}
"""


def _clean_sitemap_metadata(node: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {
        "id": node["id"],
        "kind": node["kind"],
        "label": node["label"],
        "has_descendants": node["hasDescendants"],
    }
    meta = node.get("metadata")
    if isinstance(meta, dict) and (meta.get("isTls") is not None or meta.get("port")):
        meta_out: dict[str, Any] = {}
        if meta.get("isTls") is not None:
            meta_out["is_tls"] = meta["isTls"]
        if meta.get("port"):
            meta_out["port"] = meta["port"]
        cleaned["metadata"] = meta_out
    return cleaned


def _clean_sitemap_request_summary(req: dict[str, Any] | None) -> dict[str, Any] | None:
    """Same field names as ``list_requests`` emits for a request_summary."""
    if not req:
        return None
    out: dict[str, Any] = {}
    if req.get("method"):
        out["method"] = req["method"]
    if req.get("path"):
        out["path"] = req["path"]
    resp = req.get("response") or {}
    if resp.get("statusCode"):
        out["status_code"] = resp["statusCode"]
    return out or None


def _clean_sitemap_response(resp: dict[str, Any]) -> dict[str, Any]:
    """Same field names as ``list_requests`` emits for a response_summary."""
    out: dict[str, Any] = {}
    if resp.get("statusCode"):
        out["status_code"] = resp["statusCode"]
    if resp.get("length"):
        out["length"] = resp["length"]
    if resp.get("roundtripTime"):
        out["roundtrip_ms"] = resp["roundtripTime"]
    return out


async def list_sitemap_with_client(
    client: CaidoClient,
    *,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
    page_size: int = _SITEMAP_PAGE_SIZE,
) -> dict[str, Any]:
    """Browse Caido's discovered sitemap.

    The Caido GraphQL ``sitemap*Entries`` operations don't support native
    pagination, so we fetch all edges for the requested level and slice
    client-side.
    """
    if parent_id:
        raw = await client.graphql.query(
            _SITEMAP_DESCENDANTS_QUERY,
            variables={"parentId": parent_id, "depth": depth},
        )
        data = raw.get("sitemapDescendantEntries") or {}
    else:
        raw = await client.graphql.query(
            _SITEMAP_ROOTS_QUERY,
            variables={"scopeId": scope_id},
        )
        data = raw.get("sitemapRootEntries") or {}

    edges = data.get("edges") or []
    total = (data.get("count") or {}).get("value", 0)
    skip = max(0, (page - 1) * page_size)
    sliced = [edge["node"] for edge in edges[skip : skip + page_size]]

    cleaned: list[dict[str, Any]] = []
    for node in sliced:
        entry = _clean_sitemap_metadata(node)
        summary = _clean_sitemap_request_summary(node.get("request"))
        if summary:
            entry["request"] = summary
        cleaned.append(entry)

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "success": True,
        "entries": cleaned,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_count": total,
        "has_more": page < total_pages,
    }


async def view_sitemap_entry_with_client(
    client: CaidoClient,
    entry_id: str,
) -> dict[str, Any]:
    raw = await client.graphql.query(_SITEMAP_ENTRY_QUERY, variables={"id": entry_id})
    entry = raw.get("sitemapEntry")
    if not entry:
        return {"success": False, "error": f"Sitemap entry {entry_id} not found"}

    cleaned = _clean_sitemap_metadata(entry)
    primary = entry.get("request") or {}
    if primary:
        primary_clean: dict[str, Any] = {}
        if primary.get("method"):
            primary_clean["method"] = primary["method"]
        if primary.get("path"):
            primary_clean["path"] = primary["path"]
        if primary.get("response"):
            primary_clean["response"] = _clean_sitemap_response(primary["response"])
        if primary_clean:
            cleaned["request"] = primary_clean

    related = entry.get("requests") or {}
    related_edges = related.get("edges") or []
    related_nodes = [edge["node"] for edge in related_edges]
    related_clean = [
        summary
        for summary in (_clean_sitemap_request_summary(n) for n in related_nodes)
        if summary is not None
    ]
    cleaned["related_requests"] = {
        "requests": related_clean,
        "total_count": (related.get("count") or {}).get("value", 0),
    }
    return {"success": True, "entry": cleaned}


async def list_sitemap(
    *,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
    page_size: int = _SITEMAP_PAGE_SIZE,
) -> dict[str, Any]:
    return await call_with_client(
        lambda client: list_sitemap_with_client(
            client,
            scope_id=scope_id,
            parent_id=parent_id,
            depth=depth,
            page=page,
            page_size=page_size,
        )
    )


async def view_sitemap_entry(entry_id: str) -> dict[str, Any]:
    return await call_with_client(lambda client: view_sitemap_entry_with_client(client, entry_id))


__all__ = [
    "RequestPart",
    "ScopeAction",
    "SitemapDepth",
    "SortBy",
    "SortOrder",
    "clear_scope_decisions",
    "close_client",
    "get_client",
    "get_scope_decisions",
    "list_requests",
    "list_sitemap",
    "repeat_request",
    "scope_rules",
    "view_request",
    "view_sitemap_entry",
]
