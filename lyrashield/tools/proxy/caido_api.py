"""Shared Caido proxy helpers and sandbox-importable ``caido_api`` module."""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import json
import os
import re
import socket
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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
# (AWS/GCP/Azure IMDS at 169.254.169.254). Host gateway and cloud metadata
# hostnames are blocked unless the operator has explicitly opted in.
_LINK_LOCAL_NETWORKS: tuple[ipaddress.IPv4Network, ipaddress.IPv6Network] = (
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv6Network("fe80::/10"),
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


def _private_range_block_reason(hostname: str) -> str | None:
    """Return a block reason when replay targets private space it may not reach."""
    policy = load_egress_policy()
    allow_private = (
        policy.allow_private_egress
        if policy is not None
        else os.environ.get(_PRIVATE_EGRESS_OPT_IN_ENV, "").strip().lower() in {"1", "true", "yes"}
    )
    if allow_private:
        return None
    hostname = hostname.lower().rstrip(".")
    if policy is not None and hostname in policy.authorized_hosts:
        return None
    for raw in _resolve_hostname_ips(hostname):
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if any(ip in net for net in _PRIVATE_NETWORKS):
            return (
                f"private-range address {ip} (not an authorized target; the "
                "scan's read-only egress policy file controls this)"
            )
    return None


_BLOCKED_METADATA_HOSTS = frozenset(
    {"metadata.google.internal", "metadata.google.internal.", "metadata.google", "metadata.google."}
)
# Cloud metadata IPs not covered by link-local ranges.
# Alibaba Cloud IMDS: 100.100.100.200 (not in 169.254.0.0/16).
_BLOCKED_METADATA_IPS = frozenset({ipaddress.ip_address("100.100.100.200")})
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


def _check_replay_url_host(url: str) -> str | None:
    """Return a human-readable block reason, or None if the host is allowed."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return f"non-HTTP scheme {parsed.scheme!r}"
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None
    if hostname in _BLOCKED_METADATA_HOSTS:
        return f"cloud metadata host {hostname!r}"
    if not _host_gateway_allowed() and hostname in {
        "host.docker.internal",
        "host.docker.internal.",
    }:
        return "host.docker.internal (set STRIX_SANDBOX_ALLOW_HOST_GATEWAY=1 to allow)"
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None:
        if ip in _BLOCKED_METADATA_IPS:
            return f"cloud metadata IP {ip}"
        for net in _LINK_LOCAL_NETWORKS:
            if ip in net:
                return f"link-local address {ip}"
    # Private-range guard also resolves DNS names, so a hostname that points
    # into RFC1918/loopback space is caught the same way as a literal IP.
    return _private_range_block_reason(hostname)


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
    except socket.gaierror:
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


def _check_ip_against_blocklist(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if ip in _BLOCKED_METADATA_IPS:
        raise ValueError(f"Caido URL points to cloud metadata IP: {ip}")
    if any(ip in net for net in _LINK_LOCAL_NETWORKS):
        raise ValueError(f"Caido URL points to link-local address: {ip}")


def _validate_caido_url_host(url: str) -> None:
    """Block cloud-metadata and link-local hosts for the Caido GraphQL URL.

    Resolves hostnames before checking IPs so DNS-based metadata aliases (e.g.
    ``xip.io`` hosts pointing to ``169.254.169.254``) are caught as well.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"Invalid Caido URL scheme: {parsed.scheme!r}")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError(f"Invalid Caido URL, missing hostname: {url}")
    if hostname in _BLOCKED_METADATA_HOSTS:
        raise ValueError(f"Caido URL points to cloud metadata host: {hostname!r}")
    for raw in _resolve_hostname_ips(hostname):
        try:
            ip = ipaddress.ip_address(raw)
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
    block_reason = _check_replay_url_host(url)
    if block_reason:
        raise ValueError(f"URL is blocked ({block_reason}): {url}")
    is_tls = parsed.scheme.lower() == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    final_headers = {**headers}
    final_headers.setdefault("Host", parsed.netloc)
    final_headers.setdefault("User-Agent", "strix")
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
    return ConnectionInfoInput(host=host, port=port, is_tls=is_tls), raw


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


def parse_raw_request(raw_content: str) -> dict[str, Any]:
    lines = raw_content.split("\n")
    request_line = lines[0].strip().split(" ")
    if len(request_line) < 2:
        raise ValueError("Invalid request line format")
    method, url_path = request_line[0], request_line[1]

    parsed_headers: dict[str, str] = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            key, value = line.split(":", 1)
            parsed_headers[key.strip()] = value.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""
    return {"method": method, "url_path": url_path, "headers": parsed_headers, "body": body}


def full_url_from_components(
    original: Any,
    components: dict[str, Any],
    modifications: dict[str, Any],
) -> str:
    if "url" in modifications:
        return str(modifications["url"])
    headers = components["headers"]
    host_header = headers.get("Host") or original.host
    scheme = "https" if original.is_tls else "http"
    return f"{scheme}://{host_header}{components['url_path']}"


def apply_modifications(
    components: dict[str, Any],
    modifications: dict[str, Any],
    full_url: str,
) -> dict[str, Any]:
    headers = dict(components["headers"])
    body = components["body"]
    final_url = full_url

    if "params" in modifications:
        parsed = urlparse(final_url)
        existing = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
        existing.update(modifications["params"])
        final_url = urlunparse(parsed._replace(query=urlencode(existing)))
    if "headers" in modifications:
        headers.update(modifications["headers"])
    if "body" in modifications:
        body = modifications["body"]
    if "cookies" in modifications:
        cookies: dict[str, str] = {}
        if headers.get("Cookie"):
            for cookie in headers["Cookie"].split(";"):
                if "=" in cookie:
                    k, v = cookie.split("=", 1)
                    cookies[k.strip()] = v.strip()
        cookies.update(modifications["cookies"])
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    return {
        "method": components["method"],
        "url": final_url,
        "headers": headers,
        "body": body,
    }


_REPLAY_SEND_TIMEOUT_SECONDS = 30.0


async def replay_send_raw(
    client: CaidoClient,
    *,
    raw: bytes,
    connection: ConnectionInfoInput,
) -> dict[str, Any]:
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
        raw_str = result.request.raw.decode("utf-8", errors="replace")
        components = parse_raw_request(raw_str)
        full_url = full_url_from_components(original, components, mods)
        modified = apply_modifications(components, mods, full_url)
        connection, raw = build_raw_request(
            method=modified["method"],
            url=modified["url"],
            headers=modified["headers"],
            body=modified["body"],
        )
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
    "close_client",
    "get_client",
    "list_requests",
    "list_sitemap",
    "repeat_request",
    "scope_rules",
    "view_request",
    "view_sitemap_entry",
]
