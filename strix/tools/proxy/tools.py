"""Caido proxy tools — host-side via ``caido-sdk-client``.

The five tools delegate directly to ``caido_sdk_client.Client`` instances
held in the per-scan agent context. No sandbox round-trip; the SDK
talks GraphQL to the in-container Caido sidecar via the host-mapped
port resolved at session create time.

Tools: ``list_requests``, ``view_request``, ``send_request``,
``repeat_request``, ``scope_rules``.
"""

from __future__ import annotations

import dataclasses
import re
import time
from dataclasses import is_dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper
from caido_sdk_client.types import (
    ConnectionInfoInput,
    CreateReplaySessionFromRaw,
    CreateReplaySessionOptions,
    CreateScopeOptions,
    ReplaySendOptions,
    RequestGetOptions,
    UpdateScopeOptions,
)

from strix.tools._decorator import dump_tool_result, strix_tool


if TYPE_CHECKING:
    from caido_sdk_client import Client


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


def _ctx_client(ctx: RunContextWrapper) -> Client | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner.get("caido_client")


def _serialize(value: Any) -> Any:
    """Recursively convert SDK dataclasses/Pydantic objects to JSON-safe primitives."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {k: _serialize(v) for k, v in dataclasses.asdict(value).items()}
    if hasattr(value, "model_dump"):
        return _serialize(value.model_dump())
    if isinstance(value, dict):
        return {str(k): _serialize(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_serialize(v) for v in value]
    return str(value)


def _no_client() -> str:
    return dump_tool_result(
        {
            "success": False,
            "error": "Caido client not initialized in context.",
        },
    )


# ----------------------------------------------------------------------
# list_requests
# ----------------------------------------------------------------------
@strix_tool(timeout=120)
async def list_requests(
    ctx: RunContextWrapper,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> str:
    """List captured HTTP requests from the Caido proxy with HTTPQL filtering.

    Caido HTTPQL syntax (operators differ by field type):

    - **Integer fields** (``resp.code``, ``req.port``, ``id``,
      ``roundtrip``) — ``eq``, ``gt``, ``gte``, ``lt``, ``lte``, ``ne``.
      Examples: ``resp.code.eq:200``, ``resp.code.gte:400``,
      ``req.port.eq:443``.
    - **Text/byte fields** (``req.method``, ``req.host``, ``req.path``,
      ``req.query``, ``req.ext``, ``req.raw``) — ``regex``, ``cont``
      (substring), ``eq``. Examples: ``req.method.eq:"POST"``,
      ``req.path.cont:"/api/"``, ``req.host.regex:".*\\.example\\.com"``.
    - **Date fields** (``req.created_at``) — ``gt``, ``lt`` with ISO
      timestamps: ``req.created_at.gt:"2024-01-01T00:00:00Z"``.
    - **Combine** with ``AND`` / ``OR``: ``req.method.eq:"POST" AND
      resp.code.gte:400``.
    - **Special**: ``source:intercept`` (only intercepted requests),
      ``preset:"name"``.

    For sitemap-style tree traversal use HTTPQL filters: drill into a
    host with ``req.host.eq:"example.com"`` then narrow paths with
    ``req.path.cont:"/api/"``.

    Pagination is cursor-based. Pass the ``end_cursor`` from the
    ``page_info`` of one call as ``after`` to the next.

    Args:
        httpql_filter: Caido HTTPQL query (optional).
        first: Number of entries to return (default 50).
        after: Cursor from a previous response's ``page_info.end_cursor``.
        sort_by: One of ``timestamp`` / ``host`` / ``method`` / ``path``
            / ``status_code`` / ``response_time`` / ``response_size``
            / ``source``.
        sort_order: ``asc`` or ``desc``.
        scope_id: Restrict to a Caido scope (managed via ``scope_rules``).
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    try:
        builder = client.request.list().first(first)
        if httpql_filter:
            builder = builder.filter(httpql_filter)
        if after:
            builder = builder.after(after)
        if scope_id:
            builder = builder.scope(scope_id)

        target, field = _REQ_FIELD_MAP[sort_by]
        if sort_order == "asc":
            builder = builder.ascending(target, field)
        else:
            builder = builder.descending(target, field)

        connection = await builder.execute()

        entries = []
        for edge in connection.edges:
            req = edge.node.request
            resp = edge.node.response
            entries.append(
                {
                    "cursor": edge.cursor,
                    "request": {
                        "id": req.id,
                        "host": req.host,
                        "port": req.port,
                        "method": req.method,
                        "path": req.path,
                        "query": req.query,
                        "is_tls": req.is_tls,
                        "created_at": req.created_at.isoformat(),
                    },
                    "response": (
                        {
                            "id": resp.id,
                            "status_code": resp.status_code,
                            "length": resp.length,
                            "roundtrip_ms": resp.roundtrip_time,
                            "created_at": resp.created_at.isoformat(),
                        }
                        if resp is not None
                        else None
                    ),
                },
            )

        return dump_tool_result(
            {
                "success": True,
                "entries": entries,
                "page_info": {
                    "has_next_page": connection.page_info.has_next_page,
                    "has_previous_page": connection.page_info.has_previous_page,
                    "start_cursor": connection.page_info.start_cursor,
                    "end_cursor": connection.page_info.end_cursor,
                },
            },
        )
    except Exception as exc:  # noqa: BLE001
        return dump_tool_result({"success": False, "error": f"list_requests failed: {exc}"})


# ----------------------------------------------------------------------
# view_request
# ----------------------------------------------------------------------
@strix_tool(timeout=60)
async def view_request(
    ctx: RunContextWrapper,
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> str:
    """View a captured request or its response, optionally regex-searched.

    Two modes:

    - **With** ``search_pattern`` (compact regex hits) — returns up to 20
      matches with ``before`` / ``after`` context and position. Useful
      for hunting reflected input, leaked URLs, hidden parameters.
    - **Without** ``search_pattern`` (full content with line pagination)
      — returns the page of raw content plus ``has_more`` flag.

    Common search patterns:

    - API endpoints: ``/api/[a-zA-Z0-9._/-]+``
    - URLs: ``https?://[^\\s<>"']+``
    - Query parameters: ``[?&][a-zA-Z0-9_]+=([^&\\s<>"']+)``
    - Specific input reflection: search for the value you submitted.

    Args:
        request_id: Request ID from ``list_requests``.
        part: ``"request"`` or ``"response"``.
        search_pattern: Optional regex; switches the response shape to
            compact hits.
        page: 1-indexed page number (only when no ``search_pattern``).
        page_size: Lines per page.
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    try:
        opts = RequestGetOptions(
            request_raw=(part == "request"),
            response_raw=(part == "response"),
        )
        result = await client.request.get(request_id, opts)
        if result is None:
            return dump_tool_result(
                {"success": False, "error": f"Request {request_id} not found"},
            )

        raw_bytes = (
            result.request.raw
            if part == "request"
            else (result.response.raw if result.response is not None else None)
        )
        if raw_bytes is None:
            return dump_tool_result(
                {
                    "success": False,
                    "error": f"No raw {part} for {request_id}",
                },
            )
        content = raw_bytes.decode("utf-8", errors="replace")

        if search_pattern:
            return dump_tool_result(_regex_hits(content, search_pattern))

        return dump_tool_result(_paginate_lines(content, page=page, page_size=page_size))
    except Exception as exc:  # noqa: BLE001
        return dump_tool_result({"success": False, "error": f"view_request failed: {exc}"})


def _regex_hits(content: str, pattern: str) -> dict[str, Any]:
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return {"success": False, "error": f"Invalid regex: {exc}"}

    hits = []
    for match in regex.finditer(content):
        start, end = match.span()
        before = content[max(0, start - 40) : start]
        after = content[end : end + 40]
        hits.append(
            {
                "match": match.group(0),
                "position": start,
                "before": before,
                "after": after,
            },
        )
        if len(hits) >= 20:
            break

    return {"success": True, "hits": hits, "total_hits": len(hits)}


def _paginate_lines(content: str, *, page: int, page_size: int) -> dict[str, Any]:
    lines = content.splitlines()
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "success": True,
        "content": "\n".join(lines[start:end]),
        "page": page,
        "page_size": page_size,
        "total_lines": len(lines),
        "has_more": end < len(lines),
    }


# ----------------------------------------------------------------------
# send_request
# ----------------------------------------------------------------------
@strix_tool(timeout=120, strict_mode=False)
async def send_request(
    ctx: RunContextWrapper,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> str:
    """Send an arbitrary HTTP request through the Caido proxy.

    Use this for one-off probes (test endpoints, reach external APIs).
    For modifying-and-replaying a request you've already captured, use
    ``repeat_request`` instead — it inherits the original headers /
    cookies / auth and only patches the fields you specify.

    Args:
        method: ``"GET"`` / ``"POST"`` / ``"PUT"`` / ``"DELETE"`` / etc.
        url: Full URL with protocol.
        headers: Optional header dict.
        body: Optional request body string.
        timeout: Per-request timeout in seconds (default 30).
    """
    del timeout  # The SDK applies its own timeout via the GraphQL settings.
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    try:
        connection, raw = _build_raw_request(
            method=method, url=url, headers=headers or {}, body=body
        )
        return await _replay_send(client, raw=raw, connection=connection)
    except Exception as exc:  # noqa: BLE001
        return dump_tool_result({"success": False, "error": f"send_request failed: {exc}"})


# ----------------------------------------------------------------------
# repeat_request
# ----------------------------------------------------------------------
@strix_tool(timeout=120, strict_mode=False)
async def repeat_request(
    ctx: RunContextWrapper,
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> str:
    """Repeat a captured request, optionally patching individual fields.

    The standard pentesting workflow with this tool:

    1. ``browser_action`` (or live target traffic) → request gets
       captured by Caido.
    2. ``list_requests`` → find the request ID you want to manipulate.
    3. ``repeat_request`` → send a modified version (auth-bypass test,
       payload injection, parameter tampering).

    Mirrors the manual "browse → capture → modify → test" flow used in
    real pentesting. Inherits everything from the original request
    (headers, cookies, auth, method, URL) and overlays only the fields
    you specify in ``modifications``.

    Args:
        request_id: ID of the original request (from ``list_requests``).
        modifications: Patch dict. Recognized keys:

            - ``url`` — replace the URL.
            - ``params`` — dict of query-string keys to add/update.
            - ``headers`` — dict of headers to add/update.
            - ``body`` — replace the body string entirely.
            - ``cookies`` — dict of cookies to add/update.
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()
    mods = modifications or {}

    try:
        result = await client.request.get(request_id, RequestGetOptions(request_raw=True))
        if result is None or result.request.raw is None:
            return dump_tool_result(
                {"success": False, "error": f"Request {request_id} not found"},
            )

        original = result.request
        raw_str = result.request.raw.decode("utf-8", errors="replace")
        components = _parse_raw_request(raw_str)
        full_url = _full_url_from_components(original, components, mods)
        modified = _apply_modifications(components, mods, full_url)
        connection, raw = _build_raw_request(
            method=modified["method"],
            url=modified["url"],
            headers=modified["headers"],
            body=modified["body"],
        )
        return await _replay_send(client, raw=raw, connection=connection)
    except Exception as exc:  # noqa: BLE001
        return dump_tool_result({"success": False, "error": f"repeat_request failed: {exc}"})


# ----------------------------------------------------------------------
# scope_rules
# ----------------------------------------------------------------------
@strix_tool(timeout=60)
async def scope_rules(
    ctx: RunContextWrapper,
    action: ScopeAction,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> str:
    """CRUD on Caido scope rules (allow/deny patterns).

    Scopes filter which traffic Caido tools see. Use them to focus on a
    target, exclude noisy assets (CDNs, static files), or define a
    bug-bounty allowlist.

    Pattern semantics:

    - Glob wildcards: ``*`` (any), ``?`` (single), ``[abc]`` (one of),
      ``[a-z]`` (range), ``[^abc]`` (none of).
    - **Empty allowlist = allow all domains.**
    - **Denylist always overrides allowlist.**

    Common denylist for noisy static assets:
    ``["*.gif", "*.jpg", "*.png", "*.css", "*.js", "*.ico", "*.svg",
    "*woff*", "*.ttf"]``.

    Each scope has a unique id usable as ``scope_id`` in
    ``list_requests``.

    Args:
        action:

            - ``list`` — return all scopes.
            - ``get`` — single scope by ``scope_id``.
            - ``create`` — needs ``scope_name``, optionally
              ``allowlist`` / ``denylist``.
            - ``update`` — needs ``scope_id`` + ``scope_name``;
              allowlist / denylist replace the previous values.
            - ``delete`` — needs ``scope_id``.

        allowlist: Domain patterns to include (e.g.
            ``["*.example.com", "api.test.com"]``).
        denylist: Patterns to exclude.
        scope_id: Required for ``get`` / ``update`` / ``delete``.
        scope_name: Required for ``create`` / ``update``.
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    try:
        if action == "list":
            scopes = await client.scope.list()
            return dump_tool_result(
                {"success": True, "scopes": [_serialize(s) for s in scopes]},
            )
        if action == "get":
            if not scope_id:
                return dump_tool_result(
                    {"success": False, "error": "scope_id required for get"},
                )
            scope = await client.scope.get(scope_id)
            return dump_tool_result({"success": True, "scope": _serialize(scope)})
        if action == "create":
            if not scope_name:
                return dump_tool_result(
                    {"success": False, "error": "scope_name required for create"},
                )
            scope = await client.scope.create(
                CreateScopeOptions(
                    name=scope_name,
                    allowlist=list(allowlist or []),
                    denylist=list(denylist or []),
                ),
            )
            return dump_tool_result({"success": True, "scope": _serialize(scope)})
        if action == "update":
            if not scope_id or not scope_name:
                return dump_tool_result(
                    {
                        "success": False,
                        "error": "scope_id and scope_name required for update",
                    },
                )
            scope = await client.scope.update(
                scope_id,
                UpdateScopeOptions(
                    name=scope_name,
                    allowlist=list(allowlist or []),
                    denylist=list(denylist or []),
                ),
            )
            return dump_tool_result({"success": True, "scope": _serialize(scope)})
        # action == "delete" — exhaustive Literal
        if not scope_id:
            return dump_tool_result(
                {"success": False, "error": "scope_id required for delete"},
            )
        await client.scope.delete(scope_id)
        return dump_tool_result({"success": True, "deleted": scope_id})
    except Exception as exc:  # noqa: BLE001
        return dump_tool_result({"success": False, "error": f"scope_rules failed: {exc}"})


# ----------------------------------------------------------------------
# Helpers — request build / parse / modify
# ----------------------------------------------------------------------
def _build_raw_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> tuple[ConnectionInfoInput, bytes]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    is_tls = parsed.scheme.lower() == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    final_headers = {**headers}
    final_headers.setdefault("Host", parsed.netloc)
    final_headers.setdefault("User-Agent", "strix")
    if body and "Content-Length" not in {k.title() for k in final_headers}:
        final_headers["Content-Length"] = str(len(body.encode("utf-8")))

    lines = [f"{method.upper()} {path} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in final_headers.items())
    raw = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")

    return ConnectionInfoInput(host=host, port=port, is_tls=is_tls), raw


def _parse_raw_request(raw_content: str) -> dict[str, Any]:
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


def _full_url_from_components(
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


def _apply_modifications(
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


async def _replay_send(
    client: Client,
    *,
    raw: bytes,
    connection: ConnectionInfoInput,
) -> str:
    started = time.time()
    session = await client.replay.sessions.create(
        CreateReplaySessionOptions(
            request_source=CreateReplaySessionFromRaw(raw=raw, connection=connection),
        ),
    )
    result = await client.replay.send(
        session.id,
        ReplaySendOptions(raw=raw, connection=connection),
    )
    elapsed_ms = int((time.time() - started) * 1000)

    response: dict[str, Any] | None = None
    response_raw = result.entry.response_raw if hasattr(result.entry, "response_raw") else None
    if response_raw is not None:
        response = {
            "raw": response_raw.decode("utf-8", errors="replace"),
        }

    return dump_tool_result(
        {
            "success": result.status == "DONE",
            "status": result.status,
            "error": result.error,
            "session_id": str(session.id),
            "elapsed_ms": elapsed_ms,
            "response": response,
        },
    )
