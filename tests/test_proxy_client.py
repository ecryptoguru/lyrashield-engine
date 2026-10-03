"""Tests for the shared Caido client lifecycle and proxy call serialization.

Covers the caching + serialization guarantees of ``caido_api.call_with_client``
(the sandbox-imported path) and ``proxy.tools._call`` (the host-side path). The
Caido GraphQL transport is not concurrency-safe, so both paths must run one
call at a time against the shared client.
"""

from __future__ import annotations

import asyncio
import socket
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, Mock

import pytest
from agents.tool_context import ToolContext
from caido_sdk_client import Client
from caido_sdk_client.types import ConnectionInfoInput, ReplaySendOptions

from lyrashield.tools.proxy import caido_api, tools
from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.tools.proxy import tools as strix_tools


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    caido_api._CLIENT_CACHE.clear()
    yield
    caido_api._CLIENT_CACHE.clear()


async def test_call_with_client_reuses_cached_client(monkeypatch: pytest.MonkeyPatch) -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def _new() -> Any:
        raise AssertionError("_new_client must not run when a client is cached")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is cached


async def test_call_with_client_creates_and_caches_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _FakeClient("fresh")

    async def _new() -> Any:
        return created

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is created
    assert caido_api._CLIENT_CACHE["default"] is created


async def test_failed_init_does_not_poison_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _new() -> Any:
        raise ConnectionRefusedError("caido not up yet")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    async def fn(_client: Any) -> str:
        return "unreachable"

    with pytest.raises(ConnectionRefusedError):
        await caido_api.call_with_client(fn)
    assert "default" not in caido_api._CLIENT_CACHE


async def test_call_with_client_propagates_errors() -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def fn(_client: Any) -> str:
        raise ValueError("Invalid HTTPQL filter")

    with pytest.raises(ValueError, match="Invalid HTTPQL"):
        await caido_api.call_with_client(fn)
    assert caido_api._CLIENT_CACHE["default"] is cached


async def test_call_with_client_serializes_concurrent_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caido_api._CLIENT_CACHE["default"] = cast("Any", _FakeClient("shared"))

    async def _new() -> Any:
        raise AssertionError("no new client expected")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(caido_api.call_with_client(fn) for _ in range(6)))
    assert state["max"] == 1


async def test_host_call_serializes_concurrent_calls() -> None:
    client = _FakeClient("host")
    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(tools._call(cast("Any", client), fn) for _ in range(6)))
    assert state["max"] == 1


def _headers_named(raw: bytes, name: str) -> list[str]:
    head = raw.decode("utf-8").split("\r\n\r\n", 1)[0]
    return [
        line.split(":", 1)[1].strip()
        for line in head.split("\r\n")[1:]
        if line.split(":", 1)[0].strip().lower() == name.lower()
    ]


def test_build_raw_request_recomputes_content_length_for_modified_body() -> None:
    # The captured request declared Content-Length: 12 (original body); the
    # replayed body is longer. The emitted request must carry exactly one
    # Content-Length equal to the ACTUAL body length, or the target truncates
    # the modified payload (or the connection desyncs).
    body = '{"user":"a\' OR 1=1 -- injected long payload"}'
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://203.0.113.10/login",
        headers={"content-length": "12", "Content-Type": "application/json"},
        body=body,
    )
    sent_body = raw.decode("utf-8").split("\r\n\r\n", 1)[1]
    assert sent_body == body
    assert _headers_named(raw, "Content-Length") == [str(len(body.encode("utf-8")))]


def test_build_raw_request_drops_transfer_encoding_for_modified_body() -> None:
    body = '{"user":"updated"}'
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://203.0.113.10/login",
        headers={
            "tRaNsFeR-EnCoDiNg": "chunked",
            "Content-Length": "7",
            "Content-Type": "application/json",
        },
        body=body,
    )
    assert _headers_named(raw, "Transfer-Encoding") == []
    assert _headers_named(raw, "Content-Length") == [str(len(body.encode("utf-8")))]


def test_build_raw_request_drops_stale_content_length_for_empty_body() -> None:
    # A body cleared to empty must not keep the inherited (non-zero) length.
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://203.0.113.10/x",
        headers={"Content-Length": "12"},
        body="",
    )
    assert _headers_named(raw, "Content-Length") == []


def test_captured_host_header_does_not_replace_transport_authority() -> None:
    original = SimpleNamespace(host="recorded.example", port=8443, is_tls=True)
    components = caido_api.parse_raw_request("GET /admin HTTP/1.1\r\nHost: virtual.example\r\n\r\n")

    assert caido_api.full_url_from_components(original, components, {}) == (
        "https://recorded.example:8443/admin"
    )


def test_parse_raw_request_preserves_binary_body_and_duplicate_header_lines() -> None:
    raw = (
        b"POST /upload HTTP/1.1\r\nHost: target.example\r\n"
        b"X-Tag: one\r\nx-tag: two\r\nContent-Length: 3\r\n\r\n\x00\xffx"
    )

    components = caido_api.parse_raw_request(raw)

    assert components["body"] == b"\x00\xffx"
    assert components["header_lines"] == [
        "Host: target.example",
        "X-Tag: one",
        "x-tag: two",
        "Content-Length: 3",
    ]


@pytest.fixture
def replay_client(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Exercise real Caido SDK option models while replacing its transport calls."""
    client = Client("http://127.0.0.1:48080")
    monkeypatch.setattr(
        client.graphql,
        "query",
        AsyncMock(
            return_value={
                "upstreamProxiesHttp": [],
                "upstreamProxiesSocks": [],
                "upstreamPlugins": [],
            }
        ),
    )
    monkeypatch.setattr(
        client.replay.sessions,
        "create",
        AsyncMock(return_value=SimpleNamespace(id="session")),
    )
    monkeypatch.setattr(
        client.replay,
        "send",
        AsyncMock(
            return_value=SimpleNamespace(
                status="DONE", error=None, entry=SimpleNamespace(response=None)
            )
        ),
    )
    monkeypatch.setattr(
        caido_api,
        "load_egress_policy",
        lambda: caido_api.EgressPolicy(authorized_hosts=frozenset({"target.example"})),
    )
    return client


async def test_replay_pins_the_validated_dns_answer_without_changing_http_authority(
    monkeypatch: pytest.MonkeyPatch, replay_client: Any
) -> None:
    resolve = Mock(side_effect=[["203.0.113.5"], ["203.0.113.9"]])
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", resolve)
    connection, raw = caido_api.build_raw_request(
        method="GET", url="https://target.example/", headers={}, body=""
    )

    await caido_api.replay_send_raw(replay_client, connection=connection, raw=raw)

    options = replay_client.replay.send.call_args.args[1]
    assert isinstance(options, ReplaySendOptions)
    assert options.connection.host == "203.0.113.9"
    assert options.connection.sni == "target.example"
    assert options.connection.is_tls
    assert b"Host: target.example" in options.raw
    assert resolve.call_count == 2
    await replay_client.aclose()


async def test_replay_rechecks_dns_before_creating_a_session(
    monkeypatch: pytest.MonkeyPatch, replay_client: Any
) -> None:
    caido_api.clear_scope_decisions()
    resolve = Mock(side_effect=[["203.0.113.5"], ["::ffff:169.254.169.254"]])
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", resolve)
    connection, raw = caido_api.build_raw_request(
        method="GET", url="https://target.example/", headers={}, body=""
    )

    with pytest.raises(ValueError, match="link-local"):
        await caido_api.replay_send_raw(replay_client, connection=connection, raw=raw)

    replay_client.replay.sessions.create.assert_not_called()
    replay_client.replay.send.assert_not_called()
    assert caido_api.get_scope_decisions()["violations"][-1]["rule"] == "link_local"
    await replay_client.aclose()


@pytest.mark.parametrize("resolved_ip", ["127.0.0.1", "10.1.2.3"])
async def test_replay_rejects_authorized_hostname_resolving_to_private_address(
    monkeypatch: pytest.MonkeyPatch, replay_client: Any, resolved_ip: str
) -> None:
    caido_api.clear_scope_decisions()
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: ["203.0.113.5"])
    connection, raw = caido_api.build_raw_request(
        method="GET", url="http://target.example/", headers={}, body=""
    )
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: [resolved_ip])

    with pytest.raises(ValueError, match="private-range"):
        await caido_api.replay_send_raw(replay_client, connection=connection, raw=raw)

    replay_client.replay.sessions.create.assert_not_called()
    replay_client.replay.send.assert_not_called()
    await replay_client.aclose()


async def test_replay_preserves_authority_when_the_verified_target_relay_is_active(
    monkeypatch: pytest.MonkeyPatch, replay_client: Any
) -> None:
    replay_client.graphql.query.return_value["upstreamProxiesHttp"] = [
        {
            "id": "relay",
            "enabled": True,
            "connection": {"host": "127.0.0.1", "port": 48081, "isTLS": False},
            "allowlist": ["*"],
            "denylist": [],
        }
    ]
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: ["203.0.113.5"])
    connection, raw = caido_api.build_raw_request(
        method="GET", url="https://target.example/", headers={}, body=""
    )

    await caido_api.replay_send_raw(replay_client, connection=connection, raw=raw)

    options = replay_client.replay.send.call_args.args[1]
    assert options.connection.host == "target.example"
    assert b"Host: target.example" in options.raw
    await replay_client.aclose()


async def test_replay_rejects_an_unverified_caido_upstream(
    replay_client: Any,
) -> None:
    replay_client.graphql.query.return_value["upstreamProxiesHttp"] = [
        {
            "id": "unexpected",
            "enabled": True,
            "connection": {"host": "proxy.evil", "port": 8080, "isTLS": False},
            "allowlist": ["*"],
            "denylist": [],
        }
    ]

    with pytest.raises(ValueError, match="verified target relay"):
        await caido_api.replay_send_raw(
            replay_client,
            connection=ConnectionInfoInput(host="203.0.113.5", port=443, is_tls=True),
            raw=b"GET / HTTP/1.1\r\nHost: target.example\r\n\r\n",
        )

    replay_client.replay.sessions.create.assert_not_called()
    replay_client.replay.send.assert_not_called()
    await replay_client.aclose()


def test_build_replay_request_preserves_captured_bytes_and_transport_authority() -> None:
    original = SimpleNamespace(
        raw=(
            b"POST /upload HTTP/1.1\r\nHost: virtual.example\r\n"
            b"X-Tag: one\r\nx-tag: two\r\nContent-Length: 3\r\n\r\n\x00\xffx"
        ),
        host="recorded.example",
        port=8443,
        is_tls=True,
    )

    connection, raw = caido_api.build_replay_request(original, {})

    assert connection.host == "recorded.example"
    assert connection.port == 8443
    assert connection.is_tls
    assert raw == original.raw


@pytest.mark.parametrize("public_sink", ["api", "tool"])
async def test_public_repeat_request_replays_original_capture_without_normalizing_bytes(
    monkeypatch: pytest.MonkeyPatch, replay_client: Any, public_sink: str
) -> None:
    captured = b"POST /upload HTTP/1.1\r\nHost: virtual.example\r\n"
    captured += b"X-Tag: one\r\nx-tag: two\r\nContent-Length: 3\r\n\r\n\x00\xffx"
    original = SimpleNamespace(
        raw=captured,
        host="recorded.example",
        port=8443,
        is_tls=True,
    )
    monkeypatch.setattr(
        caido_api,
        "get_request_with_client",
        AsyncMock(return_value=SimpleNamespace(request=original)),
    )
    monkeypatch.setattr(
        caido_api,
        "load_egress_policy",
        lambda: caido_api.EgressPolicy(
            authorized_hosts=frozenset({"recorded.example", "virtual.example"})
        ),
    )
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: ["203.0.113.9"])
    if public_sink == "api":

        async def call_with_test_client(fn: Any) -> Any:
            return await fn(replay_client)

        monkeypatch.setattr(caido_api, "call_with_client", call_with_test_client)
        await caido_api.repeat_request("request-1")
    else:
        context = ToolContext(
            context={"caido_client": replay_client},
            tool_name="repeat_request",
            tool_call_id="call-1",
            tool_arguments='{"request_id":"request-1"}',
        )
        await tools.repeat_request.on_invoke_tool(context, '{"request_id":"request-1"}')

    options = replay_client.replay.send.call_args.args[1]
    assert isinstance(options, ReplaySendOptions)
    assert options.raw == captured
    assert options.connection.host == "203.0.113.9"
    assert options.connection.port == 8443
    assert options.connection.sni == "recorded.example"
    assert options.connection.is_tls
    await replay_client.aclose()


def test_replay_parameter_patch_keeps_unmodified_duplicate_query_and_headers() -> None:
    original = SimpleNamespace(
        raw=(
            b"GET /?keep=one&keep=two&replace=old HTTP/1.1\r\n"
            b"Host: recorded.example\r\nX-Tag: first\r\nx-tag: second\r\n\r\n"
        ),
        host="recorded.example",
        port=443,
        is_tls=True,
    )

    _connection, raw = caido_api.build_replay_request(original, {"params": {"replace": "new"}})

    assert b"GET /?keep=one&keep=two&replace=new HTTP/1.1\r\n" in raw
    assert b"X-Tag: first\r\nx-tag: second\r\n" in raw


def test_cross_origin_url_patch_drops_captured_credentials_unless_replaced() -> None:
    original = SimpleNamespace(
        raw=(
            b"GET /private HTTP/1.1\r\nHost: recorded.example\r\n"
            b"Cookie: session=secret\r\nAuthorization: Bearer old\r\n"
            b"Proxy-Authorization: Basic old\r\nX-Trace: keep\r\n\r\n"
        ),
        host="recorded.example",
        port=443,
        is_tls=True,
    )

    _connection, raw = caido_api.build_replay_request(
        original,
        {
            "url": "https://other.example:443/new",
            "headers": {
                "authorization": "Bearer explicit",
                "proxy-authorization": "Basic explicit",
            },
            "cookies": {"mode": "test"},
        },
    )

    assert b"Host: other.example:443\r\n" in raw
    assert b"Authorization: Bearer explicit\r\n" in raw
    assert b"Proxy-Authorization: Basic explicit\r\n" in raw
    assert b"Cookie: mode=test\r\n" in raw
    assert b"session=secret" not in raw
    assert b"Proxy-Authorization: Basic old\r\n" not in raw
    assert b"X-Trace: keep\r\n" in raw


def test_origin_normalization_keeps_credentials_for_same_origin() -> None:
    original = SimpleNamespace(
        raw=(
            b"GET /private HTTP/1.1\r\nHost: recorded.example\r\n"
            b"Cookie: session=secret\r\nAuthorization: Bearer old\r\n\r\n"
        ),
        host="recorded.example",
        port=443,
        is_tls=True,
    )

    _connection, raw = caido_api.build_replay_request(
        original, {"url": "HTTPS://RECORDED.EXAMPLE:443/next"}
    )

    assert b"Cookie: session=secret\r\n" in raw
    assert b"Authorization: Bearer old\r\n" in raw


async def test_public_repeat_request_does_not_forward_credentials_to_new_origin(
    monkeypatch: pytest.MonkeyPatch, replay_client: Any
) -> None:
    original = SimpleNamespace(
        raw=(
            b"GET /private HTTP/1.1\r\nHost: recorded.example\r\n"
            b"Cookie: session=secret\r\nAuthorization: Bearer old\r\n"
            b"Proxy-Authorization: Basic old\r\n\r\n"
        ),
        host="recorded.example",
        port=443,
        is_tls=True,
    )
    monkeypatch.setattr(
        caido_api,
        "get_request_with_client",
        AsyncMock(return_value=SimpleNamespace(request=original)),
    )
    monkeypatch.setattr(
        caido_api,
        "load_egress_policy",
        lambda: caido_api.EgressPolicy(
            authorized_hosts=frozenset({"recorded.example", "other.example"})
        ),
    )
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: ["203.0.113.9"])

    async def call_with_test_client(fn: Any) -> Any:
        return await fn(replay_client)

    monkeypatch.setattr(caido_api, "call_with_client", call_with_test_client)
    await caido_api.repeat_request("request-1", modifications={"url": "https://other.example/"})

    options = replay_client.replay.send.call_args.args[1]
    assert isinstance(options, ReplaySendOptions)
    assert b"Cookie:" not in options.raw
    assert b"Authorization:" not in options.raw
    assert b"Proxy-Authorization:" not in options.raw
    await replay_client.aclose()


@pytest.mark.parametrize(
    "raw, reason",
    [
        (
            b"GET / HTTP/1.1\r\nHost: outside.example\r\n\r\n",
            "authorized scope",
        ),
        (
            b"GET http://outside.example/private HTTP/1.1\r\nHost: target.example\r\n\r\n",
            "authorized scope",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: target.example\r\nHost: outside.example\r\n\r\n",
            "multiple Host",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: target.example\r\nHost: target.example\r\n\r\n",
            "multiple Host",
        ),
    ],
)
async def test_replay_sink_rejects_unscoped_or_ambiguous_http_authority(
    replay_client: Any, monkeypatch: pytest.MonkeyPatch, raw: bytes, reason: str
) -> None:
    caido_api.clear_scope_decisions()
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: ["203.0.113.5"])

    with pytest.raises(ValueError, match=reason):
        await caido_api.replay_send_raw(
            replay_client,
            connection=ConnectionInfoInput(host="target.example", port=443, is_tls=True),
            raw=raw,
        )

    replay_client.replay.sessions.create.assert_not_called()
    replay_client.replay.send.assert_not_called()
    await replay_client.aclose()


async def test_replay_sink_preserves_capture_with_two_authorized_authorities(
    replay_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = (
        b"GET http://virtual.example/path HTTP/1.1\r\n"
        b"Host: target.example\r\nX-Trace: exact\r\n\r\n"
    )
    monkeypatch.setattr(
        caido_api,
        "load_egress_policy",
        lambda: caido_api.EgressPolicy(
            authorized_hosts=frozenset({"target.example", "virtual.example"})
        ),
    )
    monkeypatch.setattr(caido_api, "_resolve_hostname_ips", lambda _host: ["203.0.113.5"])

    await caido_api.replay_send_raw(
        replay_client,
        connection=ConnectionInfoInput(host="target.example", port=80, is_tls=False),
        raw=raw,
    )

    options = replay_client.replay.send.call_args.args[1]
    assert options.raw == raw
    await replay_client.aclose()


def test_replay_denies_unspecified_dns_address_even_for_authorized_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        caido_api,
        "load_egress_policy",
        lambda: caido_api.EgressPolicy(
            authorized_hosts=frozenset({"target.example"}),
            allow_private_egress=True,
        ),
    )

    denial = caido_api._replay_denial(
        "https://target.example/",
        resolved_ips=["0.0.0.0"],
    )

    assert denial is not None
    assert denial[1] == "non_routable_destination"


class _Ctx:
    def __init__(self, context: Any) -> None:
        self.context = context


async def test_ctx_client_returns_client_when_present() -> None:
    client = _FakeClient("host")
    got = await strix_tools._ctx_client(cast("Any", _Ctx({"caido_client": client})))
    assert got is client


def test_ctx_client_returns_none_without_client() -> None:
    assert tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert tools._ctx_client(cast("Any", _Ctx(None))) is None


def test_build_raw_request_rejects_crlf_in_header_value() -> None:
    """CRLF in a header value must not pass through to the raw request."""
    with pytest.raises(ValueError, match="forbidden characters"):
        caido_api.build_raw_request(
            method="GET",
            url="https://203.0.113.10/",
            headers={"X-Evil": "value\r\nX-Injected: yes"},
            body="",
        )


def test_build_raw_request_rejects_nul_in_header_name() -> None:
    """NUL in a header name must not pass through to the raw request."""
    with pytest.raises(ValueError, match="forbidden characters"):
        caido_api.build_raw_request(
            method="GET",
            url="https://203.0.113.10/",
            headers={"X-Evil\x00": "value"},
            body="",
        )


def test_build_raw_request_accepts_clean_headers() -> None:
    """Clean headers must still be accepted and produce a valid raw request."""
    _conn, raw = caido_api.build_raw_request(
        method="GET",
        url="https://203.0.113.10/",
        headers={"X-Clean": "value"},
        body="",
    )
    assert b"X-Clean: value" in raw


def test_replay_denial_blocks_non_http_scheme() -> None:
    """Non-HTTP schemes (file://, gopher://) must be blocked."""
    assert caido_api._replay_denial("file:///etc/passwd")[1] == "non_http_scheme"
    assert caido_api._replay_denial("gopher://example.com/")[1] == "non_http_scheme"


def test_replay_denial_blocks_google_metadata() -> None:
    """Google cloud metadata hostname must be blocked."""
    reason = caido_api._replay_denial("http://metadata.google.internal/")
    assert reason is not None
    assert reason[1] == "cloud_metadata"
    assert "metadata" in reason[0]


def test_replay_denial_blocks_link_local_ipv4() -> None:
    """Link-local IPv4 (AWS/Azure IMDS at 169.254.169.254) must be blocked."""
    reason = caido_api._replay_denial("http://169.254.169.254/")
    assert reason is not None
    assert reason[1] == "link_local"
    assert "169.254.169.254" in reason[0]


def test_replay_denial_blocks_link_local_ipv6() -> None:
    """Link-local IPv6 must be blocked."""
    reason = caido_api._replay_denial("http://[fe80::1]/")
    assert reason is not None
    assert reason[1] == "link_local"
    assert "link-local" in reason[0]


def test_replay_denial_blocks_alibaba_metadata() -> None:
    """Alibaba Cloud metadata IP (100.100.100.200) must be blocked."""
    reason = caido_api._replay_denial("http://100.100.100.200/")
    assert reason is not None
    assert reason[1] == "cloud_metadata"
    assert "metadata" in reason[0]


def test_replay_denial_blocks_host_gateway_by_default() -> None:
    """host.docker.internal must be blocked unless explicitly opted in."""
    reason = caido_api._replay_denial("http://host.docker.internal/")
    assert reason is not None
    assert reason[1] == "host_gateway"
    assert "host.docker.internal" in reason[0]


def test_replay_denial_allows_normal_host() -> None:
    """Normal external hosts must not be blocked."""
    assert caido_api._replay_denial("https://203.0.113.10/") is None


def test_build_raw_request_rejects_non_http_scheme() -> None:
    """build_raw_request must reject non-HTTP URL schemes."""
    with pytest.raises(ValueError, match="non-HTTP scheme"):
        caido_api.build_raw_request(
            method="GET",
            url="file://example.com/etc/passwd",
            headers={},
            body="",
        )


def test_build_raw_request_rejects_link_local_ip() -> None:
    """build_raw_request must reject replay to link-local addresses."""
    with pytest.raises(ValueError, match="link-local"):
        caido_api.build_raw_request(
            method="GET",
            url="http://169.254.169.254/latest/meta-data/",
            headers={},
            body="",
        )


def test_build_raw_request_rejects_alibaba_metadata() -> None:
    """build_raw_request must reject replay to Alibaba Cloud metadata IP."""
    with pytest.raises(ValueError, match="metadata"):
        caido_api.build_raw_request(
            method="GET",
            url="http://100.100.100.200/latest/meta-data/",
            headers={},
            body="",
        )


def test_validate_scope_allowlist_rejects_empty() -> None:
    """Empty allowlist must be rejected (it allows all domains)."""
    error = tools._validate_scope_allowlist(None)
    assert error is not None
    assert "at least one" in error

    error = tools._validate_scope_allowlist([])
    assert error is not None
    assert "at least one" in error


def test_validate_scope_allowlist_rejects_match_all() -> None:
    """Match-all patterns like '*' must be rejected."""
    error = tools._validate_scope_allowlist(["*"])
    assert error is not None
    assert "too broad" in error


def test_validate_scope_allowlist_rejects_wildcard_only() -> None:
    """Patterns with no literal host characters must be rejected."""
    error = tools._validate_scope_allowlist(["*.?[]"])
    assert error is not None
    assert "too broad" in error


def test_validate_scope_allowlist_accepts_valid_patterns() -> None:
    """Valid patterns with literal host segments must be accepted."""
    assert tools._validate_scope_allowlist(["*.example.com", "api.test.com"]) is None


def test_is_match_all_pattern_detects_pure_wildcards() -> None:
    """_is_match_all_pattern must return True for patterns with no alnum chars."""
    assert tools._is_match_all_pattern("*") is True
    assert tools._is_match_all_pattern("*.?") is True
    assert tools._is_match_all_pattern("") is True


def test_is_match_all_pattern_allows_literal_hosts() -> None:
    """_is_match_all_pattern must return False for patterns with alnum chars."""
    assert tools._is_match_all_pattern("*.example.com") is False
    assert tools._is_match_all_pattern("api.test.com") is False


def test_validate_caido_url_host_allows_localhost() -> None:
    caido_api._validate_caido_url_host("http://127.0.0.1:48080")


def test_validate_caido_url_host_allows_case_insensitive_scheme() -> None:
    caido_api._validate_caido_url_host("HTTP://127.0.0.1:48080")


def test_validate_caido_url_host_blocks_link_local_ip() -> None:
    with pytest.raises(ValueError, match="link-local"):
        caido_api._validate_caido_url_host("http://169.254.169.254:48080")


def test_validate_caido_url_host_blocks_metadata_ip() -> None:
    with pytest.raises(ValueError, match="metadata"):
        caido_api._validate_caido_url_host("http://100.100.100.200:48080")


def test_validate_caido_url_host_blocks_metadata_host() -> None:
    with pytest.raises(ValueError, match="metadata"):
        caido_api._validate_caido_url_host("http://metadata.google.internal:48080")


def test_validate_caido_url_host_blocks_resolved_link_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_getaddrinfo(
        _host: str,
        _port: Any,
        *_args: Any,
        **_kwargs: Any,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("169.254.169.254", 0),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    with pytest.raises(ValueError, match="link-local"):
        caido_api._validate_caido_url_host("http://metadata-spoof.example.com:48080")


def test_validate_caido_url_host_allows_resolved_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_getaddrinfo(
        _host: str,
        _port: Any,
        *_args: Any,
        **_kwargs: Any,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 0),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    caido_api._validate_caido_url_host("http://caido.example.com:48080")


async def test_ctx_client_returns_none_without_client_strix() -> None:
    assert await strix_tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert await strix_tools._ctx_client(cast("Any", _Ctx(None))) is None


async def test_ctx_client_resolves_bootstrap_handle() -> None:
    client = _FakeClient("host")

    async def _bootstrap() -> Any:
        return client

    handle = CaidoBootstrapHandle(asyncio.ensure_future(_bootstrap()))
    got = await strix_tools._ctx_client(cast("Any", _Ctx({"caido_client": handle})))
    assert got is client


async def test_ctx_client_degrades_when_bootstrap_failed() -> None:
    async def _bootstrap() -> Any:
        raise RuntimeError("caido never came up")

    handle = CaidoBootstrapHandle(asyncio.ensure_future(_bootstrap()))
    assert await strix_tools._ctx_client(cast("Any", _Ctx({"caido_client": handle}))) is None
