"""Tests for the shared Caido client lifecycle and proxy call serialization.

Covers the caching + serialization guarantees of ``caido_api.call_with_client``
(the sandbox-imported path) and ``proxy.tools._call`` (the host-side path). The
Caido GraphQL transport is not concurrency-safe, so both paths must run one
call at a time against the shared client.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Any, cast

import pytest

from lyrashield.tools.proxy import caido_api, tools


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
        url="https://example.com/login",
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
        url="https://example.com/login",
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
        url="https://example.com/x",
        headers={"Content-Length": "12"},
        body="",
    )
    assert _headers_named(raw, "Content-Length") == []


class _Ctx:
    def __init__(self, context: Any) -> None:
        self.context = context


def test_ctx_client_returns_client_when_present() -> None:
    client = _FakeClient("host")
    got = tools._ctx_client(cast("Any", _Ctx({"caido_client": client})))
    assert got is client


def test_ctx_client_returns_none_without_client() -> None:
    assert tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert tools._ctx_client(cast("Any", _Ctx(None))) is None


def test_build_raw_request_rejects_crlf_in_header_value() -> None:
    """CRLF in a header value must not pass through to the raw request."""
    with pytest.raises(ValueError, match="forbidden characters"):
        caido_api.build_raw_request(
            method="GET",
            url="https://example.com/",
            headers={"X-Evil": "value\r\nX-Injected: yes"},
            body="",
        )


def test_build_raw_request_rejects_nul_in_header_name() -> None:
    """NUL in a header name must not pass through to the raw request."""
    with pytest.raises(ValueError, match="forbidden characters"):
        caido_api.build_raw_request(
            method="GET",
            url="https://example.com/",
            headers={"X-Evil\x00": "value"},
            body="",
        )


def test_build_raw_request_accepts_clean_headers() -> None:
    """Clean headers must still be accepted and produce a valid raw request."""
    _conn, raw = caido_api.build_raw_request(
        method="GET",
        url="https://example.com/",
        headers={"X-Clean": "value"},
        body="",
    )
    assert b"X-Clean: value" in raw


def test_check_replay_url_host_blocks_non_http_scheme() -> None:
    """Non-HTTP schemes (file://, gopher://) must be blocked."""
    assert caido_api._check_replay_url_host("file:///etc/passwd") is not None
    assert caido_api._check_replay_url_host("gopher://example.com/") is not None


def test_check_replay_url_host_blocks_google_metadata() -> None:
    """Google cloud metadata hostname must be blocked."""
    reason = caido_api._check_replay_url_host("http://metadata.google.internal/")
    assert reason is not None
    assert "metadata" in reason


def test_check_replay_url_host_blocks_link_local_ipv4() -> None:
    """Link-local IPv4 (AWS/Azure IMDS at 169.254.169.254) must be blocked."""
    reason = caido_api._check_replay_url_host("http://169.254.169.254/")
    assert reason is not None
    assert "link-local" in reason


def test_check_replay_url_host_blocks_link_local_ipv6() -> None:
    """Link-local IPv6 must be blocked."""
    reason = caido_api._check_replay_url_host("http://[fe80::1]/")
    assert reason is not None
    assert "link-local" in reason


def test_check_replay_url_host_blocks_alibaba_metadata() -> None:
    """Alibaba Cloud metadata IP (100.100.100.200) must be blocked."""
    reason = caido_api._check_replay_url_host("http://100.100.100.200/")
    assert reason is not None
    assert "metadata" in reason


def test_check_replay_url_host_blocks_host_gateway_by_default() -> None:
    """host.docker.internal must be blocked unless explicitly opted in."""
    reason = caido_api._check_replay_url_host("http://host.docker.internal/")
    assert reason is not None
    assert "host.docker.internal" in reason


def test_check_replay_url_host_allows_normal_host() -> None:
    """Normal external hosts must not be blocked."""
    assert caido_api._check_replay_url_host("https://example.com/") is None


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
