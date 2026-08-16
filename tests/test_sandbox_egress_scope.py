"""Default Caido scope + private-range replay egress guard."""

from __future__ import annotations

from typing import Any

import pytest

from lyrashield.runtime.session_manager import (
    derive_authorized_target_hosts,
    derive_default_scope_allowlist,
)
from lyrashield.tools.proxy import caido_api


def _url_target(url: str) -> dict[str, Any]:
    return {"type": "web_application", "details": {"target_url": url}}


def _ip_target(ip: str) -> dict[str, Any]:
    return {"type": "ip_address", "details": {"target_ip": ip}}


def test_derive_authorized_target_hosts_urls_and_ips() -> None:
    hosts = derive_authorized_target_hosts(
        [
            _url_target("https://app.example.com:8443/"),
            _ip_target("203.0.113.10"),
            {"type": "repository", "details": {"target_repo": "https://github.com/org/repo"}},
            {"type": "local_code", "details": {"target_path": "/workspace/src"}},
        ]
    )
    assert hosts == {"app.example.com", "203.0.113.10"}


def test_derive_authorized_target_hosts_strips_ports_and_cidr() -> None:
    hosts = derive_authorized_target_hosts(
        [_ip_target("10.1.2.3:8080"), _url_target("http://192.168.7.7:3000")]
    )
    assert hosts == {"10.1.2.3", "192.168.7.7"}


def test_default_scope_allowlist_covers_subdomains_but_not_ip_literals() -> None:
    assert derive_default_scope_allowlist({"example.com", "198.51.100.4"}) == [
        "198.51.100.4",
        "example.com",
        "*.example.com",
    ]


@pytest.fixture(autouse=True)
def _reset_authorized_hosts() -> None:
    caido_api.set_authorized_target_hosts(set())


def test_replay_blocks_private_ranges_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", raising=False)
    for url in (
        "http://10.0.0.5/",
        "http://172.16.4.4/",
        "http://192.168.1.1/admin",
        "http://127.0.0.1:8080/",
        "http://[::1]/",
    ):
        reason = caido_api._check_replay_url_host(url)
        assert reason is not None, url
        assert "private-range" in reason


def test_replay_allows_public_hosts_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", raising=False)
    assert caido_api._check_replay_url_host("https://example.com/") is None
    assert caido_api._check_replay_url_host("http://203.0.113.10/") is None


def test_replay_allows_authorized_private_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", raising=False)
    caido_api.set_authorized_target_hosts({"10.2.3.4", "staging.internal.corp"})
    assert caido_api._check_replay_url_host("http://10.2.3.4:8000/") is None
    assert caido_api._check_replay_url_host("https://staging.internal.corp/") is None
    # Other private hosts stay blocked.
    assert caido_api._check_replay_url_host("http://10.9.9.9/") is not None


def test_replay_private_opt_in_env_allows_all_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", "1")
    assert caido_api._check_replay_url_host("http://10.0.0.5/") is None


def test_replay_still_blocks_metadata_even_with_private_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", "1")
    assert caido_api._check_replay_url_host("http://169.254.169.254/") is not None
    assert caido_api._check_replay_url_host("http://metadata.google.internal/") is not None
