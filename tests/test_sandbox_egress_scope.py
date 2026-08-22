"""Default Caido scope + private-range replay egress guard.

The guard's authorization source is a per-run policy file that the trusted
host mounts read-only into the sandbox; module-global mutable state and the
agent-settable ``STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS`` opt-in are no longer
authoritative once a policy file exists.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


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
def _no_policy_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(caido_api._EGRESS_POLICY_ENV, raising=False)
    monkeypatch.delenv(caido_api._EGRESS_POLICY_TRUST_RW_ENV, raising=False)
    monkeypatch.delenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", raising=False)
    monkeypatch.setattr(caido_api, "_in_container", lambda: False)
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: False)
    # Default policy path must not leak the host's /run into tests.
    monkeypatch.setattr(caido_api, "_DEFAULT_EGRESS_POLICY_PATH", str(tmp_path / "absent.json"))


def _write_policy(
    tmp_path: Path,
    *,
    authorized_hosts: list[str],
    allow_private_egress: bool = False,
) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "scan_id": "scan-test",
                "authorized_hosts": authorized_hosts,
                "allow_private_egress": allow_private_egress,
            }
        ),
        encoding="utf-8",
    )
    return path


def _trusted_policy(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    *,
    in_container: bool = True,
) -> None:
    monkeypatch.setenv(caido_api._EGRESS_POLICY_ENV, str(path))
    monkeypatch.setattr(caido_api, "_in_container", lambda: in_container)
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: True)


def test_replay_blocks_private_ranges_by_default() -> None:
    assert caido_api.load_egress_policy() is None
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


def test_replay_blocks_private_ranges_with_userinfo_tricks() -> None:
    assert caido_api.load_egress_policy() is None
    # Userinfo must never smuggle a private host past the guard.
    assert caido_api._check_replay_url_host("http://user:pass@10.0.0.5/") is not None
    assert caido_api._check_replay_url_host("http://10.0.0.5:8080@10.0.0.9/") is not None


def test_replay_allows_public_hosts_by_default() -> None:
    assert caido_api.load_egress_policy() is None
    assert caido_api._check_replay_url_host("https://example.com/") is None
    assert caido_api._check_replay_url_host("http://203.0.113.10/") is None


def test_replay_allows_authorized_private_target_from_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path, authorized_hosts=["10.2.3.4", "staging.internal.corp"])
    _trusted_policy(monkeypatch, path)
    assert caido_api._check_replay_url_host("http://10.2.3.4:8000/") is None
    assert caido_api._check_replay_url_host("https://staging.internal.corp/") is None
    # Other private hosts stay blocked.
    assert caido_api._check_replay_url_host("http://10.9.9.9/") is not None


def test_policy_opt_in_allows_private_but_metadata_stays_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path, authorized_hosts=[], allow_private_egress=True)
    _trusted_policy(monkeypatch, path)
    assert caido_api._check_replay_url_host("http://10.0.0.5/") is None
    assert caido_api._check_replay_url_host("http://169.254.169.254/") is not None
    assert caido_api._check_replay_url_host("http://metadata.google.internal/") is not None


def test_policy_on_writable_mount_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path, authorized_hosts=["10.2.3.4"], allow_private_egress=True)
    monkeypatch.setenv(caido_api._EGRESS_POLICY_ENV, str(path))
    monkeypatch.setattr(caido_api, "_in_container", lambda: True)
    # Agent-crafted file: readable, but not on a read-only mount.
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: False)
    policy = caido_api.load_egress_policy()
    assert policy is not None
    assert policy.authorized_hosts == frozenset()
    assert policy.allow_private_egress is False
    assert caido_api._check_replay_url_host("http://10.2.3.4/") is not None
    # The agent-settable opt-in env must not override a present-but-untrusted policy.
    monkeypatch.setenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", "1")
    assert caido_api._check_replay_url_host("http://10.2.3.4/") is not None


def test_malformed_policy_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")
    _trusted_policy(monkeypatch, path)
    policy = caido_api.load_egress_policy()
    assert policy == caido_api._FAIL_CLOSED_POLICY
    assert caido_api._check_replay_url_host("http://10.2.3.4/") is not None


def test_host_side_trust_opt_in_honors_writable_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path, authorized_hosts=["10.2.3.4"])
    monkeypatch.setenv(caido_api._EGRESS_POLICY_ENV, str(path))
    monkeypatch.setenv(caido_api._EGRESS_POLICY_TRUST_RW_ENV, "1")
    monkeypatch.setattr(caido_api, "_in_container", lambda: False)
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: False)
    assert caido_api._check_replay_url_host("http://10.2.3.4/") is None


def test_host_side_trust_opt_in_ignored_inside_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path, authorized_hosts=["10.2.3.4"])
    monkeypatch.setenv(caido_api._EGRESS_POLICY_ENV, str(path))
    monkeypatch.setenv(caido_api._EGRESS_POLICY_TRUST_RW_ENV, "1")
    monkeypatch.setattr(caido_api, "_in_container", lambda: True)
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: False)
    assert caido_api._check_replay_url_host("http://10.2.3.4/") is not None


def test_legacy_opt_in_env_still_works_without_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    assert caido_api.load_egress_policy() is None
    monkeypatch.setenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", "1")
    assert caido_api._check_replay_url_host("http://10.0.0.5/") is None
