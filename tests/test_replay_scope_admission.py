"""Per-request scope admission against the recorded authorized host set.

Replay requests must be checked against the egress policy recorded for the
run — not the mutable proxy config. Requests outside the recorded scope are
denied and logged as scope-violation evidence in the decision ledger.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Iterator

import pytest

from lyrashield.runtime.session_manager import write_egress_policy
from lyrashield.tools.proxy import caido_api


@pytest.fixture(autouse=True)
def _ledger(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the scope-decision ledger and policy/env state per test."""
    caido_api.clear_scope_decisions()
    monkeypatch.delenv("LYRASHIELD_EGRESS_POLICY", raising=False)
    monkeypatch.delenv("STRIX_RUN_ID", raising=False)
    monkeypatch.delenv("STRIX_SANDBOX_ALLOW_PRIVATE_EGRESS", raising=False)
    # Behave as in-container: the mounted policy file is the only authority.
    monkeypatch.setattr(caido_api, "_in_container", lambda: True)
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: True)
    yield
    caido_api.clear_scope_decisions()


def _policy(
    monkeypatch: pytest.MonkeyPatch,
    authorized_hosts: list[str],
    *,
    allow_private_egress: bool = False,
) -> None:
    _mount, host_dir = write_egress_policy(
        "scan-scope",
        set(authorized_hosts),
        allow_private_egress=allow_private_egress,
    )
    monkeypatch.setenv("STRIX_RUN_ID", "scan-scope")
    monkeypatch.setenv("LYRASHIELD_EGRESS_POLICY", str(Path(host_dir) / "policy.json"))


def _send(url: str, method: str = "GET") -> Any:
    return caido_api.build_raw_request(method=method, url=url, headers={}, body="")


def test_in_scope_host_admitted_and_recorded(monkeypatch: Any) -> None:
    _policy(monkeypatch, ["app.example.com"])
    _conn, raw = _send("https://app.example.com/login")
    assert raw.startswith(b"GET /login")
    decisions = caido_api.get_scope_decisions()
    assert decisions["admitted_hosts"] == {"app.example.com": 1}
    assert decisions["violations"] == []


def test_out_of_scope_public_host_denied_as_violation(monkeypatch: Any) -> None:
    _policy(monkeypatch, ["app.example.com"])
    with pytest.raises(ValueError, match="outside the recorded authorized scope"):
        _send("https://evil.example.net/?token=secret")
    decisions = caido_api.get_scope_decisions()
    assert len(decisions["violations"]) == 1
    entry = decisions["violations"][0]
    assert entry["rule"] == "outside_authorized_scope"
    assert entry["host"] == "evil.example.net"
    # Evidence URLs never carry credentials or query strings.
    assert "token=secret" not in entry["url"]
    assert entry["url"] == "https://evil.example.net/"


def test_subdomain_of_authorized_host_in_scope(monkeypatch: Any) -> None:
    _policy(monkeypatch, ["example.com"])
    _conn, _raw = _send("https://api.example.com/")
    with pytest.raises(ValueError, match="outside the recorded authorized scope"):
        _send("https://notexample.com/")


def test_authorized_ip_matches_exactly_not_by_widening(monkeypatch: Any) -> None:
    _policy(monkeypatch, ["203.0.113.10"])
    _conn, _raw = _send("http://203.0.113.10/")
    with pytest.raises(ValueError, match="outside the recorded authorized scope"):
        _send("http://203.0.113.11/")


def test_empty_authorized_scope_denies_all_replay(monkeypatch: Any) -> None:
    _policy(monkeypatch, [])
    for url in ("https://example.com/", "https://api.target.io/"):
        with pytest.raises(ValueError, match="outside the recorded authorized scope"):
            _send(url)
    decisions = caido_api.get_scope_decisions()
    assert len(decisions["violations"]) == 2


def test_private_egress_opt_in_extends_scope_to_private_only(monkeypatch: Any) -> None:
    _policy(monkeypatch, [], allow_private_egress=True)
    _conn, _raw = _send("http://10.0.0.5/")
    with pytest.raises(ValueError, match="outside the recorded authorized scope"):
        _send("https://example.com/")


def test_no_policy_keeps_legacy_guard() -> None:
    """Without a recorded scope the blocklists still apply; public hosts pass."""
    _conn, _raw = _send("https://example.com/")
    with pytest.raises(ValueError, match="private-range"):
        _send("http://10.0.0.5/")
    decisions = caido_api.get_scope_decisions()
    assert decisions["admitted_hosts"] == {"example.com": 1}
    assert decisions["violations"][0]["rule"] == "private_range"


def test_fail_closed_policy_denies_everything(tmp_path: Path, monkeypatch: Any) -> None:
    """An untrusted/malformed policy mounts fail-closed: nothing is in scope."""
    policy_dir = tmp_path / "rw-policy"
    policy_dir.mkdir(mode=0o700)
    policy_dir.chmod(0o700)
    (policy_dir / "policy.json").write_text('{"version": 1, "scan_id": "scan-scope"}')
    monkeypatch.setenv("STRIX_RUN_ID", "scan-scope")
    monkeypatch.setenv("LYRASHIELD_EGRESS_POLICY", str(policy_dir / "policy.json"))
    with pytest.raises(ValueError):
        _send("https://app.example.com/")
    decisions = caido_api.get_scope_decisions()
    assert decisions["violations"]
    assert decisions["violations"][0]["rule"] == "outside_authorized_scope"


def test_violation_ledger_is_bounded(monkeypatch: Any) -> None:
    monkeypatch.setattr(caido_api, "_SCOPE_VIOLATION_LIMIT", 5)
    caido_api.clear_scope_decisions()
    for i in range(8):
        with contextlib.suppress(ValueError):
            _send(f"http://169.254.169.{i}/")
    decisions = caido_api.get_scope_decisions()
    assert len(decisions["violations"]) == 5
    assert decisions["dropped"] == 3


def test_clear_scope_decisions_resets_ledger(monkeypatch: Any) -> None:
    _policy(monkeypatch, ["app.example.com"])
    with pytest.raises(ValueError):
        _send("https://evil.example.net/")
    caido_api.clear_scope_decisions()
    decisions = caido_api.get_scope_decisions()
    assert decisions == {"violations": [], "dropped": 0, "admitted_hosts": {}}
