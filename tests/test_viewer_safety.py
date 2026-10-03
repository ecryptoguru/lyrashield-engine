"""Regression tests for untrusted local-viewer requests and run artifacts."""

from __future__ import annotations

import http.client
import json
import socket
import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlsplit

import pytest

from lyrashield.interface.viewer import server as viewer_server
from lyrashield.interface.viewer.server import build_runs_payload, resolve_run_dir, serve
from lyrashield.interface.viewer.transcript import (
    build_run_state,
    read_report_markdown,
    read_vulnerabilities,
)


if TYPE_CHECKING:
    from pathlib import Path


def _make_run(
    base: Path,
    name: str,
    *,
    status: str = "running",
    end_time: str | None = None,
) -> Path:
    run_dir = base / name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": name, "status": status, "end_time": end_time}),
        encoding="utf-8",
    )
    return run_dir


def _start_viewer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_dir: Path,
    *,
    host: str = "127.0.0.1",
):
    assets = tmp_path / "bundle"
    assets.mkdir(exist_ok=True)
    (assets / "index.html").write_text("<!doctype html><div id='root'></div>", encoding="utf-8")
    monkeypatch.setattr(viewer_server, "bundle_dir", lambda: assets)
    return serve(run_dir, host=host, open_browser=False)


def _session_cookie(url: str, token: str) -> str:
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=2)
    try:
        connection.request("GET", "/?" + urlencode({"token": token}))
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        cookie = response.getheader("Set-Cookie")
        assert cookie is not None
        return cookie.split(";", 1)[0]
    finally:
        connection.close()


def _post_raw(port: int, cookie: str, *, length: int | str, initial_body: bytes = b"") -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(
            (
                "POST /api/agents/steer HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Cookie: {cookie}\r\n"
                f"Content-Length: {length}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            + initial_body
        )
        return client.recv(4096)


def test_runs_payload_ignores_symlinked_run_directories_and_records(tmp_path: Path) -> None:
    base = tmp_path / "runs"
    base.mkdir()
    safe = _make_run(base, "safe", status="completed", end_time="2026-10-02T00:00:00Z")
    outside = _make_run(tmp_path, "outside", status="completed", end_time="2026-10-02T00:00:00Z")
    (base / "linked-directory").symlink_to(outside, target_is_directory=True)

    linked_record = _make_run(
        base, "linked-record", status="completed", end_time="2026-10-02T00:00:00Z"
    )
    (linked_record / "run.json").unlink()
    (linked_record / "run.json").symlink_to(outside / "run.json")

    payload = build_runs_payload(base, verified=True)

    assert [entry["name"] for entry in payload["runs"]] == ["safe"]
    assert payload["count"] == 1
    assert safe.is_dir()


def test_resolve_run_dir_rejects_symlinked_run_record(tmp_path: Path) -> None:
    base = tmp_path / "runs"
    base.mkdir()
    run_dir = _make_run(base, "linked", status="completed", end_time="2026-10-02T00:00:00Z")
    outside = tmp_path / "private-run.json"
    outside.write_text(json.dumps({"run_name": "private"}), encoding="utf-8")
    (run_dir / "run.json").unlink()
    (run_dir / "run.json").symlink_to(outside)

    assert resolve_run_dir(base, "linked", run_dir) is None


def test_resolve_run_dir_rejects_symlinked_default_run(tmp_path: Path) -> None:
    base = tmp_path / "runs"
    base.mkdir()
    outside = _make_run(tmp_path, "outside-default", status="completed")
    default_run = base / "linked-default"
    default_run.symlink_to(outside, target_is_directory=True)

    assert resolve_run_dir(base, None, default_run) is None


@pytest.mark.parametrize("artifact", ["vulnerabilities.json", "penetration_test_report.md"])
def test_run_artifact_readers_reject_symlinks(tmp_path: Path, artifact: str) -> None:
    run_dir = _make_run(
        tmp_path,
        "linked-artifact",
        status="completed",
        end_time="2026-10-02T00:00:00Z",
    )
    outside = tmp_path / f"outside-{artifact}"
    outside.write_text(
        "[]" if artifact == "vulnerabilities.json" else "private report",
        encoding="utf-8",
    )
    (run_dir / artifact).symlink_to(outside)

    with pytest.raises(OSError):
        if artifact == "vulnerabilities.json":
            read_vulnerabilities(run_dir)
        else:
            read_report_markdown(run_dir)


@pytest.mark.parametrize("linked_component", [".state", "agents.json", "agents.db"])
def test_transcript_rejects_symlinked_state_inputs(tmp_path: Path, linked_component: str) -> None:
    run_dir = _make_run(tmp_path, "linked-transcript", status="completed")
    state_dir = run_dir / ".state"
    outside_state = tmp_path / "outside-state"
    outside_state.mkdir()
    outside_agents = outside_state / "agents.json"
    outside_agents.write_text(
        json.dumps(
            {
                "statuses": {"root": "completed"},
                "names": {"root": "OUTSIDE-RUN-SECRET"},
                "parent_of": {"root": None},
            }
        ),
        encoding="utf-8",
    )
    if linked_component == ".state":
        state_dir.symlink_to(outside_state, target_is_directory=True)
    else:
        state_dir.mkdir()
        agents = state_dir / "agents.json"
        if linked_component == "agents.json":
            agents.symlink_to(outside_agents)
        else:
            agents.write_bytes(outside_agents.read_bytes())
            outside_db = outside_state / "agents.db"
            outside_db.write_text("outside database", encoding="utf-8")
            (state_dir / "agents.db").symlink_to(outside_db)

    with pytest.raises(OSError):
        build_run_state(run_dir)


def test_default_symlink_run_is_not_served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = _make_run(tmp_path, "outside-default-api", status="completed")
    default_run = tmp_path / "linked-default-api"
    default_run.symlink_to(outside, target_is_directory=True)
    httpd, url, token = _start_viewer(tmp_path, monkeypatch, default_run)
    try:
        cookie = _session_cookie(url, token)
        parts = urlsplit(url)
        connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=2)
        try:
            connection.request("GET", "/api/run", headers={"Cookie": cookie})
            response = connection.getresponse()
            assert response.status == 404
            response.read()
        finally:
            connection.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ipv6_loopback_viewer_binds_and_emits_bracketed_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 is unavailable")
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is unavailable")

    run_dir = _make_run(tmp_path, "ipv6")
    httpd, url, _token = _start_viewer(tmp_path, monkeypatch, run_dir, host="::1")
    try:
        assert url.startswith("http://[::1]:")
        connection = http.client.HTTPConnection("::1", httpd.server_address[1], timeout=2)
        try:
            connection.request("GET", "/")
            assert connection.getresponse().status == 200
        finally:
            connection.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("length", [65537, -1, "not-a-number"])
def test_post_rejects_invalid_or_oversized_content_length_without_reading_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: int | str
) -> None:
    run_dir = _make_run(tmp_path, "post-limit")
    httpd, url, token = _start_viewer(tmp_path, monkeypatch, run_dir)
    try:
        cookie = _session_cookie(url, token)
        started = time.monotonic()
        response = _post_raw(httpd.server_address[1], cookie, length=length)  # type: ignore[arg-type]
        expected = b"HTTP/1.0 413" if length == 65537 else b"HTTP/1.0 400"
        assert response.startswith(expected)
        assert time.monotonic() - started < 1.0
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_post_body_timeout_returns_408_and_releases_request_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(viewer_server, "POST_BODY_TIMEOUT_SECONDS", 0.1, raising=False)
    run_dir = _make_run(tmp_path, "post-timeout")
    httpd, url, token = _start_viewer(tmp_path, monkeypatch, run_dir)
    try:
        cookie = _session_cookie(url, token)
        started = time.monotonic()
        response = _post_raw(httpd.server_address[1], cookie, length=2, initial_body=b"{")
        assert response.startswith(b"HTTP/1.0 408")
        assert time.monotonic() - started < 1.0
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_slow_request_headers_are_closed_within_the_header_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(viewer_server, "REQUEST_HEADER_TIMEOUT_SECONDS", 0.1, raising=False)
    run_dir = _make_run(tmp_path, "slow-headers")
    httpd, _url, _token = _start_viewer(tmp_path, monkeypatch, run_dir)
    try:
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=2) as client:
            client.sendall(
                (
                    "POST /api/agents/steer HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{httpd.server_address[1]}\r\n"
                ).encode("ascii")
            )
            client.settimeout(1)
            assert client.recv(4096) == b""
        assert time.monotonic() - started < 1.0
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("body", [b"[]", b"{", b"\xff"])
def test_post_rejects_invalid_or_non_object_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    run_dir = _make_run(tmp_path, "post-json")
    httpd, url, token = _start_viewer(tmp_path, monkeypatch, run_dir)
    try:
        cookie = _session_cookie(url, token)
        response = _post_raw(httpd.server_address[1], cookie, length=len(body), initial_body=body)
        assert response.startswith(b"HTTP/1.0 400")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_missing_report_is_empty_and_unreadable_report_raises(tmp_path: Path) -> None:
    live = _make_run(tmp_path, "live")
    assert read_report_markdown(live) == ""

    finished = _make_run(
        tmp_path,
        "finished",
        status="completed",
        end_time="2026-10-02T00:00:00Z",
    )
    assert read_report_markdown(finished) == ""


def test_unreadable_report_is_not_returned_as_an_empty_success(tmp_path: Path) -> None:
    run_dir = _make_run(
        tmp_path,
        "unreadable",
        status="completed",
        end_time="2026-10-02T00:00:00Z",
    )
    (run_dir / "penetration_test_report.md").mkdir()

    with pytest.raises(IsADirectoryError):
        read_report_markdown(run_dir)


def test_report_endpoint_fails_when_report_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(
        tmp_path,
        "unreadable-endpoint",
        status="completed",
        end_time="2026-10-02T00:00:00Z",
    )
    (run_dir / "penetration_test_report.md").mkdir()
    httpd, url, token = _start_viewer(tmp_path, monkeypatch, run_dir)
    try:
        cookie = _session_cookie(url, token)
        parts = urlsplit(url)
        connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=2)
        try:
            connection.request("GET", "/api/report", headers={"Cookie": cookie})
            response = connection.getresponse()
            assert response.status == 500
            response.read()
        finally:
            connection.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
