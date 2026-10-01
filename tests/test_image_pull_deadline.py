"""Docker image pulls must not outlive the shared scan allowance."""

from __future__ import annotations

import json
import multiprocessing
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from lyrashield.interface.image_pull import _run_bounded_docker_operation, _stop_docker_worker
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError


def _blocked_docker_worker(sender: Any, _image: str, _expected_digest: str) -> None:
    sender.send(("pulling", None))
    time.sleep(2)
    sender.send(("complete", True))


def _slow_cleanup_worker(sender: Any, _image: str, _expected_digest: str) -> None:
    sender.send(("complete", False))
    time.sleep(2)


def _docker_daemon_handler(stage: str, reached: threading.Event) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def _json(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path == "/version":
                if stage == "connection":
                    reached.set()
                    time.sleep(12)
                    return
                self._json(200, {"ApiVersion": "1.41", "Version": "test"})
                return
            if stage in {"inspect", "silent_pull"} and "/images/test-image/json" in self.path:
                if stage == "inspect":
                    reached.set()
                    time.sleep(12)
                    return
                self._json(404, {"message": "No such image: test-image"})
                return
            if "/_ping" in self.path:
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")
                return
            self._json(404, {"message": "not found"})

        def do_POST(self) -> None:
            if stage == "silent_pull" and "/images/create" in self.path:
                reached.set()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                # Docker-py's line iterator waits for the body while the fake
                # daemon keeps the response open, modeling a silent pull.
                self.send_header("Content-Length", "4096")
                self.end_headers()
                self.wfile.flush()
                time.sleep(12)
                return
            self._json(404, {"message": "not found"})

    return Handler


def _start_fake_docker_daemon(stage: str, reached: threading.Event) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _docker_daemon_handler(stage, reached))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class _UnreapableProcess:
    pid = 4321

    def __init__(self) -> None:
        self.calls: list[str] = []

    def is_alive(self) -> bool:
        return True

    def terminate(self) -> None:
        self.calls.append("terminate")

    def kill(self) -> None:
        self.calls.append("kill")

    def join(self, *, timeout: float) -> None:
        self.calls.append(f"join:{timeout}")

    def close(self) -> None:
        self.calls.append("close")


def test_silent_docker_operation_is_terminated_and_reaped_at_deadline() -> None:
    deadline = RunDeadline.start(0.5)
    active_before = {process.pid for process in multiprocessing.active_children()}
    started = time.monotonic()

    with pytest.raises(RunDeadlineExceededError):
        _run_bounded_docker_operation("test-image", "", deadline, worker=_blocked_docker_worker)

    assert time.monotonic() - started < 1.5
    assert {process.pid for process in multiprocessing.active_children()} <= active_before


def test_slow_child_cleanup_cannot_overrun_the_scan_deadline() -> None:
    deadline = RunDeadline.start(0.2)
    active_before = {process.pid for process in multiprocessing.active_children()}
    started = time.monotonic()

    with pytest.raises(RunDeadlineExceededError):
        _run_bounded_docker_operation("test-image", "", deadline, worker=_slow_cleanup_worker)

    assert time.monotonic() - started < 1.0
    assert {process.pid for process in multiprocessing.active_children()} <= active_before


@pytest.mark.parametrize("stage", ["connection", "inspect", "silent_pull"])
def test_docker_connection_inspect_and_pull_are_deadline_bound(
    stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached = threading.Event()
    server = _start_fake_docker_daemon(stage, reached)
    monkeypatch.setenv("DOCKER_HOST", f"tcp://127.0.0.1:{server.server_port}")
    monkeypatch.delenv("DOCKER_TLS_VERIFY", raising=False)
    monkeypatch.delenv("DOCKER_CERT_PATH", raising=False)
    monkeypatch.delenv("DOCKER_API_VERSION", raising=False)
    # Allow spawn/import overhead while leaving the fake daemon blocked far
    # beyond the supervised deadline.
    # A spawned worker imports the engine before reaching the daemon. Keep the
    # deadline comfortably above that startup cost while the fake operation
    # itself remains blocked well beyond the allowance.
    deadline = RunDeadline.start(5.0)
    active_before = {process.pid for process in multiprocessing.active_children()}
    started = time.monotonic()

    try:
        with pytest.raises(RunDeadlineExceededError):
            _run_bounded_docker_operation("test-image", "", deadline)
    finally:
        server.shutdown()
        server.server_close()

    assert reached.wait(timeout=0.1), f"fake Docker daemon did not reach {stage}"
    assert time.monotonic() - started < 6.5
    assert {process.pid for process in multiprocessing.active_children()} <= active_before


def test_worker_that_survives_kill_emits_a_bounded_cleanup_failure() -> None:
    process = _UnreapableProcess()
    started = time.monotonic()

    with pytest.raises(RuntimeError, match="4321"):
        _stop_docker_worker(process)  # type: ignore[arg-type]

    assert time.monotonic() - started < 0.1
    assert process.calls == ["terminate", "join:0.2", "kill", "join:0.2"]
