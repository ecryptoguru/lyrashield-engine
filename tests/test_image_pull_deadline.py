"""Docker image pulls must not outlive the shared scan allowance."""

from __future__ import annotations

import importlib
import json
import multiprocessing
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import Mock, call

import pytest

from lyrashield.interface.image_pull import _run_bounded_docker_operation, _stop_docker_worker
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError


# Importing the CLI/TUI in a spawned worker is setup for the stage-specific
# checks below. Bound that separately from the operation's much shorter budget.
# The real-clock test also covers terminating a worker during startup.
_WORKER_STARTUP_TIMEOUT_SECONDS = 10.0


def _blocked_docker_worker(sender: Any, _image: str, _expected_digest: str) -> None:
    sender.send(("pulling", None))
    time.sleep(2)
    sender.send(("complete", True))


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


def test_worker_import_startup_consumes_the_real_deadline(tmp_path, monkeypatch) -> None:
    importing = tmp_path / "importing"
    entered = tmp_path / "entered"
    module = tmp_path / "slow_docker_worker_import.py"
    module.write_text(
        "import multiprocessing, time\n"
        "from pathlib import Path\n"
        "if multiprocessing.current_process().name != 'MainProcess':\n"
        f"    Path({str(importing)!r}).touch()\n"
        "    time.sleep(12)\n"
        "def worker(sender, image, digest):\n"
        f"    Path({str(entered)!r}).touch()\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    worker_module = importlib.import_module(module.stem)
    active_before = {process.pid for process in multiprocessing.active_children()}
    started = time.monotonic()

    with pytest.raises(RunDeadlineExceededError):
        _run_bounded_docker_operation(
            "test-image", "", RunDeadline.start(0.5), worker=worker_module.worker
        )

    assert time.monotonic() - started < 1.5
    assert importing.exists(), "the worker must reach the deliberately blocked import"
    assert not entered.exists(), "the deadline must stop imports before entering the worker"
    assert {process.pid for process in multiprocessing.active_children()} <= active_before


def test_completed_worker_wait_is_bounded_before_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    receiver = Mock()
    receiver.poll.return_value = True
    receiver.recv.return_value = ("complete", False)
    process = Mock()
    process.pid = 4321
    process.is_alive.side_effect = [True, True, False, False]
    context = Mock()
    context.Pipe.return_value = (receiver, Mock())
    context.Process.return_value = process
    monkeypatch.setattr(multiprocessing, "get_context", lambda _method: context)

    assert not _run_bounded_docker_operation("test-image", "", RunDeadline.start(3600))

    assert process.join.call_args_list == [
        call(timeout=1.0),
        call(timeout=0.2),
        call(timeout=0),
    ]
    process.terminate.assert_called_once()
    process.close.assert_called_once()


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
    active_before = {process.pid for process in multiprocessing.active_children()}
    started = time.monotonic()
    operation_started: float | None = None

    def operation_clock() -> float:
        nonlocal operation_started
        now = time.monotonic()
        if reached.is_set():
            if operation_started is None:
                operation_started = now
            return now - operation_started
        # Never let broken setup hang the test. A worker that fails to reach
        # the stage is stopped and then fails the reachability assertion.
        return now - started if now - started >= _WORKER_STARTUP_TIMEOUT_SECONDS else 0.0

    deadline = RunDeadline.start(0.5, clock=operation_clock)

    try:
        with pytest.raises(RunDeadlineExceededError):
            _run_bounded_docker_operation("test-image", "", deadline)
    finally:
        server.shutdown()
        server.server_close()

    assert reached.is_set(), (
        f"fake Docker daemon did not reach {stage} during bounded worker startup"
    )
    assert operation_started is not None
    assert time.monotonic() - operation_started < 1.5
    assert time.monotonic() - started < _WORKER_STARTUP_TIMEOUT_SECONDS + 1.5
    assert {process.pid for process in multiprocessing.active_children()} <= active_before


def test_worker_that_survives_kill_emits_a_bounded_cleanup_failure() -> None:
    process = _UnreapableProcess()
    started = time.monotonic()

    with pytest.raises(RuntimeError, match="4321"):
        _stop_docker_worker(process)  # type: ignore[arg-type]

    assert time.monotonic() - started < 0.1
    assert process.calls == ["terminate", "join:0.2", "kill", "join:0.2"]
