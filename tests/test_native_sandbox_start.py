"""Real disposable native admission and externally owned stopped-process cleanup."""

from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import docker
import pytest

from lyrashield.runtime import controller_authority, sandbox_start


pytest_plugins = ("tests.test_controller_backend",)


BASE = (
    "ghcr.io/ecryptoguru/lyrashield-sandbox@"
    "sha256:33ba62763f46440d2a86154a939331fa6cde4e0398536fb05deb314471c1dfce"
)
ROOT = Path(__file__).resolve().parents[1]


def ticket_for(
    runtime: dict[str, Any],
    clock: dict[str, Any],
    *,
    deadline_ns: int | None = None,
    execution_ns: int | None = None,
    argv: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    resource = {
        "schema": sandbox_start.RESOURCE_SCHEMA,
        "scanId": "scan",
        **runtime["connection"].binding,
        "containerId": "c" * 64,
        "imageDigest": runtime["authority"]["sandboxDigest"],
        "manifestChecksum": runtime["grant"]["manifestChecksum"],
        "runtimePolicyDigest": runtime["authority"]["runtimePolicyDigest"],
        "workspaceRoot": "/workspace",
    }
    resource = dict(runtime.get("nativeResource", resource))
    command = {"argv": argv or ["/usr/bin/true"], "cwd": "/workspace", "user": "pentester"}
    now = int(clock["monotonicNs"])
    ticket = {
        "schema": sandbox_start.TICKET_SCHEMA,
        "purpose": "sandbox-tool-start",
        **{key: value for key, value in resource.items() if key not in {"schema", "workspaceRoot"}},
        "guardId": "guard",
        "requestId": "request",
        "commandId": "command",
        "authorityChecksum": "sha256:" + "d" * 64,
        "actionChecksum": "sha256:" + "e" * 64,
        "resourceDescriptorChecksum": sandbox_start.checksum(sandbox_start.canonical(resource)),
        "runtimeAuthorityChecksum": sandbox_start.checksum(
            runtime["runtimeAuthority"]["raw"].encode()
        ),
        "command": command,
        "commandSha256": sandbox_start.checksum(sandbox_start.canonical(command)),
        "clock": {
            "id": "CLOCK_MONOTONIC",
            "bootId": clock["bootId"],
            "timeNamespace": clock["timeNamespace"],
            "issuedAtNs": str(now),
            "deadlineNs": str(deadline_ns or now + 5_000_000_000),
        },
        "executionDeadlineNs": str(execution_ns or now + 20_000_000_000),
    }
    return ticket, resource


@pytest.fixture
def native(runtime: dict[str, Any], tmp_path: Path) -> Any:
    """Read-only checked-source overlay on exact pinned base, no image rebuild."""
    client = docker.from_env(timeout=15)
    client.ping()
    context = tmp_path / "source"
    context.mkdir()
    volumes = {}
    for name in ("controller_authority.py", "sandbox_start.py"):
        source = context / name
        source.write_bytes((ROOT / "lyrashield/runtime" / name).read_bytes())
        volumes[str(source)] = {"bind": "/opt/lyrashield/" + name, "mode": "ro"}
    public = context / "controller-qualification-key.json"
    public.write_text(json.dumps(runtime_key(runtime)))
    volumes[str(public)] = {
        "bind": "/opt/lyrashield/controller-qualification-key.json",
        "mode": "ro",
    }
    container = client.containers.run(
        BASE,
        detach=True,
        name="lyra-native-fixture-" + uuid.uuid4().hex,
        network_mode="none",
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
        pids_limit=128,
        mem_limit="256m",
        tmpfs={
            "/etc/lyrashield": "rw,noexec,nosuid,uid=0,gid=0,mode=0755,size=1m",
            "/run/lyrashield/tickets": "rw,noexec,nosuid,uid=0,gid=0,mode=0755,size=1m",
            "/workspace": "rw,nosuid,uid=1000,gid=1000,mode=0700,size=1m",
        },
        volumes=volumes,
        platform="linux/amd64",
        user="pentester",
        entrypoint=["/app/.venv/bin/python", "-I", "-c", "import time;time.sleep(300)"],
    )
    try:
        runtime["authority"]["sandboxDigest"] = container.image.id
        runtime["runtimeAuthority"] = runtime["signAuthority"](runtime["authority"])
        resource = ticket_for(
            runtime, {"monotonicNs": "1", "bootId": "fixture", "timeNamespace": "fixture"}
        )[1]
        resource["containerId"] = container.id
        runtime["nativeResource"] = resource
        install_record(
            container,
            "/etc/lyrashield",
            "runtime-authority.json",
            json.dumps(runtime["runtimeAuthority"]).encode(),
        )
        install_record(
            container, "/etc/lyrashield", "sandbox-resource.json", sandbox_start.canonical(resource)
        )
        yield client, container
    finally:
        container.remove(force=True)
        client.close()


def runtime_key(_runtime: dict[str, Any]) -> dict[str, Any]:
    # Existing fixture has replaced only the consumer's pinned-key function.
    from lyrashield.runtime import controller_backend  # noqa: PLC0415

    return controller_backend._pinned_key()


def native_clock(container: Any) -> dict[str, Any]:
    result = container.exec_run(
        [
            "/app/.venv/bin/python",
            "-I",
            "-c",
            "from pathlib import Path;import time,json;print(json.dumps({"
            "'monotonicNs':str(time.clock_gettime_ns(time.CLOCK_MONOTONIC)),"
            "'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),"
            "'timeNamespace':str(Path('/proc/self/ns/time').readlink())}))",
        ],
        user="pentester",
    )
    assert result.exit_code == 0
    return json.loads(result.output)


def install_record(container: Any, target: str, name: str, data: bytes) -> None:
    # Fixture-only trusted controller writes public records into its root-owned
    # namespace; the admitted pentester process has no Docker access or write rights.
    result = container.exec_run(
        [
            "/app/.venv/bin/python",
            "-I",
            "-c",
            "from pathlib import Path;import os,base64,sys;p=Path(sys.argv[1])/sys.argv[2];"
            "f=p.open('xb');f.write(base64.b64decode(sys.argv[3]));f.flush();os.fsync(f.fileno());"
            "f.close();p.chmod(0o444)",
            target,
            name,
            base64.b64encode(data).decode(),
        ],
        user="root",
    )
    assert result.exit_code == 0, result.output


def install_ticket(container: Any, runtime: dict[str, Any], ticket: dict[str, Any]) -> None:
    install_record(
        container,
        "/run/lyrashield/tickets",
        "request.json",
        json.dumps(runtime["sign"](ticket)).encode(),
    )


def command() -> list[str]:
    return [
        "/app/.venv/bin/python",
        "-I",
        "/opt/lyrashield/sandbox_start.py",
        "--ticket",
        "/run/lyrashield/tickets/request.json",
    ]


def test_late_precreated_docker_exec_never_admits(runtime: dict[str, Any], native: Any) -> None:
    client, container = native
    clock = native_clock(container)
    now = int(clock["monotonicNs"])
    ticket, _ = ticket_for(runtime, clock, deadline_ns=now + 1_000_000_000)
    install_ticket(container, runtime, ticket)
    original = client.api.exec_create(container.id, command(), user="pentester")["Id"]
    time.sleep(1.2)
    stdout, stderr = client.api.exec_start(original, demux=True)
    assert stdout in (None, b"") and b"admission unavailable" in stderr
    assert sandbox_start.ADMISSION_PREFIX not in stderr
    assert client.api.exec_inspect(original)["ExitCode"] == 125


def test_native_admission_preserves_tool_output(runtime: dict[str, Any], native: Any) -> None:
    _, container = native
    ticket, _ = ticket_for(
        runtime,
        native_clock(container),
        argv=[
            "/app/.venv/bin/python",
            "-I",
            "-c",
            "import sys;sys.stdout.write('tool-out');sys.stderr.write('tool-err')",
        ],
    )
    install_ticket(container, runtime, ticket)
    result = container.exec_run(command(), user="pentester", demux=True)
    stdout, stderr = result.output
    frame, tool_stderr = stderr.split(b"\n", 1)
    assert result.exit_code == 0 and stdout == b"tool-out" and tool_stderr == b"tool-err"
    assert frame.startswith(sandbox_start.ADMISSION_PREFIX)
    receipt = json.loads(frame[len(sandbox_start.ADMISSION_PREFIX) :])
    assert receipt["requestId"] == ticket["requestId"]
    assert int(receipt["admittedAtNs"]) < int(ticket["clock"]["deadlineNs"])


def test_protected_whole_sandbox_watchdog_terminates_stopped_tool(
    runtime: dict[str, Any], native: Any
) -> None:
    client, container = native
    clock = native_clock(container)
    now = int(clock["monotonicNs"])
    ticket, _ = ticket_for(
        runtime,
        clock,
        deadline_ns=now + 2_000_000_000,
        execution_ns=now + 3_000_000_000,
        argv=[
            "/app/.venv/bin/python",
            "-I",
            "-c",
            "import os,signal;os.write(1,b'TOOL_STOPPED\\n');"
            "os.kill(os.getpid(),signal.SIGSTOP);os.write(1,b'LATE_WORK')",
        ],
    )
    install_ticket(container, runtime, ticket)
    before_read = time.monotonic()
    current = int(native_clock(container)["monotonicNs"])
    remaining = (int(ticket["executionDeadlineNs"]) - current) / 1_000_000_000
    # Mapping from the pre-read host sample conservatively subtracts transport
    # latency. The production owner uses the qualified shared Linux clock itself.
    local_deadline = before_read + remaining
    watchdog = threading.Timer(max(0.0, local_deadline - time.monotonic()), container.kill)
    watchdog.start()
    original = client.api.exec_create(container.id, command(), user="pentester")["Id"]
    chunks = []
    paused = threading.Event()

    def consume() -> None:
        for stdout, stderr in client.api.exec_start(original, stream=True, demux=True):
            chunks.append((stdout or b"") + (stderr or b""))
            if b"TOOL_STOPPED" in b"".join(chunks):
                paused.set()

    # Separately owned host control remains runnable when sandbox work is stopped.
    reader = threading.Thread(target=consume)
    reader.start()
    try:
        assert paused.wait(2)
        reader.join(6)
        watchdog.join(6)
        container.reload()
        assert not reader.is_alive() and container.status == "exited"
        assert not client.api.exec_inspect(original)["Running"]
        assert b"LATE_WORK" not in b"".join(chunks)
    finally:
        watchdog.cancel()
        container.reload()
        if container.status != "exited":
            container.kill()
        reader.join(6)


@pytest.mark.parametrize(
    "field,value",
    [
        ("operationId", "other"),
        ("containerId", "other"),
        ("commandSha256", "sha256:" + "f" * 64),
        ("runtimePolicyDigest", "sha256:" + "f" * 64),
        ("clock.bootId", "other-boot"),
        ("clock.timeNamespace", "other-namespace"),
        ("clock.deadlineNs", "10000001001"),
        ("executionDeadlineNs", "300000001001"),
    ],
)
def test_ticket_replay_cannot_rebind_original_resource(
    runtime: dict[str, Any], monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    monkeypatch.setattr(controller_authority, "_pinned_key", lambda: runtime_key(runtime))
    read_text = Path.read_text
    readlink = Path.readlink
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *args, **kwargs: (
            "fixture"
            if str(path) == "/proc/sys/kernel/random/boot_id"
            else read_text(path, *args, **kwargs)
        ),
    )
    monkeypatch.setattr(
        Path,
        "readlink",
        lambda path: Path("fixture") if str(path) == "/proc/self/ns/time" else readlink(path),
    )
    ticket, resource = ticket_for(
        runtime, {"monotonicNs": "1000", "bootId": "fixture", "timeNamespace": "fixture"}
    )
    if field.startswith("clock."):
        ticket["clock"][field.split(".")[1]] = value
    else:
        ticket[field] = value
    with pytest.raises(controller_authority.ControllerUnavailableError):
        sandbox_start.validate_start_ticket(
            runtime["sign"](ticket),
            runtime["runtimeAuthority"],
            resource,
            sandbox_start.canonical(resource),
        )
