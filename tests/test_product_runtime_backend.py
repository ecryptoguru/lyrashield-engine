"""LyraShield scans must construct the LyraShield Docker adapter."""

from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from agents.sandbox.errors import ExecNonZeroError
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import DockerSandboxSession
from agents.sandbox.types import User

from lyrashield.runtime import backends


def test_product_runtime_selects_the_product_docker_backend() -> None:
    assert backends.get_backend("docker") is backends.docker_backend


@pytest.mark.asyncio
async def test_docker_backend_adds_pentester_to_sdk_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    class Session:
        async def start(self) -> None:
            return None

    class Client:
        def __init__(self, _transport: Any) -> None:
            self.strix_bind_mounts: list[dict[str, Any]] = []

        async def create(self, *, options: Any, manifest: Manifest) -> Session:
            seen["manifest"] = manifest
            seen["options"] = options
            return Session()

    monkeypatch.setattr("docker.from_env", MagicMock(return_value=object()))
    monkeypatch.setattr("lyrashield.runtime.docker_client.StrixDockerSandboxClient", Client)
    monkeypatch.setattr(
        "lyrashield.runtime.docker_client.assert_sdk_docker_compatibility", lambda: None
    )
    manifest = Manifest()

    await backends.docker_backend(image="test", manifest=manifest, exposed_ports=())

    assert seen["manifest"].users == [User(name="pentester")]
    assert manifest.users == []  # Preserve the caller-owned manifest.


@pytest_asyncio.fixture
async def sdk_session(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Exercise the pinned SDK session logic with only Docker transport mocked."""
    container = MagicMock(id="identity-test", status="running")
    api = container.client.api
    calls: list[dict[str, Any]] = []
    execs: dict[str, dict[str, Any]] = {}
    pid_paths: set[str] = set()
    created_pid_paths: set[str] = set()
    pid_directory = SimpleNamespace(owner="pentester", mode=0o711)

    def exec_run(**kwargs: Any) -> Any:
        calls.append(kwargs)
        command = kwargs["cmd"]
        if 'pid_user="$2"' in " ".join(command):
            pid_paths.add(command[-2])
            created_pid_paths.add(command[-2])
        if command[:1] == ["rm"] and command[-1] in pid_paths:
            user = kwargs.get("user") or "root"
            owns_directory = user == pid_directory.owner
            if not owns_directory and user != "root" and not pid_directory.mode & 0o002:
                return SimpleNamespace(exit_code=1, output=(b"", b"Permission denied"))
            pid_paths.remove(command[-1])
        if command[:1] == ["ls"]:
            return SimpleNamespace(exit_code=0, output=(b"", b""))
        if command[:1] == ["useradd"] and command[-1] == "pentester":
            return SimpleNamespace(exit_code=9, output=(b"", b"account is image-managed"))
        return SimpleNamespace(exit_code=0, output=(b"1000\n", b""))

    def exec_create(_container_id: str, cmd: list[str], **kwargs: Any) -> dict[str, str]:
        record = {"cmd": cmd, **kwargs}
        calls.append(record)
        exec_id = str(len(execs))
        execs[exec_id] = record
        return {"Id": exec_id}

    api.exec_create.side_effect = exec_create
    api.exec_inspect.side_effect = lambda _exec_id: {"Running": False, "ExitCode": 0}
    container.exec_run.side_effect = exec_run
    sock = MagicMock()
    sock.recv.return_value = b""
    monkeypatch.setattr(
        DockerSandboxSession,
        "_start_exec_socket",
        staticmethod(lambda **_kwargs: SimpleNamespace(sock=sock, raw_sock=sock, close=sock.close)),
    )
    monkeypatch.setattr(DockerSandboxSession, "_ensure_runtime_helpers", AsyncMock())
    monkeypatch.setattr(
        DockerSandboxSession, "_validate_path_access", AsyncMock(side_effect=lambda path, **_: path)
    )
    monkeypatch.setattr(
        "lyrashield.runtime.docker_client.StrixDockerSandboxClient._create_container",
        AsyncMock(return_value=container),
    )
    monkeypatch.setattr("docker.from_env", MagicMock)
    manifest = Manifest()
    client, session = await backends.docker_backend(
        image="test", manifest=manifest, exposed_ports=()
    )
    yield SimpleNamespace(
        client=client,
        session=session,
        calls=calls,
        manifest=manifest,
        pid_paths=pid_paths,
        created_pid_paths=created_pid_paths,
        pid_directory=pid_directory,
    )
    await session.pty_terminate_all()


@pytest.mark.asyncio
async def test_sdk_start_bootstraps_image_owned_pentester(sdk_session: Any) -> None:
    assert sdk_session.session.state.manifest.users == [User(name="pentester")]
    assert sdk_session.manifest.users == []
    assert any(call["cmd"] == ["id", "-u", "pentester"] for call in sdk_session.calls)
    assert not any(call["cmd"][:1] == ["useradd"] for call in sdk_session.calls)


@pytest.mark.parametrize("uid", [b"0\n", b"not-a-uid\n", b""])
@pytest.mark.asyncio
async def test_image_owned_pentester_must_have_nonroot_uid(sdk_session: Any, uid: bytes) -> None:
    inner = sdk_session.session._inner
    inner._container.exec_run.side_effect = None
    inner._container.exec_run.return_value = SimpleNamespace(exit_code=0, output=(uid, b""))
    with pytest.raises(RuntimeError, match="nonzero UID"):
        await inner._exec_checked_nonzero(
            "useradd", "-U", "-M", "-s", "/usr/sbin/nologin", "pentester"
        )


@pytest.mark.asyncio
async def test_missing_image_owned_account_fails_sdk_start(sdk_session: Any) -> None:
    inner = sdk_session.session._inner
    inner._container.exec_run.side_effect = None
    inner._container.exec_run.return_value = SimpleNamespace(exit_code=1, output=(b"", b"missing"))
    with pytest.raises(ExecNonZeroError):
        await inner._exec_checked_nonzero(
            "useradd", "-U", "-M", "-s", "/usr/sbin/nologin", "pentester"
        )


@pytest.mark.asyncio
async def test_sdk_commands_and_file_operations_use_pentester(sdk_session: Any) -> None:
    session = sdk_session.session
    sdk_session.calls.clear()
    await session.exec("id", "-u", shell=False)
    await session.read(Path("/workspace/read.txt"))
    await session.write(Path("/workspace/write.txt"), io.BytesIO(b"test"))
    await session.mkdir(Path("/workspace/dir"))
    await session.rm(Path("/workspace/write.txt"))
    await session.ls(Path("/workspace"))
    await session.pty_exec_start("id", "-u", shell=False, tty=True, yield_time_s=0.25)
    assert any(
        call.get("stdin") is True and call.get("user") == "pentester" for call in sdk_session.calls
    )
    assert all(
        call.get("user") == "pentester"
        or 'pid_user="$2"' in " ".join(call.get("cmd", []))
        or (
            call.get("cmd", [])[:3] == ["rm", "-f", "--"]
            and call["cmd"][-1] in sdk_session.created_pid_paths
        )
        for call in sdk_session.calls
    )


@pytest.mark.parametrize("user", ["root", "0", "0:0", "", "other", User(name="root")])
@pytest.mark.parametrize(
    "operation", ["exec", "pty_exec_start", "read", "write", "mkdir", "rm", "ls"]
)
@pytest.mark.asyncio
async def test_product_session_rejects_alternate_identity(
    sdk_session: Any, user: Any, operation: str
) -> None:
    before = len(sdk_session.calls)
    args: tuple[Any, ...] = (Path("/workspace/test"),)
    if operation == "write":
        args += (io.BytesIO(b"test"),)
    with pytest.raises(ValueError, match="must run as pentester"):
        await getattr(sdk_session.session, operation)(*args, user=user)
    assert len(sdk_session.calls) == before


@pytest.mark.asyncio
async def test_sdk_pty_cleanup_never_uses_root(sdk_session: Any) -> None:
    inner = sdk_session.session._inner
    pid_path = inner._ARCHIVE_STAGING_DIR / "0123456789abcdef0123456789abcdef_pty.pid"
    await inner._prepare_user_pty_pid_path(path=pid_path, user="pentester")
    sdk_session.calls.clear()
    await inner._kill_pty_pid_path(pid_path)
    assert [call.get("user") for call in sdk_session.calls] == ["pentester", "pentester"]
    assert not sdk_session.pid_paths


@pytest.mark.asyncio
async def test_pty_cleanup_parent_replacement_cannot_escalate(
    sdk_session: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """If the staging path is replaced, cleanup still cannot unlink as root."""
    inner = sdk_session.session._inner
    pid_path = inner._ARCHIVE_STAGING_DIR / "0123456789abcdef0123456789abcdef_pty.pid"
    sdk_session.pid_paths.add(str(pid_path))
    sdk_session.pid_directory.owner = "root"  # Model a raced path resolving to root-owned storage.

    await inner._rm_best_effort(pid_path)

    assert sdk_session.calls[-1]["user"] == "pentester"
    assert str(pid_path) in sdk_session.pid_paths
    assert "Failed to remove SDK PTY PID file" in caplog.text


@pytest.mark.parametrize(
    "path",
    [
        Path("/workspace/0123456789abcdef0123456789abcdef_pty.pid"),
        Path("/tmp/sandbox-docker-archive/nested/0123456789abcdef0123456789abcdef_pty.pid"),  # noqa: S108
        Path("/tmp/sandbox-docker-archive/../0123456789abcdef0123456789abcdef_pty.pid"),  # noqa: S108
        Path("/tmp/sandbox-docker-archive/not-a-uuid_pty.pid"),  # noqa: S108
        Path("/tmp/sandbox-docker-archive/0123456789ABCDEF0123456789ABCDEF_pty.pid"),  # noqa: S108
    ],
)
@pytest.mark.asyncio
async def test_privileged_pty_unlink_rejects_non_sdk_paths(sdk_session: Any, path: Path) -> None:
    sdk_session.calls.clear()
    with pytest.raises(ValueError, match="Invalid SDK PTY PID cleanup path"):
        await sdk_session.session._inner._rm_best_effort(path)
    assert not sdk_session.calls
