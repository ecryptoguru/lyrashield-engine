"""Attach-only native SDK sandbox over the private, scan-bound controller RPC.

This adapter cannot create containers or install grants. The controller owns
images, identities, mounts, network policy and durable command idempotency.
An unavailable acknowledgement holds the original command and closes admission
to new tool mutations; it is never retried under a fresh operation identity.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import math
import os
import shlex
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from agents.sandbox.manifest import Manifest
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.sandbox.session.pty_types import PtyExecUpdate
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.session.sandbox_session_state import SandboxSessionState
from agents.sandbox.snapshot import NoopSnapshot
from agents.sandbox.types import ExecResult, ExposedPortEndpoint, User

from lyrashield.runtime.controller_authority import (
    _REQUIRED_CAPABILITIES as _NATIVE_REQUIRED_CAPABILITIES,
)
from lyrashield.runtime.controller_authority import (
    ControllerUnavailableError,
    _boolean,
    _bytes,
    _integer,
    _pinned_key,
    _reject,
    _text,
    _tool_origin,
)
from lyrashield.runtime.controller_authority import (
    verify_installed_grant as _verify_installed_grant,
)
from lyrashield.runtime.controller_authority import (
    verify_runtime_authority as _verify_runtime_authority,
)


MAX_FILE_BYTES = 8 * 1024 * 1024
_REQUIRED_CAPABILITIES = _NATIVE_REQUIRED_CAPABILITIES
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 24 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300.0
GRANT_SCHEMA = "lyrashield-runtime-sandbox-grant/v1"


class ControllerOperationUnknownError(ControllerUnavailableError):
    """The original operation may have executed and must be reconciled."""

    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        super().__init__(f"Controller operation {request_id} requires reconciliation")


def manifest_checksum(manifest: Manifest) -> str:
    data = json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ControllerConnection:
    url: str
    token: str = field(repr=False)
    attempt_id: str
    operation_id: str
    authority_epoch_id: str
    sandbox_handle: str
    runtime_authority: Any = field(default=None, repr=False)

    @property
    def binding(self) -> dict[str, str]:
        return {
            "attemptId": self.attempt_id,
            "operationId": self.operation_id,
            "authorityEpochId": self.authority_epoch_id,
            "sandboxHandle": self.sandbox_handle,
        }

    @classmethod
    def from_environment(cls) -> ControllerConnection:
        names = (
            "TOOL_URL",
            "TOOL_TOKEN",
            "ATTEMPT_ID",
            "OPERATION_ID",
            "AUTHORITY_EPOCH_ID",
            "SANDBOX_HANDLE",
        )
        values = [_text(os.environ.get(f"LYRASHIELD_SUPERVISOR_{name}")) for name in names]
        # HTTP is confined to explicitly constructed disposable-test clients.
        parsed = urlsplit(values[0])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            _reject()
        if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            _reject()
        for value in values[2:]:
            if any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for c in value
            ):
                _reject()
        envelope = json.loads(
            _text(os.environ.get("LYRASHIELD_SUPERVISOR_RUNTIME_AUTHORITY"), max_length=128 * 1024)
        )
        authority = verify_runtime_authority(envelope, values[4])
        origin = _tool_origin(values[0].rstrip("/"))
        if origin != authority["toolChannel"]["origin"]:
            _reject()
        if not values[1].isascii() or any(c in values[1] for c in "\r\n"):
            _reject()
        values[0] = origin
        return cls(
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            values[5],
            runtime_authority=envelope,
        )


def verify_runtime_authority(runtime_authority: Any, epoch_id: str) -> dict[str, Any]:
    return _verify_runtime_authority(
        runtime_authority, epoch_id, key=_pinned_key(), now=int(datetime.now(UTC).timestamp())
    )


def verify_installed_grant(
    envelope: Any, connection: ControllerConnection, runtime_authority: Any
) -> dict[str, Any]:
    return _verify_installed_grant(
        envelope,
        connection,
        runtime_authority,
        key=_pinned_key(),
        now=int(datetime.now(UTC).timestamp()),
    )


class ControllerClient:
    """Bounded authenticated RPC; server retains every original mutation ID."""

    def __init__(
        self, connection: ControllerConnection, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.connection = connection
        if connection.runtime_authority is None and not isinstance(transport, httpx.MockTransport):
            _reject()
        if connection.runtime_authority is not None:
            authority = verify_runtime_authority(
                connection.runtime_authority, connection.authority_epoch_id
            )
            if connection.url != authority["toolChannel"]["origin"]:
                _reject()
        self.http = httpx.AsyncClient(
            base_url=connection.url,
            headers={"Authorization": f"Bearer {connection.token}"},
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            timeout=330,
        )
        self.unknown_request_ids: dict[str, None] = {}
        self._mutation_lock = asyncio.Lock()
        self.stop_request_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(connection.binding, sort_keys=True) + "/stop")
        )

    @property
    def unknown_request_id(self) -> str | None:
        return next(iter(self.unknown_request_ids), None)

    async def call(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        mutation: bool = False,
        request_id: str | None = None,
        recovery: bool = False,
        validate: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if mutation and not recovery:
            async with self._mutation_lock:
                return await self._call(
                    path, body, mutation=mutation, request_id=request_id, validate=validate
                )
        # Physical recovery stop cannot wait behind a 300-second command.
        # It retains its own stable ID alongside any unresolved command IDs.
        return await self._call(
            path,
            body,
            mutation=mutation,
            request_id=request_id,
            recovery=recovery,
            validate=validate,
        )

    async def _call(  # noqa: PLR0912
        self,
        path: str,
        body: dict[str, Any] | None,
        *,
        mutation: bool,
        request_id: str | None = None,
        recovery: bool = False,
        validate: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if mutation and self.unknown_request_id and not recovery:
            raise ControllerOperationUnknownError(self.unknown_request_id)
        payload = {"binding": self.connection.binding, **(body or {})}
        if mutation:
            request_id = request_id or str(uuid.uuid4())
            payload["requestId"] = request_id
            payload.setdefault("commandId", request_id)
        method = "POST" if body is not None or mutation else "GET"
        try:
            async with self.http.stream(
                method,
                f"/v1/sandbox/{self.connection.attempt_id}/{path}",
                json=payload if method == "POST" else None,
                headers={"X-LyraShield-Sandbox-Handle": self.connection.sandbox_handle},
                timeout=330 if mutation else (40 if path.startswith("pty/") else 10),
            ) as response:
                if response.status_code != 200:
                    _reject()
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        _reject()
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get("binding") != self.connection.binding:
                _reject()
            if mutation and result.get("requestId") != request_id:
                _reject()
            if mutation and result.get("status") != "COMPLETED":
                raise ControllerOperationUnknownError(request_id or "")
            if validate is not None:
                validate(result)
            if mutation and request_id is not None:
                await self._acknowledge(request_id, result)
        except (
            httpx.HTTPError,
            ValueError,
            ControllerUnavailableError,
            asyncio.CancelledError,
        ) as error:
            if mutation:
                if request_id is not None:
                    self.unknown_request_ids[request_id] = None
                if isinstance(error, asyncio.CancelledError):
                    raise
                raise ControllerOperationUnknownError(request_id or "") from None
            raise ControllerUnavailableError("Controller read unavailable") from None
        return result

    async def _acknowledge(self, request_id: str, result: dict[str, Any]) -> None:
        raw = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        checksum = "sha256:" + hashlib.sha256(raw).hexdigest()

        def validate_ack(response: dict[str, Any]) -> None:
            if (
                response.get("requestId") != request_id
                or response.get("status") != "ACKNOWLEDGED"
                or response.get("responseChecksum") != checksum
            ):
                _reject()

        for attempt in range(3):
            try:
                await self._call(
                    f"request/{request_id}/ack",
                    {"requestId": request_id, "responseChecksum": checksum},
                    mutation=False,
                    validate=validate_ack,
                )
            except ControllerUnavailableError:
                if attempt == 2:
                    raise
            else:
                return

    async def delete(self, session: Any) -> None:
        if getattr(getattr(session, "_inner", session), "client", None) is not self:
            _reject()
        await self.call("stop", mutation=True, request_id=self.stop_request_id, recovery=True)
        state = await self.call("state")
        if state.get("running") is not False:
            _reject()
        await self.http.aclose()

    async def close(self) -> None:
        await self.http.aclose()


class ControllerSessionState(SandboxSessionState):
    type: Literal["lyrashield-controller"] = "lyrashield-controller"


class ControllerSession(BaseSandboxSession):
    def __init__(
        self,
        client: ControllerClient,
        manifest: Manifest,
        exposed_ports: tuple[int, ...],
        image: str,
    ) -> None:
        self.client = client
        self.expected_image = image
        self.state = ControllerSessionState(
            manifest=manifest,
            exposed_ports=exposed_ports,
            snapshot=NoopSnapshot(id=client.connection.sandbox_handle),
        )
        self.installed_grant: dict[str, Any] | None = None
        self._pty_output_cursors: dict[int, int] = {}
        self._pty_locks: dict[int, asyncio.Lock] = {}
        self._grant_refresh_lock = asyncio.Lock()
        self._runtime_authority: Any = None

    async def start(self) -> None:
        # SDK startup would provision users/mounts/environment. This is an
        # already prepared sandbox; only the independently signed installed
        # receipt can authorize attaching to it.
        response = await self.client.call("state")
        grant = verify_installed_grant(
            response.get("grant"), self.client.connection, response.get("runtimeAuthority")
        )
        if (
            self.client.connection.runtime_authority is not None
            and response.get("runtimeAuthority") != self.client.connection.runtime_authority
        ):
            _reject()
        if response.get("running") is not True:
            _reject()
        if grant["manifestChecksum"] != manifest_checksum(self.state.manifest):
            _reject()
        if self.expected_image != grant["imageDigest"] and not self.expected_image.endswith(
            "@" + grant["imageDigest"]
        ):
            _reject()
        if grant["workspaceRoot"] != self.state.manifest.root:
            _reject()
        if sorted(grant["exposedPorts"]) != sorted(self.state.exposed_ports):
            _reject()
        self.installed_grant = grant
        self._runtime_authority = response.get("runtimeAuthority")
        self.state.workspace_root_ready = True

    async def _ensure_admission(self) -> None:
        grant = self.installed_grant
        if grant is None:
            _reject()
        if int(datetime.now(UTC).timestamp()) < grant["expiresAt"] - 60:
            return
        async with self._grant_refresh_lock:
            grant = self.installed_grant
            if grant is None:
                _reject()
            if int(datetime.now(UTC).timestamp()) < grant["expiresAt"] - 60:
                return
            # This is a read-only renewal of the same attempt. The protected
            # server must fence the live OPEN epoch before issuing the grant.
            response = await self.client.call("state")
            refreshed = verify_installed_grant(
                response.get("grant"), self.client.connection, response.get("runtimeAuthority")
            )
            if (
                response.get("running") is not True
                or response.get("runtimeAuthority") != self._runtime_authority
            ):
                _reject()

            def static(value: dict[str, Any]) -> dict[str, Any]:
                return {
                    key: item for key, item in value.items() if key not in {"issuedAt", "expiresAt"}
                }

            if (
                static(refreshed) != static(grant)
                or refreshed["issuedAt"] < grant["issuedAt"]
                or refreshed["expiresAt"] <= grant["expiresAt"]
            ):
                _reject()
            self.installed_grant = refreshed

    def _admit(self) -> dict[str, Any]:
        grant = self.installed_grant
        if grant is None or int(datetime.now(UTC).timestamp()) >= grant["expiresAt"]:
            _reject()
        return grant

    def assert_scan_authority(
        self, scan_id: str, authorized_hosts: set[str], *, relay_required: bool
    ) -> None:
        grant = self._admit()
        if (
            grant["scanId"] != scan_id
            or sorted(grant["authorizedHosts"]) != sorted(authorized_hosts)
            or grant["relayRequired"] != relay_required
        ):
            _reject()

    def _path(self, path: Path) -> str:
        root = PurePosixPath(self._admit()["workspaceRoot"])
        value = PurePosixPath(str(path))
        if ".." in value.parts or "\x00" in str(path):
            _reject()
        value = value if value.is_absolute() else root / value
        if not value.is_relative_to(root):
            _reject()
        # The server additionally opens beneath the approved directory using
        # no-follow descriptor traversal; lexical containment alone is not a
        # server authorization proof.
        return str(value)

    def _prepare_exec_command(
        self, *command: str | Path, shell: bool | list[str], user: str | User | None
    ) -> list[str]:
        identity = user.name if isinstance(user, User) else user
        if identity not in {None, "pentester"}:
            _reject()
        argv = [_text(str(value)) for value in command]
        if not argv or len(argv) > 256:
            _reject()
        if shell:
            joined = argv[0] if len(argv) == 1 else shlex.join(argv)
            argv = ([*shell] if isinstance(shell, list) else ["sh", "-lc"]) + [joined]
        return argv

    def _exec_body(self, argv: list[str], timeout: float | None) -> dict[str, Any]:
        self._admit()
        seconds = MAX_TIMEOUT_SECONDS if timeout is None else timeout
        if (
            not isinstance(seconds, (int, float))
            or isinstance(seconds, bool)
            or not math.isfinite(seconds)
            or not 0 < seconds <= MAX_TIMEOUT_SECONDS
        ):
            _reject()
        return {
            "argv": argv,
            "cwd": self.state.manifest.root,
            "user": "pentester",
            "timeoutSeconds": seconds,
            "maxOutputBytes": MAX_OUTPUT_BYTES,
        }

    async def _exec_internal(
        self, *command: str | Path, timeout: float | None = None
    ) -> ExecResult:
        await self._ensure_admission()
        result = await self.client.call(
            "exec",
            self._exec_body([str(c) for c in command], timeout),
            mutation=True,
            validate=self._validate_exec_result,
        )
        return ExecResult(
            stdout=_bytes(result.get("stdoutBase64"), maximum=MAX_OUTPUT_BYTES),
            stderr=_bytes(result.get("stderrBase64"), maximum=MAX_OUTPUT_BYTES),
            exit_code=_integer(result.get("exitCode"), minimum=-255, maximum=255),
        )

    @staticmethod
    def _validate_exec_result(result: dict[str, Any]) -> None:
        stdout = _bytes(result.get("stdoutBase64"), maximum=MAX_OUTPUT_BYTES)
        stderr = _bytes(result.get("stderrBase64"), maximum=MAX_OUTPUT_BYTES)
        if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
            _reject()
        _integer(result.get("exitCode"), minimum=-255, maximum=255)

    async def read(self, path: Path, *, user: str | User | None = None) -> io.IOBase:
        await self._ensure_admission()
        self._prepare_exec_command("true", shell=False, user=user)
        result = await self.client.call(
            "files/read", {"path": self._path(path), "maxBytes": MAX_FILE_BYTES}
        )
        return self._checked_stream(result, "dataBase64", MAX_FILE_BYTES)

    @staticmethod
    def _checked_stream(result: dict[str, Any], key: str, maximum: int) -> io.BytesIO:
        data = _bytes(result.get(key), maximum=maximum)
        if result.get("sha256") != hashlib.sha256(data).hexdigest():
            _reject()
        return io.BytesIO(data)

    async def write(self, path: Path, data: io.IOBase, *, user: str | User | None = None) -> None:
        await self._ensure_admission()
        self._prepare_exec_command("true", shell=False, user=user)
        content = data.read(MAX_FILE_BYTES + 1)
        if not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES:
            _reject()
        await self.client.call(
            "files/write",
            {
                "path": self._path(path),
                "dataBase64": base64.b64encode(content).decode(),
                "sha256": hashlib.sha256(content).hexdigest(),
            },
            mutation=True,
        )

    async def running(self) -> bool:
        result = await self.client.call("state")
        return _boolean(result.get("running"))

    async def persist_workspace(self) -> io.IOBase:
        await self._ensure_admission()
        self._admit()
        result = await self.client.call("workspace/persist", {"maxBytes": MAX_ARCHIVE_BYTES})
        return self._checked_stream(result, "archiveBase64", MAX_ARCHIVE_BYTES)

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        await self._ensure_admission()
        self._admit()
        content = data.read(MAX_ARCHIVE_BYTES + 1)
        if not isinstance(content, bytes) or len(content) > MAX_ARCHIVE_BYTES:
            _reject()
        await self.client.call(
            "workspace/hydrate",
            {
                "archiveBase64": base64.b64encode(content).decode(),
                "sha256": hashlib.sha256(content).hexdigest(),
            },
            mutation=True,
        )

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        await self._ensure_admission()
        self._admit()
        result = await self.client.call(f"port/{port}")
        host = _text(result.get("host"), max_length=253)
        if any(c in host for c in "/?#@") or type(result.get("tls")) is not bool:
            _reject()
        # Endpoint authority is protected-channel supplied and restricted on
        # the server to the installed port grant, never a container inspect.
        query = result.get("query", "")
        # The existing Caido SDK appends /graphql to its base URL and cannot
        # preserve URL query credentials. Require a protected private tunnel;
        # never silently drop a supplied authentication query.
        if query != "":
            _reject()
        return ExposedPortEndpoint(
            host=host,
            port=_integer(result.get("port"), minimum=1, maximum=65535),
            tls=result["tls"],
            query=query,
        )

    def _validate_pty_result(
        self, result: dict[str, Any], expected_session_id: int | None = None
    ) -> None:
        process = result.get("sessionId")
        exit_code = result.get("exitCode")
        tokens = result.get("originalTokenCount")
        if expected_session_id is not None and process != expected_session_id:
            _reject()
        if process is not None:
            process = _integer(process, minimum=1)
            cursor = _integer(result.get("outputCursor"))
            if cursor < self._pty_output_cursors.get(process, 0):
                _reject()
        _bytes(result.get("outputBase64"), maximum=MAX_OUTPUT_BYTES)
        if exit_code is not None:
            _integer(exit_code, minimum=-255, maximum=255)
        if tokens is not None:
            _integer(tokens)
        if process is None and exit_code is None:
            _reject()

    def _pty_update(self, result: dict[str, Any]) -> PtyExecUpdate:
        self._validate_pty_result(result)
        process = result.get("sessionId")
        exit_code = result.get("exitCode")
        tokens = result.get("originalTokenCount")
        if process is not None:
            self._pty_output_cursors[process] = result["outputCursor"]
        return PtyExecUpdate(
            process_id=None if process is None else _integer(process, minimum=1),
            output=_bytes(result.get("outputBase64"), maximum=MAX_OUTPUT_BYTES),
            exit_code=None if exit_code is None else _integer(exit_code, minimum=-255, maximum=255),
            original_token_count=None if tokens is None else _integer(tokens),
        )

    @staticmethod
    def _pty_bounds(yield_time_s: float | None, max_output_tokens: int | None) -> dict[str, Any]:
        seconds = 1.0 if yield_time_s is None else yield_time_s
        if (
            not isinstance(seconds, (int, float))
            or isinstance(seconds, bool)
            or not math.isfinite(seconds)
            or not 0 <= seconds <= 30
        ):
            _reject()
        tokens = (
            10000
            if max_output_tokens is None
            else _integer(max_output_tokens, minimum=1, maximum=100000)
        )
        return {"yieldTimeSeconds": seconds, "maxOutputTokens": tokens}

    async def pty_exec_start(
        self,
        *command: str | Path,
        timeout: float | None = None,
        shell: bool | list[str] = True,
        user: str | User | None = None,
        tty: bool = False,
        yield_time_s: float | None = None,
        max_output_tokens: int | None = None,
    ) -> PtyExecUpdate:
        await self._ensure_admission()
        body = self._exec_body(
            self._prepare_exec_command(*command, shell=shell, user=user),  # nosec B604: builds an authenticated sandbox RPC body, never launches a host shell
            timeout,
        )
        body.update(self._pty_bounds(yield_time_s, max_output_tokens))
        body["tty"] = _boolean(tty)
        return self._pty_update(
            await self.client.call(
                "pty/start", body, mutation=True, validate=self._validate_pty_result
            )
        )

    async def pty_write_stdin(
        self,
        *,
        session_id: int,
        chars: str,
        yield_time_s: float | None = None,
        max_output_tokens: int | None = None,
    ) -> PtyExecUpdate:
        await self._ensure_admission()
        _integer(session_id, minimum=1)
        lock = self._pty_locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            return await self._pty_write_stdin(
                session_id=session_id,
                chars=chars,
                yield_time_s=yield_time_s,
                max_output_tokens=max_output_tokens,
            )

    async def _pty_write_stdin(
        self,
        *,
        session_id: int,
        chars: str,
        yield_time_s: float | None,
        max_output_tokens: int | None,
    ) -> PtyExecUpdate:
        self._admit()
        _integer(session_id, minimum=1)
        if not isinstance(chars, str) or len(chars.encode()) > MAX_FILE_BYTES:
            _reject()
        if not chars:
            bounds = self._pty_bounds(yield_time_s, max_output_tokens)
            cursor = self._pty_output_cursors.get(session_id, 0)
            query = (
                f"yieldTimeSeconds={bounds['yieldTimeSeconds']}"
                f"&maxOutputTokens={bounds['maxOutputTokens']}&outputCursor={cursor}"
            )
            return self._pty_update(
                await self.client.call(
                    f"pty/{session_id}?{query}",
                    validate=lambda result: self._validate_pty_result(result, session_id),
                )
            )
        body = {
            "sessionId": session_id,
            "chars": chars,
            "outputCursor": self._pty_output_cursors.get(session_id, 0),
            **self._pty_bounds(yield_time_s, max_output_tokens),
        }
        return self._pty_update(
            await self.client.call(
                "pty/stdin",
                body,
                mutation=True,
                validate=lambda result: self._validate_pty_result(result, session_id),
            )
        )

    async def pty_terminate_all(self) -> None:
        await self._ensure_admission()
        self._admit()
        await self.client.call("pty/terminate", mutation=True)


def assert_controller_scan_authority(
    session: Any, scan_id: str, authorized_hosts: set[str], *, relay_required: bool
) -> None:
    inner = getattr(session, "_inner", session)
    if not isinstance(inner, ControllerSession):
        _reject()
    inner.assert_scan_authority(scan_id, authorized_hosts, relay_required=relay_required)


async def controller_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Attach to a trusted prepared sandbox; never provision caller mounts."""
    if bind_mounts:
        raise ControllerUnavailableError(
            "Controller attachment requires approved immutable mount descriptors"
        )
    client = ControllerClient(ControllerConnection.from_environment())
    inner = ControllerSession(client, manifest, exposed_ports, image)
    try:
        await inner.start()
    except BaseException:
        await client.close()
        raise
    return client, SandboxSession(inner)
