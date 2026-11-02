"""Session-owned native-host access to Caido over the existing Docker exec API.

No container port, network, host gateway, or arbitrary destination is exposed.
Only the fixed in-container loopback API is reachable through this listener.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agents.sandbox.types import ExposedPortEndpoint


_CHUNK = 65536
_MAX_FRAME = 1024 * 1024
_MAX_CONNECTIONS = 8
_DAEMON_TIMEOUT = 3
_SHUTDOWN_TIMEOUT = 1
logger = logging.getLogger(__name__)
# Fixed argv and destination; no shell, arguments, environment, or URL derived
# from a local HTTP client can change the exec identity or TCP destination.
_FORWARDER = """import contextlib, os, socket, threading
s = socket.create_connection(('127.0.0.1', 48080), timeout=3)
s.settimeout(None)
def upload():
    try:
        while data := os.read(0, 65536):
            s.sendall(data)
        s.shutdown(socket.SHUT_WR)
    except OSError:
        with contextlib.suppress(OSError):
            s.shutdown(socket.SHUT_RDWR)
threading.Thread(target=upload, daemon=True).start()
try:
    while data := s.recv(65536):
        view = memoryview(data)
        while view:
            view = view[os.write(1, view):]
finally:
    with contextlib.suppress(OSError):
        s.shutdown(socket.SHUT_RDWR)
    s.close()
"""


@dataclass(eq=False)
class _ExecChannel:
    sock: socket.socket
    response: Any

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.sock.close()
        with contextlib.suppress(Exception):
            self.response.close()


def _open_channel(api: Any, container_id: str) -> _ExecChannel:
    # Pinned docker-py exec_create/exec_start wire format. Explicit per-call
    # timeouts bound the two synchronous discovery requests independently of
    # the worker transport's global timeout; no background reader threads.
    response = api._post_json(
        api._url("/containers/{0}/exec", container_id),
        data={
            "Container": container_id,
            "User": "pentester",
            "Privileged": False,
            "Tty": False,
            "AttachStdin": True,
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": ["python3", "-I", "-u", "-c", _FORWARDER],
        },
        timeout=_DAEMON_TIMEOUT,
    )
    try:
        exec_id = api._result(response, json=True)["Id"]
    finally:
        response.close()
    response = api._post_json(
        api._url("/exec/{0}/start", exec_id),
        data={"Tty": False, "Detach": False},
        headers={"Connection": "Upgrade", "Upgrade": "tcp"},
        stream=True,
        timeout=_DAEMON_TIMEOUT,
    )
    try:
        wrapped = api._get_raw_response_socket(response)
        raw = getattr(wrapped, "_sock", wrapped)
        if not isinstance(raw, socket.socket):
            raise TypeError("local Docker exec did not return a socket")  # noqa: TRY301
        raw.settimeout(0)
        return _ExecChannel(raw, response)
    except BaseException:
        response.close()
        raise


class _ChannelLease:
    """One connection slot, retained until its worker-owned late result closes."""

    def __init__(self, release: Callable[[_ChannelLease], None]) -> None:
        self._lock = threading.Lock()
        self._release = release
        self._closed = False
        self._opening = False
        self._channel: _ExecChannel | None = None

    def begin_open(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            self._opening = True
            return True

    def failed_open(self) -> None:
        with self._lock:
            self._opening = False
            release = self._closed
        if release:
            self._release(self)

    def open(self, api: Any, container_id: str) -> _ExecChannel | None:
        try:
            channel = _open_channel(api, container_id)
        except BaseException:
            self.failed_open()
            raise
        with self._lock:
            if not self._closed:
                self._channel = channel
                self._opening = False
                return channel
        # This branch runs in the executor worker. Neither disposal nor slot
        # release needs a callback on the potentially already-closed UI loop.
        try:
            channel.close()
        finally:
            with self._lock:
                self._opening = False
            self._release(self)
        return None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            channel, self._channel = self._channel, None
            release = not self._opening
        try:
            if channel is not None:
                channel.close()
        finally:
            if release:
                self._release(self)


async def _recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    loop = asyncio.get_running_loop()
    while len(result) < size:
        chunk = await loop.sock_recv(sock, size - len(result))
        if not chunk:
            if result:
                raise EOFError("truncated Docker exec frame")
            return b""
        result.extend(chunk)
    return bytes(result)


async def _from_docker(sock: socket.socket, writer: asyncio.StreamWriter) -> None:
    # Non-TTY exec output has an eight-byte Docker stdout/stderr frame header;
    # stdin remains raw bytes. Never forward stderr or log request/response data.
    while header := await _recv_exact(sock, 8):
        stream, size = struct.unpack("!BxxxI", header)
        if header[1:4] != b"\0\0\0" or stream != 1 or size > _MAX_FRAME:
            raise ValueError("invalid Docker control-plane output frame")
        if size:
            payload = await _recv_exact(sock, size)
            if not payload:
                raise EOFError("missing Docker exec frame payload")
            writer.write(payload)
            await writer.drain()


async def _to_docker(reader: asyncio.StreamReader, sock: socket.socket) -> None:
    loop = asyncio.get_running_loop()
    while payload := await reader.read(_CHUNK):
        await loop.sock_sendall(sock, payload)
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_WR)


class DockerControlPlaneTunnel:
    """One loopback listener with bounded, backpressured Docker exec streams."""

    _server: asyncio.Server
    endpoint: ExposedPortEndpoint

    def __init__(self, api: Any, container_id: str) -> None:
        self._api = api
        self._container_id = container_id
        self._closed = False
        self._tasks: set[asyncio.Task[None]] = set()
        self._lease_lock = threading.Lock()
        self._leases: set[_ChannelLease] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    @classmethod
    async def create(cls, api: Any, container_id: str) -> DockerControlPlaneTunnel:
        tunnel = cls(api, container_id)
        tunnel._server = await asyncio.start_server(
            tunnel._accept, "127.0.0.1", 0, limit=_CHUNK, start_serving=False
        )
        try:
            await tunnel._server.start_serving()
        except BaseException:
            await tunnel.aclose()
            raise
        port = tunnel._server.sockets[0].getsockname()[1]
        tunnel.endpoint = ExposedPortEndpoint(host="127.0.0.1", port=port, tls=False)
        return tunnel

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with self._lease_lock:
            if self._closed or len(self._leases) >= _MAX_CONNECTIONS:
                writer.transport.abort()
                return
            lease = _ChannelLease(self._release_lease)
            self._leases.add(lease)
        task = asyncio.create_task(self._relay(reader, writer, lease))
        self._writers.add(writer)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _release_lease(self, lease: _ChannelLease) -> None:
        with self._lease_lock:
            self._leases.discard(lease)

    async def _relay(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, lease: _ChannelLease
    ) -> None:
        pumps: set[asyncio.Task[None]] = set()
        try:
            if not lease.begin_open():
                return
            try:
                future = asyncio.get_running_loop().run_in_executor(
                    None, lease.open, self._api, self._container_id
                )
            except BaseException:
                lease.failed_open()
                raise
            # Retrieving an abandoned exception avoids asyncio diagnostics;
            # channel disposal and slot release are owned by the worker lease.
            future.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            channel = await asyncio.wait_for(asyncio.shield(future), 2 * _DAEMON_TIMEOUT + 1)
            if channel is None:
                return
            down = asyncio.create_task(_from_docker(channel.sock, writer))
            up = asyncio.create_task(_to_docker(reader, channel.sock))
            pumps = {up, down}
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
            if down not in done:
                await down  # Preserve responses after the local client half-closes.
        except Exception as exc:
            # Exception text may contain protocol data; log only its type.
            logger.debug("Docker control-plane channel closed (%s)", type(exc).__name__)
        finally:
            # Retain every handle while draining: session deletion can abort
            # this finalizer's writer and close its lease before cancelling it.
            writer.close()
            try:
                for pump in pumps:
                    pump.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
                # A normal response may drain slowly; it keeps its slot and
                # remains owned until closure. Only session shutdown aborts it.
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
            finally:
                # Keep draining writers owned until closure or forced abort.
                writer.transport.abort()
                lease.close()
                self._writers.discard(writer)

    async def aclose(self) -> None:
        with self._lease_lock:
            self._closed = True
            leases = tuple(self._leases)
        self._server.close()
        for writer in tuple(self._writers):
            writer.transport.abort()
            self._writers.discard(writer)
        for lease in leases:
            lease.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        try:
            async with asyncio.timeout(_SHUTDOWN_TIMEOUT):
                await asyncio.gather(*tasks, return_exceptions=True)
                await self._server.wait_closed()
        except TimeoutError:
            logger.warning("Docker control-plane shutdown deadline reached after transport abort")
        self._tasks.difference_update(task for task in tasks if task.done())
