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
from dataclasses import dataclass
from typing import Any

from agents.sandbox.types import ExposedPortEndpoint


_CHUNK = 65536
_MAX_FRAME = 1024 * 1024
_MAX_CONNECTIONS = 8
_DAEMON_TIMEOUT = 3
logger = logging.getLogger(__name__)
# Fixed argv and destination; no shell, arguments, environment, or URL derived
# from a local HTTP client can change the exec identity or TCP destination.
_FORWARDER = """import os, selectors, socket
s = socket.create_connection(('127.0.0.1', 48080), timeout=3)
s.settimeout(None)
poll = selectors.DefaultSelector()
poll.register(0, selectors.EVENT_READ)
poll.register(s, selectors.EVENT_READ)
try:
    while True:
        for key, _ in poll.select():
            if key.fileobj == 0:
                data = os.read(0, 65536)
                if not data:
                    poll.unregister(0)
                    s.shutdown(socket.SHUT_WR)
                else:
                    s.sendall(data)
            else:
                data = s.recv(65536)
                if not data:
                    raise SystemExit(0)
                view = memoryview(data)
                while view:
                    view = view[os.write(1, view):]
finally:
    poll.close()
    s.close()
"""


@dataclass(eq=False)
class _ExecChannel:
    sock: socket.socket
    response: Any

    def close(self) -> None:
        self.sock.close()
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
        self._channels: set[_ExecChannel] = set()
        self._opening: set[asyncio.Future[_ExecChannel]] = set()
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
        if self._closed or len(self._tasks) + len(self._opening) >= _MAX_CONNECTIONS:
            writer.close()
            return
        task = asyncio.create_task(self._relay(reader, writer))
        self._writers.add(writer)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        channel = None
        future = None
        abandoned = False
        pumps: set[asyncio.Task[None]] = set()
        try:
            future = asyncio.get_running_loop().run_in_executor(
                None, _open_channel, self._api, self._container_id
            )
            self._opening.add(future)

            def late_close(done: asyncio.Future[_ExecChannel]) -> None:
                self._opening.discard(done)
                if self._closed or abandoned:
                    # The callback also owns any channel returned after its
                    # connection task was cancelled/timed out.
                    with contextlib.suppress(Exception):
                        done.result().close()

            future.add_done_callback(late_close)
            channel = await asyncio.wait_for(asyncio.shield(future), 2 * _DAEMON_TIMEOUT + 1)
            self._channels.add(channel)
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
            abandoned = True
            if channel is None and future is not None and future.done():
                with contextlib.suppress(Exception):
                    future.result().close()
            # Close handles before any cleanup await: delete can cancel this
            # handler while it is already draining its own finally block.
            writer.close()
            self._writers.discard(writer)
            if channel is not None:
                self._channels.discard(channel)
                channel.close()
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1)

    async def aclose(self) -> None:
        self._closed = True
        self._server.close()
        for writer in tuple(self._writers):
            writer.close()
        for channel in tuple(self._channels):
            channel.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.difference_update(tasks)
        self._writers.clear()
        await self._server.wait_closed()
