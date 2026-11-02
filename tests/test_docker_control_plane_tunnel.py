"""Exercise real loopback forwarding and Docker exec framing without a daemon."""

from __future__ import annotations

import asyncio
import socket
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from lyrashield.runtime import docker_control_plane as tunnel


def channel_pair():
    local, peer = socket.socketpair()
    local.settimeout(0)
    peer.settimeout(0)
    return tunnel._ExecChannel(local, SimpleNamespace(close=Mock())), peer


async def framed_send(peer, payload):
    frame = struct.pack("!BxxxI", 1, len(payload)) + payload
    loop = asyncio.get_running_loop()
    # Fragment both the Docker header and payload across socket reads.
    await loop.sock_sendall(peer, frame[:3])
    await asyncio.sleep(0)
    await loop.sock_sendall(peer, frame[3:])


@pytest.mark.asyncio
async def test_http_upgrade_and_binary_websocket_bytes_are_preserved(monkeypatch):
    loop = asyncio.get_running_loop()
    received = []
    peers = []
    workers = []
    request = b"GET /graphql HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    upgrade = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
    websocket = b"\x82\x86\x00\x00\x00\x00\x00\xff\r\n\x00\x81"

    async def daemon(peer):
        try:
            received.append(await tunnel._recv_exact(peer, len(request)))
            await framed_send(peer, upgrade)
            received.append(await tunnel._recv_exact(peer, len(websocket)))
            await framed_send(peer, websocket)
        finally:
            peer.close()

    def open_channel(_api, container_id):
        assert container_id == "owned"
        channel, peer = channel_pair()
        peers.append(channel)
        loop.call_soon_threadsafe(lambda: workers.append(asyncio.create_task(daemon(peer))))
        return channel

    monkeypatch.setattr(tunnel, "_open_channel", open_channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
    reader, writer = await asyncio.open_connection(relay.endpoint.host, relay.endpoint.port)
    try:
        writer.write(request)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(upgrade)), 2) == upgrade
        writer.write(websocket)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(websocket)), 2) == websocket
        assert received == [request, websocket]
    finally:
        writer.close()
        await writer.wait_closed()
        await relay.aclose()
        await asyncio.gather(*workers)
    assert not relay._tasks
    assert not relay._channels
    assert all(item.sock.fileno() == -1 for item in peers)
    with pytest.raises(OSError):
        await asyncio.open_connection(relay.endpoint.host, relay.endpoint.port)


@pytest.mark.asyncio
async def test_client_half_close_keeps_response_readable(monkeypatch):
    loop = asyncio.get_running_loop()
    channel, peer = channel_pair()
    monkeypatch.setattr(tunnel, "_open_channel", lambda *_args: channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")

    async def daemon():
        data = bytearray()
        while chunk := await loop.sock_recv(peer, 128):
            data.extend(chunk)
        assert data == b"request"
        await framed_send(peer, b"response-after-eof")
        peer.close()

    worker = asyncio.create_task(daemon())
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.endpoint.port)
    try:
        writer.write(b"request")
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), 2) == b"response-after-eof"
        await worker
    finally:
        writer.close()
        await writer.wait_closed()
        await relay.aclose()
        peer.close()


@pytest.mark.parametrize(
    "frame",
    [
        struct.pack("!BxxxI", 2, 5) + b"error",
        struct.pack("!BxxxI", 1, 1024 * 1024 + 1),
        b"\x01\x01\x00\x00\x00\x00\x00\x01X",
        b"\x01\x00",
        struct.pack("!BxxxI", 1, 5) + b"ab",
    ],
)
@pytest.mark.asyncio
async def test_malformed_or_stderr_frames_never_reach_client(frame):
    channel, peer = channel_pair()
    writer = SimpleNamespace(write=Mock(), drain=Mock())
    try:
        await asyncio.get_running_loop().sock_sendall(peer, frame)
        peer.close()
        with pytest.raises((ValueError, EOFError)):
            await tunnel._from_docker(channel.sock, writer)
        writer.write.assert_not_called()
    finally:
        channel.close()
        peer.close()


@pytest.mark.asyncio
async def test_downstream_backpressure_stops_reading_more_frames():
    channel, peer = channel_pair()
    draining = asyncio.Event()
    release = asyncio.Event()
    writes = []

    async def drain():
        draining.set()
        await release.wait()

    writer = SimpleNamespace(write=writes.append, drain=drain)
    reader = asyncio.create_task(tunnel._from_docker(channel.sock, writer))
    try:
        await framed_send(peer, b"first")
        await asyncio.wait_for(draining.wait(), 1)
        await framed_send(peer, b"second")
        assert writes == [b"first"]
        release.set()
        peer.close()
        await asyncio.wait_for(reader, 1)
        assert writes == [b"first", b"second"]
    finally:
        release.set()
        reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)
        channel.close()
        peer.close()


@pytest.mark.asyncio
async def test_paused_streams_have_no_idle_deadline(monkeypatch):
    channel, peer = channel_pair()
    received = []
    reader = asyncio.StreamReader()
    writer = SimpleNamespace(write=received.append, drain=lambda: asyncio.sleep(0))

    def unexpected_deadline(*_args, **_kwargs):
        raise AssertionError("a paused Caido stream must not have an idle deadline")

    monkeypatch.setattr(tunnel.asyncio, "wait_for", unexpected_deadline)
    up = asyncio.create_task(tunnel._to_docker(reader, channel.sock))
    down = asyncio.create_task(tunnel._from_docker(channel.sock, writer))
    try:
        await asyncio.sleep(0)
        assert not up.done()
        assert not down.done()
        reader.feed_data(b"resumed-request")
        reader.feed_eof()
        async with asyncio.timeout(1):
            await up
            assert await tunnel._recv_exact(peer, 15) == b"resumed-request"
            await framed_send(peer, b"resumed-response")
            peer.close()
            await down
        assert received == [b"resumed-response"]
    finally:
        up.cancel()
        down.cancel()
        await asyncio.gather(up, down, return_exceptions=True)
        channel.close()
        peer.close()


@pytest.mark.asyncio
async def test_active_connection_bound_and_cleanup(monkeypatch):
    monkeypatch.setattr(tunnel, "_MAX_CONNECTIONS", 1)
    channels = []
    peers = []
    started = asyncio.Event()
    loop = asyncio.get_running_loop()

    def open_channel(*_args):
        channel, peer = channel_pair()
        channels.append(channel)
        peers.append(peer)
        loop.call_soon_threadsafe(started.set)
        return channel

    monkeypatch.setattr(tunnel, "_open_channel", open_channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.endpoint.port)
    await asyncio.wait_for(started.wait(), 2)
    second, second_writer = await asyncio.open_connection("127.0.0.1", relay.endpoint.port)
    try:
        assert await asyncio.wait_for(second.read(), 2) == b""
        assert len(channels) == 1
        await relay.aclose()
        assert await asyncio.wait_for(reader.read(), 2) == b""
        assert not relay._tasks
        assert not relay._channels
    finally:
        for item in (writer, second_writer):
            item.close()
            await item.wait_closed()
        for peer in peers:
            peer.close()
        await relay.aclose()


@pytest.mark.asyncio
async def test_cancel_during_exec_open_closes_late_channel(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    channel, peer = channel_pair()

    def open_channel(*_args):
        entered.set()
        assert release.wait(2)
        return channel

    monkeypatch.setattr(tunnel, "_open_channel", open_channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
    _reader, writer = await asyncio.open_connection("127.0.0.1", relay.endpoint.port)
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        await asyncio.wait_for(relay.aclose(), 0.2)
        release.set()
        while relay._opening:
            await asyncio.sleep(0.01)
        assert channel.sock.fileno() == -1
        assert not relay._tasks
    finally:
        release.set()
        writer.close()
        await writer.wait_closed()
        peer.close()
        await relay.aclose()


def test_exec_wire_request_has_fixed_identity_destination_and_timeout():
    channel, peer = channel_pair()
    create_response = SimpleNamespace(close=Mock())
    start_response = SimpleNamespace(close=Mock())
    api = SimpleNamespace(
        _url=lambda pattern, value: pattern.format(value),
        _post_json=Mock(side_effect=[create_response, start_response]),
        _result=lambda *_args, **_kwargs: {"Id": "exec-owned"},
        _get_raw_response_socket=lambda _response: channel.sock,
    )
    try:
        opened = tunnel._open_channel(api, "owned")
        create, start = api._post_json.call_args_list
        assert create.args == ("/containers/owned/exec",)
        spec = create.kwargs["data"]
        assert spec["User"] == "pentester"
        assert spec["Privileged"] is False
        assert spec["Tty"] is False
        assert spec["AttachStdin"] is True
        assert spec["Cmd"][:4] == ["python3", "-I", "-u", "-c"]
        assert create.kwargs["timeout"] == 3
        assert start.args == ("/exec/exec-owned/start",)
        assert start.kwargs["data"] == {"Tty": False, "Detach": False}
        assert start.kwargs["timeout"] == 3
        opened.close()
    finally:
        channel.close()
        peer.close()


def test_fixed_forwarder_streams_binary_bytes_and_half_close():
    payload = b"request\x00\xff\r\n" * 10000
    received = []
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(3)
        port = server.getsockname()[1]

        def echo():
            with server.accept()[0] as connection:
                connection.settimeout(3)
                data = bytearray()
                while chunk := connection.recv(65536):
                    data.extend(chunk)
                received.append(bytes(data))
                connection.sendall(data)

        worker = threading.Thread(target=echo)
        worker.start()
        # Validate the production script's requested address, then substitute
        # only this test server's port so tests cannot contact real Caido.
        bootstrap = f"""import socket
original = socket.create_connection
def connect(address, timeout):
    assert address == ('127.0.0.1', 48080)
    return original(('127.0.0.1', {port}), timeout)
socket.create_connection = connect
exec({tunnel._FORWARDER!r})
"""
        try:
            result = subprocess.run(  # noqa: S603 - fixed interpreter, isolated test program
                [sys.executable, "-I", "-u", "-c", bootstrap],
                input=payload,
                capture_output=True,
                timeout=5,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout == payload
            assert received == [payload]
        finally:
            worker.join(timeout=5)
        assert not worker.is_alive()
