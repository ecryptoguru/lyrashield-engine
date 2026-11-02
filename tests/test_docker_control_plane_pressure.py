"""Adverse bidirectional traffic and session lifetime checks without Docker."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import socket
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from agents.sandbox.sandboxes.docker import DockerSandboxClient

from lyrashield.runtime import docker_control_plane as tunnel
from lyrashield.runtime import session_manager
from lyrashield.runtime.docker_client import StrixDockerSandboxClient


def channel_pair():
    local, peer = socket.socketpair()
    local.settimeout(0)
    peer.settimeout(0)
    return tunnel._ExecChannel(local, SimpleNamespace(close=Mock())), peer


def test_guest_simultaneous_large_request_and_response_make_progress():
    request = (b"\x00request\xff\r\n" * (2 * 1024 * 1024 // 11 + 1))[: 2 * 1024 * 1024]
    response = (b"\x81response\x00\xff" * (2 * 1024 * 1024 // 11 + 1))[: 2 * 1024 * 1024]
    received = []
    errors = []
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]

        def peer():
            try:
                with server.accept()[0] as connection:
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
                    connection.settimeout(5)
                    # Deliberately fill the reverse direction before reading
                    # any of the simultaneously streaming request.
                    connection.sendall(response)
                    data = bytearray()
                    while chunk := connection.recv(65536):
                        data.extend(chunk)
                    received.append(bytes(data))
            except OSError as exc:
                errors.append(exc)

        worker = threading.Thread(target=peer)
        worker.start()
        bootstrap = f"""import socket
original = socket.create_connection
def connect(address, timeout):
    assert address == ('127.0.0.1', 48080)
    connection = original(('127.0.0.1', {port}), timeout)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    return connection
socket.create_connection = connect
exec({tunnel._FORWARDER!r})
"""
        try:
            result = subprocess.run(  # noqa: S603 - fixed isolated test interpreter
                [sys.executable, "-I", "-u", "-c", bootstrap],
                input=request,
                capture_output=True,
                timeout=8,
                check=False,
            )
            assert not errors, errors
            assert result.returncode == 0, result.stderr
            assert result.stdout == response
            assert received == [request]
        finally:
            worker.join(timeout=6)
        assert not worker.is_alive()


@pytest.mark.parametrize("via_bundle", [False, True])
@pytest.mark.asyncio
async def test_stalled_draining_client_cannot_block_container_delete(monkeypatch, via_bundle):
    channel, peer = channel_pair()
    monkeypatch.setattr(tunnel, "_open_channel", lambda *_args: channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
    client = socket.socket()
    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    client.settimeout(0)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(client, (relay.endpoint.host, relay.endpoint.port))
    sending = asyncio.create_task(
        loop.sock_sendall(peer, struct.pack("!BxxxI", 1, 1024 * 1024) + b"x" * 1024 * 1024)
    )
    killed = Mock()
    removed = AsyncMock()
    owner = StrixDockerSandboxClient(
        SimpleNamespace(
            containers=SimpleNamespace(get=lambda _id: SimpleNamespace(kill=killed)), close=Mock()
        )
    )
    inner = SimpleNamespace(
        _control_plane_lock=asyncio.Lock(),
        _control_plane_tunnel=relay,
        state=SimpleNamespace(container_id="owned"),
    )
    wrapper = SimpleNamespace(_inner=inner)
    monkeypatch.setattr(DockerSandboxClient, "delete", removed)
    scan_id = "pressure-bundle-delete"
    try:
        async with asyncio.timeout(2):
            while not relay._writers or not any(
                writer.transport.get_write_buffer_size() > 65536 for writer in relay._writers
            ):
                await asyncio.sleep(0.005)
        writer = next(iter(relay._writers))
        # Start the relay's graceful finalizer before session cleanup. It must
        # stay owned while a non-reading peer prevents its output from draining.
        for task in tuple(relay._tasks):
            task.cancel()
        async with asyncio.timeout(1):
            while not writer.is_closing():
                await asyncio.sleep(0)
        if via_bundle:
            session_manager._SESSION_CACHE[scan_id] = {"client": owner, "session": wrapper}
            assert await asyncio.wait_for(session_manager.cleanup(scan_id), 0.3) == "removed"
            assert scan_id not in session_manager._SESSION_CACHE
            assert session_manager._CLEANUP_RECEIPTS[scan_id]["status"] == "removed"
            owner.docker_client.close.assert_called_once()
        else:
            await asyncio.wait_for(owner.delete(wrapper), 0.3)
        killed.assert_called_once()
        removed.assert_awaited_once_with(wrapper)
        assert not relay._tasks
        assert not relay._server.is_serving()
    finally:
        client.close()
        peer.close()
        sending.cancel()
        await asyncio.gather(sending, return_exceptions=True)
        await asyncio.wait_for(relay.aclose(), 2)
        session_manager._SESSION_CACHE.pop(scan_id, None)
        session_manager._CLEANUP_RECEIPTS.pop(scan_id, None)


@pytest.mark.asyncio
async def test_draining_connection_keeps_its_admission_slot(monkeypatch):
    monkeypatch.setattr(tunnel, "_MAX_CONNECTIONS", 1)
    channels = []
    peers = []

    def open_channel(*_args):
        channel, peer = channel_pair()
        channels.append(channel)
        peers.append(peer)
        return channel

    monkeypatch.setattr(tunnel, "_open_channel", open_channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
    client = socket.socket()
    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    client.settimeout(0)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(client, (relay.endpoint.host, relay.endpoint.port))
    sending = None
    second_writer = None
    try:
        async with asyncio.timeout(1):
            while not peers:
                await asyncio.sleep(0)
        sending = asyncio.create_task(
            loop.sock_sendall(peers[0], struct.pack("!BxxxI", 1, 1024 * 1024) + b"x" * 1024 * 1024)
        )
        async with asyncio.timeout(1):
            while not any(
                writer.transport.get_write_buffer_size() > 65536 for writer in relay._writers
            ):
                await asyncio.sleep(0.005)
        writer = next(iter(relay._writers))
        for task in tuple(relay._tasks):
            task.cancel()
        async with asyncio.timeout(1):
            while not writer.is_closing():
                await asyncio.sleep(0)
        second, second_writer = await asyncio.open_connection(
            relay.endpoint.host, relay.endpoint.port
        )
        assert await asyncio.wait_for(second.read(), 0.2) == b""
        assert len(channels) == 1
    finally:
        client.close()
        if second_writer is not None:
            second_writer.close()
            await second_writer.wait_closed()
        if sending is not None:
            sending.cancel()
            await asyncio.gather(sending, return_exceptions=True)
        await relay.aclose()
        for peer in peers:
            peer.close()


def test_late_open_is_disposed_even_after_owning_loop_closes(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    disposed = threading.Event()
    channel, peer = channel_pair()
    channel.response.close.side_effect = disposed.set

    def open_channel(*_args):
        entered.set()
        assert release.wait(3)
        return channel

    monkeypatch.setattr(tunnel, "_open_channel", open_channel)
    loop = asyncio.new_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)
    client = socket.socket()

    async def setup():
        relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
        client.connect((relay.endpoint.host, relay.endpoint.port))
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.005)
        await asyncio.wait_for(relay.aclose(), 0.2)
        return relay

    try:
        relay = loop.run_until_complete(setup())
        client.close()
        loop.close()  # Match the TUI's supported immediate-loop-close cleanup.
        release.set()
        assert disposed.wait(1), "late channel disposal depended on the closed event loop"
        assert channel.sock.fileno() == -1
        assert not relay._leases
    finally:
        release.set()
        client.close()
        executor.shutdown(wait=True)
        channel.close()
        peer.close()
        if not loop.is_closed():
            loop.close()


def test_published_worker_channel_is_owned_before_loop_handoff(monkeypatch):
    published = threading.Event()
    release = threading.Event()
    channel, peer = channel_pair()
    original_open = tunnel._ChannelLease.open

    def delayed_handoff(lease, *args):
        result = original_open(lease, *args)
        published.set()
        assert release.wait(3)
        return result

    monkeypatch.setattr(tunnel, "_open_channel", lambda *_args: channel)
    monkeypatch.setattr(tunnel._ChannelLease, "open", delayed_handoff)
    loop = asyncio.new_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)
    client = socket.socket()

    async def setup():
        relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
        client.connect((relay.endpoint.host, relay.endpoint.port))
        async with asyncio.timeout(1):
            while not published.is_set():
                await asyncio.sleep(0.005)
        await asyncio.wait_for(relay.aclose(), 0.2)
        assert channel.sock.fileno() == -1
        channel.response.close.assert_called_once()
        return relay

    try:
        relay = loop.run_until_complete(setup())
        client.close()
        loop.close()
        release.set()
        executor.shutdown(wait=True)
        assert not relay._leases
        channel.response.close.assert_called_once()
    finally:
        release.set()
        client.close()
        executor.shutdown(wait=True)
        channel.close()
        peer.close()
        if not loop.is_closed():
            loop.close()


def test_late_failed_worker_releases_slot_after_loop_close(monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def failing_open(*_args):
        entered.set()
        assert release.wait(3)
        raise OSError("bounded daemon open failed")

    monkeypatch.setattr(tunnel, "_open_channel", failing_open)
    loop = asyncio.new_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)
    client = socket.socket()

    async def setup():
        relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
        client.connect((relay.endpoint.host, relay.endpoint.port))
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.005)
        await relay.aclose()
        return relay

    try:
        relay = loop.run_until_complete(setup())
        client.close()
        loop.close()
        release.set()
        executor.shutdown(wait=True)
        assert not relay._leases
    finally:
        release.set()
        client.close()
        executor.shutdown(wait=True)
        if not loop.is_closed():
            loop.close()


@pytest.mark.asyncio
async def test_eight_slow_opens_admit_eight_slots_and_hold_orphans(monkeypatch):
    release = threading.Event()
    lock = threading.Lock()
    channels = []
    peers = []

    def open_channel(*_args):
        channel, peer = channel_pair()
        with lock:
            channels.append(channel)
            peers.append(peer)
        assert release.wait(3)
        return channel

    monkeypatch.setattr(tunnel, "_open_channel", open_channel)
    relay = await tunnel.DockerControlPlaneTunnel.create(object(), "owned")
    clients = []
    try:
        for _ in range(8):
            clients.append(await asyncio.open_connection(relay.endpoint.host, relay.endpoint.port))
            await asyncio.sleep(0.01)
        for _ in range(100):
            if len(channels) == 8:
                break
            await asyncio.sleep(0.005)
        assert len(channels) == 8, "each in-progress connection must consume exactly one slot"
        ninth, ninth_writer = await asyncio.open_connection(
            relay.endpoint.host, relay.endpoint.port
        )
        clients.append((ninth, ninth_writer))
        assert await asyncio.wait_for(ninth.read(), 0.2) == b""
        tasks = tuple(relay._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        orphan_ninth, orphan_writer = await asyncio.open_connection(
            relay.endpoint.host, relay.endpoint.port
        )
        clients.append((orphan_ninth, orphan_writer))
        assert await asyncio.wait_for(orphan_ninth.read(), 0.2) == b""
        assert len(channels) == 8
        release.set()
        async with asyncio.timeout(1):
            while any(channel.sock.fileno() != -1 for channel in channels):
                await asyncio.sleep(0.005)
        reused = await asyncio.open_connection(relay.endpoint.host, relay.endpoint.port)
        clients.append(reused)
        async with asyncio.timeout(1):
            while len(channels) != 9:
                await asyncio.sleep(0.005)
    finally:
        release.set()
        for _reader, writer in clients:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        await relay.aclose()
        for peer in peers:
            peer.close()
