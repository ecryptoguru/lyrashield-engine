"""Regression tests for the AnyIO 4.14.2 security patch.

The frozen dependency audit flagged anyio 4.14.1 with CVE-2026-63374,
CVE-2026-64847 and CVE-2026-63349 (fixed in 4.14.2). These tests pin the two
upstream behaviors the engine's frozen environment relies on:

* ``open_process``/``run_process`` must forward ``extra_groups`` to the async
  backend. In 4.14.1 the backend kwarg was populated from ``group`` instead,
  silently dropping the requested supplementary groups. The backend is mocked,
  so no real privilege-changing subprocess is ever spawned.
* ``TLSStream.wrap`` must encode international hostnames with IDNA 2008
  (UTS #46) before handing ``server_hostname`` to ``ssl``. 4.14.1 passed the
  raw string, letting ``ssl`` apply the obsolete IDNA 2003 mapping. Certificate
  validation is never disabled here.
"""

import importlib
import ssl
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


pytest.importorskip("anyio", reason="patched dependency under test")

_sockets = importlib.import_module("anyio._core._sockets")
_subprocesses = importlib.import_module("anyio._core._subprocesses")
_tls = importlib.import_module("anyio.streams.tls")

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="supplementary-group subprocess options are POSIX-only; "
    "the Linux sandbox image is the covered runtime",
)


@linux_only
async def test_open_process_forwards_extra_groups_to_backend(monkeypatch):
    """``extra_groups`` must reach the backend unchanged.

    anyio 4.14.1 populated the backend's ``extra_groups`` kwarg from ``group``,
    silently dropping the requested supplementary groups.
    """
    backend = SimpleNamespace(open_process=AsyncMock(return_value=Mock(name="process")))
    monkeypatch.setattr(_subprocesses, "get_async_backend", Mock(return_value=backend))

    await _subprocesses.open_process(
        ["fixture-command"],
        user=65534,
        group=65534,
        extra_groups=[100, 200],
        umask=0o077,
    )

    backend.open_process.assert_awaited_once()
    kwargs = backend.open_process.await_args.kwargs
    assert kwargs["extra_groups"] == [100, 200]
    assert kwargs["group"] == 65534
    assert kwargs["user"] == 65534
    assert kwargs["umask"] == 0o077


@linux_only
async def test_open_process_omits_extra_groups_when_unset(monkeypatch):
    """Unset POSIX identity options must not reach the backend at all."""
    backend = SimpleNamespace(open_process=AsyncMock(return_value=Mock(name="process")))
    monkeypatch.setattr(_subprocesses, "get_async_backend", Mock(return_value=backend))

    await _subprocesses.open_process(["fixture-command"])

    kwargs = backend.open_process.await_args.kwargs
    assert "extra_groups" not in kwargs
    assert "group" not in kwargs
    assert "user" not in kwargs
    assert "umask" not in kwargs


@linux_only
async def test_run_process_forwards_extra_groups(monkeypatch):
    """``run_process`` must hand ``extra_groups`` through to ``open_process``."""
    process = SimpleNamespace(
        stdin=None,
        stdout=None,
        stderr=None,
        wait=AsyncMock(return_value=0),
        returncode=0,
    )
    process_cm = AsyncMock(name="process-acm")
    process_cm.__aenter__.return_value = process
    open_process = AsyncMock(name="open_process", return_value=process_cm)
    monkeypatch.setattr(_subprocesses, "open_process", open_process)

    result = await _subprocesses.run_process(
        ["fixture-command"], check=False, extra_groups=[100, 200]
    )

    open_process.assert_awaited_once()
    assert open_process.await_args.kwargs["extra_groups"] == [100, 200]
    process.wait.assert_awaited_once()
    assert result.returncode == 0


def _capture_wrap_bio(context: ssl.SSLContext) -> dict[str, object]:
    """Record the arguments anyio hands to ``SSLContext.wrap_bio``.

    The real context keeps its certificate validation settings untouched; only
    the ``wrap_bio`` call is observed so no handshake (and no network I/O) is
    performed.
    """
    captured: dict[str, object] = {}
    ssl_object = SimpleNamespace(do_handshake=Mock(return_value=None))

    def capture(bio_in, bio_out, *, server_side, server_hostname):  # noqa: ARG001
        captured["server_side"] = server_side
        captured["server_hostname"] = server_hostname
        return ssl_object

    context.wrap_bio = capture
    return captured


async def test_tls_wrap_encodes_hostname_with_idna2008():
    """IDN hostnames are encoded with IDNA 2008 before certificate checking.

    ``ssl`` encodes a ``str`` ``server_hostname`` with the obsolete IDNA 2003
    codec (``faß.de`` -> ``fass.de``); the patched stream pre-encodes with the
    dependency's supported IDNA 2008 behavior so the certificate hostname check
    sees ``xn--fa-hia.de``.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    captured = _capture_wrap_bio(context)

    transport = SimpleNamespace(send=AsyncMock(), receive=AsyncMock(), aclose=AsyncMock())
    stream = await _tls.TLSStream.wrap(transport, hostname="faß.de", ssl_context=context)

    assert isinstance(stream, _tls.TLSStream)
    assert captured["server_side"] is False
    server_hostname = captured["server_hostname"]
    assert isinstance(server_hostname, bytes)
    assert server_hostname == _sockets.idna2008_resolve("faß.de") == b"xn--fa-hia.de"
    # The IDNA 2003 mapping (ß -> ss) must not reach hostname verification.
    assert server_hostname != "faß.de".encode("idna")


async def test_tls_wrap_passes_ascii_hostname_as_bytes():
    """Plain ASCII hostnames still arrive at ``wrap_bio`` as encoded bytes."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    captured = _capture_wrap_bio(context)

    transport = SimpleNamespace(send=AsyncMock(), receive=AsyncMock(), aclose=AsyncMock())
    await _tls.TLSStream.wrap(transport, hostname="example.com", ssl_context=context)

    assert captured["server_hostname"] == b"example.com"
