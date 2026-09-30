"""Real HTTPS clients retain CA verification through inspectable forwarding."""

import datetime
import json
import shutil
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from lyrashield.runtime.target_relay_proxy import make_server


def test_bridge_rejects_cleartext_remote_origin(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires HTTPS"):
        make_server(
            "http://lrg1.payload.signature@relay.example",
            tmp_path / "ca.crt",
            tmp_path / "ca.key",
            0,
        )


def write_ca(root: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Relay test CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = root / "ca.crt", root / "ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def relay_bridge(tmp_path: Path):
    requests = []
    replies = {}

    class Relay(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            pass

        def handle_forward(self) -> None:
            requests.append((self.command, self.path, self.headers.get("X-Lyra-Relay-Grant")))
            url = urlsplit(self.path)
            if url.path in replies:
                self.wfile.write(replies[url.path])
            elif (
                url.hostname != "target.example"
                or unquote(url.path).startswith("/admin")
                or self.command == "POST"
            ):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"scoped denial")
            elif url.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://other.example/out")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"url": self.path}).encode())

        do_GET = handle_forward  # noqa: N815 - stdlib callback
        do_HEAD = handle_forward  # noqa: N815 - stdlib callback
        do_POST = handle_forward  # noqa: N815 - stdlib callback

    cert, key = write_ca(tmp_path)
    relay = ThreadingHTTPServer(("127.0.0.1", 0), Relay)
    bridge = make_server(
        f"http://lrg1.payload.signature@127.0.0.1:{relay.server_port}", cert, key, 0
    )
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in (relay, bridge)
    ]
    for thread in threads:
        thread.start()
    try:
        yield bridge.server_port, cert, requests, replies
    finally:
        for server in (bridge, relay):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


def curl(port: int, cert: Path | None, path: str, *args: str) -> subprocess.CompletedProcess:
    executable = shutil.which("curl")
    assert executable
    return subprocess.run(  # noqa: S603 - fixed test client and fixture destinations
        [
            executable,
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--noproxy",
            "",
            "--proxy",
            f"http://127.0.0.1:{port}",
            *(["--cacert", str(cert)] if cert else []),
            *args,
            f"https://target.example{path}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_https_curl_retains_tls_and_forwards_inspectable_request(relay_bridge) -> None:
    port, cert, requests, _replies = relay_bridge
    response = curl(port, cert, "/public?x=1")
    assert response.returncode == 0, response.stderr
    assert json.loads(response.stdout) == {"url": "https://target.example/public?x=1"}
    assert requests == [("GET", "https://target.example/public?x=1", "lrg1.payload.signature")]


@pytest.mark.parametrize(
    "path,args",
    [("/%61dmin", ()), ("/public", ("--request", "POST")), ("/redirect", ("--location",))],
)
def test_https_policy_denials_survive_bridge(
    relay_bridge, path: str, args: tuple[str, ...]
) -> None:
    port, cert, _requests, _replies = relay_bridge
    response = curl(port, cert, path, "--write-out", "%{http_code}", *args)
    assert response.returncode == 0, response.stderr
    assert response.stdout.endswith("403")


def test_https_client_rejects_untrusted_testing_ca(relay_bridge) -> None:
    port, _cert, requests, _replies = relay_bridge
    response = curl(port, None, "/public")
    assert response.returncode != 0
    assert requests == []


def framed_response(relay_bridge, upstream: bytes, method: str = "GET"):
    """Read the whole downstream wire so clients cannot hide illegal bodies."""
    port, _cert, requests, replies = relay_bridge
    replies["/framing"] = upstream
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(
            f"{method} http://target.example/framing HTTP/1.1\r\n"
            "Host: target.example\r\nConnection: close\r\n\r\n".encode()
        )
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    head, body = b"".join(chunks).split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    headers = [tuple(line.lower().split(":", 1)) for line in lines[1:]]
    assert requests == [(method, "http://target.example/framing", "lrg1.payload.signature")]
    return int(lines[0].split()[1]), [(key, value.strip()) for key, value in headers], body


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_representation_length_survives_head(relay_bridge, method: str) -> None:
    status, headers, body = framed_response(
        relay_bridge, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata", method
    )
    assert status == 200
    assert ("content-length", "4") in headers
    assert body == (b"data" if method == "GET" else b"")


@pytest.mark.parametrize("status", [101, 204])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_forbidden_response_framing(relay_bridge, status: int, method: str) -> None:
    observed, headers, body = framed_response(
        relay_bridge, f"HTTP/1.1 {status} Test\r\nContent-Length: 4\r\n\r\ndata".encode(), method
    )
    assert observed == status
    assert not any(key == "content-length" for key, _value in headers)
    assert body == b""


@pytest.mark.parametrize("method,status", [("HEAD", 200), ("GET", 304)])
@pytest.mark.parametrize(
    "length_headers,expected",
    [
        (b"Content-Length: 123\r\n", "123"),
        (b"Content-Length: 0\r\n", "0"),
        (b"Content-Length: 000123\r\n", "123"),
        (b"", None),
        (b"Content-Length: -1\r\n", None),
        (b"Content-Length: +1\r\n", None),
        (b"Content-Length: invalid\r\n", None),
        (b"Content-Length: 4, 4\r\n", None),
        (b"Content-Length: 4\r\nContent-Length: 4\r\n", None),
        (b"Content-Length: 4\r\nContent-Length: 5\r\n", None),
        (b"Content-Length: 4\r\nConnection: Content-Length\r\n", None),
        (b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", None),
    ],
)
def test_bodyless_representation_length_is_conservative(
    relay_bridge, method: str, status: int, length_headers: bytes, expected: str | None
) -> None:
    observed, headers, body = framed_response(
        relay_bridge,
        f"HTTP/1.1 {status} Test\r\n".encode() + length_headers + b"\r\nillegal",
        method,
    )
    assert observed == status
    assert [value for key, value in headers if key == "content-length"] == (
        [expected] if expected is not None else []
    )
    assert body == b""


def test_all_response_connection_fields_are_stripped(relay_bridge) -> None:
    status, headers, body = framed_response(
        relay_bridge,
        b"HTTP/1.1 200 OK\r\nConnection: X-First\r\nConnection: x-SECOND, Content-Length\r\n"
        b"X-First: private\r\nX-Second: private\r\nContent-Length: 4\r\n"
        b"X-End-To-End: retained\r\n\r\ndata",
    )
    assert status == 200
    assert body == b"data"
    assert ("x-end-to-end", "retained") in headers
    assert not any(key in {"x-first", "x-second"} for key, _value in headers)
    assert [value for key, value in headers if key == "connection"] == ["close"]
    assert [value for key, value in headers if key == "content-length"] == ["4"]


def test_chunked_response_is_buffered_and_reframed(relay_bridge) -> None:
    status, headers, body = framed_response(
        relay_bridge,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n"
        b"2\r\nda\r\n2\r\nta\r\n0\r\nX-Trailer: private\r\n\r\n",
    )
    assert status == 200
    assert body == b"data"
    assert ("content-length", "4") in headers
    assert not any(key in {"transfer-encoding", "trailer", "x-trailer"} for key, _value in headers)


@pytest.mark.parametrize(
    "upstream",
    [
        b"",
        b"not HTTP\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\ncut",
        b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\ndata",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\ndata!",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ndata",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"
        b"4\r\ndata\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ncut",
    ],
)
def test_transport_and_ambiguous_lengths_fail_before_success(relay_bridge, upstream: bytes) -> None:
    status, _headers, body = framed_response(relay_bridge, upstream)
    assert status == 502
    assert b"Relay transport failed" in body


def test_oversized_response_fails_before_success(relay_bridge, monkeypatch) -> None:
    monkeypatch.setattr("lyrashield.runtime.target_relay_proxy.MAX_RESPONSE_BYTES", 16)
    status, _headers, body = framed_response(
        relay_bridge, b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n" + b"x" * 17
    )
    assert status == 502
    assert b"Relay response exceeds bound" in body
