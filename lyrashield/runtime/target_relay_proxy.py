"""Sandbox-local TLS inspection bridge to the scan-scoped target relay.

Clients use a normal HTTP proxy. HTTPS terminates with the sandbox's existing
trusted testing CA; every decrypted request is forwarded in absolute form to
the relay, which alone resolves targets, verifies their TLS, and enforces scope.
No client-controlled destination is ever dialed by this bridge.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import http.client
import ipaddress
import os
import pwd
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socket import socket
from urllib.parse import unquote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
HOP_HEADERS = {
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "x-lyra-relay-grant",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "host",
    "content-length",
}


def certificate_context(
    host: str, issuer: x509.Certificate, key: ec.EllipticCurvePrivateKey
) -> ssl.SSLContext:
    """Issue a short-lived leaf; private key files exist only during loading."""
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    alternative_name: x509.GeneralName
    try:
        alternative_name = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alternative_name = x509.DNSName(host)
    now = datetime.datetime.now(datetime.UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
        .issuer_name(issuer.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([alternative_name]), critical=False)
        .sign(key, hashes.SHA256())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    with tempfile.TemporaryDirectory(prefix="relay-leaf-") as temporary:
        cert = Path(temporary) / "cert.pem"
        private = Path(temporary) / "key.pem"
        cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private.chmod(0o600)
        context.load_cert_chain(cert, private)
    return context


def make_server(
    relay_url: str, ca_cert: Path, ca_key: Path, port: int = 48081
) -> ThreadingHTTPServer:
    relay = urlsplit(relay_url)
    if relay.scheme not in ("http", "https") or not relay.hostname or not relay.username:
        raise ValueError("Authenticated relay origin required")
    if relay.scheme == "http" and relay.hostname not in ("127.0.0.1", "::1"):
        raise ValueError("Authenticated relay requires HTTPS outside loopback")
    relay_host = relay.hostname
    grant = unquote(relay.username)
    issuer = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    key = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("Sandbox testing CA must use an EC key")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Do not prefetch bytes from the TLS handshake following CONNECT.
        rbufsize = 0
        timeout = 30
        tunnel_host: str | None = None

        def log_message(self, _format: str, *_args: object) -> None:
            # URLs, proxy credentials and target responses are sensitive.
            pass

        def do_CONNECT(self) -> None:
            if self.tunnel_host is not None:
                self.send_error(403, "Nested tunnel denied")
                return
            try:
                target = urlsplit("//" + self.path)
                host = target.hostname
                valid = (
                    host
                    and target.port == 443
                    and not target.username
                    and not target.path
                    and not target.query
                    and not target.fragment
                )
                if not valid or host is None:
                    self.send_error(403, "Invalid HTTPS authority")
                    return
                context = certificate_context(host, issuer, key)
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.wfile.flush()
                self.connection = context.wrap_socket(self.connection, server_side=True)
                self.rfile = self.connection.makefile("rb", self.rbufsize)
                self.wfile = self.connection.makefile("wb", 0)
                self.tunnel_host = host
                self.close_connection = False
                self.handle_one_request()
            except (ValueError, OSError):
                self.close_connection = True

        def request_body(self) -> bytes | None:
            lengths = self.headers.get_all("Content-Length", [])
            try:
                size = int(lengths[0]) if lengths else 0
            except ValueError:
                self.send_error(400, "Invalid content length")
                return None
            if len(lengths) > 1 or size < 0 or size > MAX_BODY_BYTES:
                self.send_error(413, "Request body exceeds bound")
                return None
            body = bytearray()
            while len(body) < size:
                chunk = self.rfile.read(size - len(body))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) != size:
                self.send_error(400, "Incomplete request body")
                return None
            return bytes(body)

        def forward(self) -> None:
            self.close_connection = True
            if self.headers.get("Transfer-Encoding") or self.headers.get("Upgrade"):
                self.send_error(400, "Streaming request or protocol upgrade unsupported")
                return
            if self.tunnel_host:
                if not self.path.startswith("/") or self.path.startswith("//"):
                    self.send_error(400, "Expected origin-form request")
                    return
                host = f"[{self.tunnel_host}]" if ":" in self.tunnel_host else self.tunnel_host
                url = f"https://{host}{self.path}"
            else:
                target = urlsplit(self.path)
                if (
                    target.scheme != "http"
                    or not target.hostname
                    or target.username
                    or target.password
                ):
                    self.send_error(400, "Expected absolute HTTP URL")
                    return
                url = self.path
            body = self.request_body()
            if body is None:
                return
            connection_headers = {
                name.strip().lower() for name in self.headers.get("Connection", "").split(",")
            }
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in HOP_HEADERS | connection_headers
            }
            headers["X-Lyra-Relay-Grant"] = grant
            connection_type = (
                http.client.HTTPSConnection
                if relay.scheme == "https"
                else http.client.HTTPConnection
            )
            connection = connection_type(relay_host, relay.port, timeout=30)
            try:
                connection.request(self.command, url, body=body or None, headers=headers)
                response = connection.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    self.send_error(502, "Relay response exceeds bound")
                    return
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in HOP_HEADERS:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
            except (OSError, http.client.HTTPException):
                # Buffer before replying so transport failures cannot appear
                # as a successful truncated target response.
                with contextlib.suppress(OSError):
                    self.send_error(502, "Relay transport failed")
                self.close_connection = True
            finally:
                connection.close()

        do_GET = forward  # noqa: N815 - stdlib callback
        do_HEAD = forward  # noqa: N815 - stdlib callback
        do_POST = forward  # noqa: N815 - stdlib callback
        do_PUT = forward  # noqa: N815 - stdlib callback
        do_PATCH = forward  # noqa: N815 - stdlib callback
        do_DELETE = forward  # noqa: N815 - stdlib callback
        do_OPTIONS = forward  # noqa: N815 - stdlib callback

    class BoundedServer(ThreadingHTTPServer):
        slots = threading.BoundedSemaphore(16)

        def process_request_thread(
            self, request: socket | tuple[bytes, socket], client_address: object
        ) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

        def process_request(
            self, request: socket | tuple[bytes, socket], client_address: object
        ) -> None:
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            super().process_request(request, client_address)

    server = BoundedServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=48081)
    args = parser.parse_args()
    server = make_server(
        Path("/run/lyrashield-relay/upstream").read_text(encoding="ascii"),
        Path("/app/certs/ca.crt"),
        Path("/app/certs/ca.key"),
        args.port,
    )
    if os.getuid() != 0:
        raise RuntimeError("Relay bridge must start as root before dropping privileges")
    identity = pwd.getpwnam("nobody")
    os.setgroups([])
    os.setgid(identity.pw_gid)
    os.setuid(identity.pw_uid)
    with server:
        server.serve_forever()


if __name__ == "__main__":
    main()
