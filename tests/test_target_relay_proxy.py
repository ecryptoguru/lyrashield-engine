"""Real HTTPS clients retain CA verification through inspectable forwarding."""

import datetime
import json
import shutil
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

    class Relay(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            pass

        def handle_forward(self) -> None:
            requests.append((self.command, self.path, self.headers.get("X-Lyra-Relay-Grant")))
            url = urlsplit(self.path)
            if (
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
        yield bridge.server_port, cert, requests
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
    port, cert, requests = relay_bridge
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
    port, cert, _requests = relay_bridge
    response = curl(port, cert, path, "--write-out", "%{http_code}", *args)
    assert response.returncode == 0, response.stderr
    assert response.stdout.endswith("403")


def test_https_client_rejects_untrusted_testing_ca(relay_bridge) -> None:
    port, _cert, requests = relay_bridge
    response = curl(port, None, "/public")
    assert response.returncode != 0
    assert requests == []
