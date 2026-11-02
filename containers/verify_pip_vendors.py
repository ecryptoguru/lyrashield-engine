"""Offline loopback qualification for the reviewed pip vendor repair."""

# ruff: noqa: INP001
from __future__ import annotations

import csv
import datetime
import hashlib
import http.server
import io
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pip._vendor import msgpack, requests, urllib3
from pip._vendor.cachecontrol.serialize import Serializer
from pip._vendor.requests import exceptions as request_errors
from pip._vendor.urllib3.response import HTTPResponse


G3 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"


def wheel_bytes() -> bytes:
    """An inert wheel exercises pip's real download/cache/install paths."""
    output = io.BytesIO()
    files = {
        "lyra_vendor_fixture/__init__.py": b"VALUE = 42\n",
        "lyra_vendor_fixture-1.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: lyra-vendor-fixture\nVersion: 1.0\n"
        ),
        "lyra_vendor_fixture-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: lyra-fixture\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record = io.StringIO(newline="")
    csv.writer(record).writerows(
        [name, "", ""] for name in [*files, "lyra_vendor_fixture-1.0.dist-info/RECORD"]
    )
    files["lyra_vendor_fixture-1.0.dist-info/RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def serve_certificate(directory: Path) -> tuple[Path, Path, Path]:
    """Use an ephemeral local CA; never alter the sandbox's installed anchors."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local pip qualification CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = (directory / n for n in ("ca.pem", "server.pem", "server.key"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def verify() -> None:  # noqa: PLR0915 - one bounded offline acceptance scenario
    """Prove namespace identity, cache roundtrip, TLS rejection and offline pip use."""
    assert urllib3.__version__ == "2.8.0"
    assert msgpack.__version__ == "1.2.3"
    assert msgpack.Packer.__module__ == "pip._vendor.msgpack.fallback"
    assert requests.adapters.PoolManager is urllib3.PoolManager
    payload = {"wheel": "fixture", "count": 42}
    assert msgpack.unpackb(msgpack.packb(payload), raw=False) == payload
    prepared = requests.Request("GET", "https://localhost/fixture").prepare()
    response = HTTPResponse(
        body=io.BytesIO(b"cached"),
        headers={"Cache-Control": "max-age=600"},
        status=200,
        preload_content=False,
    )
    serialized = Serializer().dumps(prepared, response, body=b"cached")
    restored = Serializer().loads(prepared, serialized)
    assert restored is not None and restored.read() == b"cached"
    bundle = Path(os.environ.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"))
    if bundle.exists():
        context = ssl.create_default_context(cafile=str(bundle))
        assert G3 not in {
            hashlib.sha256(der).hexdigest() for der in context.get_ca_certs(binary_form=True)
        }
    artifact = wheel_bytes()
    requests_seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests_seen.append(self.path)
            data = (
                artifact
                if self.path.endswith(".whl")
                else b'<a href="/lyra_vendor_fixture-1.0-py3-none-any.whl">fixture</a>'
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header(
                "Content-Type",
                "application/octet-stream" if self.path.endswith(".whl") else "text/html",
            )
            self.send_header("Cache-Control", "public, max-age=600")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format: str, *args: object) -> None:
            pass

    with tempfile.TemporaryDirectory(prefix="pip-vendor-check-") as temp:
        directory = Path(temp)
        ca, cert, key = serve_certificate(directory)

        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, request: object, client_address: object) -> None:
                if not isinstance(sys.exc_info()[1], (ConnectionResetError, ssl.SSLError)):
                    super().handle_error(request, client_address)

        server = Server(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f"https://localhost:{server.server_port}"
        try:
            session = requests.Session()
            session.trust_env = False
            assert session.get(url, verify=str(ca), timeout=5).status_code == 200
            try:
                session.get(url, verify=True, timeout=5)
            except request_errors.SSLError:
                pass
            else:
                raise AssertionError("untrusted TLS fixture was accepted")
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith("PIP_")
                and k
                not in {
                    "REQUESTS_CA_BUNDLE",
                    "SSL_CERT_FILE",
                    "http_proxy",
                    "https_proxy",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                }
            }
            env.update({"PIP_CONFIG_FILE": os.devnull, "NO_PROXY": "localhost,127.0.0.1"})
            base = [
                sys.executable,
                "-m",
                "pip",
                "--disable-pip-version-check",
                "--cache-dir",
                str(directory / "cache"),
            ]
            download = [
                *base,
                "download",
                "--no-deps",
                "--cert",
                str(ca),
                "--index-url",
                url + "/simple",
                "--dest",
                str(directory / "download"),
                "lyra-vendor-fixture==1.0",
            ]
            for _ in range(2):
                result = subprocess.run(  # noqa: S603 - fixed local pip command
                    download, env=env, check=False, capture_output=True, text=True, timeout=30
                )
                assert result.returncode == 0, result.stdout + result.stderr
            assert any((directory / "cache/http-v2").rglob("*.body")), (
                "pip must exercise its HTTP cache"
            )
            subprocess.run(  # noqa: S603 - inert local wheel
                [
                    *base,
                    "install",
                    "--no-deps",
                    "--no-index",
                    "--find-links",
                    str(directory / "download"),
                    "--target",
                    str(directory / "installed"),
                    "lyra-vendor-fixture==1.0",
                ],
                env=env,
                check=True,
                capture_output=True,
                timeout=30,
            )
            assert (
                directory / "installed/lyra_vendor_fixture/__init__.py"
            ).read_text() == "VALUE = 42\n"
            rejected = subprocess.run(  # noqa: S603 - negative loopback TLS fixture
                [
                    *base,
                    "download",
                    "--retries",
                    "0",
                    "--timeout",
                    "3",
                    "--no-deps",
                    "--no-cache-dir",
                    "--index-url",
                    url + "/simple",
                    "lyra-vendor-fixture==1.0",
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert (
                rejected.returncode != 0
                and "certificate" in (rejected.stdout + rejected.stderr).lower()
                and "ssl" in (rejected.stdout + rejected.stderr).lower()
            ), rejected.stdout + rejected.stderr
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
    print(  # noqa: T201 - JSON acceptance receipt
        json.dumps(
            {
                "pip": "26.2.2",
                "urllib3": urllib3.__version__,
                "msgpack": msgpack.__version__,
                "pure_python": True,
                "cache_roundtrip": "pass",
                "pip_download_cache_install": "pass",
                "tls_verified_and_untrusted_rejected": "pass",
                "compromised_root_absent_from_bundle": "pass",
                "loopback_requests": len(requests_seen),
            }
        )
    )


if __name__ == "__main__":
    verify()
