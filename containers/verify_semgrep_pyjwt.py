"""Offline, real Semgrep JWT/CLI compatibility checks for the reviewed PyJWT patch.

Run with /app/.venv/bin/python in the built sandbox on an internal network.
All JWT keys are ephemeral and JWKS traffic remains on the loopback fixture.
"""

# ruff: noqa: INP001

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.threading import ThreadingInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from semgrep.mcp.utilities.token_verifier import IntrospectionTokenVerifier


def main() -> None:
    assert version("semgrep") == "1.178.0"
    assert version("PyJWT") == "2.15.1"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid="fixture", alg="RS256", use="sig")
    requests: list[str] = []

    class Origin(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.1:{self.server.server_port}/unexpected"
                )
                self.end_headers()
                return
            payload = json.dumps({"keys": [public]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{origin.server_port}"
        verifier = IntrospectionTokenVerifier(url + "/introspect", url + "/jwks", url)
        claims = {"client_id": "fixture", "scope": "read", "exp": int(time.time()) + 120}
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture"})
        accepted = asyncio.run(verifier.verify_token(token))
        assert (
            accepted is not None and accepted.client_id == "fixture" and accepted.scopes == ["read"]
        )
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(claims, wrong_key, algorithm="RS256", headers={"kid": "fixture"})
        assert asyncio.run(verifier.verify_token(forged)) is None
        expired = jwt.encode(
            claims | {"exp": int(time.time()) - 120},
            key,
            algorithm="RS256",
            headers={"kid": "fixture"},
        )
        assert asyncio.run(verifier.verify_token(expired)) is None
        redirect_verifier = IntrospectionTokenVerifier(url + "/introspect", url + "/redirect", url)
        try:
            asyncio.run(redirect_verifier.verify_token(token))
        except jwt.PyJWKClientError:
            pass
        else:
            raise AssertionError("Redirected JWKS must not produce an accepted token")
        assert requests == ["/jwks", "/redirect"], requests
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)

    verify_telemetry()
    verify_cli()
    print(  # noqa: T201 - explicit offline compatibility receipt
        "Semgrep/PyJWT: RS256 accepted; forged/expired denied; "
        "JWKS redirect denied; telemetry context/export passed; CLI finding passed"
    )


def _telemetry_server(received: list[bytes]) -> ThreadingHTTPServer:
    class TelemetryOrigin(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

        def do_POST(self) -> None:
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

    return ThreadingHTTPServer(("127.0.0.1", 0), TelemetryOrigin)


def verify_telemetry() -> None:
    """Exercise the exact telemetry graph used by the unchanged Semgrep CLI."""

    assert version("mcp") == "1.30.0"
    assert version("opentelemetry-api") == "1.45.1"
    assert version("opentelemetry-sdk") == "1.45.1"
    received = []

    origin = _telemetry_server(received)
    server_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    server_thread.start()
    provider = TracerProvider()
    memory = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(memory))
    tracer = provider.get_tracer("semgrep-compat")
    request_instrumentor = RequestsInstrumentor()
    thread_instrumentor = ThreadingInstrumentor()
    request_instrumentor.instrument(tracer_provider=provider)
    thread_instrumentor.instrument()
    try:

        def child() -> None:
            with tracer.start_as_current_span("compat-child"):
                requests.get(f"http://127.0.0.1:{origin.server_port}/", timeout=5)

        with tracer.start_as_current_span("compat-root"):
            worker = threading.Thread(target=child)
            worker.start()
            worker.join(timeout=10)
            assert not worker.is_alive()
        spans = memory.get_finished_spans()
        root = next(span for span in spans if span.name == "compat-root")
        nested = next(span for span in spans if span.name == "compat-child")
        assert nested.parent.span_id == root.context.span_id
        assert any(span.kind.name == "CLIENT" for span in spans)
        exporter = OTLPSpanExporter(
            endpoint=f"http://127.0.0.1:{origin.server_port}/v1/traces", timeout=5
        )
        try:
            assert exporter.export(spans) is SpanExportResult.SUCCESS
        finally:
            exporter.shutdown()
        assert received and b"semgrep-compat" in received[0]
    finally:
        request_instrumentor.uninstrument()
        thread_instrumentor.uninstrument()
        provider.shutdown()
        origin.shutdown()
        origin.server_close()
        server_thread.join(timeout=5)


def verify_cli() -> None:
    environment = os.environ | {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    cli = [str(Path(sys.executable).with_name("semgrep"))]
    result = subprocess.run(  # noqa: S603 - fixed installed CLI and local fixture
        [*cli, "--version"], env=environment, capture_output=True, text=True, check=True, timeout=30
    )
    assert result.stdout.strip() == "1.178.0", result.stdout
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        rule = root / "rule.yaml"
        target = root / "fixture.py"
        rule.write_text(
            "rules:\n- id: fixture-eval\n  languages: [python]\n  severity: ERROR\n"
            "  message: fixture\n  pattern: eval($X)\n",
            encoding="utf-8",
        )
        target.write_text("eval(user_input)\n", encoding="utf-8")
        result = subprocess.run(  # noqa: S603 - fixed CLI flags and local fixture
            [
                *cli,
                "--config",
                str(rule),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                str(target),
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        findings = json.loads(result.stdout)
        assert not findings["errors"], findings["errors"]
        assert len(findings["results"]) == 1, findings
        assert findings["results"][0]["check_id"].endswith("fixture-eval"), findings


if __name__ == "__main__":
    main()
