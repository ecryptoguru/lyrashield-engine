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
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from semgrep.mcp.utilities.token_verifier import IntrospectionTokenVerifier


def main() -> None:
    assert version("semgrep") == "1.178.0"
    assert version("PyJWT") == "2.14.0"
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

    verify_cli()
    print(  # noqa: T201 - explicit offline compatibility receipt
        "Semgrep/PyJWT: RS256 accepted; forged/expired denied; "
        "JWKS redirect denied; CLI finding passed"
    )


def verify_cli() -> None:
    environment = os.environ | {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    cli = ["/app/.venv/bin/semgrep"]
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
