#!/usr/bin/python3
"""Bounded offline API regressions for amended system Python and fresh seeds."""

# Each test imports the real runtime API independently. Inputs are local synthetic fixtures.
# ruff: noqa: PLC0415, S603, S702, ARG002, ARG005
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


class RuntimeSecurityTests(unittest.TestCase):
    def test_h2_duplicate_host_and_normal_http2(self):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import RequestReceived
        from h2.exceptions import ProtocolError

        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/fixture"),
            (b"host", b"fixture.invalid"),
        ]

        def receive(values):
            client = H2Connection(
                H2Configuration(client_side=True, validate_outbound_headers=False)
            )
            server = H2Connection(H2Configuration(client_side=False))
            client.initiate_connection()
            server.receive_data(client.data_to_send())
            client.send_headers(1, values, end_stream=True)
            return server.receive_data(client.data_to_send())

        events = receive(headers)
        self.assertTrue(any(isinstance(e, RequestReceived) for e in events))
        with self.assertRaises(ProtocolError):
            receive([*headers, (b"host", b"other.invalid")])

    def test_hpack_integer_limits(self):
        from hpack.exceptions import HPACKDecodingError
        from hpack.hpack import decode_integer, encode_integer

        for prefix in range(1, 9):
            for n in (0, 127, 16384, 0xFFFFFFFF):
                encoded = encode_integer(n, prefix)
                self.assertEqual(decode_integer(encoded, prefix), (n, len(encoded)))
            with self.assertRaises(HPACKDecodingError):
                decode_integer(encode_integer(0x100000000, prefix), prefix)
        for data in (b"\x1f" + b"\x80" * 10 + b"\0", b"\x1f\x80"):
            with self.assertRaises(HPACKDecodingError):
                decode_integer(data, 5)

    def test_private_jaraco_tar_api(self):
        from setuptools._vendor.jaraco import context

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for member_name, symlink in [
                ("prefix/normal.txt", False),
                ("prefix/../escape.txt", False),
                ("prefix/link", True),
            ]:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    member = tarfile.TarInfo(member_name)
                    if symlink:
                        member.type = tarfile.SYMTYPE
                        member.linkname = "../../escape.txt"
                        archive.addfile(member)
                    else:
                        member.size = 7
                        archive.addfile(member, io.BytesIO(b"fixture"))
                output = root / "out"
                with patch.object(
                    context.urllib.request, "urlopen", return_value=io.BytesIO(stream.getvalue())
                ):
                    if member_name == "prefix/normal.txt":
                        with context.tarball("https://fixture.invalid/a.tar", target_dir=output):
                            self.assertEqual((output / "normal.txt").read_text(), "fixture")
                    else:
                        with (
                            self.assertRaises(tarfile.FilterError),
                            context.tarball("https://fixture.invalid/a.tar", target_dir=output),
                        ):
                            pass
                self.assertFalse((root / "escape.txt").exists())

    def test_mako_sibling_rejected_and_rendering(self):
        from mako import exceptions
        from mako.lookup import TemplateLookup
        from mako.template import Template

        self.assertEqual(Template("Hello ${name}").render(name="fixture"), "Hello fixture")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "templates").mkdir()
            (root / "internal.txt").write_text("sibling sentinel")
            (root / "templates/normal.txt").write_text("Report ${count}")
            lookup = TemplateLookup(directories=[str(root / "templates")])
            self.assertEqual(lookup.get_template("/normal.txt").render(count=2), "Report 2")
            for name in ("//../internal.txt", "///../internal.txt", "/../internal.txt"):
                with self.assertRaises(exceptions.TemplateLookupException):
                    lookup.get_template(name)

    def test_soupsieve_valid_and_adversarial_selectors(self):
        import soupsieve
        from bs4 import BeautifulSoup

        soup = BeautifulSoup('<main><p class="item">fixture</p></main>', "html.parser")
        self.assertEqual(
            soup.select_one(" /* leading */ main > p.item /* trailing */ ").text, "fixture"
        )
        start = time.monotonic()
        for selector in (
            "a" * 12000 + "!",
            "a" * 12000 + "\\",
            "p" + " " * 16000,
            "/*" + "*" * 12000 + "/ p",
            "[x=" + "a" * 12000 + "!]",
        ):
            with contextlib.suppress(soupsieve.SelectorSyntaxError):
                soupsieve.compile(selector)
        self.assertLess(time.monotonic() - start, 5)

    def test_oauth_pkce_uses_constant_time_api(self):
        from oauthlib.oauth2.rfc6749.grant_types import authorization_code as code

        verifier = "fixture-verifier"
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        with patch.object(code.hmac, "compare_digest", wraps=code.hmac.compare_digest) as compare:
            self.assertTrue(code.code_challenge_method_s256(verifier, challenge))
            self.assertFalse(code.code_challenge_method_s256(verifier, challenge + "x"))
            self.assertTrue(code.code_challenge_method_plain(verifier, verifier))
            self.assertFalse(code.code_challenge_method_plain(verifier, "wrong"))
            self.assertEqual(compare.call_count, 4)

    def test_oauth_pkce_malformed_input_is_protocol_error(self):
        from urllib.parse import urlencode

        from oauthlib.common import Request
        from oauthlib.oauth2.rfc6749.grant_types.authorization_code import AuthorizationCodeGrant

        validator = Mock()

        def authenticate(request):
            request.client = SimpleNamespace(client_id="fixture")
            return True

        validator.authenticate_client.side_effect = authenticate
        validator.validate_code.return_value = True
        grant = AuthorizationCodeGrant(validator)
        for method, challenge, verifier in [
            ("plain", "valid", "invalid-é"),
            ("S256", "invalid-é", "valid"),
            ("plain", "valid", "wrong"),
            ("S256", "wrong", "valid"),
        ]:
            validator.get_code_challenge.return_value = challenge
            validator.get_code_challenge_method.return_value = method
            request = Request(
                "https://fixture.invalid/token",
                http_method="POST",
                body=urlencode(
                    {
                        "grant_type": "authorization_code",
                        "client_id": "fixture",
                        "code": "inert",
                        "code_verifier": verifier,
                    }
                ),
            )
            handler = Mock()
            _, body, status = grant.create_token_response(request, handler)
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body)["error"], "invalid_grant")
            handler.create_token.assert_not_called()

    def test_oauth_device_scope_is_authoritative_even_when_empty(self):
        from oauthlib.common import Request
        from oauthlib.oauth2.rfc8628.grant_types.device_code import DeviceCodeGrant
        from oauthlib.oauth2.rfc8628.request_validator import RequestValidator

        class Validator(RequestValidator):
            stored = None

            def authenticate_client(self, request):
                request.client = SimpleNamespace(client_id="fixture")
                return True

            def validate_grant_type(self, *_args):
                return True

            def validate_scopes(self, _client_id, scopes, *_args):
                return set(scopes) <= {"read", "admin"}

            def get_default_scopes(self, *_args):
                return ["read"]

            def validate_device_code(self, _client_id, _code, request):
                request.user = "fixture-user"
                if self.stored is not None:
                    request.scopes = self.stored.copy()
                return "authorized"

            def client_authentication_required(self, _request):
                return True

            def save_bearer_token(self, *_args):
                pass

        validator = Validator()
        grant = DeviceCodeGrant(validator)
        for stored in ([], ["read"], None):
            validator.stored = stored
            for supplied in ("", "&scope=admin"):
                request = Request(
                    "https://fixture.invalid/token",
                    http_method="POST",
                    body="grant_type=urn:ietf:params:oauth:grant-type:device_code"
                    "&client_id=fixture&device_code=approved" + supplied,
                )
                handler = Mock()
                handler.create_token.side_effect = lambda req, *_args: {
                    "access_token": "inert",
                    "scope": " ".join(req.scopes),
                }
                _, body, status = grant.create_token_response(request, handler)
                if stored is None:
                    self.assertEqual(status, 400)
                    self.assertEqual(json.loads(body)["error"], "server_error")
                    handler.create_token.assert_not_called()
                else:
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body)["scope"], " ".join(stored))

    def test_oauth_device_grant_status_and_client_api(self):
        from oauthlib.common import Request
        from oauthlib.oauth2.rfc6749.errors import (
            InvalidGrantError,
            InvalidRequestError,
        )
        from oauthlib.oauth2.rfc8628.clients.device import DeviceClient
        from oauthlib.oauth2.rfc8628.errors import (
            AccessDenied,
            AuthorizationPendingError,
            ExpiredTokenError,
            SlowDownError,
        )
        from oauthlib.oauth2.rfc8628.grant_types.device_code import DeviceCodeGrant
        from oauthlib.oauth2.rfc8628.request_validator import RequestValidator

        class Validator(RequestValidator):
            status = None

            def authenticate_client(self, request):
                request.client = SimpleNamespace(client_id="fixture")
                return True

            def validate_grant_type(self, *args):
                return True

            def validate_scopes(self, *args):
                return True

            def get_default_scopes(self, *args):
                return ["fixture"]

            def validate_device_code(self, client_id, code, request):
                self.last = (client_id, code)
                if self.status == "authorized":
                    request.user = "fixture-user"
                    request.scopes = ["fixture-scope"]
                return self.status

        validator = Validator()
        grant = DeviceCodeGrant(validator)

        def request(body="device_code=fixture-code"):
            return Request(
                "https://fixture.invalid/token",
                http_method="POST",
                body="grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=fixture&"
                + body,
            )

        for status, error in [
            (None, InvalidGrantError),
            ("unknown", InvalidGrantError),
            ("authorization_pending", AuthorizationPendingError),
            ("slow_down", SlowDownError),
            ("expired_token", ExpiredTokenError),
            ("access_denied", AccessDenied),
        ]:
            validator.status = status
            with self.assertRaises(error):
                grant.validate_token_request(request())
        with self.assertRaises(InvalidRequestError):
            grant.validate_token_request(request(""))
        handler = Mock()
        handler.create_token.return_value = {
            "access_token": "fixture-token",
            "token_type": "Bearer",
        }
        validator.client_authentication_required = lambda req: True
        validator.save_token = Mock()
        validator.status = "authorization_pending"
        _, body, status = grant.create_token_response(request(), handler)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "authorization_pending")
        handler.create_token.assert_not_called()
        validator.status = None
        _, body, status = grant.create_token_response(request(), handler)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "invalid_grant")
        handler.create_token.assert_not_called()
        validator.status = "authorized"
        _, body, status = grant.create_token_response(request(), handler)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["access_token"], "fixture-token")
        handler.create_token.assert_called_once()
        req = request()
        grant.validate_token_request(req)
        self.assertEqual(validator.last, ("fixture", "fixture-code"))
        self.assertEqual(req.scopes, ["fixture-scope"])
        self.assertEqual(req.user, "fixture-user")
        with self.assertRaises(InvalidRequestError):
            grant.validate_token_request(request("device_code=a&device_code=b"))
        client = DeviceClient("fixture")
        self.assertIn(
            "device_code=fixture-code", client.prepare_request_body(device_code="fixture-code")
        )

    def test_pip_actual_vendor_and_msgpack_fallback(self):
        from pip._vendor import msgpack, requests, urllib3

        self.assertEqual(urllib3.__version__, "2.8.0")
        adapter = requests.adapters.HTTPAdapter()
        self.assertIs(type(adapter.poolmanager), urllib3.PoolManager)
        self.assertIn("fallback", msgpack.Packer.__module__)
        self.assertIn("fallback", msgpack.Unpacker.__module__)
        self.assertEqual(msgpack.unpackb(msgpack.packb({"fixture": 2}), raw=False), {"fixture": 2})

    def test_leaf_apis_and_tool_libraries(self):
        import anyio
        import dns.message
        import jwt
        import mitmproxy.http
        import msgpack
        import pyasn1.codec.der.decoder
        import pyasn1.codec.der.encoder
        from pyasn1.type.univ import Integer
        from tornado.escape import url_escape, url_unescape

        async def fixture():
            await anyio.sleep(0)

        anyio.run(fixture)
        packet = dns.message.make_query("fixture.invalid", "A")
        self.assertEqual(dns.message.from_wire(packet.to_wire()).question, packet.question)
        encoded = jwt.encode(
            {"fixture": "ok"}, "fixture-secret-key-of-at-least-32-bytes", algorithm="HS256"
        )
        self.assertEqual(
            jwt.decode(encoded, "fixture-secret-key-of-at-least-32-bytes", algorithms=["HS256"])[
                "fixture"
            ],
            "ok",
        )
        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(encoded, "other-secret-key-of-at-least-32-bytes", algorithms=["HS256"])
        self.assertEqual(msgpack.unpackb(msgpack.packb([1, "fixture"]), raw=False), [1, "fixture"])
        value, rest = pyasn1.codec.der.decoder.decode(pyasn1.codec.der.encoder.encode(Integer(42)))
        self.assertEqual(int(value), 42)
        self.assertEqual(rest, b"")
        self.assertEqual(url_unescape(url_escape("fixture /?")), "fixture /?")
        request = mitmproxy.http.Request.make("GET", "https://fixture.invalid/")
        self.assertEqual(request.host, "fixture.invalid")

    def test_wapiti_actual_html_report(self):
        from wapitiCore.report.htmlreportgenerator import HTMLReportGenerator

        generator = HTMLReportGenerator()
        generator.set_report_info(
            target="https://fixture.invalid/",
            scope="url",
            date=time.gmtime(0),
            version="fixture",
            auth=None,
            crawled_pages=[],
            crawled_pages_nbr=0,
            detailed_report_level=0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report"
            generator.generate_report(str(output))
            pages = list(output.glob("fixture.invalid_*.html"))
            self.assertEqual(len(pages), 1)
            self.assertIn("fixture.invalid", pages[0].read_text())

    def test_ndiff_actual_xml_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, port in [("old.xml", 80), ("new.xml", 443)]:
                (root / name).write_text(
                    '<?xml version="1.0"?><nmaprun scanner="nmap" args="fixture" version="7.99">'
                    '<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
                    f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
                    "</port></ports></host></nmaprun>"
                )
            result = subprocess.run(
                ["/usr/bin/ndiff", str(root / "old.xml"), str(root / "new.xml")],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("80/tcp", result.stdout)
            self.assertIn("443/tcp", result.stdout)

    def test_downstream_receipts_match_installed_bytes(self):
        from verify_receipts import verify

        verify()

    def test_actual_system_module_origins(self):
        import importlib

        for name in (
            "pip",
            "pip._vendor.urllib3",
            "anyio",
            "dns",
            "jwt",
            "msgpack",
            "pyasn1",
            "tornado",
            "h2",
            "hpack",
            "soupsieve",
            "mako",
            "oauthlib",
            "setuptools._vendor.jaraco.context",
        ):
            module = importlib.import_module(name)
            self.assertTrue(
                str(Path(module.__file__).resolve()).startswith("/usr/lib/python3/dist-packages/"),
                (name, module.__file__),
            )

    def test_fresh_offline_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            environment = Path(tmp) / "venv"
            subprocess.run(
                ["/usr/bin/python3", "-m", "venv", str(environment)], check=True, timeout=60
            )
            python = str(environment / "bin/python")
            subprocess.run(
                [
                    python,
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links=/usr/share/python-wheels",
                    "setuptools==78.1.1",
                ],
                check=True,
                timeout=60,
            )
            code = """import pip._vendor.urllib3 as u; import pip._vendor.requests as r
import setuptools, pkg_resources
from setuptools._vendor.jaraco import context
assert u.__version__ == '2.8.0'
assert type(r.adapters.HTTPAdapter().poolmanager) is u.PoolManager
assert hasattr(context, '_default_filter')
print('fresh offline seed verified', setuptools.__version__, u.__version__)
"""
            subprocess.run([python, "-c", code], check=True, timeout=30)
            subprocess.run(
                [
                    python,
                    str(Path(__file__).resolve()),
                    "RuntimeSecurityTests.test_private_jaraco_tar_api",
                    "RuntimeSecurityTests.test_pip_actual_vendor_and_msgpack_fallback",
                ],
                check=True,
                timeout=30,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
