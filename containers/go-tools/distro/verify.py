"""Check installed distro packages and exercise their CLIs against loopback."""

# ruff: noqa: INP001
import argparse
import ctypes
import hashlib
import http.server
import json
import os
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_installed() -> None:
    supplement_path = Path("/usr/local/share/lyrashield/go-tools/distro/applications.cdx.json")
    entries = json.loads(supplement_path.read_text())["components"]
    components = {entry["name"]: entry for entry in entries}
    assert len(components) == len(entries) == 4
    for name, version in (
        ("ffuf", "2.2.1-1"),
        ("naabu", "2.6.1-0kali1"),
        ("nuclei", "3.11.1-0kali1"),
        ("subfinder", "2.16.0-0kali1"),
    ):
        binary = Path("/usr/bin") / name
        assert Path(shutil.which(name) or "").resolve() == binary
        actual = subprocess.check_output(  # noqa: S603 - fixed installed package
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}", name], text=True
        )
        assert actual == version + "+lyra1", (name, actual)
        integrity = subprocess.check_output(  # noqa: S603 - fixed package verification
            ["/usr/bin/dpkg", "--verify", name], text=True
        )
        assert not integrity, (name, integrity)
        receipt = Path("/usr/share/doc") / name / "lyrashield-build"
        assert (receipt / "binary.sha256").read_text().split() == [
            file_digest(binary),
            f"usr/bin/{name}",
        ]
        module = (receipt / "go.mod").read_text().splitlines()[0].removeprefix("module ")
        component = components.pop(module)
        upstream = version.rsplit("-", 1)[0]
        assert component["version"] == "v" + upstream
        assert component["purl"] == f"pkg:golang/{module}@v{upstream}"
        props = {item["name"]: item["value"] for item in component["properties"]}
        descriptor = receipt / f"{name}_{version}.dsc"
        assert file_digest(descriptor) == props["lyrashield:kali:source-descriptor-sha256"]
        expected_orig = props["lyrashield:kali:orig-tar-sha256"]
        assert any(
            line.split()[:1] == [expected_orig]
            and line.split()[-1] == f"{name}_{upstream}.orig.tar.gz"
            for line in descriptor.read_text().splitlines()
        )
        assert (receipt / "graph.sha256").read_text().split() == [
            file_digest(receipt / "go.mod"),
            "go.mod",
            file_digest(receipt / "go.sum"),
            "go.sum",
        ]
    assert not components

    # Naabu's Go pcap bindings use dlopen, so neither ldd nor package installation
    # alone establishes that the linked runtime actually provides pcap APIs.
    pcap = ctypes.CDLL("libpcap.so.0.8")
    pcap.pcap_lib_version.restype = ctypes.c_char_p
    assert b"libpcap" in pcap.pcap_lib_version()


def verify_loopback() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "hit").write_text("lyra-loopback-match")
        (root / "words").write_text("hit\nmissing\n")
        (root / "providers.yaml").write_text("{}\n")
        (root / "fixture.yaml").write_text(
            "id: lyra-loopback\ninfo:\n  name: Loopback fixture\n  author: lyra\n  severity: info\n"
            "http:\n  - method: GET\n    path: ['{{BaseURL}}/hit']\n    matchers:\n"
            "      - type: word\n        words: ['lyra-loopback-match']\n"
        )
        env = {
            k: v
            for k, v in os.environ.items()
            if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
        }
        env.update(
            HOME=temp, XDG_CONFIG_HOME=temp, NO_PROXY="127.0.0.1", DISABLE_CLOUD_UPLOAD="true"
        )

        def run(*command: str, expected: int = 0) -> str:
            result = subprocess.run(  # noqa: S603 - fixed tools and loopback inputs
                command,
                cwd=root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
            assert result.returncode == expected, (command, result.returncode, result.stdout)
            return result.stdout

        def handler(*args, **kwargs):
            return http.server.SimpleHTTPRequestHandler(*args, directory=temp, **kwargs)

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            port = str(server.server_port)
            url = "http://127.0.0.1:" + port
            try:
                run(
                    "ffuf",
                    "-s",
                    "-noninteractive",
                    "-w",
                    "words",
                    "-u",
                    url + "/FUZZ",
                    "-mc",
                    "200",
                    "-o",
                    "hits.json",
                    "-of",
                    "json",
                )
                assert [
                    r["url"] for r in json.loads((root / "hits.json").read_text())["results"]
                ] == [url + "/hit"]
                found = run(
                    "naabu",
                    "-host",
                    "127.0.0.1",
                    "-p",
                    port,
                    "-s",
                    "c",
                    "-duc",
                    "-silent",
                    "-retries",
                    "1",
                    "-verify",
                )
                assert "127.0.0.1:" + port in found, found
                run("nuclei", "-validate", "-duc", "-ni", "-t", "fixture.yaml")
                found = run(
                    "nuclei", "-duc", "-ni", "-silent", "-nc", "-t", "fixture.yaml", "-u", url
                )
                assert "lyra-loopback" in found and url in found, found
            finally:
                server.shutdown()
                thread.join()

        run(
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.maximum_version = ssl.TLSVersion.TLSv1_2
        tls.set_ciphers("AES128-SHA:@SECLEVEL=0")
        tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as legacy:
            legacy.socket = tls.wrap_socket(legacy.socket, server_side=True)
            thread = threading.Thread(target=legacy.serve_forever)
            thread.start()
            url = f"https://127.0.0.1:{legacy.server_port}"
            try:
                run(
                    "ffuf",
                    "-s",
                    "-noninteractive",
                    "-w",
                    "words",
                    "-u",
                    url + "/FUZZ",
                    "-mc",
                    "200",
                    "-o",
                    "tls.json",
                    "-of",
                    "json",
                )
                assert [
                    r["url"] for r in json.loads((root / "tls.json").read_text())["results"]
                ] == [url + "/hit"]
            finally:
                legacy.shutdown()
                thread.join()
        verify_sha1_limit(root, run)
        verify_subfinder(root, run)


def verify_subfinder(root: Path, run: Callable[..., str]) -> None:
    name = "found.fixture.invalid"
    queries: list[str] = []
    requests: list[str] = []

    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"http://{name}/artifact\n".encode())

    class Resolver(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            message, udp = self.request
            end = message.index(b"\0", 12) + 1
            labels = message[12 : end - 1]
            parts = []
            while labels:
                size = labels[0]
                parts.append(labels[1 : size + 1].decode())
                labels = labels[size + 1 :]
            host = ".".join(parts)
            queries.append(host)
            record = b""
            if host == name and message[end : end + 2] == b"\0\1":
                record = struct.pack("!HHHIH4s", 0xC00C, 1, 1, 10, 4, socket.inet_aton("192.0.2.7"))
            header = message[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(record), 0, 0)
            udp.sendto(header + message[12 : end + 4] + record, self.client_address)

    with (
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy) as proxy,
        socketserver.UDPServer(("127.0.0.1", 0), Resolver) as dns,
    ):
        (root / "resolvers.txt").write_text(f"127.0.0.1:{dns.server_address[1]}\n")
        threads = [threading.Thread(target=s.serve_forever) for s in (proxy, dns)]
        for thread in threads:
            thread.start()
        try:
            assert "v2.16.0" in run("subfinder", "-version")
            output = run(
                "subfinder",
                "-duc",
                "-d",
                "fixture.invalid",
                "-s",
                "waybackarchive",
                "-v",
                "-active",
                "-ip",
                "-oJ",
                "-pc",
                "providers.yaml",
                "-rL",
                "resolvers.txt",
                "-r",
                f"127.0.0.1:{dns.server_address[1]}",
                "-proxy",
                f"http://127.0.0.1:{proxy.server_port}",
                "-timeout",
                "3",
            )
            assert "Loading provider config from providers.yaml" in output, output
            hits = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            assert any(hit.get("host") == name and hit.get("ip") == "192.0.2.7" for hit in hits), (
                output,
                requests,
                queries,
            )
            assert name in queries and any(
                "web.archive.org/cdx/search/cdx" in req for req in requests
            )
        finally:
            proxy.shutdown()
            dns.shutdown()
            for thread in threads:
                thread.join()

    (root / "invalid-provider.yaml").write_text("waybackarchive: [\n")
    rejected = run(
        "subfinder",
        "-duc",
        "-d",
        "fixture.invalid",
        "-s",
        "waybackarchive",
        "-pc",
        "invalid-provider.yaml",
        "-rL",
        "missing-resolvers.txt",
        expected=1,
    )
    assert "Could not read providers from invalid-provider.yaml" in rejected, rejected
    assert "missing-resolvers.txt" in rejected, rejected


def verify_sha1_limit(root: Path, run: Callable[..., str]) -> None:
    # Check the advertised limitation against an actual SHA-1-only peer.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        address = f"127.0.0.1:{reservation.getsockname()[1]}"
    profile = ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0", "-sigalgs", "RSA+SHA1"]
    server = subprocess.Popen(  # noqa: S603 - fixture bound to loopback
        [
            "/usr/bin/openssl",
            "s_server",
            "-accept",
            address,
            "-cert",
            "cert.pem",
            "-key",
            "key.pem",
            "-www",
            *profile,
        ],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for attempt in range(60):
            if server.poll() is not None:
                raise RuntimeError("OpenSSL failed to start the SHA-1-only loopback peer")
            try:
                with socket.create_connection(
                    ("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=1
                ):
                    break
            except ConnectionRefusedError:
                if attempt == 59:
                    raise
                time.sleep(0.05)
        # A positive control rules out a broken server producing an empty ffuf match.
        probe = subprocess.run(  # noqa: S603 - fixed loopback control
            ["/usr/bin/openssl", "s_client", "-connect", address, *profile],
            capture_output=True,
            text=True,
            input="",
            timeout=10,
            check=True,
        )
        assert "ECDHE-RSA-AES128-SHA" in probe.stdout, probe.stderr
        run(
            "ffuf",
            "-s",
            "-noninteractive",
            "-w",
            "words",
            "-u",
            f"https://{address}/FUZZ",
            "-mc",
            "200",
            "-o",
            "sha1.json",
            "-of",
            "json",
        )
        assert json.loads((root / "sha1.json").read_text())["results"] == []
    finally:
        server.terminate()
        server.wait(timeout=5)


def verify_syn() -> None:
    # Run only in the separate network-none CAP_NET_RAW fixture. A CONNECT
    # fallback can find the same port, so require the actual capture evidence.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = str(listener.getsockname()[1])
        result = subprocess.run(  # noqa: S603 - fixed loopback target
            [
                "/usr/bin/naabu",
                "-duc",
                "-no-color",
                "-host",
                "127.0.0.1",
                "-s",
                "s",
                "-interface",
                "lo",
                "-p",
                port,
                "-retries",
                "1",
                "-debug",
            ],
            text=True,
            capture_output=True,
            check=True,
            timeout=45,
        )
        output = result.stdout + result.stderr
        assert "Running SYN scan with CAP_NET_RAW privileges" in output, output
        assert "Received Transport (TCP) scan response" in output, output
        assert f"127.0.0.1:{port}" in result.stdout, output


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Package evidence requires Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--receipts-only", action="store_true")
    mode.add_argument("--syn", action="store_true")
    args = parser.parse_args()
    if args.syn:
        verify_syn()
    else:
        verify_installed()
        if not args.receipts_only:
            verify_loopback()
    print("Distro Go package verification passed.")  # noqa: T201
