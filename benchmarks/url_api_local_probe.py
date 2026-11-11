"""Run a non-claimable URL/API diagnostic with a local TLS target and real relay."""

from __future__ import annotations

import argparse
import datetime
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from benchmarks.corpus.v3.validate import validate
from benchmarks.offline_sca_probe import digest
from benchmarks.run import BENCH_ROOT, PRODUCT_REPO, source_state


CORPUS = BENCH_ROOT / "corpus/v3"
FIXTURES = BENCH_ROOT / "fixtures/url_api/v1"
RUNNER = BENCH_ROOT / "run_url_api_local.ts"


def input_hashes() -> dict[str, str]:
    paths = [
        CORPUS / "corpus.json",
        CORPUS / "adjudications.json",
        CORPUS / "held-out.json",
        CORPUS / "advisories/frozen.json",
        BENCH_ROOT / "profiles/v1/paths.json",
        BENCH_ROOT / "offline_sca_probe.py",
        RUNNER,
        Path(__file__),
        *[FIXTURES / name for name in ("index.html", "openapi.json", "health.json")],
    ]
    return {str(path.relative_to(BENCH_ROOT.parent)): digest(path) for path in paths}


def create_certificates(root: Path) -> dict[str, Path]:
    now = datetime.datetime.now(datetime.UTC)

    def authority(name: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        private = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(private, hashes.SHA256())
        )
        return private, cert

    ca_key, ca = authority("URL/API local diagnostic CA")
    _, wrong_ca = authority("URL/API untrusted diagnostic CA")
    target_key = ec.generate_private_key(ec.SECP256R1())
    target = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")]))
        .issuer_name(ca.subject)
        .public_key(target_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    paths = {
        name: root / name for name in ("ca.pem", "wrong-ca.pem", "target.pem", "target-key.pem")
    }
    for name, cert in (("ca.pem", ca), ("wrong-ca.pem", wrong_ca), ("target.pem", target)):
        paths[name].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths["target-key.pem"].write_bytes(
        target_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    paths["target-key.pem"].chmod(0o600)
    return paths


def execute(paths: dict[str, Path], runtime_path: str) -> dict[str, Any]:
    proc = subprocess.run(
        [
            str(PRODUCT_REPO / "apps/worker/node_modules/.bin/tsx"),
            str(RUNNER),
            "--fixture",
            str(FIXTURES),
            "--ca",
            str(paths["ca.pem"]),
            "--wrong-ca",
            str(paths["wrong-ca.pem"]),
            "--cert",
            str(paths["target.pem"]),
            "--key",
            str(paths["target-key.pem"]),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            "PATH": runtime_path,
            "HOME": str(paths["ca.pem"].parent),
            "TMPDIR": str(paths["ca.pem"].parent),
            "LYRASHIELD_AI_DIR": str(PRODUCT_REPO),
        },
    )
    if proc.returncode != 0:
        raise RuntimeError(f"local URL/API execution failed: {proc.stderr[-2000:]}")
    records = [
        line.removeprefix("URLPROBE:")
        for line in proc.stdout.splitlines()
        if line.startswith("URLPROBE:")
    ]
    if len(records) != 1:
        raise RuntimeError("local URL/API output was incomplete")
    result = json.loads(records[0])
    if not isinstance(result, dict):
        raise TypeError("local URL/API result was malformed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="new directory for retained evidence"
    )
    args = parser.parse_args()
    try:
        validate(CORPUS)
        before_inputs = input_hashes()
        review = json.loads((CORPUS / "adjudications.json").read_text())["review"]["status"]
        held_out = json.loads((CORPUS / "held-out.json").read_text())["status"]
        profiles = json.loads((BENCH_ROOT / "profiles/v1/paths.json").read_text())["profiles"]
        profile_status = next(p["status"] for p in profiles if p["id"] == "url_api")
        node = shutil.which("node")
        tsx = PRODUCT_REPO / "apps/worker/node_modules/.bin/tsx"
        if not node or not tsx.is_file():
            raise RuntimeError("local runtime identity unavailable")  # noqa: TRY301
        node = str(Path(node).resolve())
        runtime_path = f"{Path(node).parent}:/usr/bin:/bin"
        runtime = {
            "nodePath": node,
            "nodeSha256": digest(Path(node)),
            "path": runtime_path,
            "tsxShimSha256": digest(tsx),
        }
        sources = {"engine": source_state(BENCH_ROOT.parent), "product": source_state(PRODUCT_REPO)}
        # tsx creates a Unix socket under TMPDIR; macOS limits its path length.
        short_tmp = "/tmp" if Path("/tmp").is_dir() else None  # noqa: S108 -- private mkdtemp below
        with tempfile.TemporaryDirectory(prefix="lyra-url-", dir=short_tmp) as directory:
            paths = create_certificates(Path(directory))
            result = execute(paths, runtime_path)
            identity = result.get("targetIdentity")
            if (
                not isinstance(identity, dict)
                or identity.get("host") != "fixture.test"
                or type(identity.get("port")) is not int
                or not 1 <= identity["port"] <= 65535
                or identity.get("certificateSha256") != digest(paths["target.pem"])
            ):
                raise RuntimeError("local target identity was incomplete")  # noqa: TRY301
            public_certificates = {
                name: paths[name].read_bytes() for name in ("ca.pem", "wrong-ca.pem", "target.pem")
            }
            after_sources = {
                "engine": source_state(BENCH_ROOT.parent),
                "product": source_state(PRODUCT_REPO),
            }
            if (
                before_inputs != input_hashes()
                or sources != after_sources
                or runtime["nodeSha256"] != digest(Path(node))
                or runtime["tsxShimSha256"] != digest(tsx)
            ):
                raise RuntimeError("inputs or source changed during the diagnostic")  # noqa: TRY301
            args.output.mkdir(parents=True, exist_ok=False)
            for name, data in public_certificates.items():
                (args.output / name).write_bytes(data)
            result_path = args.output / "diagnostic.json"
            result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            receipt = {
                "schemaVersion": "lyrashield-local-url-api-diagnostic/1.0.0",
                "fixtureSet": "local-url-api-v1",
                "profile": "url_api",
                "profileStatus": profile_status,
                "diagnosticStatus": "NOT_MEASURED",
                "claimStatus": "NOT_REPORTABLE",
                "adjudicationStatus": review,
                "heldOutStatus": held_out,
                "image": None,
                "modelRoute": None,
                "sources": sources,
                "runtime": runtime,
                "runnerSha256": digest(RUNNER),
                "corpusSha256": digest(CORPUS / "corpus.json"),
                "fixtureSha256": {
                    name: digest(FIXTURES / name)
                    for name in ("index.html", "openapi.json", "health.json")
                },
                "inputSha256": before_inputs,
                "resultSha256": digest(result_path),
                "scopeGrantSha256": result["scopeGrantSha256"],
                "targetIdentity": identity,
                "tls": {
                    "caSha256": digest(args.output / "ca.pem"),
                    "untrustedCaSha256": digest(args.output / "wrong-ca.pem"),
                    "targetCertSha256": digest(args.output / "target.pem"),
                },
                "limitations": [
                    "Synthetic local response bytes are not frozen v3 corpus cases.",
                    "Test-only resolver and port overrides target loopback; "
                    "production DNS and ingress are not exercised.",
                    "The scanner fetch adapter is diagnostic; engine TLS bridge, worker admission, "
                    "and model routes are not exercised.",
                    "The ephemeral signed grant is not retained and cannot be independently "
                    "reverified from this receipt.",
                    "No qualified image, held-out data, independent adjudication, "
                    "or benchmark claim is established.",
                ],
            }
            (args.output / "receipt.json").write_text(
                json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
            )
    except (
        OSError,
        ValueError,
        TypeError,
        AssertionError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Local URL/API diagnostic failed: {exc}", file=sys.stderr)
        return 1
    print(f"Retained local URL/API diagnostic in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
