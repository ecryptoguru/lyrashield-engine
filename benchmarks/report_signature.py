"""Sign and verify retained evaluation reports with Ed25519."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SCHEMA_VERSION = "lyrashield-report-signature/1.0.0"
ALGORITHM = "ed25519"


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def sign_payload(payload: bytes, private_key: Ed25519PrivateKey) -> dict[str, Any]:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "publicKey": _b64(public_key),
        "signature": _b64(private_key.sign(payload)),
    }


def verify_payload(payload: bytes, envelope: dict[str, Any]) -> bool:
    if (
        envelope.get("schemaVersion") != SCHEMA_VERSION
        or envelope.get("algorithm") != ALGORITHM
        or not isinstance(envelope.get("payloadSha256"), str)
        or not isinstance(envelope.get("publicKey"), str)
        or not isinstance(envelope.get("signature"), str)
    ):
        return False
    payload_digest = hashlib.sha256(payload).hexdigest()
    if payload_digest != envelope["payloadSha256"]:
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_unb64(envelope["publicKey"]))
        public_key.verify(_unb64(envelope["signature"]), payload)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify_file(payload_path: Path, envelope_path: Path) -> bool:
    try:
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(envelope, dict) and verify_payload(payload_path.read_bytes(), envelope)


def sign_file(payload_path: Path, private_key_path: Path, output_path: Path) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("report signing key must be Ed25519")
    envelope = sign_payload(payload_path.read_bytes(), private_key)
    output_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--payload", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--output", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--payload", required=True)
    verify_parser.add_argument("--signature", required=True)
    args = parser.parse_args()
    if args.command == "sign":
        sign_file(Path(args.payload), Path(args.private_key), Path(args.output))
        return 0
    valid = verify_file(Path(args.payload), Path(args.signature))
    print(json.dumps({"valid": valid}, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
