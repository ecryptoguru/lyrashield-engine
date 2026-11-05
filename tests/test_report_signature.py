"""Ed25519 report-signature contract and mutation-sensitive verification."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.report_signature import sign_payload, verify_payload


if TYPE_CHECKING:
    from pathlib import Path


def test_report_signature_rejects_changed_payload_and_envelope(tmp_path: Path) -> None:
    payload = json.dumps({"status": "COMPLETE", "precision": 0.5}).encode()
    envelope = sign_payload(payload, Ed25519PrivateKey.generate())
    assert verify_payload(payload, envelope)

    changed_payload = payload.replace(b"0.5", b"0.9")
    assert not verify_payload(changed_payload, envelope)
    assert not verify_payload(payload, {**envelope, "payloadSha256": "0" * 64})
    assert not verify_payload(payload, {**envelope, "signature": "invalid"})

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert private_pem
    assert tmp_path.is_dir()
