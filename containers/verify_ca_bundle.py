"""Require a readable, complete effective CA bundle and reject compromised G3."""

# ruff: noqa: INP001
from __future__ import annotations

import hashlib
import os
import re
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


G3 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)


def verify_effective_bundle() -> None:
    """Reject absent, malformed or compromised bundles before emitting success."""
    bundle = Path(os.environ.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"))
    text = bundle.read_text(encoding="utf-8")
    blocks = CERTIFICATE.findall(text)
    remainder = CERTIFICATE.sub("", text)
    if not blocks or any(
        line.strip() and not line.lstrip().startswith("#") for line in remainder.splitlines()
    ):
        raise ValueError("missing or malformed effective CA bundle")
    for block in blocks:
        der = ssl.PEM_cert_to_DER_cert(block)
        certificate = x509.load_der_x509_certificate(der)
        canonical = certificate.public_bytes(Encoding.DER)
        if canonical != der:
            raise ValueError("noncanonical or trailing DER in effective CA bundle")
        if hashlib.sha256(canonical).hexdigest() == G3:
            raise ValueError("compromised emSign G3 in effective CA bundle")
    context = ssl.create_default_context(cafile=str(bundle))
    loaded = context.get_ca_certs(binary_form=True)
    if G3 in {hashlib.sha256(der).hexdigest() for der in loaded}:
        raise ValueError("compromised emSign G3 loaded by TLS context")
    if not loaded:
        raise ValueError("effective CA bundle has no usable CA certificates")
