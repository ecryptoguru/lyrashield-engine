"""Pinned public runtime authority verification, without SDK or network imports."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Protocol, cast
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


GRANT_SCHEMA = "lyrashield-runtime-sandbox-grant/v1"


class AuthorityConnection(Protocol):
    @property
    def authority_epoch_id(self) -> str: ...

    @property
    def binding(self) -> dict[str, str]: ...


_REQUIRED_CAPABILITIES = frozenset(
    {"exec", "pty", "files", "ports", "network_policy", "mounts", "exec_constraints"},
)
_AUTHORITY_FIELDS = frozenset(
    {
        "productRevision",
        "engineRevision",
        "workerDigest",
        "sandboxDigest",
        "brokerDigest",
        "supervisorDigest",
        "providerGatewayDigest",
        "migrationChecksum",
        "runtimePolicyDigest",
        "schema",
        "purpose",
        "epochId",
        "epoch",
        "issuedAt",
        "acceptanceDigest",
        "sandboxGrantSigner",
        "issuer",
        "toolChannel",
    }
)


class ControllerUnavailableError(RuntimeError):
    """The protected controller cannot prove safe tool execution."""


def _reject() -> NoReturn:
    raise ControllerUnavailableError("Controller response failed authority validation")


def _text(value: Any, *, max_length: int = 8192) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or "\x00" in value:
        _reject()
    return value


def _integer(value: Any, *, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject()
    return value


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        _reject()
    return cast("bool", value)


def _bytes(value: Any, *, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        _reject()
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        _reject()
    if len(decoded) > maximum:
        _reject()
    return decoded


def _pinned_key() -> dict[str, Any]:
    return cast(
        "dict[str, Any]",
        json.loads(Path(__file__).with_name("controller-qualification-key.json").read_text()),
    )


def _tool_origin(value: Any) -> str:
    origin = _text(value, max_length=1024)
    parsed = urlsplit(origin)
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or not host.isascii()
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        _reject()
    labels = host.split(".")
    if not all(
        label
        and len(label) <= 63
        and label[0] != "-"
        and label[-1] != "-"
        and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
        for label in labels
    ):
        _reject()
    try:
        port = parsed.port
    except ValueError:
        _reject()
    if port is not None and (port == 443 or not 1 <= port <= 65535):
        _reject()
    canonical = f"https://{host}" + (f":{port}" if port is not None else "")
    if canonical != origin:
        _reject()
    return canonical


def _public_key(jwk: Any) -> rsa.RSAPublicKey:
    if (
        not isinstance(jwk, dict)
        or set(jwk) != {"kty", "n", "e"}
        or jwk["kty"] != "RSA"
        or jwk["e"] != "AQAB"
    ):
        _reject()
    modulus = _text(jwk["n"], max_length=1024)
    if any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in modulus
    ):
        _reject()
    try:
        raw = base64.urlsafe_b64decode(modulus + "=" * (-len(modulus) % 4))
        if not raw or raw[0] == 0:
            _reject()
        key = rsa.RSAPublicNumbers(65537, int.from_bytes(raw)).public_key()
    except ValueError:
        _reject()
    if key.key_size < 3072:
        _reject()
    return key


def _verify_envelope(envelope: Any, key: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {"raw", "result"}:
        _reject()
    result = envelope["result"]
    if not isinstance(result, dict) or set(result) != {"algorithm", "keyId", "signature"}:
        _reject()
    if result["algorithm"] != "RS256" or result["keyId"] != key["keyId"]:
        _reject()
    payload = _text(envelope["raw"], max_length=128 * 1024).encode()
    signature = _bytes(result["signature"], maximum=1024)
    try:
        public_key = _public_key(key["publicKey"])
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        record = json.loads(payload)
    except (InvalidSignature, ValueError, UnicodeDecodeError, KeyError):
        _reject()
    if (
        not isinstance(record, dict)
        or json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        != envelope["raw"]
    ):
        _reject()
    return record


def verify_runtime_authority(  # noqa: PLR0912
    runtime_authority: Any,
    epoch_id: str,
    *,
    key: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify the public root before contacting any credential-bearing endpoint."""
    root_key = _pinned_key() if key is None else key
    authority = _verify_envelope(runtime_authority, root_key)
    if set(authority) != _AUTHORITY_FIELDS:
        _reject()
    channel = authority["toolChannel"]
    if (
        not isinstance(channel, dict)
        or set(channel) != {"schema", "origin"}
        or channel["schema"] != "lyrashield-sandbox-tool-channel/1"
    ):
        _reject()
    _tool_origin(channel["origin"])
    for name in ("productRevision", "engineRevision"):
        value = _text(authority[name])
        if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            _reject()
    for name in _AUTHORITY_FIELDS & {
        "workerDigest",
        "sandboxDigest",
        "brokerDigest",
        "supervisorDigest",
        "providerGatewayDigest",
        "migrationChecksum",
        "runtimePolicyDigest",
        "acceptanceDigest",
    }:
        value = _text(authority[name])
        if (
            len(value) != 71
            or not value.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in value[7:])
        ):
            _reject()
    issuer = authority["issuer"]
    if not isinstance(issuer, dict) or set(issuer) != {
        "repositoryId",
        "repositoryOwnerId",
        "workflow",
        "source",
        "runId",
        "attempt",
    }:
        _reject()
    if (
        issuer["repositoryId"] != "1286618458"
        or issuer["repositoryOwnerId"] != "116722580"
        or issuer["workflow"] != ".github/workflows/issue-runtime-qualification.yml"
        or issuer["source"] != authority["productRevision"]
    ):
        _reject()
    if not all(
        isinstance(issuer[name], str)
        and issuer[name].isascii()
        and issuer[name].isdigit()
        and int(issuer[name]) > 0
        for name in ("runId", "attempt")
    ):
        _reject()
    now = int(datetime.now(UTC).timestamp()) if now is None else now
    if (
        authority.get("schema") != "lyrashield-installed-runtime-authority/1"
        or authority.get("purpose") != "launch-qualified-controller"
    ):
        _reject()
    issued = _integer(authority.get("issuedAt"), minimum=1)
    if issued > now:
        _reject()
    if authority.get("epochId") != epoch_id:
        _reject()
    signer = authority.get("sandboxGrantSigner")
    if not isinstance(signer, dict) or set(signer) != {
        "schema",
        "purpose",
        "keyId",
        "epochId",
        "epoch",
        "publicKey",
        "algorithm",
        "publicKeySha256",
    }:
        _reject()
    if (
        signer["schema"] != "lyrashield-sandbox-grant-signer/1"
        or signer["purpose"] != "sandbox-tool-grants"
    ):
        _reject()
    if signer["epochId"] != authority["epochId"] or signer["epoch"] != _integer(
        authority.get("epoch"), minimum=1
    ):
        _reject()
    _text(signer["keyId"])
    if (
        signer["algorithm"] != "RS256"
        or not isinstance(signer["publicKey"], dict)
        or set(signer["publicKey"]) != {"kty", "n", "e"}
    ):
        _reject()
    public_key = _public_key(signer["publicKey"])
    if public_key.public_numbers() == _public_key(root_key["publicKey"]).public_numbers():
        _reject()
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if signer["publicKeySha256"] != "sha256:" + hashlib.sha256(der).hexdigest():
        _reject()
    return authority


def verify_installed_grant(  # noqa: PLR0912
    envelope: Any,
    connection: AuthorityConnection,
    runtime_authority: Any,
    *,
    key: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    authority = verify_runtime_authority(
        runtime_authority, connection.authority_epoch_id, key=key, now=now
    )
    grant = _verify_envelope(envelope, authority["sandboxGrantSigner"])
    issued = authority["issuedAt"]
    now = int(datetime.now(UTC).timestamp()) if now is None else now
    if "sha256:" + str(grant.get("policyChecksum")) != authority.get(
        "runtimePolicyDigest"
    ) or grant.get("imageDigest") != authority.get("sandboxDigest"):
        _reject()
    if not isinstance(grant, dict) or grant.get("schema") != GRANT_SCHEMA:
        _reject()
    if grant.get("installed") is not True:
        _reject()
    for name, value in connection.binding.items():
        if grant.get(name) != value:
            _reject()
    _text(grant.get("scanId"))
    grant_issued = _integer(grant.get("issuedAt"))
    grant_expires = _integer(grant.get("expiresAt"))
    if not issued <= grant_issued <= now < grant_expires <= grant_issued + 900:
        _reject()
    for name in ("manifestChecksum", "policyChecksum"):
        value = _text(grant.get(name))
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            _reject()
    image = _text(grant.get("imageDigest"))
    if (
        not image.startswith("sha256:")
        or len(image) != 71
        or any(c not in "0123456789abcdef" for c in image[7:])
    ):
        _reject()
    root = _text(grant.get("workspaceRoot"))
    if not root.startswith("/") or ".." in PurePosixPath(root).parts:
        _reject()
    if type(grant.get("relayRequired")) is not bool:
        _reject()
    capabilities = grant.get("capabilities")
    required = _REQUIRED_CAPABILITIES | ({"scoped_relay"} if grant["relayRequired"] else set())
    if not isinstance(capabilities, dict):
        _reject()
    for name in required:
        capability = capabilities.get(name)
        if not isinstance(capability, dict) or capability.get("status") != "supported":
            _reject()
        _text(capability.get("detail"))
        if not isinstance(capability.get("evidence"), dict) or not capability["evidence"]:
            _reject()
    if not isinstance(grant.get("authorizedHosts"), list) or not all(
        isinstance(host, str) and host for host in grant["authorizedHosts"]
    ):
        _reject()
    if not isinstance(grant.get("exposedPorts"), list):
        _reject()
    for port in grant["exposedPorts"]:
        _integer(port, minimum=1, maximum=65535)
    return grant
