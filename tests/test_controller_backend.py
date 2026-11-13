"""Attach authority, native tools and lost-acknowledgement regression coverage."""

from __future__ import annotations

import base64
import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from agents.sandbox.errors import ExposedPortUnavailableError
from agents.sandbox.manifest import Manifest
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.types import User
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from lyrashield.runtime import backends
from lyrashield.runtime import controller_backend as controller
from lyrashield.runtime.capabilities import probe_session_capabilities


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def grant_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture
def runtime(
    monkeypatch: pytest.MonkeyPatch, signing_key: rsa.RSAPrivateKey, grant_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    connection = controller.ControllerConnection(
        "http://localhost",
        "ephemeral-test-grant",
        "attempt",
        "operation",
        "epoch",
        "opaque-sandbox",
    )
    manifest = Manifest(users=[User(name="pentester")])
    public = signing_key.public_key().public_numbers()

    def encode_number(value: int) -> str:
        return (
            base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8))
            .decode()
            .rstrip("=")
        )

    monkeypatch.setattr(
        controller,
        "_pinned_key",
        lambda: {
            "keyId": "managed-test-key",
            "publicKey": {"kty": "RSA", "e": encode_number(public.e), "n": encode_number(public.n)},
        },
    )
    now = int(datetime.now(UTC).timestamp())
    grant = {
        "schema": controller.GRANT_SCHEMA,
        "scanId": "scan",
        **connection.binding,
        "installed": True,
        "imageDigest": "sha256:" + "a" * 64,
        "manifestChecksum": controller.manifest_checksum(manifest),
        "policyChecksum": "b" * 64,
        "workspaceRoot": "/workspace",
        "exposedPorts": [8080],
        "authorizedHosts": ["fixture.example"],
        "relayRequired": True,
        "issuedAt": now - 60,
        "expiresAt": now + 300,
        "capabilities": {
            name: {
                "status": "supported",
                "detail": "independently observed fixture",
                "evidence": {"receipt": "observed"},
            }
            for name in controller._REQUIRED_CAPABILITIES | {"scoped_relay"}
        },
    }

    def envelope(value: dict[str, Any], key: rsa.RSAPrivateKey, key_id: str) -> dict[str, Any]:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return {
            "raw": raw,
            "result": {
                "algorithm": "RS256",
                "keyId": key_id,
                "signature": base64.b64encode(
                    key.sign(raw.encode(), padding.PKCS1v15(), hashes.SHA256())
                ).decode(),
            },
        }

    grant_public = grant_key.public_key().public_numbers()
    der = grant_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    authority = {
        "productRevision": "c" * 40,
        "engineRevision": "d" * 40,
        **dict.fromkeys(
            (
                "workerDigest",
                "brokerDigest",
                "supervisorDigest",
                "providerGatewayDigest",
                "migrationChecksum",
                "acceptanceDigest",
            ),
            "sha256:" + "e" * 64,
        ),
        "sandboxDigest": grant["imageDigest"],
        "runtimePolicyDigest": "sha256:" + grant["policyChecksum"],
        "schema": "lyrashield-installed-runtime-authority/1",
        "purpose": "launch-qualified-controller",
        "epochId": connection.authority_epoch_id,
        "epoch": 1,
        "issuedAt": now - 60,
        "expiresAt": now + 600,
        "sandboxGrantSigner": {
            "schema": "lyrashield-sandbox-grant-signer/1",
            "purpose": "sandbox-tool-grants",
            "keyId": "local-grant-key",
            "epochId": connection.authority_epoch_id,
            "epoch": 1,
            "algorithm": "RS256",
            "publicKeySha256": "sha256:" + hashlib.sha256(der).hexdigest(),
            "publicKey": {"kty": "RSA", "e": "AQAB", "n": encode_number(grant_public.n)},
        },
        "issuer": {
            "repositoryId": "1286618458",
            "repositoryOwnerId": "116722580",
            "workflow": ".github/workflows/issue-runtime-qualification.yml",
            "source": "c" * 40,
            "runId": "123",
            "attempt": "1",
        },
    }
    return {
        "connection": connection,
        "manifest": manifest,
        "grant": grant,
        "sign": lambda value: envelope(value, grant_key, "local-grant-key"),
        "runtimeAuthority": envelope(authority, signing_key, "managed-test-key"),
        "authority": authority,
        "signAuthority": lambda value: envelope(value, signing_key, "managed-test-key"),
    }


def response(runtime: dict[str, Any], **values: Any) -> dict[str, Any]:
    return {
        "binding": runtime["connection"].binding,
        "runtimeAuthority": runtime["runtimeAuthority"],
        **values,
    }


async def attached(
    runtime: dict[str, Any], handler: Any
) -> tuple[controller.ControllerClient, controller.ControllerSession]:
    client = controller.ControllerClient(
        runtime["connection"], transport=httpx.MockTransport(handler)
    )
    inner = controller.ControllerSession(
        client, runtime["manifest"], (8080,), runtime["grant"]["imageDigest"]
    )
    await inner.start()
    return client, inner


def test_backend_is_explicit_and_docker_default_is_preserved() -> None:
    assert backends.get_backend("controller") is controller.controller_backend
    assert backends.get_backend("docker") is backends.docker_backend
    assert not controller.ControllerSession.__abstractmethods__


@pytest.mark.parametrize(
    "field,value",
    [
        ("installed", False),
        ("sandboxHandle", "other"),
        ("authorityEpochId", "revoked"),
        ("expiresAt", 1000),
        ("imageDigest", "sha256:" + "x" * 64),
        ("workspaceRoot", "/workspace/../host"),
    ],
)
def test_signed_grant_still_requires_current_installed_authority(
    runtime: dict[str, Any], field: str, value: Any
) -> None:
    grant = {**runtime["grant"], field: value}
    with pytest.raises(controller.ControllerUnavailableError):
        controller.verify_installed_grant(
            runtime["sign"](grant), runtime["connection"], runtime["runtimeAuthority"]
        )


def test_signature_tampering_and_caller_keys_fail(runtime: dict[str, Any]) -> None:
    envelope = runtime["sign"](runtime["grant"])
    envelope["raw"] = "{}"
    with pytest.raises(controller.ControllerUnavailableError):
        controller.verify_installed_grant(
            envelope, runtime["connection"], runtime["runtimeAuthority"]
        )
    envelope = runtime["sign"](runtime["grant"])
    envelope["publicKey"] = "caller-controlled"
    with pytest.raises(controller.ControllerUnavailableError):
        controller.verify_installed_grant(
            envelope, runtime["connection"], runtime["runtimeAuthority"]
        )


def test_missing_observed_network_capability_fails(runtime: dict[str, Any]) -> None:
    runtime["grant"]["capabilities"].pop("network_policy")
    with pytest.raises(controller.ControllerUnavailableError):
        controller.verify_installed_grant(
            runtime["sign"](runtime["grant"]), runtime["connection"], runtime["runtimeAuthority"]
        )


@pytest.mark.parametrize("change", ["manifest", "image", "unsigned", "not-running"])
async def test_attach_never_materializes_or_creates(runtime: dict[str, Any], change: str) -> None:
    requests = []
    grant = {**runtime["grant"]}
    if change == "manifest":
        grant["manifestChecksum"] = "c" * 64
    if change == "image":
        grant["imageDigest"] = "sha256:" + "c" * 64

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=response(
                runtime,
                running=change != "not-running",
                grant=None if change == "unsigned" else runtime["sign"](grant),
            ),
        )

    with pytest.raises(controller.ControllerUnavailableError):
        await attached(runtime, handle)
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path.endswith("/state")


async def test_complete_native_sdk_tool_surface(runtime: dict[str, Any]) -> None:
    requests: list[dict[str, Any]] = []
    data = b"proof\n"
    encoded = base64.b64encode(data).decode()

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        requests.append({"path": request.url.path, "method": request.method, **body})
        assert request.headers["Authorization"] == "Bearer ephemeral-test-grant"
        result = response(runtime, requestId=body.get("requestId"), status="COMPLETED")
        path = request.url.path
        if path.endswith("/state"):
            result.update(running=True, grant=runtime["sign"](runtime["grant"]))
        elif path.endswith("/exec"):
            result.update(stdoutBase64=encoded, stderrBase64="", exitCode=0)
        elif path.endswith(("/files/read", "/workspace/persist")):
            result.update(
                dataBase64=encoded, archiveBase64=encoded, sha256=hashlib.sha256(data).hexdigest()
            )
        elif "/pty/" in path and not path.endswith("/terminate"):
            result.update(
                sessionId=1001,
                outputBase64=encoded,
                outputCursor=6,
                exitCode=None,
                originalTokenCount=2,
            )
        elif "/port/" in path:
            result.update(host="private-controller", port=8080, tls=True, query="")
        return httpx.Response(200, json=result)

    client, inner = await attached(runtime, handle)
    session = SandboxSession(inner)
    result = await session.exec("printf", "proof", shell=False, user="pentester")
    assert result.stdout == data
    assert (await session.read(Path("proof.txt"))).read() == data
    await session.write(Path("proof.txt"), io.BytesIO(data))
    assert (await inner.persist_workspace()).read() == data
    await inner.hydrate_workspace(io.BytesIO(data))
    update = await session.pty_exec_start("echo proof", user="pentester")
    assert update.process_id == 1001 and update.output == data
    await session.pty_write_stdin(session_id=1001, chars="hello\n")
    await session.pty_write_stdin(session_id=1001, chars="")
    await inner.pty_terminate_all()
    assert await inner.running()
    assert (await session.resolve_exposed_port(8080)).tls
    mutations = [item for item in requests if item.get("requestId")]
    assert len({item["requestId"] for item in mutations}) == len(mutations)
    assert all(item["binding"] == runtime["connection"].binding for item in mutations)
    assert all(
        "image" not in item and "bindMounts" not in item and "environment" not in item
        for item in requests
    )
    exec_request = next(item for item in requests if item["path"].endswith("/exec"))
    assert exec_request["argv"] == ["printf", "proof"]
    assert exec_request["user"] == "pentester"
    await client.close()


async def test_lost_ack_holds_original_and_never_replays(runtime: dict[str, Any]) -> None:
    commands: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/state"):
            return httpx.Response(
                200, json=response(runtime, running=True, grant=runtime["sign"](runtime["grant"]))
            )
        commands.append(json.loads(request.content))
        raise httpx.ReadTimeout("acknowledgement lost")

    client, inner = await attached(runtime, handle)
    with pytest.raises(controller.ControllerOperationUnknownError) as first:
        await inner.exec("touch once", user="pentester")
    with pytest.raises(controller.ControllerOperationUnknownError) as second:
        await inner.exec("touch once", user="pentester")
    assert first.value.request_id == second.value.request_id == commands[0]["requestId"]
    assert len(commands) == 1
    await client.close()


async def test_stop_retry_retains_original_identity(runtime: dict[str, Any]) -> None:
    stop_ids = []
    stopped = False

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal stopped
        if request.url.path.endswith("/state"):
            return httpx.Response(
                200,
                json=response(
                    runtime, running=not stopped, grant=runtime["sign"](runtime["grant"])
                ),
            )
        body = json.loads(request.content)
        stop_ids.append(body["requestId"])
        stopped = True
        if len(stop_ids) == 1:
            raise httpx.ReadTimeout("stop acknowledgement lost")
        return httpx.Response(
            200, json=response(runtime, requestId=body["requestId"], status="COMPLETED")
        )

    client, inner = await attached(runtime, handle)
    with pytest.raises(controller.ControllerOperationUnknownError):
        await client.delete(inner)
    await client.delete(inner)
    assert stop_ids[0] == stop_ids[1]


async def test_user_path_byte_limits_and_port_grants_fail_before_rpc(
    runtime: dict[str, Any],
) -> None:
    requests = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200, json=response(runtime, running=True, grant=runtime["sign"](runtime["grant"]))
        )

    client, inner = await attached(runtime, handle)
    for path in (Path("/etc/passwd"), Path("../escape")):
        with pytest.raises(controller.ControllerUnavailableError):
            await inner.read(path)
    with pytest.raises(controller.ControllerUnavailableError):
        await inner.exec("true", user="root")
    with pytest.raises(controller.ControllerUnavailableError):
        await inner.write(Path("huge"), io.BytesIO(b"x" * (controller.MAX_FILE_BYTES + 1)))
    with pytest.raises(ExposedPortUnavailableError):
        await inner.resolve_exposed_port(2375)
    assert len(requests) == 1
    await client.close()


async def test_capability_record_requires_same_installed_scope(runtime: dict[str, Any]) -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=response(runtime, running=True, grant=runtime["sign"](runtime["grant"]))
        )

    client, inner = await attached(runtime, handle)
    inner.assert_scan_authority("scan", {"fixture.example"}, relay_required=True)
    with pytest.raises(controller.ControllerUnavailableError):
        inner.assert_scan_authority("other-scan", {"fixture.example"}, relay_required=True)
    args = {
        "backend_name": "controller",
        "client": client,
        "session": inner,
        "caido_client": None,
        "caido_endpoint": None,
        "bind_mounts": [],
        "relay_configured": True,
    }
    matched = probe_session_capabilities(**args, authorized_hosts=["fixture.example"])
    assert matched["capabilities"]["network_policy"]["status"] == "supported"
    denied = probe_session_capabilities(**args, authorized_hosts=["other.example"])
    assert denied["capabilities"]["network_policy"]["status"] == "absent"
    assert denied["preflight"]["failures"]
    await client.close()


@pytest.mark.parametrize("change", ["epoch", "purpose", "fingerprint", "issuer", "undelegated-key"])
def test_root_delegation_must_match_epoch_role_and_issuer(
    runtime: dict[str, Any], change: str
) -> None:
    authority = json.loads(json.dumps(runtime["authority"]))
    if change == "epoch":
        authority["sandboxGrantSigner"]["epochId"] = "old-epoch"
    elif change == "purpose":
        authority["sandboxGrantSigner"]["purpose"] = "arbitrary-controller-signing"
    elif change == "fingerprint":
        authority["sandboxGrantSigner"]["publicKeySha256"] = "sha256:" + "f" * 64
    elif change == "issuer":
        authority["issuer"]["workflow"] = ".github/workflows/caller-workflow.yml"
    else:
        authority["sandboxGrantSigner"]["keyId"] = "undelegated-key"
    with pytest.raises(controller.ControllerUnavailableError):
        controller.verify_installed_grant(
            runtime["sign"](runtime["grant"]),
            runtime["connection"],
            runtime["signAuthority"](authority),
        )


def test_production_connection_rejects_insecure_origin_and_secret_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "TOOL_URL",
        "TOOL_TOKEN",
        "ATTEMPT_ID",
        "OPERATION_ID",
        "AUTHORITY_EPOCH_ID",
        "SANDBOX_HANDLE",
    ):
        monkeypatch.setenv(f"LYRASHIELD_SUPERVISOR_{name}", "test")
    monkeypatch.setenv("LYRASHIELD_SUPERVISOR_TOOL_URL", "http://localhost")
    with pytest.raises(controller.ControllerUnavailableError):
        controller.ControllerConnection.from_environment()
    monkeypatch.setenv("LYRASHIELD_SUPERVISOR_TOOL_URL", "https://private-controller")
    connection = controller.ControllerConnection.from_environment()
    assert "token='test'" not in repr(connection)
