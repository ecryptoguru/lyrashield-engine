"""Capability-probe matrix and preflight semantics for sandbox sessions.

The probe must reflect what the backend verifiably delivered — supported,
absent, or unprobed — and never assume. A required control resting on an
absent capability fails preflight; an unprobed one becomes a named
degradation rather than a silent gap.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from lyrashield.runtime import session_manager
from lyrashield.runtime.capabilities import (
    STATUS_ABSENT,
    STATUS_SUPPORTED,
    STATUS_UNPROBED,
    SandboxPreflightError,
    evaluate_preflight,
    probe_session_capabilities,
)


_NETWORK = "lyrashield-sandbox"
_POLICY_TARGET = "/run/lyrashield-egress/policy.json"


def _docker_attrs(
    *,
    network: str = _NETWORK,
    internal_attached: list[str] | None = None,
    mounts: list[dict[str, Any]] | None = None,
    memory: int = 2 << 30,
    nano_cpus: int = 2_000_000_000,
    pids: int = 512,
) -> dict[str, Any]:
    return {
        "HostConfig": {
            "NetworkMode": network,
            "Memory": memory,
            "NanoCpus": nano_cpus,
            "PidsLimit": pids,
            "CapAdd": ["NET_RAW", "NET_ADMIN"],
            "SecurityOpt": ["no-new-privileges"],
        },
        "NetworkSettings": {
            "Networks": {name: {} for name in (internal_attached or [network])},
        },
        "Mounts": mounts
        if mounts is not None
        else [{"Type": "bind", "Destination": _POLICY_TARGET, "RW": False}],
    }


class _FakeContainers:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self._attrs = attrs

    def get(self, _container_id: str) -> Any:
        return SimpleNamespace(attrs=self._attrs)


class _FakeNetworks:
    def __init__(self, internal: bool) -> None:
        self._internal = internal

    def get(self, _name: str) -> Any:
        return SimpleNamespace(attrs={"Internal": self._internal})


def _docker_client(attrs: dict[str, Any], *, internal: bool = True) -> Any:
    return SimpleNamespace(
        docker_client=SimpleNamespace(
            containers=_FakeContainers(attrs),
            networks=_FakeNetworks(internal),
        )
    )


class _Session:
    def __init__(self, container_id: str | None = "abc123") -> None:
        self._inner = SimpleNamespace(container_id=container_id)
        self.supports_pty = False

    async def exec(self, *_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(ok=lambda: True, stdout=b"", stderr=b"", exit_code=0)

    async def resolve_exposed_port(self, _port: int) -> Any:
        return SimpleNamespace(tls=False, host="127.0.0.1", port=48080)


def _probe(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "backend_name": "docker",
        "client": _docker_client(_docker_attrs()),
        "session": _Session(),
        "caido_client": SimpleNamespace(),
        "caido_endpoint": SimpleNamespace(tls=False, host="127.0.0.1", port=48080),
        "bind_mounts": [
            {"source": "/var/empty/policy.json", "target": _POLICY_TARGET, "read_only": True}
        ],
        "authorized_hosts": ["app.example.com"],
        "relay_configured": False,
    }
    kwargs.update(overrides)
    return probe_session_capabilities(**kwargs)


@pytest.fixture(autouse=True)
def _sandbox_network_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", _NETWORK)


def test_probe_all_supported_on_verified_docker() -> None:
    record = _probe()
    caps = record["capabilities"]
    assert record["backend"] == "docker"
    assert record["authorized_hosts"] == ["app.example.com"]
    for name in (
        "exec",
        "ports",
        "proxy_capture",
        "network_policy",
        "mounts",
        "exec_constraints",
    ):
        assert caps[name]["status"] == STATUS_SUPPORTED, (name, caps[name])
    assert record["preflight"] == {"degradations": [], "failures": []}


def test_probe_non_docker_marks_introspection_unprobed() -> None:
    record = _probe(backend_name="remote", client=SimpleNamespace())
    caps = record["capabilities"]
    # Session-API capabilities are still probed on any backend.
    assert caps["exec"]["status"] == STATUS_SUPPORTED
    assert caps["ports"]["status"] == STATUS_SUPPORTED
    # Backend-introspection capabilities are unprobed — never assumed.
    for name in ("network_policy", "mounts", "exec_constraints"):
        assert caps[name]["status"] == STATUS_UNPROBED, (name, caps[name])
    controls = {d["control"] for d in record["preflight"]["degradations"]}
    assert {"deny_by_default_egress", "egress_policy_delivery", "resource_limits"} <= controls
    assert record["preflight"]["failures"] == []


def test_probe_absent_exec_is_preflight_failure() -> None:
    record = _probe(session=SimpleNamespace())
    assert record["capabilities"]["exec"]["status"] == STATUS_ABSENT
    controls = {f["control"] for f in record["preflight"]["failures"]}
    assert "agent_exec" in controls


def test_probe_absent_proxy_client_is_preflight_failure() -> None:
    record = _probe(caido_client=None)
    assert record["capabilities"]["proxy_capture"]["status"] == STATUS_ABSENT
    controls = {f["control"] for f in record["preflight"]["failures"]}
    assert "traffic_capture" in controls


def test_probe_missing_policy_mount_fails_when_targets_exist() -> None:
    attrs = _docker_attrs(mounts=[])
    record = _probe(client=_docker_client(attrs), authorized_hosts=["app.example.com"])
    assert record["capabilities"]["mounts"]["status"] == STATUS_ABSENT
    assert _POLICY_TARGET in record["capabilities"]["mounts"]["evidence"]["missing"]
    controls = {f["control"] for f in record["preflight"]["failures"]}
    assert "scoped_replay" in controls


def test_probe_missing_policy_mount_degrades_without_targets() -> None:
    attrs = _docker_attrs(mounts=[])
    record = _probe(client=_docker_client(attrs), authorized_hosts=[])
    assert record["capabilities"]["mounts"]["status"] == STATUS_ABSENT
    assert record["preflight"]["failures"] == []
    controls = {d["control"] for d in record["preflight"]["degradations"]}
    assert "egress_policy_delivery" in controls


def test_probe_writable_policy_mount_is_absent() -> None:
    attrs = _docker_attrs(mounts=[{"Type": "bind", "Destination": _POLICY_TARGET, "RW": True}])
    record = _probe(client=_docker_client(attrs))
    assert record["capabilities"]["mounts"]["status"] == STATUS_ABSENT
    assert _POLICY_TARGET in record["capabilities"]["mounts"]["evidence"]["writable"]


def test_probe_non_internal_network_is_absent() -> None:
    record = _probe(client=_docker_client(_docker_attrs(), internal=False))
    assert record["capabilities"]["network_policy"]["status"] == STATUS_ABSENT
    controls = {f["control"] for f in record["preflight"]["failures"]}
    assert "deny_by_default_egress" in controls


def test_probe_extra_network_attachment_is_absent() -> None:
    attrs = _docker_attrs(internal_attached=[_NETWORK, "bridge"])
    record = _probe(client=_docker_client(attrs))
    assert record["capabilities"]["network_policy"]["status"] == STATUS_ABSENT


def test_probe_unbounded_resources_is_degradation_not_failure() -> None:
    attrs = _docker_attrs(memory=0, nano_cpus=0, pids=0)
    record = _probe(client=_docker_client(attrs))
    assert record["capabilities"]["exec_constraints"]["status"] == STATUS_ABSENT
    assert record["preflight"]["failures"] == []
    controls = {d["control"] for d in record["preflight"]["degradations"]}
    assert "resource_limits" in controls


def test_probe_exception_becomes_unprobed_not_crash() -> None:
    class BrokenSession:
        @property
        def exec(self) -> Any:
            raise RuntimeError("boom")

        async def resolve_exposed_port(self, _port: int) -> Any:
            return SimpleNamespace(tls=False, host="127.0.0.1", port=48080)

    # A probe that itself raises records ``unprobed`` — never crashes setup.
    record = _probe(session=BrokenSession())
    assert record["capabilities"]["exec"]["status"] == STATUS_UNPROBED
    assert "probe raised" in record["capabilities"]["exec"]["detail"]


def test_evaluate_preflight_missing_capabilities_are_unprobed() -> None:
    preflight = evaluate_preflight({}, authorized_hosts=["a.example.com"], relay_configured=False)
    # Nothing probed → nothing fails outright, but every required control is
    # named as degraded rather than silently assumed.
    assert preflight["failures"] == []
    controls = {d["control"] for d in preflight["degradations"]}
    assert {
        "agent_exec",
        "proxy_channel",
        "traffic_capture",
        "deny_by_default_egress",
        "egress_policy_delivery",
        "resource_limits",
    } <= controls


@pytest.mark.asyncio
async def test_create_or_reuse_records_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attrs = _docker_attrs()
    client = _docker_client(attrs)
    session = _Session()

    async def backend(**_kwargs: Any) -> tuple[Any, Any]:
        return client, session

    async def caido(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace()

    scan_id = "cap-probe-scan"
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", caido)
    session_manager._SESSION_CACHE.pop(scan_id, None)
    try:
        bundle = await session_manager.create_or_reuse(
            scan_id,
            image="test-image",
            local_sources=[],
            targets=[
                {"type": "web_application", "details": {"target_url": "https://app.example.com"}}
            ],
        )
    finally:
        session_manager._SESSION_CACHE.pop(scan_id, None)

    caps = bundle["sandbox_capabilities"]
    assert caps["backend"] == "docker"
    assert caps["capabilities"]["exec"]["status"] == STATUS_SUPPORTED
    assert caps["capabilities"]["network_policy"]["status"] == STATUS_SUPPORTED
    assert caps["capabilities"]["mounts"]["status"] == STATUS_SUPPORTED
    assert caps["preflight"]["failures"] == []


@pytest.mark.asyncio
async def test_create_or_reuse_preflight_failure_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deleted: list[str] = []
    closed: list[str] = []

    class NoExecSession:
        async def resolve_exposed_port(self, _port: int) -> Any:
            return SimpleNamespace(tls=False, host="127.0.0.1", port=48080)

    class Client:
        async def delete(self, _session: Any) -> None:
            deleted.append("deleted")

    class CaidoStub:
        async def aclose(self) -> None:
            closed.append("closed")

    async def backend(**_kwargs: Any) -> tuple[Any, Any]:
        return Client(), NoExecSession()

    async def caido(*_args: Any, **_kwargs: Any) -> Any:
        return CaidoStub()

    scan_id = "cap-preflight-fail"
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", caido)
    session_manager._SESSION_CACHE.pop(scan_id, None)
    try:
        with pytest.raises(SandboxPreflightError, match="agent_exec"):
            await session_manager.create_or_reuse(scan_id, image="test-image", local_sources=[])
    finally:
        session_manager._SESSION_CACHE.pop(scan_id, None)

    assert deleted == ["deleted"]
