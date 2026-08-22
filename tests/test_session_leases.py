"""Sandbox lease serialization and per-run egress policy isolation (I14)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from lyrashield.runtime import session_manager


def _fake_backend_factory(behavior: dict[str, Any]):
    """Backend double recording creations and returning fake sessions."""

    async def _backend(
        *,
        image: str,  # noqa: ARG001 - backend signature is fixed
        manifest: Any,
        exposed_ports: tuple[int, ...],  # noqa: ARG001
        bind_mounts: list[dict[str, Any]] | None = None,
    ) -> tuple[Any, Any]:
        behavior["creations"] += 1
        await asyncio.sleep(0.01)  # widen the race window the lock must close
        client = MagicMock()
        client.delete = _async_noop
        session = MagicMock()
        endpoint = MagicMock(host="127.0.0.1", port=48080, tls=False)
        session.resolve_exposed_port = _async_value(endpoint)
        behavior["manifests"].append(manifest)
        behavior["bind_mounts"].append(list(bind_mounts or []))
        return client, session

    return _backend


async def _async_noop(*_args: Any, **_kwargs: Any) -> None:
    return None


def _async_value(value: Any):
    async def _run(*_args: Any, **_kwargs: Any) -> Any:
        return value

    return _run


def _url_target(url: str) -> dict[str, Any]:
    return {"type": "web_application", "details": {"target_url": url}}


@pytest.fixture(autouse=True)
def _clean_cache():
    session_manager._SESSION_CACHE.clear()
    # Module locks bind to the event loop that first acquires them; give each
    # test (pytest-asyncio creates a loop per test) fresh locks.
    session_manager._CACHE_LOCK = asyncio.Lock()
    session_manager._CREATION_LOCK = asyncio.Lock()
    yield
    session_manager._SESSION_CACHE.clear()


@pytest.fixture
def _stubbed_bootstraps(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    behavior: dict[str, Any] = {"creations": 0, "manifests": [], "bind_mounts": []}
    monkeypatch.setattr(
        session_manager, "get_backend", lambda _name: _fake_backend_factory(behavior)
    )
    monkeypatch.setattr(
        session_manager,
        "bootstrap_caido",
        _async_value(MagicMock()),
    )
    monkeypatch.setattr(
        session_manager,
        "_create_default_scope",
        _async_value((None, None)),
    )
    settings = MagicMock()
    settings.runtime.backend = "docker"
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
    return behavior


@pytest.mark.asyncio
async def test_concurrent_same_scan_id_creates_one_session(_stubbed_bootstraps) -> None:
    behavior = _stubbed_bootstraps
    bundles = await asyncio.gather(
        *(
            session_manager.create_or_reuse(
                "scan-same",
                image="img:1",
                local_sources=[],
                targets=[_url_target("https://one.example.com/")],
            )
            for _ in range(5)
        )
    )
    assert behavior["creations"] == 1
    assert all(bundle is bundles[0] for bundle in bundles)
    assert len(session_manager._SESSION_CACHE) == 1
    await session_manager.cleanup("scan-same")


@pytest.mark.asyncio
async def test_concurrent_different_scan_ids_get_isolated_policies(_stubbed_bootstraps) -> None:
    behavior = _stubbed_bootstraps
    bundle_a, bundle_b = await asyncio.gather(
        session_manager.create_or_reuse(
            "scan-a",
            image="img:1",
            local_sources=[],
            targets=[_url_target("https://a.example.com/")],
        ),
        session_manager.create_or_reuse(
            "scan-b",
            image="img:1",
            local_sources=[],
            targets=[_url_target("https://b.example.com/")],
        ),
    )
    assert behavior["creations"] == 2

    def _policy_mount(bundle: dict[str, Any]) -> dict[str, Any]:
        return next(m for m in bundle_mounts(bundle) if m["target"].endswith("policy.json"))

    def bundle_mounts(bundle: dict[str, Any]) -> list[dict[str, Any]]:
        # bind_mounts recorded per creation; map through the policy dir on disk.
        policy_dir = bundle["egress_policy_dir"]
        for mounts in behavior["bind_mounts"]:
            for mount in mounts:
                if mount["source"].startswith(policy_dir):
                    return mounts
        raise AssertionError(f"no bind mounts found for {policy_dir}")

    mount_a = _policy_mount(bundle_a)
    mount_b = _policy_mount(bundle_b)
    assert mount_a["read_only"] is True and mount_b["read_only"] is True
    policy_a = json.loads(Path(mount_a["source"]).read_text(encoding="utf-8"))
    policy_b = json.loads(Path(mount_b["source"]).read_text(encoding="utf-8"))
    assert policy_a["authorized_hosts"] == ["a.example.com"]
    assert policy_b["authorized_hosts"] == ["b.example.com"]
    # Neither run can replay toward the other's target: each policy file
    # authorizes only its own run's hosts.
    assert "a.example.com" in policy_a["authorized_hosts"]
    assert "a.example.com" not in policy_b["authorized_hosts"]
    await asyncio.gather(session_manager.cleanup("scan-a"), session_manager.cleanup("scan-b"))
    assert not Path(mount_a["source"]).exists()
    assert not Path(mount_b["source"]).exists()


@pytest.mark.asyncio
async def test_manifest_carries_policy_env(_stubbed_bootstraps) -> None:
    behavior = _stubbed_bootstraps
    await session_manager.create_or_reuse(
        "scan-env",
        image="img:1",
        local_sources=[],
        targets=[_url_target("https://env.example.com/")],
    )
    manifest = behavior["manifests"][0]
    value = manifest.environment.value
    assert value["LYRASHIELD_EGRESS_POLICY"] == "/run/lyrashield-egress/policy.json"
    await session_manager.cleanup("scan-env")
