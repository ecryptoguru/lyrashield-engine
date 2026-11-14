"""The root builder and controller attach path use identical pinned SDK bytes."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from lyrashield.runtime import session_manager
from lyrashield.runtime.controller_manifest import (
    build_controller_manifest,
    controller_manifest_input,
    controller_source_snapshots,
    read_controller_manifest,
)
from tests.test_session_cleanup import _stub_startup


@pytest.mark.parametrize("relay_required", [False, True])
def test_manifest_round_trip_has_no_host_paths_or_credentials(relay_required: bool) -> None:
    raw = controller_manifest_input(
        build_controller_manifest("scan-fixture", relay_required=relay_required)
    )
    manifest, relay = read_controller_manifest(raw, "scan-fixture")
    assert controller_manifest_input(manifest) == raw
    assert relay is relay_required
    assert manifest.entries == {}
    assert manifest.extra_path_grants == ()
    assert manifest.root == "/workspace"
    assert manifest.environment.value["STRIX_RUN_ID"] == "scan-fixture"
    assert "TOKEN" not in raw and "KEY" not in raw
    assert "tmp" not in raw.split("/")


@pytest.mark.parametrize("change", ["scan", "canonical", "credential", "grant", "root", "proxy"])
def test_manifest_rejects_tamper_and_foreign_bindings(change: str) -> None:
    raw = controller_manifest_input(build_controller_manifest("scan-fixture", relay_required=False))
    value = json.loads(raw)
    if change == "scan":
        with pytest.raises(ValueError):
            read_controller_manifest(raw, "other-scan")
        return
    if change == "canonical":
        raw = json.dumps(value)
    elif change == "credential":
        value["environment"]["value"]["LLM_API_KEY"] = "untrusted"
    elif change == "grant":
        value["extra_path_grants"] = [{"path": "/private"}]
    elif change == "root":
        value["root"] = "/private"
    else:
        value["environment"]["value"]["http_proxy"] = "https://outside.example"
    if change != "canonical":
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ValueError):
        read_controller_manifest(raw, "scan-fixture")


@pytest.mark.asyncio
async def test_controller_start_consumes_root_manifest_without_local_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_manager._SESSION_CACHE.clear()
    raw = controller_manifest_input(build_controller_manifest("scan-fixture", relay_required=False))
    monkeypatch.setenv("LYRASHIELD_SUPERVISOR_MANIFEST_INPUT", raw)
    mocks = _stub_startup(monkeypatch)
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        Mock(return_value=SimpleNamespace(runtime=SimpleNamespace(backend="controller"))),
    )
    monkeypatch.setattr(
        "lyrashield.runtime.controller_backend.assert_controller_scan_authority", Mock()
    )
    try:
        await session_manager.create_or_reuse(
            "scan-fixture", image="fixture-image", local_sources=[]
        )
        assert controller_manifest_input(mocks.backend.await_args.kwargs["manifest"]) == raw
        assert mocks.backend.await_args.kwargs["bind_mounts"] == []
        session_manager.build_session_entries.assert_not_called()
        session_manager.write_egress_policy.assert_not_called()
    finally:
        session_manager._SESSION_CACHE.clear()


def test_source_provenance_uses_authenticated_installed_tree() -> None:
    assert controller_source_snapshots(
        {"source": {"stagedTreeDigest": "a" * 64}}, source_required=True
    ) == [{"workspace_subdir": "source", "snapshot_digest": "a" * 64}]
    assert controller_source_snapshots(None, source_required=False) == []
    with pytest.raises(RuntimeError, match="provenance"):
        controller_source_snapshots(None, source_required=True)
