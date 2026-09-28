from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.lifecycle import sandbox_bringup


if TYPE_CHECKING:
    from pathlib import Path


class _ReportState:
    def __init__(self) -> None:
        self.run_record: dict[str, Any] = {"diff_scope": {"repos": [{"workspace_subdir": "src"}]}}
        self.capabilities: dict[str, Any] | None = None

    def set_sandbox_capabilities(self, capabilities: dict[str, Any]) -> None:
        self.capabilities = capabilities


@pytest.mark.asyncio
async def test_bring_up_sandbox_records_uploaded_provenance_and_scope(tmp_path: Path) -> None:
    state = _ReportState()
    call: dict[str, Any] = {}
    bundle = {
        "source_snapshots": [{"workspace_subdir": "src", "snapshot_digest": "sha256:uploaded"}],
        "attachment_manifest": [{"name": "notes.txt", "sha256": "a" * 64}],
        "default_scope_id": "scope-1",
        "default_scope_allowlist": ["api.example.test"],
        "sandbox_capabilities": {"network_mode": "deny_by_default"},
        "session": object(),
    }

    async def create_or_reuse(*args: Any, **kwargs: Any) -> dict[str, Any]:
        call["args"] = args
        call["kwargs"] = kwargs
        return bundle

    actual = await sandbox_bringup.bring_up_sandbox(
        scan_id="scan-sandbox",
        image="sandbox:sha256",
        local_sources=[{"path": str(tmp_path / "repo")}],
        attachments=None,
        scan_config={"targets": [{"type": "repository"}], "attachments": [{"name": "brief.txt"}]},
        create_or_reuse=create_or_reuse,
        report_state_getter=lambda: state,
    )

    assert actual is bundle
    assert call["args"] == ("scan-sandbox",)
    assert call["kwargs"]["image"] == "sandbox:sha256"
    assert call["kwargs"]["local_sources"] == [{"path": str(tmp_path / "repo")}]
    assert call["kwargs"]["targets"] == [{"type": "repository"}]
    assert call["kwargs"]["attachments"] == [{"name": "brief.txt"}]
    assert state.run_record["source_snapshots"] == bundle["source_snapshots"]
    assert state.run_record["diff_scope"]["repos"][0]["snapshot_digest"] == "sha256:uploaded"
    assert state.run_record["diff_scope"]["repos"][0]["snapshot_digest_stage"] == "uploaded_source"
    assert state.run_record["attachments"] == bundle["attachment_manifest"]
    assert state.run_record["proxy_default_scope"] == {
        "id": "scope-1",
        "name": "authorized-targets",
        "allowlist": ["api.example.test"],
    }
    assert state.capabilities == {"network_mode": "deny_by_default"}
