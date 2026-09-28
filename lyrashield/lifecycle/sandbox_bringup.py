# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Create the scan sandbox and record its uploaded evidence context."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


logger = logging.getLogger(__name__)


async def bring_up_sandbox(
    *,
    scan_id: str,
    image: str,
    local_sources: list[dict[str, Any]] | None,
    attachments: list[dict[str, Any]] | None,
    scan_config: dict[str, Any],
    create_or_reuse: Callable[..., Awaitable[dict[str, Any]]],
    report_state_getter: Callable[[], Any | None],
) -> dict[str, Any]:
    """Start/reuse the sandbox and persist the exact staged provenance."""
    logger.info("Bringing up sandbox session for scan %s", scan_id)
    bundle = await create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
        targets=list(scan_config.get("targets") or []),
        # Supporting files are untrusted evidence. They never add scan scope or
        # alter the sandbox egress policy.
        attachments=(
            attachments if attachments is not None else list(scan_config.get("attachments") or [])
        ),
    )
    logger.info("Sandbox ready for scan %s", scan_id)

    source_snapshots = bundle.get("source_snapshots")
    if source_snapshots:
        report_state = report_state_getter()
        if report_state is not None:
            # These are digests of the independent files actually uploaded,
            # not of an earlier live worktree that might have changed.
            report_state.run_record["source_snapshots"] = source_snapshots
            diff_scope = report_state.run_record.get("diff_scope")
            if isinstance(diff_scope, dict):
                for repo in diff_scope.get("repos", []):
                    if not isinstance(repo, dict):
                        continue
                    for snapshot in source_snapshots:
                        if repo.get("workspace_subdir") == snapshot.get("workspace_subdir"):
                            repo["snapshot_digest"] = snapshot["snapshot_digest"]
                            repo["snapshot_digest_stage"] = "uploaded_source"

    attachment_manifest = bundle.get("attachment_manifest")
    if attachment_manifest:
        report_state = report_state_getter()
        if report_state is not None:
            # Provenance for the staged originals mounted into the sandbox.
            report_state.run_record["attachments"] = attachment_manifest

    if bundle.get("default_scope_id"):
        report_state = report_state_getter()
        if report_state is not None:
            report_state.run_record["proxy_default_scope"] = {
                "id": bundle["default_scope_id"],
                "name": "authorized-targets",
                "allowlist": bundle.get("default_scope_allowlist") or [],
            }
    capabilities = bundle.get("sandbox_capabilities")
    if capabilities is not None:
        report_state = report_state_getter()
        if report_state is not None:
            report_state.set_sandbox_capabilities(capabilities)
    return bundle
