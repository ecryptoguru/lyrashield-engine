"""Canonical attach-only SDK manifests produced by the pinned engine image.

The controller has already installed the source, attachment and policy mounts.
No LocalDir walker, host path, credential or random staging directory enters
this manifest. The root launcher and engine consume the same canonical bytes.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from agents.sandbox.manifest import EnvEntry, Environment, EnvValue, Manifest
from agents.sandbox.types import User


_MAX_BYTES = 16 * 1024
_SCAN_ID = re.compile(r"^[A-Za-z0-9_-]{3,128}$")
_PORT = 48080


def build_controller_manifest(scan_id: str, *, relay_required: bool) -> Manifest:
    if not _SCAN_ID.fullmatch(scan_id) or type(relay_required) is not bool:
        raise ValueError("Controller manifest binding is invalid")
    proxy = f"http://127.0.0.1:{_PORT}"
    environment: dict[str, str | EnvValue | EnvEntry] = {
        "PYTHONUNBUFFERED": "1",
        "http_proxy": proxy,
        "https_proxy": proxy,
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "ALL_PROXY": proxy,
        "NO_PROXY": "localhost,127.0.0.1",
        "AGENT_BROWSER_PROXY": proxy,
        "LYRASHIELD_EGRESS_POLICY": "/run/lyrashield-egress/policy.json",
        "STRIX_RUN_ID": scan_id,
    }
    if relay_required:
        environment["STRIX_TARGET_RELAY"] = "1"
    return Manifest(
        entries={},
        environment=Environment(value=environment),
        extra_path_grants=(),
        users=[User(name="pentester")],
    )


def controller_manifest_input(manifest: Manifest) -> str:
    return json.dumps(
        manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def read_controller_manifest(raw: str, scan_id: str) -> tuple[Manifest, bool]:
    if not raw or len(raw.encode()) > _MAX_BYTES:
        raise ValueError("Installed controller manifest is unavailable")
    manifest = Manifest.model_validate_json(raw)
    environment: Any = manifest.environment.value
    relay_required = environment.get("STRIX_TARGET_RELAY") == "1"
    expected = build_controller_manifest(scan_id, relay_required=relay_required)
    if controller_manifest_input(manifest) != raw or controller_manifest_input(expected) != raw:
        raise ValueError("Installed controller manifest differs from the bound SDK manifest")
    return manifest, relay_required


def controller_source_snapshots(
    grant: dict[str, Any] | None, *, source_required: bool
) -> list[dict[str, str]]:
    source = grant.get("source") if grant else None
    if source_required and not source:
        raise RuntimeError("Controller source provenance is unavailable")
    return (
        [{"workspace_subdir": "source", "snapshot_digest": source["stagedTreeDigest"]}]
        if source
        else []
    )


def main() -> None:
    raw = sys.stdin.buffer.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise ValueError("Controller manifest input exceeds the bound")
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != {"scanId", "relayRequired"}:
        raise ValueError("Controller manifest input is invalid")
    result = controller_manifest_input(
        build_controller_manifest(request["scanId"], relay_required=request["relayRequired"])
    )
    sys.stdout.write(result)


if __name__ == "__main__":
    main()
