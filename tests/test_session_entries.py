"""Tests for build_session_entries: splitting copied vs bind-mounted sources."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from agents.sandbox.entries import LocalDir

from strix.runtime import session_manager
from strix.runtime.session_manager import (
    build_sandbox_environment,
    build_session_entries,
    get_sandbox_container_ip,
    resolve_sandbox_endpoint,
)


if TYPE_CHECKING:
    from pathlib import Path


def _source(subdir: str, path: str, *, mount: bool = False) -> dict[str, Any]:
    return {"source_path": path, "workspace_subdir": subdir, "mount": mount}


def test_copied_source_becomes_localdir_entry(tmp_path: Path) -> None:
    entries, bind_mounts, staged_dirs, grants = build_session_entries(
        [_source("repo", str(tmp_path))]
    )

    assert bind_mounts == []
    assert staged_dirs == []
    assert isinstance(entries["repo"], LocalDir)
    assert entries["repo"].src == tmp_path.resolve()
    assert any(g.path == str(tmp_path.resolve()) for g in grants)


def test_host_gateway_is_not_advertised_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_ALLOW_HOST_GATEWAY", raising=False)

    environment = build_sandbox_environment("http://127.0.0.1:48080")

    assert "HOST_GATEWAY" not in environment


def test_host_gateway_is_advertised_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_ALLOW_HOST_GATEWAY", "1")

    environment = build_sandbox_environment("http://127.0.0.1:48080")

    assert environment["HOST_GATEWAY"] == "host.docker.internal"


def test_mounted_source_becomes_bind_mount(tmp_path: Path) -> None:
    entries, bind_mounts, _staged, grants = build_session_entries(
        [_source("repo", str(tmp_path), mount=True)]
    )

    assert entries == {}
    assert bind_mounts == [
        {
            "source": str(tmp_path.resolve()),
            "target": "/workspace/repo",
            "read_only": True,
        }
    ]
    assert any(g.path == str(tmp_path.resolve()) for g in grants)


def test_mixed_sources_split_correctly(tmp_path: Path) -> None:
    copied = tmp_path / "copied"
    mounted = tmp_path / "mounted"
    copied.mkdir()
    mounted.mkdir()

    entries, bind_mounts, _staged, grants = build_session_entries(
        [
            _source("copied", str(copied)),
            _source("mounted", str(mounted), mount=True),
        ]
    )

    assert list(entries) == ["copied"]
    assert isinstance(entries["copied"], LocalDir)
    assert [m["target"] for m in bind_mounts] == ["/workspace/mounted"]
    grant_paths = {g.path for g in grants}
    assert str(copied.resolve()) in grant_paths
    assert str(mounted.resolve()) in grant_paths


def test_incomplete_sources_are_skipped() -> None:
    entries, bind_mounts, staged_dirs, grants = build_session_entries(
        [
            {"source_path": "", "workspace_subdir": "x"},
            {"source_path": "/p", "workspace_subdir": ""},
        ]
    )
    assert entries == {}
    assert bind_mounts == []
    assert staged_dirs == []
    assert grants == ()


def test_containerized_worker_uses_sandbox_bridge_address() -> None:
    assert resolve_sandbox_endpoint(
        "127.0.0.1", 64682, in_container=True, container_ip="172.17.0.3"
    ) == ("172.17.0.3", 48080)
    assert resolve_sandbox_endpoint("127.0.0.1", 64682, in_container=False) == (
        "127.0.0.1",
        64682,
    )


def test_container_ip_uses_wrapped_docker_session() -> None:
    class Container:
        def __init__(self) -> None:
            self.attrs = {"NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.3"}}}}

    class Containers:
        @staticmethod
        def get(_: str) -> Container:
            return Container()

    class DockerClient:
        containers = Containers()

    class Client:
        docker_client = DockerClient()

    class Inner:
        container_id = "sandbox-id"

    class Session:
        _inner = Inner()

    assert get_sandbox_container_ip(Client(), Session()) == "172.17.0.3"


def test_symlink_tree_is_staged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.txt").write_text("content")
    (repo / "link.txt").symlink_to(repo / "real.txt")

    entries, _mounts, staged_dirs, grants = build_session_entries([_source("repo", str(repo))])

    assert len(staged_dirs) == 1
    entry = entries["repo"]
    assert isinstance(entry, LocalDir)
    assert entry.src == staged_dirs[0]
    assert not (staged_dirs[0] / "link.txt").is_symlink()
    assert (staged_dirs[0] / "link.txt").read_text() == "content"
    assert any(g.path == str(staged_dirs[0]) for g in grants)


@pytest.mark.asyncio
async def test_create_or_reuse_passes_path_grants_to_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class Session:
        async def resolve_exposed_port(self, _port: int) -> Any:
            return SimpleNamespace(tls=False, host="127.0.0.1", port=48080)

    async def backend(**kwargs: Any) -> tuple[Any, Any]:
        captured.update(kwargs)
        return SimpleNamespace(), Session()

    async def no_caido(*_args: Any, **_kwargs: Any) -> None:
        return None

    scan_id = "manifest-grants"
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", no_caido)
    session_manager._SESSION_CACHE.pop(scan_id, None)

    try:
        await session_manager.create_or_reuse(
            scan_id,
            image="test-image",
            local_sources=[_source("repo", str(tmp_path))],
        )
    finally:
        session_manager._SESSION_CACHE.pop(scan_id, None)

    assert [grant.path for grant in captured["manifest"].extra_path_grants] == [
        str(tmp_path.resolve())
    ]
