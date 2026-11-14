"""Tests for symlink-safe LocalDir staging."""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

import pytest

from lyrashield.runtime.local_dir_staging import (
    stage_frozen_dir,
    stage_symlink_safe_dir,
    staged_tree_digest,
    tree_has_symlink,
)


if TYPE_CHECKING:
    from pathlib import Path


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "mod.py").write_text("x = 1\n")
    (repo / "README.md").write_text("readme\n")
    return repo


def test_tree_without_symlinks_used_as_is(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    upload_path, staged = stage_symlink_safe_dir(repo)

    assert staged is None
    assert upload_path == repo.resolve()
    assert not tree_has_symlink(repo)


def test_in_tree_file_symlink_is_dereferenced(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "link.py").symlink_to(repo / "pkg" / "mod.py")

    upload_path, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert upload_path == staged
    assert not (staged / "link.py").is_symlink()
    assert (staged / "link.py").read_text() == "x = 1\n"
    assert (staged / "pkg" / "mod.py").read_text() == "x = 1\n"
    assert not tree_has_symlink(staged)


def test_in_tree_relative_dir_symlink_is_dereferenced(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "pkg_alias").symlink_to("pkg")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert (staged / "pkg_alias" / "mod.py").read_text() == "x = 1\n"
    assert not tree_has_symlink(staged)


def test_out_of_tree_symlink_is_dropped(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    (repo / "escape.txt").symlink_to(outside)
    (repo / "abs_escape").symlink_to("/etc")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert not (staged / "escape.txt").exists()
    assert not (staged / "abs_escape").exists()
    assert (staged / "README.md").exists()


def test_dangling_symlink_is_dropped(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "dangling").symlink_to(repo / "does-not-exist")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert not (staged / "dangling").exists()
    assert not (staged / "dangling").is_symlink()


def test_cyclic_symlink_terminates(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "self").symlink_to(repo)
    (repo / "pkg" / "up").symlink_to("..")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert (staged / "README.md").exists()
    assert not tree_has_symlink(staged)


def test_nested_symlinks_inside_linked_dir(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    shared = repo / "shared"
    shared.mkdir()
    (shared / "conf.json").write_text("{}\n")
    (shared / "escape").symlink_to("/etc/passwd")
    (repo / "pkg" / "shared_link").symlink_to(shared)

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert (staged / "pkg" / "shared_link" / "conf.json").read_text() == "{}\n"
    assert not (staged / "pkg" / "shared_link" / "escape").exists()
    assert not (staged / "shared" / "escape").exists()


def test_staged_path_has_no_symlink_ancestor(tmp_path: Path, monkeypatch) -> None:
    """The staging directory itself must never sit behind a symlink.

    ``tempfile.mkdtemp()`` honors ``$TMPDIR``, and on macOS the default
    ``$TMPDIR`` resolves through ``/var``, which is itself a symlink to
    ``/private/var``. ``LocalDir`` rejects any symlink component in its
    source path, so returning the raw ``mkdtemp()`` result breaks every
    local-dir upload on macOS whenever the source tree contains a symlink.
    This reproduces that shape without depending on the host OS layout.
    """
    repo = _make_repo(tmp_path)
    (repo / "link.py").symlink_to(repo / "pkg" / "mod.py")

    real_tmp_root = tmp_path / "real_tmp"
    real_tmp_root.mkdir()
    symlinked_tmp_root = tmp_path / "tmp_symlink"
    symlinked_tmp_root.symlink_to(real_tmp_root)

    def fake_mkdtemp(prefix: str = "") -> str:
        real_dir = real_tmp_root / f"{prefix}fake"
        real_dir.mkdir()
        return str(symlinked_tmp_root / real_dir.name)

    monkeypatch.setattr("lyrashield.runtime.local_dir_staging.tempfile.mkdtemp", fake_mkdtemp)

    upload_path, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert upload_path == staged
    for path in (staged, *staged.parents):
        assert not path.is_symlink(), f"staged path has a symlink ancestor: {path}"


def test_frozen_staging_copies_internal_links_as_independent_bytes(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "pkg_alias").symlink_to("pkg")
    (repo / "link.py").symlink_to("pkg/mod.py")

    staged = stage_frozen_dir(repo)
    try:
        (repo / "pkg" / "mod.py").write_text("changed\n")
        assert (staged / "pkg" / "mod.py").read_text() == "x = 1\n"
        assert (staged / "pkg_alias" / "mod.py").read_text() == "x = 1\n"
        assert (staged / "link.py").read_text() == "x = 1\n"
        assert not tree_has_symlink(staged)
    finally:
        shutil.rmtree(staged)


def test_frozen_staging_rejects_directory_swap_to_external_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.py").write_text("secret\n")
    original_open = os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "pkg" and dir_fd is not None and not swapped:
            swapped = True
            (repo / "pkg").rename(repo / "parked")
            (repo / "pkg").symlink_to(outside)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_before_open)
    with pytest.raises(OSError):
        stage_frozen_dir(repo)
    assert swapped


def test_frozen_staging_rejects_temp_directory_inside_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path)
    temp_inside = repo / "staging"

    def inside_mkdtemp(*, prefix: str) -> str:
        assert prefix
        temp_inside.mkdir()
        return str(temp_inside)

    monkeypatch.setattr("lyrashield.runtime.local_dir_staging.tempfile.mkdtemp", inside_mkdtemp)
    with pytest.raises(OSError, match="contains its own staging"):
        stage_frozen_dir(repo)
    assert not temp_inside.exists()


@pytest.mark.parametrize("link_to_directory", [False, True])
def test_staged_digest_rejects_links_in_frozen_snapshot(
    tmp_path: Path, link_to_directory: bool
) -> None:
    repo = _make_repo(tmp_path)
    target = tmp_path / "outside"
    if link_to_directory:
        target.mkdir()
    else:
        target.write_text("outside\n")
    (repo / "unexpected-link").symlink_to(target, target_is_directory=link_to_directory)

    with pytest.raises(OSError):
        staged_tree_digest(repo)


def test_staged_digest_rejects_a_file_changed_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path)
    original_read = os.read
    changed = False

    def change_during_read(fd: int, count: int) -> bytes:
        nonlocal changed
        chunk = original_read(fd, count)
        if not changed:
            changed = True
            (repo / "README.md").write_text("modified while reading\n")
        return chunk

    monkeypatch.setattr(os, "read", change_during_read)
    with pytest.raises(OSError):
        staged_tree_digest(repo)


def test_staged_digest_preserves_existing_binary_path_and_content_format(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    assert staged_tree_digest(repo) == (
        "sha256:ab93f8d25dd1885e3e5d09b9bcfc70aa8f312d3b03766d49daa6d09230dd6e84"
    )
    (repo / ".gitignore").write_text("ignored.py\n")
    ignored = repo / "ignored.py"
    ignored.write_text("first\n")
    before = staged_tree_digest(repo)
    ignored.write_text("other\n")
    assert staged_tree_digest(repo) != before


def test_staged_digest_rejects_a_linked_root(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    linked = tmp_path / "linked-root"
    linked.symlink_to(repo, target_is_directory=True)
    with pytest.raises(OSError):
        staged_tree_digest(linked)


def test_staged_digest_rejects_hardlinks_and_special_entries(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    linked = repo / "hardlink"
    os.link(repo / "README.md", linked)
    with pytest.raises(OSError):
        staged_tree_digest(repo)
    linked.unlink()
    os.mkfifo(repo / "pipe")
    with pytest.raises(OSError):
        staged_tree_digest(repo)


def test_staged_digest_rejects_a_directory_swapped_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("private\n")
    original_open = os.open

    def swap_before_open(path, flags, *args, **kwargs):
        if path == "pkg" and "dir_fd" in kwargs:
            (repo / "pkg").rename(tmp_path / "original-pkg")
            (repo / "pkg").symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_before_open)
    with pytest.raises(OSError):
        staged_tree_digest(repo)
