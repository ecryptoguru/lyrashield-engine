"""Build-time rootfs metadata normalization contracts.

Covers ``containers/normalize_rootfs_metadata.py``: reviewed duplicate
JSON, the scanner-faithful directory-alias safety predicate (only aliases
the scanner would reject get materialized), fail-closed behavior,
ownership/mode preservation, idempotency, and the Dockerfile
integration. ``scripts/check_sbom_inventory.py`` is imported where parity
with the authoritative scanner matters.
"""

from __future__ import annotations

import json
import os
import runpy
import stat
from contextlib import suppress
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "containers" / "normalize_rootfs_metadata.py"
DOCKERFILE = ROOT / "containers" / "Dockerfile"

API = runpy.run_path(str(SCRIPT))
SCANNER = runpy.run_path(str(ROOT / "scripts/check_sbom_inventory.py"))

canonical_with_last_wins = API["canonical_with_last_wins"]
is_npm_metadata = API["is_npm_metadata"]
metadata_kind = API["metadata_kind"]
materialize_directory_symlinks = API["materialize_directory_symlinks"]
canonicalize_npm_metadata = API["canonicalize_npm_metadata"]
normalize = API["normalize"]
verify_clean = API["verify_clean"]


def write_package(root: Path, rel_dir: str, data: bytes, *, mode: int | None = None) -> Path:
    path = root / "usr/share/nodejs" / rel_dir
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return path


def make_dir_link(root: Path, link_rel: str, target_rel: str) -> Path:
    target = root / target_rel
    target.mkdir(parents=True, exist_ok=True)
    (target / "index.css").write_text("css")
    link = root / link_rel
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(os.path.relpath(target, link.parent), target_is_directory=True)
    return link


class TestCanonicalJson:
    @pytest.mark.parametrize("package", ["source-map", "windows-release"])
    def test_exact_reviewed_image_metadata_preserves_effective_identity(self, package):
        fixture = ROOT / "tests/fixtures/rootfs-normalization" / f"{package}.package.json"
        raw = fixture.read_bytes()
        canonical, changed = canonical_with_last_wins(raw)
        assert changed
        assert json.loads(canonical) == json.loads(raw)

    @pytest.mark.parametrize("package", ["source-map", "windows-release"])
    def test_modified_reviewed_conflicting_metadata_is_not_normalized(self, package):
        fixture = ROOT / "tests/fixtures/rootfs-normalization" / f"{package}.package.json"
        raw = fixture.read_bytes()
        with pytest.raises(ValueError, match="unreviewed duplicate"):
            canonical_with_last_wins(raw + b" ")

    def test_reviewed_source_map_duplicate_types_are_collapsed(self) -> None:
        original = (
            b'{"name": "source-map", "types": "source-map.d.ts", '
            b'"types": "source-map.d.ts", "version": "0.8.0"}'
        )
        canonical, changed = canonical_with_last_wins(original)
        assert changed
        assert json.loads(canonical) == {
            "name": "source-map",
            "types": "source-map.d.ts",
            "version": "0.8.0",
        }

    def test_nested_duplicate_keys_are_rejected(self) -> None:
        original = b'{"exports": {"import": "./a.js", "import": "./b.js"}, "name": "x"}'
        with pytest.raises(ValueError, match="unreviewed duplicate"):
            canonical_with_last_wins(original)

    def test_reviewed_windows_release_duplicate_engines_are_collapsed(self) -> None:
        original = (
            b'{"name":"windows-release","version":"6.0.0",'
            b'"engines":{"node":">=12"},"engines":{"node":">=12"}}'
        )
        canonical, changed = canonical_with_last_wins(original)
        assert changed
        assert json.loads(canonical) == {
            "name": "windows-release",
            "version": "6.0.0",
            "engines": {"node": ">=12"},
        }

    def test_clean_json_is_reported_unchanged(self) -> None:
        original = b'{\n  "name": "example",\n  "version": "1.0.0"\n}\n'
        canonical, changed = canonical_with_last_wins(original)
        assert not changed
        assert canonical == original

    def test_malformed_json_fails_closed(self) -> None:
        with pytest.raises(ValueError):
            canonical_with_last_wins(b'{"name": ')

    def test_non_object_top_level_fails_closed(self) -> None:
        with pytest.raises(TypeError):
            canonical_with_last_wins(b'["name", "version"]')

    def test_duplicated_name_and_version_are_rejected(self) -> None:
        original = b'{"name": "a", "name": "b", "version": "1", "version": "2"}'
        with pytest.raises(ValueError, match="unreviewed duplicate"):
            canonical_with_last_wins(original)

    @pytest.mark.parametrize(
        "original",
        [
            b'{"name":"x","version":"1","types":"a","types":"a"}',
            b'{"name":"source-map","version":"0.8.1","types":"a","types":"a"}',
            b'{"name":"source-map","version":"0.8.0","types":"a","types":"b"}',
            b'{"name":"source-map","name":"source-map","version":"0.8.0"}',
            b'{"name":"source-map","version":"0.8.0","version":"0.8.0"}',
            b'{"name":"source-map","version":"0.8.0","exports":{"types":"a","types":"a"}}',
            b'{"name":"windows-release","version":"6.0.0","engines":{"node":true},"engines":{"node":1}}',
        ],
    )
    def test_unreviewed_or_conflicting_duplicates_are_rejected(self, original: bytes) -> None:
        with pytest.raises(ValueError, match="unreviewed duplicate"):
            canonical_with_last_wins(original)


class TestNpmMetadataScopeParity:
    """The normalizer's npm scope must agree with the authoritative scanner."""

    @pytest.mark.parametrize(
        "name",
        [
            "usr/share/nodejs/example/package.json",
            "usr/share/nodejs/@scope/example/package.json",
            "usr/share/nodejs/npm/node_modules/example/package.json",
            "usr/share/nodejs/example/not-this.json",
            "usr/share/nodejs/example/deep/nested/package.json",
            "usr/local/lib/node_modules/example/package.json",
            "home/pentester/.npm-tools/node_modules/example/package.json",
            "usr/lib/python3/dist-packages/example/METADATA",
            "var/lib/dpkg/status",
            "usr/lib/python3/dist-packages/example/package.json",
        ],
    )
    def test_is_npm_metadata_agrees_with_scanner(self, name: str) -> None:
        assert is_npm_metadata(name) == (SCANNER["metadata_kind"](name) == "npm")

    @pytest.mark.parametrize(
        "name",
        [
            "usr/lib/python3/dist-packages/example-1.0.dist-info/METADATA",
            "app/.venv/lib/python3.14/site-packages/example-1.0.dist-info/METADATA",
        ],
    )
    def test_metadata_kind_agrees_with_scanner(self, name: str) -> None:
        assert metadata_kind(name) == SCANNER["metadata_kind"](name)


class TestCanonicalizeFiles:
    def test_duplicate_file_is_rewritten_and_parseable(self, tmp_path: Path) -> None:
        path = write_package(
            tmp_path,
            "source-map/package.json",
            b'{"name": "source-map", "types": "a", "types": "a", "version": "0.8.0"}',
            mode=0o640,
        )
        changed = canonicalize_npm_metadata(tmp_path)
        assert changed == ["usr/share/nodejs/source-map/package.json"]
        parsed = json.loads(path.read_bytes())
        assert parsed == {"name": "source-map", "types": "a", "version": "0.8.0"}
        # Mode preserved.
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
        assert (path.stat().st_uid, path.stat().st_gid) == (os.getuid(), os.getgid())

    def test_clean_file_is_not_rewritten(self, tmp_path: Path) -> None:
        original = b'{\n  "name": "clean",\n  "version": "1.0.0"\n}\n'
        path = write_package(tmp_path, "clean/package.json", original)
        changed = canonicalize_npm_metadata(tmp_path)
        assert changed == []
        assert path.read_bytes() == original

    def test_malformed_metadata_fails_closed(self, tmp_path: Path) -> None:
        write_package(tmp_path, "broken/package.json", b'{"name": ')
        with pytest.raises(ValueError, match="malformed package metadata"):
            canonicalize_npm_metadata(tmp_path)


class TestLinkMaterialization:
    def test_scanner_safe_node_self_alias_is_not_materialized(self, tmp_path):
        package = tmp_path / "usr/share/nodejs/glob"
        alias = package / "dist/node_modules/glob"
        alias.parent.mkdir(parents=True)
        (package / "package.json").write_text('{"name":"glob","version":"1.0.0"}')
        alias.symlink_to("../..", target_is_directory=True)
        assert materialize_directory_symlinks(tmp_path) == []
        assert alias.is_symlink()

    def test_alias_with_nested_symlink_is_materialized(self, tmp_path: Path) -> None:
        (tmp_path / "usr/share/fonts-font-awesome/fonts").mkdir(parents=True)
        root_fonts = tmp_path / "usr/share/fonts-font-awesome/fonts"
        (root_fonts / "b.ttf").write_bytes(b"font-b")
        (root_fonts / "FontAwesome.otf").symlink_to("b.ttf")
        link = make_dir_link(
            tmp_path,
            "usr/lib/python3/dist-packages/mitmproxy/static/fontawesome",
            "usr/share/fonts-font-awesome",
        )
        materialized = materialize_directory_symlinks(tmp_path)
        assert materialized == ["usr/lib/python3/dist-packages/mitmproxy/static/fontawesome"]
        assert not link.is_symlink()
        assert link.is_dir()
        assert (link / "fonts" / "FontAwesome.otf").read_bytes() == b"font-b"
        assert (tmp_path / "usr/share/fonts-font-awesome/fonts/b.ttf").read_bytes() == b"font-b"

    def test_alias_to_clean_subtree_is_untouched(self, tmp_path: Path) -> None:
        link = make_dir_link(
            tmp_path,
            "usr/lib/python3/dist-packages/pkg/static/fonts",
            "usr/share/fonts-minimal",
        )
        materialized = materialize_directory_symlinks(tmp_path)
        assert materialized == []
        assert link.is_symlink()

    def test_safe_npm_node_modules_alias_is_untouched(self, tmp_path: Path) -> None:
        """Node convention links whose metadata kinds agree stay aliases."""
        tool = tmp_path / "usr/share/nodejs/npm/node_modules/example"
        tool.mkdir(parents=True)
        (tool / "package.json").write_text('{"name": "example", "version": "1.0.0"}')
        link = tmp_path / "usr/share/nodejs/tool/node_modules"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("../npm/node_modules", target_is_directory=True)
        materialized = materialize_directory_symlinks(tmp_path)
        assert materialized == []
        assert link.is_symlink()

    def test_alias_projecting_metadata_to_plain_path_is_safe(self, tmp_path: Path) -> None:
        """Metadata projecting to a non-metadata alias path is scanner-safe.

        A package.json under a python-root alias has no metadata kind
        through the alias, so the scanner accepts the alias; the build
        must leave it byte-identical.
        """
        target = tmp_path / "usr/share/nodejs/npm/node_modules/inner"
        target.mkdir(parents=True)
        (target / "package.json").write_text('{"name": "inner", "version": "2.0.0"}')
        link = tmp_path / "usr/lib/python3/dist-packages/pkg/packaged"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(os.path.relpath(target, link.parent), target_is_directory=True)
        materialized = materialize_directory_symlinks(tmp_path)
        assert materialized == []
        assert link.is_symlink()

    def test_file_symlink_is_untouched(self, tmp_path: Path) -> None:
        target = tmp_path / "usr/share/fonts/file.ttf"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"ttf")
        link = tmp_path / "usr/lib/python3/dist-packages/pkg/file.ttf"
        link.parent.mkdir(parents=True)
        link.symlink_to(os.path.relpath(target, link.parent))
        assert materialize_directory_symlinks(tmp_path) == []
        assert link.is_symlink()

    def test_escaping_target_fails_closed(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "etc-outside"
        outside.mkdir(exist_ok=True)
        link = tmp_path / "usr/lib/python3/dist-packages/pkg/link"
        link.parent.mkdir(parents=True)
        link.symlink_to(os.path.relpath(outside, link.parent), target_is_directory=True)
        with pytest.raises(ValueError, match="escapes image root"):
            materialize_directory_symlinks(tmp_path)

    def test_dangling_symlink_fails_closed(self, tmp_path: Path) -> None:
        link = tmp_path / "usr/lib/python3/dist-packages/pkg/link"
        link.parent.mkdir(parents=True)
        link.symlink_to("does-not-exist", target_is_directory=True)
        with pytest.raises(ValueError, match="does not exist"):
            materialize_directory_symlinks(tmp_path)

    def test_cyclic_link_fails_closed(self, tmp_path: Path) -> None:
        base = tmp_path / "usr/lib/python3/dist-packages/pkg"
        base.mkdir(parents=True)
        first = base / "first"
        first.symlink_to("second", target_is_directory=True)
        (base / "second").symlink_to("first", target_is_directory=True)
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            materialize_directory_symlinks(tmp_path)


class TestIdempotency:
    def test_second_run_changes_nothing(self, tmp_path: Path) -> None:
        write_package(
            tmp_path,
            "source-map/package.json",
            b'{"name": "source-map", "types": "a", "types": "a", "version": "0.8.0"}',
        )
        (tmp_path / "usr/share/fonts-font-awesome/fonts").mkdir(parents=True)
        (tmp_path / "usr/share/fonts-font-awesome/fonts/b.ttf").write_bytes(b"ttf")
        (tmp_path / "usr/share/fonts-font-awesome/fonts/link.ttf").symlink_to("b.ttf")
        make_dir_link(
            tmp_path,
            "usr/lib/python3/dist-packages/pkg/static/fontawesome",
            "usr/share/fonts-font-awesome",
        )
        canonicalized, materialized = normalize(tmp_path)
        assert canonicalized == ["usr/share/nodejs/source-map/package.json"]
        assert materialized == ["usr/lib/python3/dist-packages/pkg/static/fontawesome"]
        verify_clean(tmp_path)
        # Second pass: nothing left to do, verification still passes.
        canonicalized2, materialized2 = normalize(tmp_path)
        assert canonicalized2 == []
        assert materialized2 == []


class TestAdversarialRootfs:
    def test_predictable_file_staging_symlink_never_overwrites_outside(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "root"
        path = write_package(
            root,
            "source-map/package.json",
            b'{"name":"source-map","version":"0.8.0","types":"a","types":"a"}',
        )
        sentinel = tmp_path / "sentinel"
        sentinel.write_bytes(b"untouched")
        path.with_name("package.json.normalize-tmp").symlink_to(sentinel)
        with suppress(ValueError):
            canonicalize_npm_metadata(root)
        assert sentinel.read_bytes() == b"untouched"

    @pytest.mark.parametrize("ancestor", ["usr/share/nodejs", "usr/share"])
    def test_declared_npm_root_cannot_escape_through_ancestor_symlink(
        self, tmp_path: Path, ancestor: str
    ) -> None:
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        relative = (
            "source-map/package.json"
            if ancestor.endswith("nodejs")
            else "nodejs/source-map/package.json"
        )
        manifest = outside / relative
        manifest.parent.mkdir(parents=True)
        original = b'{"name":"source-map","version":"0.8.0","types":"a","types":"a"}'
        manifest.write_bytes(original)
        alias = root / ancestor
        alias.parent.mkdir(parents=True)
        alias.symlink_to(os.path.relpath(outside, alias.parent))
        with pytest.raises(ValueError, match="escapes image root"):
            normalize(root)
        assert manifest.read_bytes() == original

    def test_root_argument_cannot_itself_be_a_symlink(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        root = tmp_path / "root"
        root.symlink_to(outside)
        with pytest.raises(ValueError, match=r"image root.*symlink"):
            normalize(root)

    @pytest.mark.parametrize("directory", [False, True])
    def test_nested_copy_symlink_cannot_escape(self, tmp_path: Path, directory: bool) -> None:
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"outside bytes")
        link = make_dir_link(root, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        nested = root / "opt/tree/nested"
        target = outside if directory else sentinel
        nested.symlink_to(os.path.relpath(target, nested.parent), target_is_directory=directory)
        with pytest.raises(ValueError, match="escapes image root"):
            materialize_directory_symlinks(root)
        assert link.is_symlink()
        assert sentinel.read_bytes() == b"outside bytes"

    def test_copy_directory_cycle_fails_closed(self, tmp_path: Path) -> None:
        link = make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (tmp_path / "opt/tree/loop").symlink_to(".")
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            materialize_directory_symlinks(tmp_path)
        assert link.is_symlink()

    @pytest.mark.parametrize(
        "operation", ["canonicalize_npm_metadata", "verify_clean", "collect_target_tree"]
    )
    def test_oversized_metadata_is_rejected_before_unbounded_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        path = write_package(tmp_path, "large/package.json", b" " * 1024)
        function = API[operation]
        monkeypatch.setitem(function.__globals__, "MAX_METADATA_BYTES", 64)
        original_read = Path.read_bytes
        sizes = []

        def record_read(candidate: Path) -> bytes:
            data = original_read(candidate)
            sizes.append(len(data))
            return data

        monkeypatch.setattr(Path, "read_bytes", record_read)
        with pytest.raises(ValueError, match="size budget"):
            if operation == "collect_target_tree":
                function(path.parent, tmp_path)
            else:
                function(tmp_path)
        assert all(size <= 64 for size in sizes)

    @pytest.mark.parametrize(
        "limit", ["MAX_PROCESS_SECONDS", "MAX_DIRECTORY_ENTRIES", "MAX_DIRECTORIES"]
    )
    def test_processing_and_empty_directory_budgets_fail_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str
    ) -> None:
        base = tmp_path / "usr/share/nodejs"
        for index in range(4):
            (base / str(index)).mkdir(parents=True)
        monkeypatch.setitem(normalize.__globals__, limit, 0)
        with pytest.raises(ValueError, match=r"budget|deadline"):
            normalize(tmp_path)

    def test_empty_directories_count_towards_copy_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        link = make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (tmp_path / "opt/tree/nested").symlink_to("index.css")
        for index in range(4):
            (tmp_path / "opt/tree" / str(index)).mkdir()
        monkeypatch.setitem(materialize_directory_symlinks.__globals__, "MAX_MATERIALIZED_FILES", 2)
        with pytest.raises(ValueError, match="file budget"):
            materialize_directory_symlinks(tmp_path)
        assert link.is_symlink()

    def test_absolute_image_symlinks_are_resolved_inside_root(self, tmp_path: Path) -> None:
        link = make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        file = tmp_path / "opt/tree/index.css"
        file.chmod(0o640)
        (tmp_path / "opt/tree/nested").symlink_to("/opt/tree/index.css")
        assert materialize_directory_symlinks(tmp_path) == [
            "usr/lib/python3/dist-packages/pkg/alias"
        ]
        assert (link / "nested").read_bytes() == b"css"
        assert stat.S_IMODE((link / "nested").stat().st_mode) == 0o640
        assert (link / "nested").stat().st_uid == file.stat().st_uid

    def test_predictable_directory_staging_name_is_not_used(self, tmp_path: Path) -> None:
        link = make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (tmp_path / "opt/tree/nested").symlink_to("index.css")
        old_stage = link.with_name("alias.normalize-tmp")
        old_stage.mkdir()
        (old_stage / "sentinel").write_bytes(b"untouched")
        assert materialize_directory_symlinks(tmp_path) == [
            "usr/lib/python3/dist-packages/pkg/alias"
        ]
        assert (old_stage / "sentinel").read_bytes() == b"untouched"

    def test_in_root_declared_npm_alias_is_materialized_when_it_hides_metadata(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "opt/nodejs/example"
        target.mkdir(parents=True)
        (target / "package.json").write_bytes(b'{"name":"example","version":"1"}')
        alias = tmp_path / "usr/share/nodejs"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("/opt/nodejs")
        assert normalize(tmp_path) == ([], ["usr/share/nodejs"])
        assert not alias.is_symlink()
        assert (alias / "example/package.json").read_bytes() == b'{"name":"example","version":"1"}'

    def test_unrelated_python_root_discovery_sibling_is_not_dereferenced(
        self, tmp_path: Path
    ) -> None:
        base = tmp_path / "usr/lib/python3/dist-packages"
        base.mkdir(parents=True)
        (base.parent.parent / "unrelated").symlink_to("/unrelated-missing-target")
        assert normalize(tmp_path) == ([], [])

    def test_scanner_safe_alias_cannot_retain_a_directory_cycle(self, tmp_path: Path) -> None:
        base = tmp_path / "usr/lib/python3/dist-packages/pkg"
        base.mkdir(parents=True)
        (base / "loop").symlink_to(".")
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            normalize(tmp_path)

    def test_directory_staging_remains_private_until_rename(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        link = make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (tmp_path / "opt/tree/nested").symlink_to("index.css")
        original_rename = os.rename
        staging_modes = []

        def record_rename(source, destination, *, src_dir_fd=None, dst_dir_fd=None):
            info = os.stat(source, dir_fd=src_dir_fd, follow_symlinks=False)
            staging_modes.append(stat.S_IMODE(info.st_mode))
            return original_rename(
                source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
            )

        monkeypatch.setattr(os, "rename", record_rename)
        materialize_directory_symlinks(tmp_path)
        assert staging_modes == [0o700]
        assert stat.S_IMODE(link.stat().st_mode) == stat.S_IMODE(
            (tmp_path / "opt/tree").stat().st_mode
        )

    @pytest.mark.parametrize(
        "operation", ["canonicalize_npm_metadata", "materialize_directory_symlinks"]
    )
    def test_source_growth_is_not_silently_truncated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        if operation == "canonicalize_npm_metadata":
            source = write_package(tmp_path, "example/package.json", b'{"name":"x","version":"1"}')
            alias = None
        else:
            alias = make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
            source = tmp_path / "opt/tree/index.css"
            (source.parent / "nested").symlink_to("index.css")
        inode = source.stat().st_ino
        original_fstat = os.fstat
        grew = False

        def grow_after_stat(fd: int):
            nonlocal grew
            info = original_fstat(fd)
            if info.st_ino == inode and not grew:
                with source.open("ab") as stream:
                    stream.write(b"extra bytes")
                grew = True
            return info

        monkeypatch.setattr(os, "fstat", grow_after_stat)
        with pytest.raises(ValueError, match="changed during"):
            API[operation](tmp_path)
        if alias is not None:
            assert alias.is_symlink()
        assert not list(tmp_path.rglob(".normalize-*"))

    @pytest.mark.parametrize("limit", ["MAX_TOTAL_METADATA_BYTES", "MAX_METADATA_FILES"])
    def test_metadata_budget_is_cumulative(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str
    ) -> None:
        data = b'{"name":"x","version":"1"}'
        write_package(tmp_path, "first/package.json", data)
        write_package(tmp_path, "second/package.json", data)
        monkeypatch.setitem(
            canonicalize_npm_metadata.__globals__,
            limit,
            len(data) if limit == "MAX_TOTAL_METADATA_BYTES" else 1,
        )
        with pytest.raises(ValueError, match=r"budget|too many"):
            canonicalize_npm_metadata(tmp_path)

    def test_copy_budget_is_cumulative_across_aliases(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("first", "second"):
            make_dir_link(tmp_path, f"usr/lib/python3/dist-packages/pkg/{name}", "opt/tree")
        (tmp_path / "opt/tree/nested").symlink_to("index.css")
        monkeypatch.setitem(materialize_directory_symlinks.__globals__, "MAX_MATERIALIZED_BYTES", 7)
        with pytest.raises(ValueError, match="total copy budget"):
            materialize_directory_symlinks(tmp_path)
        assert (tmp_path / "usr/lib/python3/dist-packages/pkg/second").is_symlink()
        assert not list(tmp_path.rglob(".normalize-*"))


class TestDestinationRaces:
    def test_file_publication_cannot_be_redirected_after_staging(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        original = b'{"name":"source-map","version":"0.8.0","types":"a","types":"a"}'
        manifest = write_package(root, "source-map/package.json", original)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "package.json").write_bytes(b"outside sentinel")
        relocated = manifest.parent.with_name("relocated")
        original_staging = API["_staging"]
        staged_names = []

        def redirect_parent(path, image, **kwargs):
            staging, fd = original_staging(path, image, **kwargs)
            staged_names.append(staging.name)
            manifest.parent.rename(relocated)
            manifest.parent.symlink_to(os.path.relpath(outside, manifest.parent.parent))
            (outside / staging.name).write_bytes(b"UNVALIDATED-REPLACEMENT")
            return staging, fd

        monkeypatch.setitem(canonicalize_npm_metadata.__globals__, "_staging", redirect_parent)
        with suppress(OSError, ValueError):
            canonicalize_npm_metadata(root)
        assert (outside / "package.json").read_bytes() == b"outside sentinel"
        assert (outside / staged_names[0]).read_bytes() == b"UNVALIDATED-REPLACEMENT"
        assert json.loads((relocated / "package.json").read_bytes()) == json.loads(original)

    def test_copy_creation_and_failure_cleanup_cannot_be_redirected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        alias = make_dir_link(root, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (root / "opt/tree/a-directory").mkdir()
        (root / "opt/tree/a-directory/file").write_bytes(b"file")
        (root / "opt/tree/nested").symlink_to("index.css")
        outside = tmp_path / "outside"
        outside.mkdir()
        relocated = alias.parent.with_name("relocated")
        original_copy = API["_copy_tree"]
        decoys = []

        def redirect_parent(target, staging, image, budget):
            name = (
                staging.name
                if isinstance(staging, Path)
                else next(path.name for path in root.glob(".normalize-*") if path.is_dir())
            )
            alias.parent.rename(relocated)
            alias.parent.symlink_to(os.path.relpath(outside, alias.parent.parent))
            decoy = outside / name
            decoy.mkdir()
            (decoy / "sentinel").write_bytes(b"outside sentinel")
            decoys.append(decoy)
            original_copy(target, staging, image, budget)
            raise ValueError("injected copy failure")

        monkeypatch.setitem(
            materialize_directory_symlinks.__globals__, "_copy_tree", redirect_parent
        )
        with pytest.raises((OSError, ValueError)):
            materialize_directory_symlinks(root)
        assert (decoys[0] / "sentinel").read_bytes() == b"outside sentinel"
        assert not (decoys[0] / "a-directory").exists()
        assert (relocated / "alias").is_symlink()
        assert not list(root.glob(".normalize-*"))

    def test_fake_stage_entry_in_package_parent_is_never_published(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = b'{"name":"source-map","version":"0.8.0","types":"a","types":"a"}'
        manifest = write_package(tmp_path, "source-map/package.json", original)
        manifest.parent.chmod(0o777)
        original_staging = API["_staging"]

        def substitute_package_entry(path, root, **kwargs):
            staging, fd = original_staging(path, root, **kwargs)
            fake = manifest.parent / staging.name
            if staging.parent == manifest.parent:
                fake.unlink()
            fake.write_bytes(b"UNVALIDATED-REPLACEMENT")
            return staging, fd

        monkeypatch.setitem(
            canonicalize_npm_metadata.__globals__, "_staging", substitute_package_entry
        )
        canonicalize_npm_metadata(tmp_path)
        assert manifest.read_bytes() != b"UNVALIDATED-REPLACEMENT"
        assert json.loads(manifest.read_bytes()) == json.loads(original)

    def test_directory_publication_uses_the_parent_held_before_redirect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        alias = make_dir_link(root, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (root / "opt/tree/nested").symlink_to("index.css")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "alias").write_bytes(b"outside sentinel")
        relocated = alias.parent.with_name("relocated")
        original_copy = API["_copy_tree"]

        def redirect_after_copy(target, staging, image, budget):
            info = original_copy(target, staging, image, budget)
            alias.parent.rename(relocated)
            alias.parent.symlink_to(os.path.relpath(outside, alias.parent.parent))
            return info

        monkeypatch.setitem(
            materialize_directory_symlinks.__globals__, "_copy_tree", redirect_after_copy
        )
        materialize_directory_symlinks(root)
        assert (outside / "alias").read_bytes() == b"outside sentinel"
        assert not (relocated / "alias").is_symlink()
        assert (relocated / "alias/nested").read_bytes() == b"css"
        assert not list(root.glob(".normalize-*"))

    def test_directory_stage_open_failure_is_cleaned_under_trusted_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        make_dir_link(tmp_path, "usr/lib/python3/dist-packages/pkg/alias", "opt/tree")
        (tmp_path / "opt/tree/nested").symlink_to("index.css")
        original_open = API["_open_relative"]

        def fail_stage_open(directory_fd, name, flags):
            if name.name.startswith(".normalize-"):
                raise OSError("injected stage open failure")
            return original_open(directory_fd, name, flags)

        monkeypatch.setitem(
            materialize_directory_symlinks.__globals__, "_open_relative", fail_stage_open
        )
        with pytest.raises(OSError, match="injected stage open failure"):
            materialize_directory_symlinks(tmp_path)
        assert not list(tmp_path.glob(".normalize-*"))

    @pytest.mark.parametrize("mode", [0o775, 0o777])
    def test_writable_image_root_is_not_a_trusted_staging_boundary(
        self, tmp_path: Path, mode: int
    ) -> None:
        root = tmp_path / "root"
        manifest = write_package(
            root,
            "source-map/package.json",
            b'{"name":"source-map","version":"0.8.0","types":"a","types":"a"}',
        )
        original = manifest.read_bytes()
        root.chmod(mode)
        with pytest.raises(ValueError, match="trusted image root"):
            normalize(root)
        assert manifest.read_bytes() == original

    def test_staged_file_stays_private_until_descriptor_relative_publication(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manifest = write_package(
            tmp_path,
            "source-map/package.json",
            b'{"name":"source-map","version":"0.8.0","types":"a","types":"a"}',
            mode=0o664,
        )
        original_rename = os.rename
        publications = []

        def record_publish(source, destination, *, src_dir_fd=None, dst_dir_fd=None):
            info = os.stat(source, dir_fd=src_dir_fd, follow_symlinks=False)
            publications.append((info.st_uid, stat.S_IMODE(info.st_mode)))
            assert src_dir_fd is not None
            assert dst_dir_fd is not None
            return original_rename(
                source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
            )

        monkeypatch.setattr(os, "rename", record_publish)
        canonicalize_npm_metadata(tmp_path)
        assert publications == [(os.geteuid(), 0o600)]
        assert stat.S_IMODE(manifest.stat().st_mode) == 0o664


class TestCycleScope:
    @pytest.mark.parametrize(
        "package",
        [
            "usr/lib/python3/dist-packages/pkg",
            "usr/share/nodejs/pkg",
            "usr/local/lib/node_modules/pkg",
        ],
    )
    def test_generic_self_cycle_is_not_a_node_convention(
        self, tmp_path: Path, package: str
    ) -> None:
        base = tmp_path / package
        base.mkdir(parents=True)
        (base / "loop").symlink_to(".")
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            normalize(tmp_path)

    def test_node_named_python_cycle_is_rejected(self, tmp_path: Path) -> None:
        alias = tmp_path / "usr/lib/python3/dist-packages/pkg/dist/node_modules/pkg"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("../..")
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            normalize(tmp_path)

    def test_actual_copy_never_deduplicates_a_node_cycle(self, tmp_path: Path) -> None:
        package = tmp_path / "usr/share/nodejs/glob"
        alias = package / "dist/node_modules/glob"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("../..")
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            API["plan_copy"](package, "glob", set(), root=tmp_path)

    def test_node_cycle_cannot_cross_declared_npm_scopes(self, tmp_path: Path) -> None:
        first = tmp_path / "usr/share/nodejs/first"
        second = tmp_path / "usr/local/lib/node_modules/second"
        for base, target in ((first, second), (second, first)):
            alias = base / "dist/node_modules/other"
            alias.parent.mkdir(parents=True)
            alias.symlink_to(os.path.relpath(target, alias.parent))
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            normalize(tmp_path)

    def test_node_back_edge_does_not_hide_a_generic_edge_in_the_cycle(self, tmp_path: Path) -> None:
        first = tmp_path / "usr/share/nodejs/first"
        second = tmp_path / "usr/share/nodejs/second"
        first.mkdir(parents=True)
        alias = second / "dist/node_modules/first"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(os.path.relpath(first, alias.parent))
        (first / "generic").symlink_to(os.path.relpath(second, first))
        with pytest.raises(ValueError, match="cyclic directory symlink"):
            API["_validate_target"](first, tmp_path, API["Budget"]())


class TestDockerfileContract:
    def test_normalizer_is_copied_and_run_as_root_after_content_steps(self) -> None:
        content = DOCKERFILE.read_text(encoding="utf-8")
        assert (
            "COPY --chown=root:root containers/normalize_rootfs_metadata.py "
            "/opt/lyrashield/normalize_rootfs_metadata.py" in content
        )
        run_line = "RUN /usr/bin/python3 /opt/lyrashield/normalize_rootfs_metadata.py --root /"
        assert run_line in content
        lines = content.splitlines()
        run_index = lines.index(run_line)
        # Must run after the last apt/pip/npm content step, still as root.
        assert run_index > max(i for i, line in enumerate(lines) if "apt-get install -y" in line)
        assert run_index > max(i for i, line in enumerate(lines) if "npm ci --omit=dev" in line)
        assert any(line == "USER root" for line in lines[:run_index])
