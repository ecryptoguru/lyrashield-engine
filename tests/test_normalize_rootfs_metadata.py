"""Build-time rootfs metadata normalization contracts.

Covers ``containers/normalize_rootfs_metadata.py``: canonical last-wins
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
    def test_top_level_duplicate_keys_resolve_last_wins(self) -> None:
        original = (
            b'{"name": "source-map", "types": "./a.d.ts", "types": "./b.d.ts", "version": "0.8.0"}'
        )
        canonical, changed = canonical_with_last_wins(original)
        assert changed
        assert json.loads(canonical) == {
            "name": "source-map",
            "types": "./b.d.ts",
            "version": "0.8.0",
        }

    def test_nested_duplicate_keys_resolve_last_wins(self) -> None:
        original = b'{"exports": {"import": "./a.js", "import": "./b.js"}, "name": "x"}'
        canonical, changed = canonical_with_last_wins(original)
        assert changed
        assert json.loads(canonical) == {"exports": {"import": "./b.js"}, "name": "x"}

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

    def test_duplicated_name_and_version_resolve_to_effective_identity(self) -> None:
        original = b'{"name": "a", "name": "b", "version": "1", "version": "2"}'
        canonical, _ = canonical_with_last_wins(original)
        parsed = json.loads(canonical)
        assert parsed["name"] == "b"
        assert parsed["version"] == "2"


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
            b'{"name": "source-map", "types": "a", "types": "b", "version": "0.8.0"}',
            mode=0o640,
        )
        changed = canonicalize_npm_metadata(tmp_path)
        assert changed == ["usr/share/nodejs/source-map/package.json"]
        parsed = json.loads(path.read_bytes())
        assert parsed == {"name": "source-map", "types": "b", "version": "0.8.0"}
        # Mode preserved.
        assert stat.S_IMODE(path.stat().st_mode) == 0o640

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
            b'{"name": "source-map", "types": "a", "types": "b", "version": "0.8.0"}',
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
