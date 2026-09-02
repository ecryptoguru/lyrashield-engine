import shutil
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _uv_sync_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [line for line in text.splitlines() if "uv sync --frozen" in line]


def test_build_script_syncs_with_viewer_extra() -> None:
    lines = _uv_sync_lines(ROOT / "scripts" / "build.sh")
    assert lines, "expected a uv sync line in scripts/build.sh"
    for line in lines:
        assert "--extra viewer" in line


def test_release_workflow_syncs_with_viewer_extra() -> None:
    lines = _uv_sync_lines(ROOT / ".github" / "workflows" / "build-release.yml")
    assert lines, "expected a uv sync line in .github/workflows/build-release.yml"
    for line in lines:
        assert "--extra viewer" in line


def test_intel_release_builds_security_fixed_crypto_statically() -> None:
    workflow = (ROOT / ".github/workflows/build-release.yml").read_text()
    assert "target: macos-x86_64" in workflow
    assert "if: matrix.target == 'macos-x86_64'" in workflow
    assert "brew install openssl@3 rust" in workflow
    assert "UV_NO_BINARY_PACKAGE=cryptography" in workflow
    assert "OPENSSL_STATIC=1" in workflow
    assert "brew --prefix openssl@3" in workflow
    assert 'otool -L "$CRYPTOGRAPHY_EXTENSION"' in workflow
    assert "cryptography must statically link OpenSSL" in workflow


def test_verify_thin_fork_syncs_with_viewer_extra() -> None:
    lines = _uv_sync_lines(ROOT / "scripts" / "verify-controlled-derivative.sh")
    assert lines, "expected a uv sync line in scripts/verify-controlled-derivative.sh"
    for line in lines:
        assert "--extra viewer" in line


def test_binary_uses_product_adapter_entrypoint() -> None:
    spec = (ROOT / "strix.spec").read_text()
    assert "['lyrashield_adapter/cli.py']" in spec
    assert "['strix/interface/main.py']" not in spec


def test_binary_bundles_product_runtime_resources() -> None:
    spec = (ROOT / "strix.spec").read_text()
    assert "lyrashield_root = project_root / 'lyrashield'" in spec
    assert "for package_root in (strix_root, lyrashield_root):" in spec
    assert "'lyrashield.interface.tui.app'" in spec
    assert "'lyrashield.interface.viewer.server'" in spec


def test_python_archives_exclude_build_only_artifacts() -> None:
    config = (ROOT / "pyproject.toml").read_text()
    assert 'exclude = ["/.coverage"]' in config
    assert '"lyrashield/interface/viewer/frontend/**"' in config


def test_source_archive_excludes_tests() -> None:
    config = (ROOT / "pyproject.toml").read_text()
    assert "[tool.hatch.build.targets.sdist]" in config
    assert '"/tests/**"' in config
    assert '"/.worktrees"' in config


def test_built_source_archive_excludes_test_and_frontend_source(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    subprocess.run(  # noqa: S603 - fixed local build command
        [uv, "build", "--sdist", "--out-dir", str(tmp_path)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    archive = next(tmp_path.glob("*.tar.gz"))
    with tarfile.open(archive, "r:gz") as source_dist:
        names = source_dist.getnames()

    forbidden = ("/tests/", "/interface/viewer/frontend/", "/.env", "/.worktrees/")
    assert not [name for name in names if any(marker in name for marker in forbidden)]


def test_product_adapter_can_run_as_a_script() -> None:
    adapter = (ROOT / "lyrashield_adapter/cli.py").read_text()
    assert 'if __name__ == "__main__":' in adapter
    assert "    main()" in adapter


def test_binary_does_not_bundle_unused_litellm_proxy_modules() -> None:
    spec = (ROOT / "strix.spec").read_text()
    assert "collect_submodules('litellm')" not in spec


def test_binary_does_not_request_missing_hidden_imports() -> None:
    spec = (ROOT / "strix.spec").read_text()
    for module in (
        "xmltodict",
        "defusedxml",
        "strix.interface.tui.app",
        "strix.interface.tui.renderers.registry",
        "strix.tools.proxy._calls",
        "strix.tools.python.tool",
    ):
        assert f"'{module}'" not in spec


def test_build_script_fails_when_binary_smoke_test_fails() -> None:
    script = (ROOT / "scripts/build.sh").read_text()
    smoke = (ROOT / "scripts/smoke_release.py").read_text()
    assert 'scripts/smoke_release.py "$RELEASE_DIR/$BINARY_NAME" "$VERSION"' in script
    assert '"$RELEASE_DIR/$BINARY_NAME" --help' not in script
    assert 'echo -e "${RED}Binary test failed${NC}"; exit 1' in script
    assert '(["--help"], "--scope-mode", False)' in smoke
