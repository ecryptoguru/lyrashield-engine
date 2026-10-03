import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from zipfile import ZipFile

import yaml


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
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-release.yml").read_text())
    build_job = workflow["jobs"]["build"]
    assert any(
        target["target"] == "macos-x86_64" for target in build_job["strategy"]["matrix"]["include"]
    )
    steps = build_job["steps"]
    setup = next(
        s for s in steps if s.get("name") == "Prepare static cryptography build for Intel macOS"
    )
    build = next(s for s in steps if s.get("name") == "Build")
    assert steps.index(setup) < steps.index(build)
    assert setup["if"] == "matrix.target == 'macos-x86_64'"
    setup_script = "\n".join(
        line for line in setup["run"].splitlines() if not line.lstrip().startswith("#")
    )
    for command in (
        "brew install openssl@3 rust",
        'echo "OPENSSL_DIR=$(brew --prefix openssl@3)"',
        'echo "OPENSSL_STATIC=1"',
        'echo "UV_NO_BINARY_PACKAGE=cryptography"',
        '} >> "$GITHUB_ENV"',
    ):
        assert command in setup_script
    build_script = "\n".join(
        line for line in build["run"].splitlines() if not line.lstrip().startswith("#")
    )
    sync = build_script.index("uv sync --frozen --extra viewer")
    intel = build_script.index('if [[ "${{ matrix.target }}" == "macos-x86_64" ]]; then')
    intel_end = build_script.index("\nfi", intel)
    package = build_script.index("uv run pyinstaller")
    assert sync < intel < intel_end < package
    check = build_script[intel:intel_end]
    inspect = check.index('otool -L "$CRYPTOGRAPHY_EXTENSION"')
    reject = check.index("if grep -E 'lib(ssl|crypto).*dylib'")
    error = check.index("cryptography must statically link OpenSSL")
    fail = check.index("exit 1", error)
    assert inspect < reject < error < fail


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

    forbidden = ("/tests/", "/interface/viewer/frontend/", "/.env", "/.worktrees/", "/desktop/")
    assert not [name for name in names if any(marker in name for marker in forbidden)]
    assert any(name.endswith("/strix/interface/tui/cmd/strix-tui/main.go") for name in names)


def test_wheel_excludes_go_sources_and_installs_from_base_dependencies(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    dist_dir = tmp_path / "dist"
    subprocess.run(  # noqa: S603 - fixed local build command
        [uv, "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(dist_dir.glob("*.whl"))

    with ZipFile(wheel) as package:
        names = package.namelist()
        go_sources = [
            name
            for name in names
            if name.startswith("strix/interface/tui/")
            and name.endswith((".go", "go.mod", "go.sum"))
        ]
        assert not go_sources
        assert "strix/interface/tui/history.py" in names
        metadata_path = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = package.read(metadata_path).decode()
        assert "Requires-Dist: mcp<2,>=1.28.1" in metadata
        assert "Requires-Dist: pypdf>=6.19.0; extra == 'viewer'" in metadata

    environment = tmp_path / "base-install"
    subprocess.run(  # noqa: S603 - fixed local venv creation
        [uv, "venv", "--python", sys.executable, str(environment)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    python = environment / "bin" / "python"
    if sys.platform == "win32":
        python = environment / "Scripts" / "python.exe"
    subprocess.run(  # noqa: S603 - install the freshly built local wheel in a clean venv
        [uv, "pip", "install", "--python", str(python), str(wheel)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    cli = environment / "bin" / "lyrashield"
    if sys.platform == "win32":
        cli = environment / "Scripts" / "lyrashield.exe"
    subprocess.run(  # noqa: S603 - exercise the installed product CLI without dev extras
        [str(cli), "--help"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    subprocess.run(  # noqa: S603 - install the same wheel with its declared optional extra
        [uv, "pip", "install", "--python", str(python), f"{wheel}[viewer]"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    subprocess.run(  # noqa: S603 - exercise the optional PDF parser and writer end to end
        [
            str(python),
            "-c",
            "from io import BytesIO; from reportlab.pdfgen import canvas; "
            "from pypdf import PdfReader; stream = BytesIO(); "
            "writer = canvas.Canvas(stream); writer.drawString(10, 10, 'viewer'); "
            "writer.showPage(); writer.save(); stream.seek(0); "
            "assert len(PdfReader(stream).pages) == 1",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )


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
