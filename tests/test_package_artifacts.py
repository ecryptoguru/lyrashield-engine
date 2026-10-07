"""Ensure source-only Go inputs stay in the sdist, not product wheels."""

import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GO_TUI_PREFIX = "strix/interface/tui/"
PRODUCT_IMPORTS = (
    "lyrashield_adapter.cli",
    "lyrashield.interface.main",
    "lyrashield.interface.tui.app",
    "lyrashield.interface.viewer.server",
    "strix.interface.tui.runtime",
)


def _is_go_build_input(path: str) -> bool:
    if GO_TUI_PREFIX not in path:
        return False
    relative = path.split(GO_TUI_PREFIX, 1)[1]
    return relative.endswith(".go") or relative in {"go.mod", "go.sum"}


def _assert_no_internal_sdist_artifacts(paths: list[str]) -> None:
    relative_paths = [path.partition("/")[2] for path in paths]
    assert not [
        path
        for path in relative_paths
        if path == ".coverage"
        or path.startswith((".coverage.", ".superpowers/", "reports/", "htmlcov/", "coverage/"))
        or path in {"coverage.xml", "coverage.json"}
    ]


def _assert_imports_from_wheel(wheel: Path, cwd: Path) -> None:
    import_script = f"""
import importlib
import sys

wheel = sys.argv[1]
sys.path.insert(0, wheel)
modules = {PRODUCT_IMPORTS!r}
for name in modules:
    module = importlib.import_module(name)
    assert module.__file__ and module.__file__.startswith(wheel + "/"), (
        name,
        module.__file__,
    )
print("wheel imports passed: " + ", ".join(modules))
"""
    subprocess.run(  # noqa: S603 - fixed import smoke code, wheel path is test-owned
        [sys.executable, "-I", "-c", import_script, str(wheel)],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def test_wheels_exclude_go_inputs_and_retain_product_python_imports(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None

    source_dist_dir = tmp_path / "source-build"
    source_dist_dir.mkdir()
    subprocess.run(  # noqa: S603 - fixed local build command
        [uv, "build", "--wheel", "--sdist", "--out-dir", str(source_dist_dir)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    source_wheel = next(source_dist_dir.glob("*.whl"))
    source_archive = next(source_dist_dir.glob("*.tar.gz"))
    with zipfile.ZipFile(source_wheel) as archive:
        source_wheel_files = archive.namelist()
    with tarfile.open(source_archive, "r:gz") as archive:
        source_archive_files = archive.getnames()

    _assert_no_internal_sdist_artifacts(source_archive_files)
    _assert_no_internal_sdist_artifacts(source_wheel_files)
    assert not [name for name in source_wheel_files if _is_go_build_input(name)]
    assert any(name.endswith("/go.mod") for name in source_archive_files)
    assert any(name.endswith("/go.sum") for name in source_archive_files)
    assert any(name.endswith("_test.go") for name in source_archive_files)
    for path in (
        "lyrashield_adapter/cli.py",
        "lyrashield/interface/main.py",
        "lyrashield/interface/tui/app.py",
        "lyrashield/interface/viewer/server.py",
        "strix/interface/tui/runtime.py",
        "strix/interface/tui/sidecar.py",
    ):
        assert path in source_wheel_files

    _assert_imports_from_wheel(source_wheel, tmp_path)

    extracted = tmp_path / "sdist-source"
    extracted.mkdir()
    with tarfile.open(source_archive, "r:gz") as archive:
        archive.extractall(extracted, filter="data")
    sdist_root = next(extracted.iterdir())
    for path in (
        ".coverage",
        ".coverage.parallel.123",
        ".superpowers/receipts/probe.txt",
        "reports/probe.txt",
        "coverage.xml",
        "coverage.json",
        "coverage/index.html",
        "htmlcov/index.html",
    ):
        artifact = sdist_root / path
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("Internal artifact must not ship", encoding="utf-8")
    sdist_wheel_dir = tmp_path / "sdist-wheel"
    sdist_wheel_dir.mkdir()
    subprocess.run(  # noqa: S603 - fixed local build command
        [uv, "build", "--wheel", "--sdist", "--out-dir", str(sdist_wheel_dir)],
        cwd=sdist_root,
        check=True,
        capture_output=True,
        text=True,
    )
    sdist_wheel = next(sdist_wheel_dir.glob("*.whl"))
    with tarfile.open(next(sdist_wheel_dir.glob("*.tar.gz")), "r:gz") as archive:
        sdist_archive_files = archive.getnames()
    _assert_no_internal_sdist_artifacts(sdist_archive_files)
    with zipfile.ZipFile(sdist_wheel) as archive:
        sdist_wheel_files = archive.namelist()
    _assert_no_internal_sdist_artifacts(sdist_wheel_files)
    assert not [name for name in sdist_wheel_files if _is_go_build_input(name)]
    for path in (
        "lyrashield_adapter/cli.py",
        "lyrashield/interface/tui/app.py",
        "lyrashield/interface/viewer/server.py",
        "strix/interface/tui/runtime.py",
    ):
        assert path in sdist_wheel_files

    _assert_imports_from_wheel(sdist_wheel, tmp_path)
