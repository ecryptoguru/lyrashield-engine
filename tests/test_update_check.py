"""Keep PyInstaller restart environment coverage for the retained substrate."""

import pytest

from strix.interface import update_check as strix_update_check


def test_restart_env_strips_pyinstaller_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("_MEIPASS2", "/stale/_MEIold")
    monkeypatch.setenv("_PYI_APPLICATION_HOME_DIR", "/stale/_MEIold")
    monkeypatch.setenv("_PYI_ARCHIVE_FILE", "/old/strix")
    monkeypatch.setenv("_PYI_PARENT_PROCESS_LEVEL", "1")
    monkeypatch.setenv("SOME_OTHER_VAR", "kept")

    env = strix_update_check.restart_env()

    assert "SOME_OTHER_VAR" in env
    assert "_MEIPASS2" not in env
    assert not any(key.startswith("_PYI_") for key in env)


def test_restart_env_restores_library_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIBRARY_PATH", "/stale/_MEIold/lib")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/lib/custom")
    monkeypatch.setenv("DYLD_LIBRARY_PATH", "/stale/_MEIold/lib")
    monkeypatch.delenv("DYLD_LIBRARY_PATH_ORIG", raising=False)

    env = strix_update_check.restart_env()

    assert env["LD_LIBRARY_PATH"] == "/usr/lib/custom"
    assert "LD_LIBRARY_PATH_ORIG" not in env
    assert "DYLD_LIBRARY_PATH" not in env
