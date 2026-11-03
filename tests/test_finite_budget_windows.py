"""Native Windows qualification: execute on windows-latest, never emulate Win32."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from lyrashield.artifacts import financial_io
from lyrashield.artifacts.financial_io import FinancialDirectory
from lyrashield.artifacts.finite_budget import STAMP, BudgetJournal, FinancialStateError
from lyrashield.artifacts.state_persistence import initial_run_record
from lyrashield.artifacts.writer import read_run_record, write_run_record


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows handles and ACLs")


def _system_tool(name: str) -> str:
    return str(Path(os.environ["SYSTEMROOT"]) / "System32" / name)


def _grant(path: Path, permission: str) -> None:
    subprocess.run(  # noqa: S603 - fixed Windows ACL utility, isolated fixture path
        [_system_tool("icacls.exe"), str(path), "/grant", f"*S-1-1-0:{permission}"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )


def test_native_windows_reparse_directory_is_rejected_before_activation(tmp_path):
    real, redirect = tmp_path / "real", tmp_path / "redirect"
    real.mkdir()
    subprocess.run(  # noqa: S603 - fixed Windows junction utility, isolated fixture paths
        [_system_tool("cmd.exe"), "/d", "/c", "mklink", "/J", str(redirect), str(real)],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    try:
        with pytest.raises(FinancialStateError):
            BudgetJournal(redirect, initial_run_record("reparse", auth_mode="api"), 1)
        assert not (real / STAMP).exists()
    finally:
        redirect.rmdir()


def test_native_windows_directory_acl_cannot_authorize_other_principal_writes(tmp_path):
    run = tmp_path / "unsafe-acl"
    run.mkdir()
    _grant(run, "(OI)(CI)M")
    legacy = initial_run_record("unsafe-acl", auth_mode="api")
    write_run_record(run, legacy)
    assert read_run_record(run) == legacy
    with pytest.raises(FinancialStateError):
        BudgetJournal(run, initial_run_record("unsafe-acl", auth_mode="api"), 1)
    assert not (run / STAMP).exists()


def test_native_windows_activation_acl_remains_private(tmp_path):
    record = initial_run_record("private-stamp", auth_mode="api")
    with BudgetJournal(tmp_path, record, 1):
        pass
    _grant(tmp_path / STAMP, "R")
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record, 1)


def test_native_windows_live_activation_handle_prevents_namespace_replacement(tmp_path):
    record = initial_run_record("live-stamp", auth_mode="api")
    with BudgetJournal(tmp_path, record, 1) as owner:
        identity = (tmp_path / STAMP).stat().st_ino
        with pytest.raises(PermissionError):
            (tmp_path / STAMP).unlink()
        attempt = owner.reserve(0.6)
        current = owner.snapshot()
        owner.settle(attempt, current, 0.1)
        assert (tmp_path / STAMP).stat().st_ino == identity
    with BudgetJournal(tmp_path, record, None) as restored:
        assert restored.spent == pytest.approx(0.1)
        restored.require_resumable()


def test_native_windows_hardlinked_financial_record_is_rejected(tmp_path):
    record = initial_run_record("hardlink", auth_mode="api")
    with BudgetJournal(tmp_path, record, 1):
        pass
    os.link(tmp_path / "run.json", tmp_path / "other-link.json")
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record, 1)


def test_native_windows_directory_delete_child_ace_is_rejected(tmp_path):
    record = initial_run_record("delete-child", auth_mode="api")
    with BudgetJournal(tmp_path, record, 1) as owner:
        owner.reserve(0.6)
    # DC alone differs from generic Modify: it permits deleting children despite
    # their own restrictive ACLs once the previous process's handles are gone.
    _grant(tmp_path, "(DC)")
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record, 1)
    assert (tmp_path / STAMP).exists()


@pytest.mark.parametrize("kind", ["hardlink", "wide-acl"])
def test_native_windows_preplanted_coordination_file_is_refused_without_mutation(tmp_path, kind):
    directory = FinancialDirectory(tmp_path)
    victim = tmp_path / "victim"
    fd = directory.open("victim", create=True, private=True)
    try:
        os.write(fd, b"retained native victim bytes")
    finally:
        os.close(fd)
    directory.close()
    path = tmp_path / ".finite-budget-transition"
    if kind == "hardlink":
        os.link(victim, path)
    else:
        directory = FinancialDirectory(tmp_path)
        fd = directory.open(path.name, create=True, private=True)
        try:
            os.write(fd, b"retained native victim bytes")
        finally:
            os.close(fd)
        directory.close()
        _grant(path, "F")
    before = path.read_bytes(), path.stat().st_nlink
    with pytest.raises((FinancialStateError, OSError)):
        BudgetJournal(tmp_path, initial_run_record("preplanted-native", auth_mode="api"), 1)
    assert (path.read_bytes(), path.stat().st_nlink) == before
    assert victim.read_bytes() == b"retained native victim bytes"
    assert not (tmp_path / STAMP).exists()
    if kind == "wide-acl":
        directory = FinancialDirectory(tmp_path)
        try:
            with pytest.raises(OSError):
                directory.open(path.name, private=True)
        finally:
            directory.close()


def test_native_windows_actual_acquired_coordination_handle_rechecks_acl(tmp_path, monkeypatch):
    capture = financial_io._capture_transition_fd
    path = tmp_path / ".finite-budget-transition"

    def broaden_acquired_handle(fd):
        _grant(path, "F")
        capture(fd)

    monkeypatch.setattr(financial_io, "_capture_transition_fd", broaden_acquired_handle)
    with pytest.raises((FinancialStateError, OSError)):
        BudgetJournal(tmp_path, initial_run_record("native-acquired-fd", auth_mode="api"), 1)
    assert not (tmp_path / STAMP).exists()
    directory = financial_io.FinancialDirectory(tmp_path)
    try:
        with pytest.raises(OSError):
            directory.open(path.name, private=True)
    finally:
        directory.close()
