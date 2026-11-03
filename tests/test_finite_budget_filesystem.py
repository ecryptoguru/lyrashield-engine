"""Native ACL and live pathname identity are financial admission boundaries."""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys

import pytest

from lyrashield.artifacts import financial_io
from lyrashield.artifacts.financial_macos import qualify_acl
from lyrashield.artifacts.finite_budget import GUARD, STAMP, BudgetJournal, FinancialStateError
from lyrashield.artifacts.state_persistence import initial_run_record
from lyrashield.artifacts.writer import write_run_record


def _record():
    return initial_run_record("filesystem-boundary", auth_mode="api")


def _ace(path, value):
    subprocess.run(  # noqa: S603 - fixed native utility and isolated fixture ACL
        ["/bin/chmod", "+a", value, str(path)], check=True, capture_output=True, timeout=10
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
@pytest.mark.parametrize(
    "boundary,permissions",
    [
        ("ancestor", "search,add_file,delete_child"),
        ("run", "search,add_file,delete_child"),
        ("record", "write,append,writesecurity"),
        ("stamp", "write,append,writesecurity"),
        ("lock", "write,append,writesecurity"),
        ("stamp", "read"),
        ("lock", "read"),
    ],
)
def test_foreign_mac_acl_cannot_authorize(tmp_path, monkeypatch, boundary, permissions):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o711)
    run = parent / "run"
    run.mkdir(mode=0o700)
    restore = boundary in {"record", "stamp"}
    if restore:
        with BudgetJournal(run, _record(), 0.055):
            pass
    if boundary in {"ancestor", "run"}:
        _ace(parent if boundary == "ancestor" else run, "everyone allow " + permissions)
    elif boundary in {"record", "stamp"}:
        _ace(run / ("run.json" if boundary == "record" else STAMP), "everyone allow " + permissions)
    else:
        original = financial_io._capture_transition_fd

        def after_acquisition(fd):
            coordination = run / ".finite-budget-transition"
            assert os.path.samestat(os.fstat(fd), coordination.stat())
            _ace(coordination, "everyone allow " + permissions)
            original(fd)

        monkeypatch.setattr(financial_io, "_capture_transition_fd", after_acquisition)
    with (
        pytest.raises((FinancialStateError, OSError)),
        BudgetJournal(run, _record(), None if restore else 0.055) as journal,
    ):
        journal.authorize(journal.reserve(0.05))


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
@pytest.mark.parametrize(
    "principal", ["everyone deny delete", "user:root allow write,append,writesecurity", "owner"]
)
def test_harmless_mac_acl_keeps_financial_capability(tmp_path, principal):
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    if principal == "owner":
        principal = f"user:{getpass.getuser()} allow write,append,writesecurity"
    _ace(run, principal)
    try:
        with BudgetJournal(run, _record(), 0.055) as journal:
            attempt = journal.reserve(0.05)
            journal.authorize(attempt)
            assert journal.snapshot()[GUARD]["pending"][0]["quote_units"] == 500000000
    finally:
        subprocess.run(["/bin/chmod", "-N", str(run)], check=True, capture_output=True, timeout=10)  # noqa: S603 - remove only the owned fixture ACL, including deny-delete


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
def test_ordinary_mac_acl_writer_is_unchanged(tmp_path):
    tmp_path.chmod(0o775)
    _ace(tmp_path, "everyone allow search,add_file,delete_child")
    write_run_record(tmp_path, _record())
    assert GUARD not in json.loads((tmp_path / "run.json").read_text())
    assert not (tmp_path / STAMP).exists()
    assert tmp_path.stat().st_mode & 0o777 == 0o775


@pytest.mark.skipif(
    os.name == "nt", reason="Windows pins open financial directories against rename"
)
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("operation", ["authorize", "reserve", "settle", "projection"])
def test_detached_posix_owner_cannot_send_or_mutate(tmp_path, alias, operation):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    run = parent / "run"
    moved = tmp_path / "moved"
    with BudgetJournal(run, _record(), 0.055) as journal:
        attempt = journal.reserve(0.05)
        snapshot = journal.snapshot()
        if alias:
            parent.rename(moved)
            parent.symlink_to(moved, target_is_directory=True)
            detached = moved / "run"
        else:
            run.rename(moved)
            detached = moved
            child = subprocess.run(  # noqa: S603 - owned interpreter and literal child program
                [
                    sys.executable,
                    "-c",
                    """
from pathlib import Path
import sys
from lyrashield.artifacts.finite_budget import BudgetJournal
from lyrashield.artifacts.state_persistence import initial_run_record
record = initial_run_record('filesystem-boundary', auth_mode='api')
with BudgetJournal(Path(sys.argv[1]), record, .055) as j:
    j.authorize(j.reserve(.05))
print('replacement-owner-authorized')
""",
                    str(run),
                ],
                text=True,
                capture_output=True,
                timeout=15,
                check=True,
            )
            assert child.stdout.strip() == "replacement-owner-authorized"
        before = (detached / "run.json").read_bytes()
        with pytest.raises(FinancialStateError):
            if operation == "authorize":
                journal.authorize(attempt)
            elif operation == "reserve":
                journal.reserve(0.001)
            elif operation == "settle":
                journal.settle(attempt, snapshot, 0.01)
            else:
                journal.write_projection(snapshot)
        assert (detached / "run.json").read_bytes() == before


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
def test_public_record_read_acl_preserves_financial_admission(tmp_path):
    with BudgetJournal(tmp_path, _record(), 0.055):
        pass
    _ace(tmp_path, "everyone allow read,search")
    _ace(tmp_path / "run.json", "everyone allow read")
    with BudgetJournal(tmp_path, _record(), None) as journal:
        journal.authorize(journal.reserve(0.05))


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
def test_acl_lookup_error_is_not_treated_as_empty_acl():
    with pytest.raises(OSError):
        qualify_acl(-1, private=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
def test_inheritance_only_foreign_mutation_acl_is_rejected_before_creation(tmp_path):
    _ace(tmp_path, "everyone allow add_file,file_inherit,directory_inherit,only_inherit")
    child = tmp_path / "must-not-exist"
    with pytest.raises(FinancialStateError):
        BudgetJournal(child, _record(), 0.055)
    assert not child.exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL")
@pytest.mark.parametrize("boundary", ["ancestor", "run", "record", "stamp"])
def test_live_mac_acl_change_denies_authorization_without_erasing_hold(tmp_path, boundary):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o711)
    run = parent / "run"
    with BudgetJournal(run, _record(), 0.055) as journal:
        attempt = journal.reserve(0.05)
        before = (run / "run.json").read_bytes()
        target = {
            "ancestor": parent,
            "run": run,
            "record": run / "run.json",
            "stamp": run / STAMP,
        }[boundary]
        _ace(target, "everyone allow write,append,writesecurity")
        with pytest.raises(FinancialStateError):
            journal.authorize(attempt)
        assert (run / "run.json").read_bytes() == before
        assert json.loads(before)[GUARD]["pending"][0]["quote_units"] == 500000000


@pytest.mark.skipif(
    os.name == "nt", reason="Windows pins open financial directories against rename"
)
def test_initial_activation_checks_directory_again_after_owner_lock(tmp_path, monkeypatch):
    run, moved = tmp_path / "run", tmp_path / "moved"
    original = financial_io.FinancialDirectory.lock

    def rename_after_lock(directory, fd):
        original(directory, fd)
        run.rename(moved)
        run.mkdir(mode=0o700)

    monkeypatch.setattr(financial_io.FinancialDirectory, "lock", rename_after_lock)
    with pytest.raises(FinancialStateError):
        BudgetJournal(run, _record(), 0.055)
    assert (moved / STAMP).read_bytes() == b""
    assert not (moved / "run.json").exists()
    assert not (run / STAMP).exists()
