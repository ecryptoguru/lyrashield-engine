"""A provider admission survives process death without becoming verified usage."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from importlib import import_module
from types import SimpleNamespace

import pytest

from lyrashield.artifacts.finite_budget import BudgetJournal, FinancialStateError
from lyrashield.artifacts.state_persistence import initial_run_record
from lyrashield.artifacts.writer import write_run_record


def record() -> dict:
    return initial_run_record("durable", auth_mode="api")


def test_unknown_hold_survives_fresh_interpreter(tmp_path):
    script = """import json,os,sys
from pathlib import Path
from lyrashield.artifacts.finite_budget import BudgetJournal
from lyrashield.artifacts.state_persistence import initial_run_record
j=BudgetJournal(Path(sys.argv[1]), initial_run_record('durable',auth_mode='api'), 1)
print(j.reserve(.6),flush=True)
os._exit(137)
"""
    result = subprocess.run(  # noqa: S603 - fixed isolated interpreter and fixture program
        [sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 137, result.stderr
    with BudgetJournal(tmp_path, record(), 1) as journal:
        assert len(journal.snapshot()["_finite_budget_guard"]["pending"]) == 1
        with pytest.raises(FinancialStateError, match="pending"):
            journal.require_resumable()
        assert journal.snapshot()["llm_usage"].get("cost", 0) == 0


def test_settlement_is_atomic_and_idempotent(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        attempt = journal.reserve(0.6)
        updated = journal.snapshot()
        updated["llm_usage"]["cost"] = 0.17
        assert journal.settle(attempt, updated, 0.17)
        assert not journal.settle(attempt, updated, 0.17)
        assert journal.snapshot()["llm_usage"]["cost"] == 0.17
        assert journal.snapshot()["_finite_budget_guard"]["pending"] == []
    with BudgetJournal(tmp_path, record(), None) as restored:
        restored.require_resumable()
        assert restored.limit == 1
        assert restored.spent == pytest.approx(0.17)


@pytest.mark.parametrize("damage", ["stamp_missing", "guard_missing", "truncated", "foreign"])
def test_activated_pair_cannot_be_reinitialized(tmp_path, damage):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        journal.reserve(0.6)
    path = tmp_path / "run.json"
    if damage == "stamp_missing":
        (tmp_path / ".finite-budget-activated").unlink()
    elif damage == "truncated":
        path.write_text('{"run_id":')
    else:
        data = json.loads(path.read_text())
        if damage == "guard_missing":
            del data["_finite_budget_guard"]
        else:
            data["_finite_budget_guard"]["epoch"] = "a" * 32
        path.write_text(json.dumps(data))
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record(), 1)


def test_stale_projection_cannot_overwrite_new_finances(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        stale = journal.snapshot()
        journal.reserve(0.6)
        with pytest.raises(FinancialStateError, match="stale"):
            journal.write_projection(stale)
        assert len(journal.snapshot()["_finite_budget_guard"]["pending"]) == 1


def test_projection_restore_preserves_known_usage_and_pending(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        old = journal.snapshot()
        old["status"] = "running"
        attempt = journal.reserve(0.6)
        known = journal.snapshot()
        known["llm_usage"]["cost"] = 0.1
        journal.settle(attempt, known, 0.1)
        journal.reserve(0.6)
        restored = journal.restore_projection(old)
        assert restored["llm_usage"]["cost"] == 0.1
        assert len(restored["_finite_budget_guard"]["pending"]) == 1


def test_budget_increase_cannot_release_unknown_and_implicit_widening_denied(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        journal.reserve(0.6)
        journal.increase_limit(2)
        with pytest.raises(FinancialStateError, match="pending"):
            journal.require_resumable()
    with pytest.raises(FinancialStateError, match="increase"):
        BudgetJournal(tmp_path, record(), 3)


def test_fsync_failure_returns_no_admission(tmp_path, monkeypatch):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        monkeypatch.setattr(os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("flush failed")))
        with pytest.raises(FinancialStateError, match=r"flush|persist"):
            journal.reserve(0.6)
        with pytest.raises(FinancialStateError):
            journal.reserve(0.1)


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX symlink construction; Windows reparse CI separate"
)
def test_stamp_symlink_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("secret")
    (tmp_path / ".finite-budget-activated").symlink_to(outside)
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record(), 1)
    assert outside.read_text() == "secret"


def test_saved_limit_restores_and_can_only_tighten_without_operator_increase(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        journal.restore_limit(0.8)
        assert journal.limit == 0.8
        with pytest.raises(FinancialStateError, match="increase"):
            journal.restore_limit(1)
    with BudgetJournal(tmp_path, record(), None) as journal:
        assert journal.limit == 0.8


def test_pending_and_identity_history_are_bounded(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        for _ in range(64):
            journal.reserve(0)
        with pytest.raises(FinancialStateError, match="capacity"):
            journal.reserve(0)
        assert len(json.dumps(journal.snapshot()["_finite_budget_guard"]).encode()) < 16 * 1024
        with pytest.raises(FinancialStateError, match="foreign"):
            journal.settle(
                journal.snapshot()["_finite_budget_guard"]["epoch"] + ":999999",
                journal.snapshot(),
                0,
            )


def test_common_writer_cannot_erase_guard_when_activation_stamp_is_missing(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as journal:
        journal.reserve(0.6)
    (tmp_path / ".finite-budget-activated").unlink()
    with pytest.raises(FinancialStateError):
        write_run_record(tmp_path, record())
    assert (
        len(json.loads((tmp_path / "run.json").read_text())["_finite_budget_guard"]["pending"]) == 1
    )


@pytest.mark.parametrize("stamp_missing", [False, True])
def test_main_initializer_preserves_finances_or_denies_missing_stamp(
    tmp_path, monkeypatch, stamp_missing
):
    main = import_module("lyrashield.interface.main")
    with BudgetJournal(tmp_path, record(), 1) as owner:
        attempt = owner.reserve(0.6)
        known = owner.snapshot()
        known["llm_usage"]["cost"] = 0.17
        owner.settle(attempt, known, 0.17)
        owner.reserve(0.6)
        before = owner.snapshot()
    monkeypatch.setattr(main, "run_dir_for", lambda _name: tmp_path)
    args = SimpleNamespace(
        run_name="durable",
        targets_info=[],
        scan_mode="quick",
        instruction=None,
        non_interactive=True,
        scope_mode="auto",
        diff_base=None,
    )
    if stamp_missing:
        (tmp_path / ".finite-budget-activated").unlink()
        with pytest.raises(FinancialStateError):
            main._persist_run_record(args)
    else:
        main._persist_run_record(args)
    restored = json.loads((tmp_path / "run.json").read_text())
    assert restored["llm_usage"] == before["llm_usage"]
    assert restored["_finite_budget_guard"] == before["_finite_budget_guard"]


@pytest.mark.parametrize("boundary", ["before_replace", "after_replace"])
def test_process_death_at_known_snapshot_boundary_never_clears_unknown_without_usage(
    tmp_path, boundary
):
    with BudgetJournal(tmp_path, record(), 1) as owner:
        attempt = owner.reserve(0.6)
    script = """import os,sys
from pathlib import Path
from lyrashield.artifacts.financial_io import FinancialDirectory
from lyrashield.artifacts.finite_budget import BudgetJournal
from lyrashield.artifacts.state_persistence import initial_run_record
owner=BudgetJournal(Path(sys.argv[1]),initial_run_record('durable',auth_mode='api'),None)
replace=FinancialDirectory.replace
def crash(self,name,payload):
    if sys.argv[3]=='after_replace':
        replace(self,name,payload)
    os._exit(137)
FinancialDirectory.replace=crash
known=owner.snapshot();known['llm_usage']['cost']=.17
owner.settle(sys.argv[2],known,.17)
"""
    child = subprocess.run(  # noqa: S603 - owned isolated interpreter and fault program
        [sys.executable, "-c", script, str(tmp_path), attempt, boundary],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert child.returncode == 137, child.stderr
    with BudgetJournal(tmp_path, record(), None) as restored:
        current = restored.snapshot()
        if boundary == "before_replace":
            assert current["llm_usage"].get("cost", 0) == 0
            assert current["_finite_budget_guard"]["pending"][0]["id"] == attempt
            with pytest.raises(FinancialStateError, match="pending"):
                restored.require_resumable()
        else:
            assert current["llm_usage"]["cost"] == 0.17
            assert current["_finite_budget_guard"]["pending"] == []
            assert restored.spent == pytest.approx(0.17)
            restored.require_resumable()


def test_fresh_hooks_restore_private_known_floor_for_budget_pause_semantics(tmp_path):
    with BudgetJournal(tmp_path, record(), 1) as owner:
        attempt = owner.reserve(0.8)
        known = owner.snapshot()
        known["llm_usage"]["cost"] = 0.1
        owner.settle(attempt, known, 0.75)
    script = """import asyncio,sys
from pathlib import Path
from lyrashield.artifacts.state import ReportState,set_global_report_state
from lyrashield.lifecycle import hooks
state=ReportState('durable');state._run_dir=Path(sys.argv[1]);state.hydrate_from_run_dir()
set_global_report_state(state)
hooks._reservation_input_rate=lambda _model:0
hooks._model_rate_card=lambda _model:(0,0,0,1)
owner=hooks.ReportUsageHooks(model='openai/gpt-6-luna',max_budget_usd=1,interactive=True)
assert owner.budget_control_state()['spent_usd']==.75
try:
    asyncio.run(owner.reserve_out_of_band_request(key='next',model='openai/gpt-6-luna',input_tokens=0,max_output_tokens=300000))
except hooks.BudgetPausedError:
    print('restored private known floor pauses before reservation')
else:
    raise AssertionError('expected an interactive budget pause')
"""
    child = subprocess.run(  # noqa: S603 - fixed isolated interpreter and fixture program
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert child.returncode == 0, child.stderr
