"""Native Windows directory handles must pin the active financial namespace."""

from __future__ import annotations

import os

import pytest

from lyrashield.artifacts.finite_budget import BudgetJournal
from lyrashield.artifacts.state_persistence import initial_run_record


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows sharing rules")


@pytest.mark.parametrize("boundary", ["run", "ancestor"])
def test_active_financial_namespace_cannot_be_renamed_until_closed(tmp_path, boundary):
    ancestor = tmp_path / "owned-parent"
    run = ancestor / "scan"
    owner = BudgetJournal(run, initial_run_record("scan", auth_mode="api"), 0.055)
    original = run if boundary == "run" else ancestor
    moved = original.with_name(original.name + "-moved")
    try:
        attempt = owner.reserve(0.05)
        with pytest.raises(OSError):
            original.rename(moved)
        assert original.is_dir()
        assert not moved.exists()
        owner.authorize(attempt)
        assert owner.snapshot()["_finite_budget_guard"]["pending"][0]["id"] == attempt
    finally:
        owner.close()
    original.rename(moved)
    assert moved.is_dir()
    assert not original.exists()
