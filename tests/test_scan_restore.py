from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.lifecycle import restore
from lyrashield.lifecycle.agents import AgentCoordinator


if TYPE_CHECKING:
    from pathlib import Path


class _Coordinator:
    def __init__(self) -> None:
        self.max_agents = 99
        self.budget_paused = False
        self.statuses: dict[str, str] = {}
        self.parent_of: dict[str, str | None] = {}
        self.snapshot_path: Path | None = None
        self.reset_values: dict[str, Any] = {}

    def set_snapshot_path(self, path: Path) -> None:
        self.snapshot_path = path

    async def restore(self, snapshot: dict[str, Any]) -> None:
        self.parent_of = snapshot["parent_of"]
        self.statuses = snapshot["statuses"]

    async def reset_budget_stops(self, **kwargs: Any) -> None:
        self.reset_values = kwargs


class _ReportState:
    def get_total_llm_cost(self) -> float:
        return 5.0


@pytest.mark.asyncio
async def test_restore_coordinator_hydrates_resume_and_rederives_budget_pause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = tmp_path / "state"
    paths.mkdir()
    agents_path = paths / "agents.json"
    agents_path.write_text(
        json.dumps({"parent_of": {"root-1": None}, "statuses": {"root-1": "stopped"}}),
        encoding="utf-8",
    )
    agents_db = paths / "agents.db"
    agents_db.touch()
    hydrated: list[str] = []
    monkeypatch.setattr(
        restore,
        "hydrate_coverage_from_disk",
        lambda _path: hydrated.append("coverage"),
    )
    monkeypatch.setattr(
        restore,
        "hydrate_threat_models_from_disk",
        lambda _path: hydrated.append("threats"),
    )
    monkeypatch.setattr(restore, "hydrate_todos_from_disk", lambda _path: hydrated.append("todos"))
    monkeypatch.setattr(restore, "hydrate_notes_from_disk", lambda _path: hydrated.append("notes"))

    coordinator, root_id = await restore.restore_coordinator(
        coordinator=None,
        coordinator_factory=_Coordinator,
        scan_mode="standard",
        state_dir=paths,
        agents_path=agents_path,
        agents_db=agents_db,
        scan_id="scan-resume",
        is_resume=True,
        max_budget_usd=5.0,
        interactive=True,
        report_state_getter=_ReportState,
        recomputed_budget_flags=lambda *_args, **_kwargs: (True, False),
    )

    assert root_id == "root-1"
    assert coordinator.snapshot_path == agents_path
    assert coordinator.max_agents == 4
    assert coordinator.reset_values == {
        "budget_stopped": True,
        "reserve_stopped": False,
        "budget_paused": True,
    }
    assert hydrated == ["coverage", "threats", "todos", "notes"]


@pytest.mark.asyncio
async def test_new_scan_uses_fresh_root_id_and_hydrates_shared_ledgers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hydrated: list[str] = []
    monkeypatch.setattr(
        restore,
        "hydrate_coverage_from_disk",
        lambda _path: hydrated.append("coverage"),
    )
    monkeypatch.setattr(
        restore,
        "hydrate_threat_models_from_disk",
        lambda _path: hydrated.append("threats"),
    )
    monkeypatch.setattr(restore, "hydrate_todos_from_disk", lambda _path: hydrated.append("todos"))
    monkeypatch.setattr(restore, "hydrate_notes_from_disk", lambda _path: hydrated.append("notes"))

    coordinator, root_id = await restore.restore_coordinator(
        coordinator=None,
        coordinator_factory=_Coordinator,
        scan_mode="quick",
        state_dir=tmp_path,
        agents_path=tmp_path / "agents.json",
        agents_db=tmp_path / "agents.db",
        scan_id="scan-new",
        is_resume=False,
        max_budget_usd=None,
        interactive=False,
        report_state_getter=lambda: None,
        recomputed_budget_flags=lambda *_args, **_kwargs: (False, False),
    )

    assert root_id
    assert root_id not in {"", "root-1"}
    assert coordinator.max_agents == 4
    assert hydrated == ["coverage", "threats"]


@pytest.mark.asyncio
async def test_quick_scan_configures_real_coordinator_concurrency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Quick concurrency ceiling is read by the live factory path in
    restore.py (parallelized in #190); no other module supplies it."""
    monkeypatch.setattr(restore, "hydrate_coverage_from_disk", lambda _path: None)
    monkeypatch.setattr(restore, "hydrate_threat_models_from_disk", lambda _path: None)

    coordinator, _ = await restore.restore_coordinator(
        coordinator=None,
        coordinator_factory=AgentCoordinator,
        scan_mode="quick",
        state_dir=tmp_path,
        agents_path=tmp_path / "agents.json",
        agents_db=tmp_path / "agents.db",
        scan_id="scan-quick",
        is_resume=False,
        max_budget_usd=None,
        interactive=False,
        report_state_getter=lambda: None,
        recomputed_budget_flags=lambda *_args, **_kwargs: (False, False),
    )

    assert type(coordinator) is AgentCoordinator
    assert coordinator.max_agents == 4


@pytest.mark.parametrize(
    ("scan_mode", "expected_limit"),
    [("quick", 4), ("standard", 4), ("deep", 6), ("unlisted", 4)],
)
def test_scan_mode_agent_limit_reaches_the_coordinator_factory(
    scan_mode: str, expected_limit: int
) -> None:
    created: list[int] = []

    def factory(*, max_agents: int = 0) -> _Coordinator:
        created.append(max_agents)
        coordinator = _Coordinator()
        coordinator.max_agents = max_agents
        return coordinator

    coordinator = restore._coordinator_for_scan_mode(
        None, scan_mode, coordinator_factory=factory
    )

    assert created == [expected_limit]
    assert coordinator.max_agents == expected_limit


def test_quick_mode_clamps_an_injected_coordinator() -> None:
    coordinator = _Coordinator()
    coordinator.max_agents = 99
    coordinator.statuses = {f"a{i}": "stopped" for i in range(4)}

    result = restore._coordinator_for_scan_mode(coordinator, "quick")

    assert result is coordinator
    assert coordinator.max_agents == 4


def test_quick_mode_rejects_an_over_limit_coordinator() -> None:
    coordinator = _Coordinator()
    coordinator.statuses = {f"a{i}": "stopped" for i in range(5)}

    with pytest.raises(RuntimeError, match="quick"):
        restore._coordinator_for_scan_mode(coordinator, "quick")
