from __future__ import annotations

import asyncio
import json
import types
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

import lyrashield.tools.todo.tools as todo_tools
import strix.tools.notes.tools as notes_tools
from lyrashield.lifecycle import execution, runner
from lyrashield.lifecycle.agents import AgentCoordinator, WaitKind
from lyrashield.lifecycle.execution import _start_child_runner, run_agent_loop
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.lifecycle.sessions import open_agent_session
from lyrashield.runtime import session_manager


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path


MAX_BUDGET = 10.0
COST_PER_CALL = 1.0


class _FakeLedger:
    def __init__(self) -> None:
        self.cost = 0.0
        self.calls: list[str] = []

    def record_sdk_usage(self, **_kwargs: Any) -> None:
        return

    def get_total_llm_cost(self) -> float:
        return self.cost


class _FakeStream:
    def __init__(
        self,
        *,
        ledger: _FakeLedger,
        hooks: ReportUsageHooks,
        context: dict[str, Any],
        agent: Any,
        coordinator: AgentCoordinator,
    ) -> None:
        self._ledger = ledger
        self._hooks = hooks
        self._context = context
        self._agent = agent
        self._coordinator = coordinator
        self.run_loop_exception: BaseException | None = None
        self.final_output = None

    async def stream_events(self) -> AsyncIterator[Any]:
        agent_id = str(self._context.get("agent_id"))
        self._ledger.cost += COST_PER_CALL
        self._ledger.calls.append(agent_id)
        ctx_wrapper = MagicMock()
        ctx_wrapper.context = self._context
        try:
            await self._hooks.on_llm_end(ctx_wrapper, self._agent, MagicMock())
        except Exception as exc:  # noqa: BLE001
            self.run_loop_exception = exc
        # Stand in for the explicit yield tool a real turn ends with. Without it
        # every turn looks like a forgotten tool call and burns the recovery
        # budget, which is a different scenario from the one under test here.
        if self._coordinator.statuses.get(agent_id) == "running":
            wait_kind: WaitKind = "user" if self._context.get("parent_id") is None else "agents"
            await self._coordinator.park_waiting(agent_id, wait_kind=wait_kind)
        items: tuple[Any, ...] = ()
        for item in items:
            yield item

    def cancel(self, mode: str = "immediate") -> None:  # noqa: ARG002
        return


def _fake_runner(ledger: _FakeLedger, coordinator: AgentCoordinator) -> Any:
    class _FakeRunner:
        @staticmethod
        def run_streamed(
            agent: Any,
            input: Any,  # noqa: A002, ARG004
            *,
            run_config: Any,  # noqa: ARG004
            context: dict[str, Any],
            max_turns: int,  # noqa: ARG004
            session: Any,  # noqa: ARG004
            hooks: ReportUsageHooks,
        ) -> _FakeStream:
            return _FakeStream(
                ledger=ledger,
                hooks=hooks,
                context=context,
                agent=agent,
                coordinator=coordinator,
            )

    return _FakeRunner


async def _noop_compact(*_args: Any, **_kwargs: Any) -> bool:
    return False


async def _wait_until(predicate: Callable[[], bool], *, timeout: float = 5.0) -> None:
    async def _poll() -> None:
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_poll(), timeout=timeout)


@pytest.mark.asyncio
async def test_full_budget_lifecycle_reserve_then_cap(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    coordinator = AgentCoordinator()
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, coordinator))
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    db_path = tmp_path / "agents.sqlite"
    sessions: list[Any] = []
    run_config = MagicMock()

    await coordinator.register("root", "strix", parent_id=None)
    root_session = open_agent_session("root", db_path)
    sessions.append(root_session)

    root_exc: list[BaseException] = []

    async def _root_loop() -> None:
        try:
            await run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=run_config,
                context={"agent_id": "root", "parent_id": None},
                max_turns=500,
                coordinator=coordinator,
                agent_id="root",
                interactive=True,
                session=root_session,
                start_parked=True,
                hooks=hooks,
            )
        except BaseException as exc:
            root_exc.append(exc)
            raise

    with patch("lyrashield.lifecycle.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(_root_loop())
        await asyncio.sleep(0.05)

        for child_id in ("child-a", "child-b"):
            await coordinator.register(child_id, "recon", parent_id="root")
            await _start_child_runner(
                parent_ctx={"agent_id": "root", "parent_id": None},
                coordinator=coordinator,
                agents_db_path=db_path,
                sessions_to_close=sessions,
                run_config=run_config,
                max_turns=500,
                interactive=True,
                child_agent=MagicMock(),
                child_id=child_id,
                name=f"recon-{child_id}",
                parent_id="root",
                task="probe things",
                initial_input=[],
                hooks=hooks,
            )
        await _wait_until(lambda: ledger.cost >= 2.0)
        reserve_before = coordinator.reserve_stopped
        assert reserve_before is False

        async def _wait_spend_above(amount: float) -> None:
            await _wait_until(lambda: ledger.cost > amount)

        turn = 0
        while ledger.cost < MAX_BUDGET * 0.90 - 1e-9:
            target = ("child-a", "child-b")[turn % 2]
            spent_before = ledger.cost
            assert await coordinator.send(target, {"from": "user", "content": "keep going"})
            await _wait_spend_above(spent_before)
            turn += 1

        await _wait_until(lambda: coordinator.reserve_stopped)

        await _wait_until(
            lambda: (
                coordinator.statuses["child-a"] == "stopped"
                and coordinator.statuses["child-b"] == "stopped"
            )
        )

        assert coordinator.reserve_stopped is True

        await _wait_until(lambda: coordinator.budget_stopped)
        assert ledger.cost == pytest.approx(MAX_BUDGET)

        assert len(ledger.calls) == 10
        assert set(ledger.calls[:9]) == {"child-a", "child-b"}
        assert ledger.calls[9] == "root"

        root_items = await root_session.get_items()
        notices = [item for item in root_items if "Budget reserve" in str(item)]
        assert len(notices) == 1

        with pytest.raises(BudgetExceededError):
            await root_task
        assert root_exc and isinstance(root_exc[0], BudgetExceededError)

        assert {aid: str(status) for aid, status in coordinator.statuses.items()} == {
            "root": "stopped",
            "child-a": "stopped",
            "child-b": "stopped",
        }
        assert coordinator.budget_stopped is True
        assert coordinator.reserve_stopped is True

    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_respawned_children_after_reserve_never_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    ledger.cost = 9.5
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child-a", "recon", parent_id="root")
    snap = await coordinator.snapshot()
    snap["reserve_stopped"] = True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.reserve_stopped is True
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, restored))

    sessions: list[Any] = []
    with patch("lyrashield.lifecycle.hooks.get_global_report_state", return_value=ledger):
        await _start_child_runner(
            parent_ctx={"agent_id": "root", "parent_id": None},
            coordinator=restored,
            agents_db_path=tmp_path / "agents.sqlite",
            sessions_to_close=sessions,
            run_config=MagicMock(),
            max_turns=500,
            interactive=True,
            child_agent=MagicMock(),
            child_id="child-a",
            name="recon-child-a",
            parent_id="root",
            task="probe things",
            initial_input=[],
            hooks=hooks,
        )
        await _wait_until(lambda: restored.statuses["child-a"] == "stopped")

    assert ledger.cost == pytest.approx(9.5)
    assert ledger.calls == []
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_resumed_parked_root_after_reserve_is_renotified_and_finalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    ledger.cost = 9.0
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.set_status("root", "waiting")
    snap = await coordinator.snapshot()
    snap["reserve_stopped"] = True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.reserve_stopped is True
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, restored))

    root_session = open_agent_session("root", tmp_path / "agents.sqlite")
    with patch("lyrashield.lifecycle.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(
            run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=MagicMock(),
                context={"agent_id": "root", "parent_id": None},
                max_turns=500,
                coordinator=restored,
                agent_id="root",
                interactive=True,
                session=root_session,
                start_parked=True,
                hooks=hooks,
            )
        )
        with pytest.raises(BudgetExceededError):
            await asyncio.wait_for(root_task, timeout=5.0)

    assert ledger.calls == ["root"]
    assert ledger.cost == pytest.approx(MAX_BUDGET)
    root_items = await root_session.get_items()
    notices = [item for item in root_items if "Budget reserve" in str(item)]
    assert len(notices) == 1
    root_session.close()


@pytest.mark.asyncio
async def test_interactive_budget_pause_then_user_message_extends_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    ledger.cost = 9.0
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET, interactive=True)
    coordinator = AgentCoordinator()
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, coordinator))
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator.set_budget_extender(hooks.extend_budget)
    await coordinator.register("root", "strix", parent_id=None)
    root_session = open_agent_session("root", tmp_path / "agents.sqlite")

    with patch("lyrashield.lifecycle.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(
            run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=MagicMock(),
                context={"agent_id": "root", "parent_id": None},
                max_turns=500,
                coordinator=coordinator,
                agent_id="root",
                interactive=True,
                session=root_session,
                start_parked=True,
                hooks=hooks,
            )
        )
        await asyncio.sleep(0.05)

        assert await coordinator.send("root", {"from": "user", "content": "go"})
        await _wait_until(lambda: coordinator.budget_paused)
        assert coordinator.statuses["root"] == "budget_paused"
        assert ledger.cost == pytest.approx(MAX_BUDGET)
        assert not root_task.done()
        assert coordinator.budget_stopped is False

        assert await coordinator.send("root", {"from": "user", "content": "keep going"})
        await _wait_until(lambda: not coordinator.budget_paused)
        await _wait_until(lambda: ledger.cost > MAX_BUDGET)
        await _wait_until(lambda: coordinator.statuses["root"] == "waiting")
        assert not root_task.done()

        root_task.cancel()
        await root_task

    root_session.close()


class _ResumeLedger(_FakeLedger):
    """Report-state stand-in covering the runner's resume bookkeeping."""

    def __init__(self, cost: float) -> None:
        super().__init__()
        self.cost = cost
        self.run_record: dict[str, Any] = {}

    def save_run_data(self) -> None:
        return

    def set_terminal_reason(self, _reason: str) -> None:
        return


def _patch_resume_scaffold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ledger: _ResumeLedger
) -> None:
    """Stub the runner around its resume bookkeeping and stop at run_agent_loop."""
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(runner, "uses_chat_completions_tool_schema", lambda _m, _s: False)
    monkeypatch.setattr(
        runner, "prompt_cache_options_for_model", lambda _m: {"mode": "explicit", "ttl": "30m"}
    )

    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _state_dir: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _state_dir: None)

    async def _create_or_reuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)

    monkeypatch.setattr(runner, "get_global_report_state", lambda: ledger)
    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: {})
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: {})
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_k: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_k: lambda **_k2: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _rid, _db, **_k: object())

    async def _run_agent_loop(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)


def _resume_snapshot(*, budget_paused: bool) -> dict[str, Any]:
    return {
        # A persisted pause parks the agent; a stale-flag resume left it
        # waiting when the prior process exited.
        "statuses": {"root": "budget_paused" if budget_paused else "waiting"},
        "parent_of": {"root": None},
        "names": {"root": "root"},
        "metadata": {"root": {"task": "", "skills": []}},
        "pending_counts": {"root": 0},
        "budget_stopped": False,
        "reserve_stopped": False,
        "budget_paused": budget_paused,
    }


def _write_resume_state(tmp_path: Path, snapshot: dict[str, Any]) -> None:
    (tmp_path / "agents.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (tmp_path / "agents.db").write_bytes(b"")


@pytest.mark.asyncio
async def test_interactive_resume_at_budget_starts_paused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh-process interactive resume at 100% budget must start paused.

    The persisted pause flag can be stale (the prior process may have exited
    before asserting it), so the pause is re-derived from the hydrated ledger.
    """
    _write_resume_state(tmp_path, _resume_snapshot(budget_paused=False))
    ledger = _ResumeLedger(cost=MAX_BUDGET)
    _patch_resume_scaffold(monkeypatch, tmp_path, ledger)
    coordinator = AgentCoordinator()

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-at-budget",
        image="img",
        coordinator=coordinator,
        interactive=True,
        max_budget_usd=MAX_BUDGET,
        resume=True,
        cleanup_on_exit=False,
    )

    assert coordinator.budget_paused is True
    # The stubbed loop "completed" the root; the pause flag — which makes the
    # user's first message extend the budget — is what the fix asserts.
    assert coordinator.statuses["root"] == "completed"


@pytest.mark.asyncio
async def test_interactive_resume_of_persisted_pause_stays_paused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A snapshot that persisted the pause must not auto-extend on resume.

    Resuming must not silently extend the budget; a user message is what lifts
    the pause (and extends the budget), matching the in-session contract.
    """
    _write_resume_state(tmp_path, _resume_snapshot(budget_paused=True))
    ledger = _ResumeLedger(cost=MAX_BUDGET)
    _patch_resume_scaffold(monkeypatch, tmp_path, ledger)
    coordinator = AgentCoordinator()

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-paused",
        image="img",
        coordinator=coordinator,
        interactive=True,
        max_budget_usd=MAX_BUDGET,
        resume=True,
        cleanup_on_exit=False,
    )

    assert coordinator.budget_paused is True
    assert coordinator.statuses["root"] == "budget_paused"
    # No budget_extended nudge was injected by the resume itself.
    assert coordinator.runtimes["root"].mailbox == []


@pytest.mark.asyncio
async def test_interactive_resume_below_budget_does_not_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resume with budget headroom starts unpaused, as before."""
    _write_resume_state(tmp_path, _resume_snapshot(budget_paused=False))
    ledger = _ResumeLedger(cost=1.0)
    _patch_resume_scaffold(monkeypatch, tmp_path, ledger)
    coordinator = AgentCoordinator()

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-headroom",
        image="img",
        coordinator=coordinator,
        interactive=True,
        max_budget_usd=MAX_BUDGET,
        resume=True,
        cleanup_on_exit=False,
    )

    assert coordinator.budget_paused is False
