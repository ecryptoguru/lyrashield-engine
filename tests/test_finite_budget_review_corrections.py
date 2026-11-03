"""Actual boundary regressions from the consolidated durability review."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from agents.models.openai_responses import OpenAIResponsesModel
from agents.usage import Usage
from openai import AsyncOpenAI

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts import writer
from lyrashield.artifacts.finite_budget import GUARD, STAMP, BudgetJournal, FinancialStateError
from lyrashield.artifacts.state import ReportState
from lyrashield.artifacts.state_persistence import initial_run_record
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import ReportUsageHooks
from lyrashield.triage import cli, service
from tests.test_ai_security_triage import _input
from tests.test_physical_budget_boundaries import _payload
from tests.test_web_search import _clear_settings_cache, _tool_ctx, web_search


def _directory_alias(alias: Path, target: Path) -> None:
    if os.name == "nt":
        command = Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe"
        subprocess.run(  # noqa: S603 - fixed Windows junction utility and owned fixture paths
            [str(command), "/d", "/c", "mklink", "/J", str(alias), str(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    else:
        alias.symlink_to(target, target_is_directory=True)


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_active_hooks", None)


@pytest.mark.parametrize("prior_cost", [0, 0.8])
@pytest.mark.parametrize("phase_allowance,completed", [(0.001, True), (0.000000001, False)])
def test_cold_actual_triage_shares_main_owner_without_replacing_total_cap(
    tmp_path, monkeypatch, prior_cost, phase_allowance, completed
):
    workspace = tmp_path / "scan-id"
    workspace.mkdir()
    run = workspace / "strix_runs" / "scan-id"
    base = initial_run_record("scan-id", auth_mode="api")
    with BudgetJournal(run, base, 1) as owner:
        known = owner.snapshot()
        known["llm_usage"]["cost"] = prior_cost
        owner.checkpoint_known(known)
    source = workspace / "ai-security-triage-input.json"
    source.write_text(_input().model_dump_json())
    output = workspace / "ai-security-triage.json"
    posts = []
    payload = _payload("responses", usage=True)
    payload["output"][0]["content"][0]["text"] = json.dumps(
        {"disposition": "NEEDS_REVIEW", "confidence": 0.7, "explanation": "Offline control"}
    )

    def accept(request):
        posts.append(request)
        return httpx.Response(200, json=payload)

    native = AsyncOpenAI(
        api_key="offline", http_client=httpx.AsyncClient(transport=httpx.MockTransport(accept))
    )
    monkeypatch.setattr(service, "configure_sdk_model_defaults", lambda *_args: None)
    monkeypatch.setattr(
        service.StrixProvider,
        "get_model",
        lambda *_args: OpenAIResponsesModel("gpt-6-luna", native),
    )
    monkeypatch.setattr(cli, "_luna_model_route", lambda: "openai/gpt-6-luna")
    try:
        assert (
            cli.run_triage_cli(
                [
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--enabled",
                    "--max-budget-usd",
                    str(phase_allowance),
                ]
            )
            == 0
        )
    finally:
        asyncio.run(native.close())
    artifact = json.loads(output.read_text())
    current = writer.read_run_record(run)
    assert artifact["status"] == ("COMPLETED" if completed else "BUDGET_STOPPED")
    assert len(posts) == int(completed)
    assert current[GUARD]["limit_units"] == 10**10
    assert current["llm_usage"]["cost"] == pytest.approx(
        prior_cost + (artifact["llmUsage"].get("cost") or 0)
    )
    if completed:
        assert 0 < artifact["llmUsage"]["cost"] < phase_allowance
    else:
        assert not artifact["llmUsage"].get("cost")
    assert current[GUARD]["pending"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("remove_stamp", [False, True])
async def test_finite_search_cannot_post_without_final_financial_authority(
    tmp_path, monkeypatch, remove_stamp
):
    state = ReportState("search")
    state._run_dir = tmp_path
    monkeypatch.setattr(state_module, "_global_report_state", state)
    journal = state.enable_finite_budget(1 if remove_stamp else 0.0001)
    if remove_stamp:
        monkeypatch.setattr(
            hooks_module,
            "_active_hooks",
            ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1, report_state=state),
        )
    calls = []

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            if remove_stamp:
                assert journal.snapshot()[GUARD]["pending"]
                # POSIX namespace fault; Windows live-handle refusal is tested natively.
                (tmp_path / STAMP).unlink()
            return self

        async def __aexit__(self, *_args):
            pass

        async def post(self, *_args, **_kwargs):
            calls.append("POST")
            return httpx.Response(
                200,
                json={"results": []},
                request=httpx.Request("POST", "https://fixture.invalid/search"),
            )

    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("PARALLEL_API_KEY", "offline")
    monkeypatch.setattr(httpx, "AsyncClient", Client)
    _clear_settings_cache()
    args = {"query": "offline CVEs", "topic": "advisory"}
    try:
        with contextlib.suppress(FinancialStateError):
            await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args))
        assert calls == []
        assert writer.read_run_record(tmp_path)["llm_usage"].get("cost", 0) == 0
    finally:
        _clear_settings_cache()


def test_known_floor_ratchets_cumulative_ledger_and_delta(tmp_path):
    with BudgetJournal(tmp_path, initial_run_record("floor", auth_mode="api"), 1) as owner:
        for quote, ledger, upper in [(0.8, 0.8, 0.1), (0.1, 0.8, 0.1)]:
            attempt = owner.reserve(quote)
            known = owner.snapshot()
            known["llm_usage"]["cost"] = ledger
            owner.settle(attempt, known, upper)
        assert owner.spent == pytest.approx(0.9)
        with pytest.raises(FinancialStateError):
            owner.reserve(0.2)


def test_duplicate_observed_callback_and_restore_keep_one_known_charge(tmp_path):
    state = ReportState("observe")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(1)
    for _ in range(2):
        state.record_observed_llm_cost(
            0.35, model="openrouter/anthropic/claude-sonnet", response_id="response-one"
        )
    assert owner.snapshot()["llm_usage"]["cost"] == 0.35
    assert owner.spent == 0.35
    owner.close()
    restored = ReportState("observe")
    restored._run_dir = tmp_path
    restored.hydrate_from_run_dir()
    new = restored.enable_finite_budget(None)
    restored.record_observed_llm_cost(
        0.35, model="anthropic/claude-sonnet", response_id="response-one"
    )
    assert new.snapshot()["llm_usage"]["cost"] == 0.35


@pytest.mark.skipif(os.name == "nt", reason="POSIX group mode compatibility")
def test_unmarked_legacy_write_keeps_group_writable_directory_compatibility(tmp_path):
    tmp_path.chmod(0o775)
    record = initial_run_record("legacy", auth_mode="api")
    writer.write_run_record(tmp_path, record)
    assert writer.read_run_record(tmp_path) == record
    assert not (tmp_path / STAMP).exists()


def test_finite_creation_does_not_mutate_through_symlink(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    _directory_alias(alias, target)
    with pytest.raises(FinancialStateError):
        BudgetJournal(alias / "new-child", initial_run_record("safe", auth_mode="api"), 1)
    assert not (target / "new-child").exists()


@pytest.mark.parametrize("restore", [False, True, "unlink"])
def test_legacy_writer_cutover_serializes_against_process_activation(  # noqa: PLR0915 - one complete cross-process fault schedule
    tmp_path, monkeypatch, restore
):
    record = initial_run_record("cutover", auth_mode="api")
    writer.write_run_record(tmp_path, record)
    entered, release = threading.Event(), threading.Event()
    errors = []
    if restore == "unlink":
        original_unlink = Path.unlink

        def delayed_unlink(path, *args, **kwargs):
            if path == tmp_path / "run.json":
                entered.set()
                assert release.wait(10)
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", delayed_unlink)
    else:
        name = "_atomic_write_bytes" if restore else "_atomic_write_text"
        original = getattr(writer, name)

        def delayed(*args, **kwargs):
            entered.set()
            assert release.wait(10)
            return original(*args, **kwargs)

        monkeypatch.setattr(writer, name, delayed)

    def write():
        try:
            if restore:
                writer.restore_revision_artifacts(
                    tmp_path,
                    {"run.json": None if restore == "unlink" else json.dumps(record).encode()},
                )
            else:
                writer.write_run_record(tmp_path, record)
        except FinancialStateError:
            pass
        except Exception as exc:  # noqa: BLE001 - relay background thread failure to its parent assertion
            errors.append(exc)

    thread = threading.Thread(target=write)
    thread.start()
    assert entered.wait(3)
    script = """from pathlib import Path
import sys
from lyrashield.artifacts.finite_budget import BudgetJournal
from lyrashield.artifacts.state_persistence import initial_run_record
print('READY',flush=True)
with BudgetJournal(Path(sys.argv[1]),initial_run_record('cutover',auth_mode='api'),1) as j:
 a=j.reserve(.8);j.authorize(a);s=j.snapshot();s['llm_usage']['cost']=.8;j.settle(a,s,.8)
"""
    child = subprocess.Popen(  # noqa: S603 - fixed isolated interpreter and fault fixture
        [sys.executable, "-c", script, str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    boot = queue.Queue()
    reader = threading.Thread(target=lambda: boot.put(child.stdout.readline()), daemon=True)
    reader.start()
    try:
        assert boot.get(timeout=20).strip() == b"READY"
        # Allow the other interpreter to reach activation. A correct transition
        # lock blocks it until the stale legacy mutation has finished.
        with contextlib.suppress(subprocess.TimeoutExpired):
            child.wait(timeout=1)
        release.set()
        thread.join(10)
        out, err = child.communicate(timeout=10)
        assert child.returncode == 0, (out, err)
        current = writer.read_run_record(tmp_path)
        assert current["llm_usage"]["cost"] == 0.8
        assert GUARD in current
        assert not errors
    finally:
        release.set()
        thread.join(10)
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)


def test_observed_then_sdk_settlement_is_one_charge_after_projection_exception(
    tmp_path, monkeypatch
):

    state = ReportState("observe-split")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(1)
    attempt = owner.reserve(0.6)
    route = "openrouter/anthropic/claude-sonnet"
    state.record_observed_llm_cost(0.35, model=route, response_id="split-response")
    assert len(owner.snapshot()[GUARD]["pending"]) == 1

    def fail_projection(**_kwargs):
        raise OSError("projection failed after financial commit")

    monkeypatch.setattr(state, "save_run_data", fail_projection)
    assert not state.record_sdk_usage(
        agent_id="root",
        model=route,
        response_id="split-response",
        usage=Usage(requests=1, input_tokens=7, output_tokens=2, total_tokens=9),
        budget_attempt=attempt,
        budget_cost=0.35,
    )
    state.record_observed_llm_cost(0.35, model=route, response_id="split-response")
    current = owner.snapshot()
    assert current["llm_usage"]["cost"] == 0.35
    assert current["llm_usage"]["total_tokens"] == 9
    assert owner.spent == 0.35
    assert current[GUARD]["pending"] == []
    owner.close()
    restored = ReportState("observe-split")
    restored._run_dir = tmp_path
    restored.hydrate_from_run_dir()
    restored.enable_finite_budget(None)
    restored.record_observed_llm_cost(0.35, model=route, response_id="split-response")
    assert restored.get_total_llm_cost() == 0.35
    assert restored.get_total_llm_usage()["total_tokens"] == 9


@pytest.mark.asyncio
async def test_finite_search_recovers_real_owner_when_hooks_are_missing(tmp_path, monkeypatch):
    state = ReportState("search-positive")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(1)
    monkeypatch.setattr(state_module, "_global_report_state", state)
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("PARALLEL_API_KEY", "offline")
    calls = []

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def post(self, *_args, **_kwargs):
            assert len(owner.snapshot()[GUARD]["pending"]) == 1
            calls.append("POST")
            return httpx.Response(
                200,
                json={"results": []},
                request=httpx.Request("POST", "https://fixture.invalid/search"),
            )

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    _clear_settings_cache()
    try:
        args = {"query": "offline advisory"}
        result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
        assert result["success"]
        assert calls == ["POST"]
        assert owner.snapshot()["llm_usage"]["cost"] == 0.001
        assert owner.snapshot()[GUARD]["pending"] == []
        assert hooks_module.get_active_hooks() is None
    finally:
        _clear_settings_cache()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["consumed", "closed", "stale"])
async def test_finite_search_checks_one_use_owner_after_client_await(tmp_path, monkeypatch, fault):
    state = ReportState("search-final")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(1)
    monkeypatch.setattr(state_module, "_global_report_state", state)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1, report_state=state)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("PARALLEL_API_KEY", "offline")
    calls = []

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            current = owner.snapshot()
            if fault == "consumed":
                owner.authorize(current[GUARD]["pending"][0]["id"])
            elif fault == "closed":
                owner.close()
            else:
                current[GUARD]["revision"] += 1
                (tmp_path / "run.json").write_text(json.dumps(current))
            return self

        async def __aexit__(self, *_args):
            pass

        async def post(self, *_args, **_kwargs):
            calls.append("POST")
            raise AssertionError("must not dispatch")

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    _clear_settings_cache()
    try:
        args = {"query": "offline advisory"}
        with contextlib.suppress(FinancialStateError):
            await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args))
        assert calls == []
        assert len(writer.read_run_record(tmp_path)[GUARD]["pending"]) == 1
    finally:
        _clear_settings_cache()


def test_cold_triage_lost_ack_denies_fresh_process_replay(tmp_path):
    workspace = tmp_path / "scan-id"
    workspace.mkdir()
    run = workspace / "strix_runs" / "scan-id"
    with BudgetJournal(run, initial_run_record("scan-id", auth_mode="api"), 1) as owner:
        current = owner.snapshot()
        current["llm_usage"]["cost"] = 0.8
        owner.checkpoint_known(current)
    source = workspace / "ai-security-triage-input.json"
    source.write_text(_input().model_dump_json())
    output = workspace / "ai-security-triage.json"
    posts = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            posts.append(self.rfile.read(int(self.headers["content-length"])))
            self.close_connection = True

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    script = """import asyncio,sys
import httpx
from openai import AsyncOpenAI,APIConnectionError
from agents.models.openai_responses import OpenAIResponsesModel
from lyrashield.triage import cli,service
native=AsyncOpenAI(api_key='offline',base_url=sys.argv[3],timeout=3)
service.configure_sdk_model_defaults=lambda *_args:None
service.StrixProvider.get_model=lambda *_args:OpenAIResponsesModel('gpt-6-luna',native)
cli._luna_model_route=lambda:'openai/gpt-6-luna'
try:
    cli.run_triage_cli(['--input',sys.argv[1],'--output',sys.argv[2],'--enabled','--max-budget-usd','.001'])
except APIConnectionError:
    pass
finally:
    asyncio.run(native.close())
"""
    command = [
        sys.executable,
        "-c",
        script,
        str(source),
        str(output),
        f"http://127.0.0.1:{server.server_port}/v1",
    ]
    try:
        first = subprocess.run(command, capture_output=True, timeout=30, check=False)  # noqa: S603 - owned loopback subprocess
        assert first.returncode == 0, first.stderr
        assert len(posts) == 1
        second = subprocess.run(command, capture_output=True, timeout=30, check=False)  # noqa: S603
        assert second.returncode != 0
        assert b"pending provider charge" in second.stderr
        assert len(posts) == 1
        current = writer.read_run_record(run)
        assert current["llm_usage"]["cost"] == 0.8
        assert current[GUARD]["limit_units"] == 10**10
        assert len(current[GUARD]["pending"]) == 1
        assert json.loads(output.read_text())["terminalReason"] == "TRIAGE_INTERRUPTED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@pytest.mark.parametrize("boundary", ["state", "preflight", "initializer", "common-writer"])
def test_finite_owned_entrypoints_verify_parents_before_any_creation(
    tmp_path, monkeypatch, boundary
):
    main = import_module("lyrashield.interface.main")
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    _directory_alias(alias, target)
    run = alias / "new-child"
    args = SimpleNamespace(run_name="safe", max_budget_usd=1, warm_up_usages=[])
    with pytest.raises((FinancialStateError, OSError)):
        if boundary == "state":
            state = ReportState("safe")
            state._run_dir = run
            state.enable_finite_budget(1)
        elif boundary == "preflight":
            monkeypatch.setattr(state_module, "run_dir_for", lambda _name: run)
            main._run_llm_preflight(args, deadline=None)
        elif boundary == "initializer":
            monkeypatch.setattr(main, "run_dir_for", lambda _name: run)
            main._persist_run_record(args)
        else:
            with BudgetJournal(
                tmp_path / "source", initial_run_record("safe", auth_mode="api"), 1
            ) as owner:
                guarded = owner.snapshot()
            writer.write_run_record(run, guarded)
    assert not (target / "new-child").exists()


def test_observed_receipt_identity_bound_never_discards_prior_known_identity(tmp_path):
    state = ReportState("bounded-observations")
    state._run_dir = tmp_path
    state.enable_finite_budget(1)
    route = "openrouter/anthropic/claude-sonnet"
    for index in range(64):
        state.record_observed_llm_cost(0.001, model=route, response_id=f"response-{index}")
    current = writer.read_run_record(tmp_path)
    assert len(current[GUARD]["observations"]) == 64
    assert len(json.dumps(current[GUARD]).encode()) < 16384
    state.record_observed_llm_cost(0.001, model=route, response_id="response-0")
    assert writer.read_run_record(tmp_path)["llm_usage"]["cost"] == 0.064
    with pytest.raises(FinancialStateError, match="capacity"):
        state.record_observed_llm_cost(0.001, model=route, response_id="response-64")
    assert writer.read_run_record(tmp_path) == current
