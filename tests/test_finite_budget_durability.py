"""Process boundaries and projection failures must never restore free allowance."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from agents.models.interface import ModelTracing
from agents.models.openai_responses import OpenAIResponsesModel
from agents.usage import Usage
from openai import APIConnectionError, AsyncOpenAI, DefaultAsyncHttpxClient

from lyrashield.artifacts.finite_budget import GUARD, STAMP, BudgetJournal, FinancialStateError
from lyrashield.artifacts.state import ReportState
from lyrashield.artifacts.state_persistence import initial_run_record
from lyrashield.artifacts.writer import (
    read_run_record,
    restore_revision_artifacts,
    snapshot_revision_artifacts,
    write_run_record,
)
from lyrashield.lifecycle import hooks
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.models import _RequestBoundTurnGuardModel


_CHILD = r"""
import asyncio, sys
from pathlib import Path
from agents import Agent, Runner, RunConfig
from openai import AsyncOpenAI
from agents.models.openai_responses import OpenAIResponsesModel
from lyrashield.artifacts.state import ReportState, set_global_report_state
from lyrashield.lifecycle.hooks import ReportUsageHooks, set_active_hooks
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.models import _RequestBoundTurnGuardModel
state=ReportState('wire-durability'); state._run_dir=Path(sys.argv[1])
state.hydrate_from_run_dir(); set_global_report_state(state)
hooks=ReportUsageHooks(model='openai/gpt-6-luna',max_budget_usd=1)
set_active_hooks(hooks)
async def run():
    async with AsyncOpenAI(api_key='offline',base_url=sys.argv[2],timeout=3) as client:
        agent=Agent(name='Root',model=_RequestBoundTurnGuardModel(OpenAIResponsesModel('gpt-6-luna',client)),
            model_settings=make_model_settings(None,model_name='openai/gpt-6-luna',bounded_budget=True,max_output_tokens=128))
        try:
            await Runner.run(agent,'offline',context={"agent_id":"root"},
                hooks=hooks,run_config=RunConfig(tracing_disabled=True))
        except Exception:
            import traceback
            traceback.print_exc()
print("READY",flush=True)
asyncio.run(run())
"""


@pytest.mark.parametrize("kill_after_accept", [False, True])
def test_lost_ack_or_process_kill_does_not_allow_fresh_paid_resume(tmp_path, kill_after_accept):
    accepted, finish = threading.Event(), threading.Event()
    posts = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            posts.append(self.rfile.read(int(self.headers["content-length"])))
            accepted.set()
            if kill_after_accept:
                finish.wait(10)
            self.close_connection = True

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = [
        sys.executable,
        "-c",
        _CHILD,
        str(tmp_path),
        f"http://127.0.0.1:{server.server_port}/v1",
    ]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603 - owned loopback child
    bootstrap = queue.Queue()
    reader = threading.Thread(target=lambda: bootstrap.put(child.stdout.readline()), daemon=True)
    reader.start()
    try:
        # Bootstrap imports have their own bounded watchdog; actual dispatch must
        # become observable promptly once the real financial owner is ready.
        assert bootstrap.get(timeout=30).strip() == b"READY", child.communicate(timeout=5)
        assert accepted.wait(10), child.communicate(timeout=5)
        # Receipt proves durable reservation preceded the physical POST.
        raw = json.loads((tmp_path / "run.json").read_text())
        assert len(raw[GUARD]["pending"]) == 1
        assert raw["llm_usage"].get("cost", 0) == 0
        if kill_after_accept:
            child.kill()
        child.communicate(timeout=10)
        # An actual fresh interpreter cannot reach a second physical submission.
        retry = subprocess.run(command, capture_output=True, timeout=10, check=False)  # noqa: S603
        assert retry.returncode != 0
        assert b"pending provider charge" in retry.stderr
        assert len(posts) == 1
        assert read_run_record(tmp_path)[GUARD]["pending"] == raw[GUARD]["pending"]
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
        finish.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        reader.join(timeout=5)


def test_second_process_owner_is_denied_without_modifying_snapshot(tmp_path):
    record = initial_run_record("owner", auth_mode="api")
    script = """from pathlib import Path
import sys
from lyrashield.artifacts.finite_budget import BudgetJournal
from lyrashield.artifacts.state_persistence import initial_run_record
BudgetJournal(Path(sys.argv[1]),initial_run_record('owner',auth_mode='api'),1).reserve(.2)
"""
    with BudgetJournal(tmp_path, record, 1) as owner:
        before = (tmp_path / "run.json").read_bytes()
        result = subprocess.run(  # noqa: S603 - owned interpreter fixture
            [sys.executable, "-c", script, str(tmp_path)],
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert result.returncode != 0
        assert (tmp_path / "run.json").read_bytes() == before
        assert owner.snapshot()[GUARD]["pending"] == []


def test_known_settlement_precedes_projection_failure_and_byte_rollback(tmp_path, monkeypatch):
    state = ReportState("settlement")
    state._run_dir = tmp_path
    owner = state.enable_finite_budget(1)
    old_projection = snapshot_revision_artifacts(tmp_path)
    attempt = owner.reserve(0.6)
    # Report generation can fail after the financial commit. Its old byte snapshot
    # must restore report contents while retaining the newly known usage.
    monkeypatch.setattr(state, "save_run_data", lambda **_kwargs: False)
    assert not state.record_sdk_usage(
        agent_id="root",
        model="openai/gpt-6-luna",
        usage=Usage(requests=1, input_tokens=7, output_tokens=2, total_tokens=9),
        budget_attempt=attempt,
        budget_cost=0.17,
    )
    paid = read_run_record(tmp_path)
    assert paid["llm_usage"]["total_tokens"] == 9
    assert paid[GUARD]["pending"] == []
    pending = owner.reserve(0.6)
    restore_revision_artifacts(tmp_path, old_projection)
    after = read_run_record(tmp_path)
    assert after["llm_usage"] == paid["llm_usage"]
    assert after[GUARD]["pending"][0]["id"] == pending
    # A stale ordinary writer cannot restore the former free allowance either.
    with pytest.raises(FinancialStateError, match="stale"):
        write_run_record(tmp_path, json.loads(old_projection["run.json"]))


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_legacy_read_and_projection_do_not_activate_or_change_contract(tmp_path, version):
    record = initial_run_record("legacy", auth_mode="api")
    record["schema_version"] = version
    write_run_record(tmp_path, record)
    assert read_run_record(tmp_path) == record
    assert GUARD not in record
    assert not (tmp_path / STAMP).exists()


@pytest.mark.parametrize(
    "damage",
    [
        "stamp_truncated",
        "stamp_duplicate",
        "guard_boolean_version",
        "guard_unknown_field",
        "pending_noncanonical",
        "record_missing",
    ],
)
def test_invalid_activated_journal_fails_closed(tmp_path, damage):
    record = initial_run_record("invalid", auth_mode="api")
    with BudgetJournal(tmp_path, record, 1) as owner:
        owner.reserve(0.6)
    path = tmp_path / "run.json"
    current = json.loads(path.read_text())
    if damage == "stamp_truncated":
        (tmp_path / STAMP).write_bytes(b"{")
    elif damage == "stamp_duplicate":
        raw = (tmp_path / STAMP).read_text()
        (tmp_path / STAMP).write_text('{"v":1,' + raw[1:])
    elif damage == "record_missing":
        path.unlink()
    else:
        if damage == "guard_boolean_version":
            current[GUARD]["v"] = True
        elif damage == "guard_unknown_field":
            current[GUARD]["unrecognized"] = 1
        else:
            current[GUARD]["pending"][0]["id"] = current[GUARD]["epoch"] + ":01"
        path.write_text(json.dumps(current))
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record, 1)


def test_activation_flush_failure_cannot_be_retried_as_legacy(tmp_path, monkeypatch):
    record = initial_run_record("flush", auth_mode="api")
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("flush failed")))
        with pytest.raises(FinancialStateError):
            BudgetJournal(tmp_path, record, 1)
    assert (tmp_path / STAMP).exists()
    with pytest.raises(FinancialStateError):
        BudgetJournal(tmp_path, record, 1)


@pytest.mark.asyncio
async def test_actual_finite_transport_requires_durable_owner_before_post(monkeypatch):
    monkeypatch.setattr(hooks, "_active_hooks", None)
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(500)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _RequestBoundTurnGuardModel(OpenAIResponsesModel("gpt-6-luna", client))
        with pytest.raises(APIConnectionError):
            await model.get_response(
                system_instructions=None,
                input="offline",
                model_settings=make_model_settings(
                    None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
                ),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            )
    assert requests == []
