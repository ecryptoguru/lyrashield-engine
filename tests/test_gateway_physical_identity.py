"""The controlled gateway receives durable scan-bound physical request identities."""

from __future__ import annotations

import asyncio
import re

import httpx
import pytest
from openai import AsyncOpenAI, DefaultAsyncHttpxClient

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.finite_budget import GUARD
from lyrashield.artifacts.state import ReportState
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import ReportUsageHooks
from lyrashield.lifecycle.runner import run_strix_scan
from lyrashield.policy.physical_requests import (
    PhysicalBudgetAdapterError,
    _authorize_durable,
    _gateway_enabled,
    _set_gateway_headers,
    durable_physical_admission,
)
from tests.finite_budget_fixtures import owned_hooks
from tests.test_physical_budget_boundaries import _model, _reply, _run


@pytest.fixture(autouse=True)
def gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hooks_module, "_active_hooks", None)
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setenv("LYRASHIELD_PROVIDER_GATEWAY_ORIGIN", "https://gateway.invalid")
    monkeypatch.setenv("STRIX_RUN_ID", "unrelated-host-scan")


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_gateway_uses_durable_attempt_identity(tmp_path, streaming: bool) -> None:
    requests: list[httpx.Request] = []
    pending_ids: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        pending_ids.extend(entry["id"] for entry in hooks._journal.snapshot()[GUARD]["pending"])
        return _reply("responses", stream=streaming)

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
        http_client=DefaultAsyncHttpxClient(
            transport=httpx.MockTransport(respond),
            headers={"x-lyra-request-id": "spoofed", "x-lyra-scan-id": "foreign-scan"},
        ),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(model="openai/gpt-6-luna", max_budget_usd=1)
        result = await _run(_model("responses", client), streaming=streaming, hooks=hooks)
        assert result.final_output == "OK"
        assert len(requests) == 1
        assert requests[0].headers["x-lyra-scan-id"] == hooks._journal.snapshot()[GUARD]["run_id"]
        assert re.fullmatch(r"[a-f0-9]{32}:[1-9][0-9]*", requests[0].headers["x-lyra-request-id"])
        assert pending_ids == [requests[0].headers["x-lyra-request-id"]]


@pytest.mark.asyncio
async def test_gateway_does_not_require_the_host_run_id_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("STRIX_RUN_ID", raising=False)
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["x-lyra-scan-id"])
        return _reply("responses", stream=False)

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(model="openai/gpt-6-luna", max_budget_usd=1)
        await _run(_model("responses", client), streaming=False, hooks=hooks)
        assert seen == [hooks._journal.snapshot()[GUARD]["run_id"]]


@pytest.mark.asyncio
async def test_concurrent_admissions_bind_each_durable_owner(tmp_path) -> None:
    states = [ReportState("scan-alpha"), ReportState("scan-beta")]
    for state in states:
        state._run_dir = tmp_path / state.run_id
    owners = [state.enable_finite_budget(1) for state in states]
    attempts = [owner.reserve(0.1) for owner in owners]

    async def admit(index: int) -> tuple[str, str]:
        with durable_physical_admission(owners[index], attempts[index]):
            await asyncio.sleep(0)
            attempt, scan_id = _authorize_durable(None)
            headers = httpx.Headers({"x-lyra-scan-id": "spoofed"})
            _set_gateway_headers(headers, gateway_enabled=True, scan_id=scan_id, attempt=attempt)
            return headers["x-lyra-scan-id"], headers["x-lyra-request-id"]

    try:
        assert await asyncio.gather(admit(0), admit(1)) == [
            ("scan-alpha", attempts[0]),
            ("scan-beta", attempts[1]),
        ]
    finally:
        for owner in owners:
            owner.close()


@pytest.mark.parametrize("origin", ["http://remote.invalid", "http://10.0.0.3", "http://localhost"])
def test_remote_cleartext_gateway_is_rejected(monkeypatch, origin: str) -> None:
    monkeypatch.setenv("LYRASHIELD_PROVIDER_GATEWAY_ORIGIN", origin)
    with pytest.raises(PhysicalBudgetAdapterError, match="gateway identity or endpoint"):
        _gateway_enabled(httpx.URL(origin + "/v1/provider/azure-ai/openai/v1/responses"))


@pytest.mark.parametrize(
    "origin", ["http://127.0.0.1:8791", "http://[::1]:8791", "https://gateway.invalid"]
)
def test_gateway_accepts_secure_or_explicit_loopback_origin(monkeypatch, origin: str) -> None:
    monkeypatch.setenv("LYRASHIELD_PROVIDER_GATEWAY_ORIGIN", origin)
    assert _gateway_enabled(httpx.URL(origin + "/v1/provider/azure-ai/openai/v1/responses"))


@pytest.mark.asyncio
async def test_runner_rejects_scan_that_disagrees_with_durable_owner() -> None:
    state = ReportState("scan-owner")
    with pytest.raises(RuntimeError, match="does not match its durable owner"):
        await run_strix_scan(
            scan_config={}, scan_id="foreign-scan", image="unused", artifact_state=state
        )


@pytest.mark.asyncio
async def test_runner_uses_durable_owner_when_scan_id_is_not_supplied(monkeypatch) -> None:
    state = ReportState("scan-owner")

    def capture_scan_id(**kwargs):
        assert kwargs["scan_id"] == state.run_id
        raise RuntimeError("captured owner")

    monkeypatch.setattr("lyrashield.lifecycle.runner.create_scan_paths", capture_scan_id)
    with pytest.raises(RuntimeError, match="captured owner"):
        await run_strix_scan(scan_config={}, image="unused", artifact_state=state)


@pytest.mark.asyncio
async def test_lost_gateway_ack_does_not_replay_and_retains_budget_hold(tmp_path) -> None:
    requests: list[httpx.Request] = []

    def lost_response(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise httpx.ReadTimeout("synthetic lost response", request=request)

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(lost_response)),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(model="openai/gpt-6-luna", max_budget_usd=1)
        with pytest.raises(PhysicalBudgetAdapterError, match="reconcile before retry"):
            await _run(_model("responses", client), streaming=False, hooks=hooks)
        assert len(requests) == 1
        assert hooks._journal.snapshot()[GUARD]["pending"]


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_missing_terminal_usage_retains_hold_without_retry(tmp_path, streaming: bool) -> None:
    requests: list[httpx.Request] = []

    def no_usage(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _reply("responses", stream=streaming, usage=False)

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(no_usage)),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(model="openai/gpt-6-luna", max_budget_usd=1)
        with pytest.raises(PhysicalBudgetAdapterError, match="reconcile before retry"):
            await _run(_model("responses", client), streaming=streaming, hooks=hooks)
        assert len(requests) == 1
        assert hooks._journal.snapshot()[GUARD]["pending"]


@pytest.mark.asyncio
async def test_interrupted_gateway_stream_retains_hold_without_retry(tmp_path) -> None:
    requests: list[httpx.Request] = []

    class Interrupted(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b": heartbeat\n\n"
            raise httpx.ReadError("synthetic interrupted stream")

    def interrupted(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=Interrupted()
        )

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(interrupted)),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(model="openai/gpt-6-luna", max_budget_usd=1)
        with pytest.raises(PhysicalBudgetAdapterError, match="reconcile before retry"):
            await _run(_model("responses", client), streaming=True, hooks=hooks)
        assert len(requests) == 1
        assert hooks._journal.snapshot()[GUARD]["pending"]


@pytest.mark.asyncio
async def test_gateway_mode_rejects_foreign_provider_endpoint(tmp_path) -> None:
    calls: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _reply("responses", stream=False)

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://foreign.invalid/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(model="openai/gpt-6-luna", max_budget_usd=1)
        with pytest.raises(PhysicalBudgetAdapterError, match="gateway identity or endpoint"):
            await _run(_model("responses", client), streaming=False, hooks=hooks)
        assert calls == []
