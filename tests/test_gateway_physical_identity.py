"""The controlled gateway receives durable scan-bound physical request identities."""

from __future__ import annotations

import asyncio
import re

import httpx
import pytest
from openai import AsyncOpenAI, DefaultAsyncHttpxClient

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.finite_budget import GUARD
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import ReportUsageHooks
from lyrashield.policy.physical_requests import PhysicalBudgetAdapterError, _gateway_scan_id
from tests.finite_budget_fixtures import owned_hooks
from tests.test_physical_budget_boundaries import _model, _reply, _run


@pytest.fixture(autouse=True)
def gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hooks_module, "_active_hooks", None)
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setenv("LYRASHIELD_PROVIDER_GATEWAY_ORIGIN", "https://gateway.invalid")
    monkeypatch.setenv("STRIX_RUN_ID", "foreign-host-scan")


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_gateway_uses_durable_attempt_identity(tmp_path, streaming: bool) -> None:
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _reply("responses", stream=streaming)

    async with AsyncOpenAI(
        api_key="synthetic-grant",
        base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
        http_client=DefaultAsyncHttpxClient(
            transport=httpx.MockTransport(respond),
            headers={"x-lyra-request-id": "spoofed", "x-lyra-scan-id": "foreign-scan"},
        ),
    ) as client:
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(
            model="openai/gpt-6-luna", max_budget_usd=1, scan_id="scan-fixture-1"
        )
        result = await _run(_model("responses", client), streaming=streaming, hooks=hooks)
        assert result.final_output == "OK"
        assert len(requests) == 1
        assert requests[0].headers["x-lyra-scan-id"] == "scan-fixture-1"
        assert re.fullmatch(r"[a-f0-9]{32}:[1-9][0-9]*", requests[0].headers["x-lyra-request-id"])


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
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(
            model="openai/gpt-6-luna", max_budget_usd=1, scan_id="scan-fixture-1"
        )
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
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(
            model="openai/gpt-6-luna", max_budget_usd=1, scan_id="scan-fixture-1"
        )
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
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(
            model="openai/gpt-6-luna", max_budget_usd=1, scan_id="scan-fixture-1"
        )
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
        hooks = owned_hooks(ReportUsageHooks, tmp_path)(
            model="openai/gpt-6-luna", max_budget_usd=1, scan_id="scan-fixture-1"
        )
        with pytest.raises(PhysicalBudgetAdapterError, match="gateway identity or endpoint"):
            await _run(_model("responses", client), streaming=False, hooks=hooks)
        assert calls == []


@pytest.mark.parametrize(
    ("origin", "allowed"),
    [
        ("http://gateway.invalid", False),
        ("http://localhost", False),
        ("http://127.0.0.1", True),
        ("http://[::1]", True),
        ("https://gateway.invalid", True),
    ],
)
def test_gateway_origin_transport_policy(monkeypatch, origin, allowed):
    monkeypatch.setenv("LYRASHIELD_PROVIDER_GATEWAY_ORIGIN", origin)
    endpoint = httpx.URL(origin + "/v1/provider/azure-ai/openai/v1/responses")
    if allowed:
        assert _gateway_scan_id(endpoint, "active-scan") == "active-scan"
    else:
        with pytest.raises(PhysicalBudgetAdapterError, match="gateway identity or endpoint"):
            _gateway_scan_id(endpoint, "active-scan")


@pytest.mark.parametrize("scan_id", [None, "", "bad scan", "x"])
def test_gateway_requires_active_scan_identity(scan_id):
    with pytest.raises(PhysicalBudgetAdapterError, match="gateway identity or endpoint"):
        _gateway_scan_id(
            httpx.URL("https://gateway.invalid/v1/provider/azure-ai/openai/v1/responses"),
            scan_id,
        )


@pytest.mark.asyncio
async def test_concurrent_gateway_scans_keep_their_own_identity(tmp_path):
    async def run_scan(scan_id):
        requests = []

        def respond(request):
            requests.append(request)
            return _reply("responses", stream=False)

        async with AsyncOpenAI(
            api_key="synthetic-grant",
            base_url="https://gateway.invalid/v1/provider/azure-ai/openai/v1",
            http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
        ) as client:
            hooks = owned_hooks(ReportUsageHooks, tmp_path)(
                model="openai/gpt-6-luna", max_budget_usd=1, scan_id=scan_id
            )
            await asyncio.sleep(0)
            await _run(_model("responses", client), streaming=False, hooks=hooks)
            assert len(requests) == 1
            assert requests[0].headers["x-lyra-scan-id"] == scan_id

    await asyncio.gather(run_scan("scan-first"), run_scan("scan-second"))
