"""Fourth-review proofs: receipt identity, sent bytes, routing and raw pricing."""

from __future__ import annotations

import asyncio
import json
from importlib import import_module
from types import SimpleNamespace

import httpx
import pytest
from agents.models.openai_responses import OpenAIResponsesModel
from openai import APIConnectionError, AsyncAzureOpenAI, AsyncOpenAI, DefaultAsyncHttpxClient
from openai._models import construct_type
from openai.types.responses import Response

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.artifacts.usage import extract_provider_usage
from lyrashield.interface import warmup
from lyrashield.lifecycle import hooks as durable_hooks_module
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.policy.models import _RequestBoundTurnGuardModel
from lyrashield.policy.physical_requests import PhysicalBudgetAdapterError, _UsageEvidence
from lyrashield.policy.settings import LlmSettings, Settings
from tests.finite_budget_fixtures import owned_hooks
from tests.test_physical_budget_boundaries import _ByteChunks, _model, _payload, _reply, _run
from tests.test_physical_budget_review_round2 import _chat_stream


@pytest.fixture(autouse=True)
def _durable_wire_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(durable_hooks_module, "_active_hooks", None)
    monkeypatch.setitem(globals(), "ReportUsageHooks", owned_hooks(ReportUsageHooks, tmp_path))


@pytest.mark.asyncio
@pytest.mark.parametrize("identity", [None, "", 42, "foreign"])
async def test_terminal_usage_must_report_its_own_identity(monkeypatch, identity):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _m: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _m: (0, 0, 0, 4687.5))
    content = _chat_stream(interim=False, final=True).replace(
        b'"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10',
        b'"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0',
    )
    lines = content.decode().splitlines()
    for index, line in enumerate(lines):
        if '"usage"' in line:
            value = json.loads(line[6:])
            if identity is None:
                value.pop("id")
            else:
                value["id"] = identity
            lines[index] = "data: " + json.dumps(value)
    content = ("\n".join(lines) + "\n").encode()
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=_ByteChunks(content)
        )

    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model("chat", client)
        result = await _run(model, streaming=True, hooks=hooks)
        assert result.final_output == "OK"
        assert result.raw_responses[0].usage.requests == 0
        with pytest.raises(BudgetExceededError):
            await _run(model, streaming=True, hooks=hooks)
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("replace_cap", [False, True])
async def test_actual_request_stream_is_validated_and_frozen(monkeypatch, replace_cap):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    sent = []

    async def request_hook(request):
        # Keep Request._content untouched: aread() would return stale bytes.
        cached = request.content
        if replace_cap:
            changed = cached.replace(b"128", b"999")
            assert len(changed) == len(cached)
        else:
            changed = json.dumps(json.loads(cached), indent=2).encode()
        request.stream = httpx.ByteStream(changed)

    class ConsumingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            actual = b"".join([chunk async for chunk in request.stream])
            sent.append((actual, request.headers))
            assert int(request.headers["content-length"]) == len(actual)
            assert "transfer-encoding" not in request.headers
            assert json.loads(actual)["max_output_tokens"] == 128
            return _reply("responses", stream=False)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(
            transport=ConsumingTransport(), event_hooks={"request": [request_hook]}
        ),
    ) as client:
        request = _run(
            _model("responses", client),
            streaming=False,
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
        )
        if replace_cap:
            with pytest.raises(APIConnectionError) as caught:
                await request
            assert isinstance(caught.value.__cause__, PhysicalBudgetAdapterError)
        else:
            assert (await request).final_output == "OK"
    assert len(sent) == (0 if replace_cap else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "api,extra",
    [
        ("chat", {"models": ["gpt-6-sol"], "route": "fallback"}),
        ("responses", {"provider": {"order": ["other"]}}),
    ],
)
async def test_unknown_routing_body_fields_are_not_qualified(monkeypatch, api, extra):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return _reply(api, stream=False)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        with pytest.raises(APIConnectionError) as caught:
            await _run(
                _model(api, client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
                extra_body=extra,
            )
        assert isinstance(caught.value.__cause__, PhysicalBudgetAdapterError)
    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["origin", "path", "query", "host", "sni"])
async def test_post_hook_destination_cannot_escape_admitted_endpoint(monkeypatch, change):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    received = []

    async def request_hook(request):
        if change == "origin":
            request.url = httpx.URL("https://different.invalid/another-deployment/chat/completions")
        elif change == "path":
            request.url = request.url.copy_with(path="/another-deployment/chat/completions")
        elif change == "query":
            request.url = request.url.copy_merge_params({"deployment": "sol"})
        elif change == "host":
            request.headers["host"] = "different.invalid"
        else:
            request.extensions["sni_hostname"] = "different.invalid"

    def respond(request):
        received.append((str(request.url), request.headers.get("authorization")))
        return _reply("chat", stream=False)

    async with AsyncOpenAI(
        api_key="synthetic-bearer",
        base_url="https://admitted.invalid/v1",
        http_client=DefaultAsyncHttpxClient(
            transport=httpx.MockTransport(respond), event_hooks={"request": [request_hook]}
        ),
    ) as client:
        with pytest.raises(APIConnectionError) as caught:
            await _run(
                _model("chat", client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
        assert isinstance(caught.value.__cause__, PhysicalBudgetAdapterError)
    assert received == []


def _cache_payload(explicit):
    body = _payload("responses", usage=True)
    body["model"] = "gpt-6-sol"
    body["usage"] = {"input_tokens": 100000, "output_tokens": 0, "total_tokens": 100000}
    if explicit:
        body["usage"]["input_tokens_details"] = {"cached_tokens": 0, "cache_write_tokens": 0}
    return body


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
async def test_raw_cache_write_absence_keeps_conservative_settlement(
    monkeypatch, streaming, explicit
):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_estimate_input_tokens", lambda *_args: 100000)

    def respond(_request):
        if streaming:
            data = (
                "data: "
                + json.dumps(
                    {
                        "type": "response.completed",
                        "sequence_number": 0,
                        "response": _cache_payload(explicit),
                    }
                )
                + "\n\ndata: [DONE]\n\n"
            )
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_ByteChunks(data.encode()),
            )
        return httpx.Response(200, json=_cache_payload(explicit))

    hooks = ReportUsageHooks(model="openai/gpt-6-sol", max_budget_usd=1)
    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _RequestBoundTurnGuardModel(OpenAIResponsesModel("gpt-6-sol", client))
        result = await _run(model, streaming=streaming, hooks=hooks)
    assert result.raw_responses[0].usage.input_tokens == 100000
    assert hooks._committed_cost_floor == pytest.approx(0.2 if explicit else 0.25)


@pytest.mark.parametrize("explicit", [False, True])
def test_preflight_cache_price_bound_survives_receipt_hydration(tmp_path, monkeypatch, explicit):
    main = import_module("lyrashield.interface.main")
    monkeypatch.setattr(state_module, "run_dir_for", lambda _name: tmp_path)
    monkeypatch.setattr(state_module, "_global_report_state", None)
    settings = Settings(
        _env_file=None, llm=LlmSettings(_env_file=None, model="openai/gpt-6-sol", api_key="offline")
    )
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(warmup, "_estimate_out_of_band_input_tokens", lambda *_args: 100000)
    client = AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json=_cache_payload(explicit))
            )
        ),
    )
    model = _RequestBoundTurnGuardModel(OpenAIResponsesModel("gpt-6-sol", client))
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kw: SimpleNamespace(get_model=lambda _name: model)
    )
    args = SimpleNamespace(run_name="raw-cache", resume=False, max_budget_usd=1, warm_up_usages=[])
    try:
        main._run_llm_preflight(args, deadline=None)
        state = args._preflight_usage_owner
        assert state.get_total_llm_cost() > 0
        restored = ReportState("raw-cache")
        restored.hydrate_from_run_dir()
        assert restored.get_total_llm_cost() == pytest.approx(0.2 if explicit else 0.25)
    finally:
        asyncio.run(client.close())


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["responses", "chat"])
@pytest.mark.parametrize("deployment", [None, "gpt-6-luna"])
async def test_admitted_azure_resource_paths_keep_native_sdk_semantics(
    monkeypatch, api, deployment
):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    received = []

    def respond(request):
        received.append(str(request.url))
        assert request.url.params["api-version"] == "2026-01-01"
        return _reply(api, stream=False)

    async with AsyncAzureOpenAI(
        api_key="offline",
        azure_endpoint="https://azure.invalid/region",
        azure_deployment=deployment,
        api_version="2026-01-01",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        result = await _run(
            _model(api, client),
            streaming=False,
            hooks=ReportUsageHooks(model="azure/gpt-6-luna", max_budget_usd=1),
        )
    assert result.final_output == "OK"
    assert len(received) == 1


def test_unknown_cache_placeholder_is_not_a_provider_bucket_receipt():
    payload = _cache_payload(explicit=False)
    evidence = _UsageEvidence(sse=False)
    evidence.feed(json.dumps(payload).encode())
    evidence.finish()
    response = construct_type(type_=Response, value=payload)
    assert evidence.matches(response)
    assert response.usage.input_tokens_details is not None
    assert extract_provider_usage(response) is None


@pytest.mark.parametrize("cached,write", [(-1, 0), (100001, 0), (1, 100000)])
def test_malformed_cache_buckets_cannot_discount_the_input_bound(cached, write):
    payload = _cache_payload(explicit=True)
    payload["usage"]["input_tokens_details"] = {
        "cached_tokens": cached,
        "cache_write_tokens": write,
    }
    evidence = _UsageEvidence(sse=False)
    evidence.feed(json.dumps(payload).encode())
    evidence.finish()
    response = construct_type(type_=Response, value=payload)
    assert evidence.matches(response)
    assert hooks_module._usage_cost_upper_bound("openai/gpt-6-sol", response.usage) == 0.25
    assert extract_provider_usage(response) is None
