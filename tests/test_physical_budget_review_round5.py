"""Final-byte and destination snapshots must survive untrusted stream callbacks."""

from __future__ import annotations

import json

import httpx
import pytest
from openai import APIConnectionError, AsyncOpenAI, DefaultAsyncHttpxClient

from lyrashield.artifacts import state as state_module
from lyrashield.lifecycle import hooks as durable_hooks_module
from lyrashield.lifecycle.hooks import ReportUsageHooks
from lyrashield.policy.physical_requests import PhysicalBudgetAdapterError
from tests.finite_budget_fixtures import owned_hooks
from tests.test_physical_budget_boundaries import _model, _reply, _run


@pytest.fixture(autouse=True)
def _durable_wire_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(durable_hooks_module, "_active_hooks", None)
    monkeypatch.setitem(globals(), "ReportUsageHooks", owned_hooks(ReportUsageHooks, tmp_path))


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["iterate", "close"])
@pytest.mark.parametrize("field", ["destination", "method", "headers", "sni"])
async def test_body_callbacks_cannot_rewrite_the_admitted_request(monkeypatch, stage, field):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    received = []

    async def request_hook(request):
        original = request.content

        def mutate():
            if field == "destination":
                request.url = httpx.URL("https://different.invalid/other")
                request.headers["host"] = "different.invalid"
            elif field == "method":
                request.method = "DELETE"
            elif field == "headers":
                request.headers["authorization"] = "Bearer altered"
            else:
                request.extensions["sni_hostname"] = "different.invalid"

        class MutatingStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                if stage == "iterate":
                    mutate()
                yield original

            async def aclose(self):
                if stage == "close":
                    mutate()

        request.stream = MutatingStream()

    class ConsumingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            body = b"".join([part async for part in request.stream])
            received.append(str(request.url))
            assert str(request.url) == "https://admitted.invalid/v1/responses"
            assert request.method == "POST"
            assert request.headers["host"] == "admitted.invalid"
            assert request.headers["authorization"] == "Bearer offline"
            assert request.extensions.get("sni_hostname") is None
            assert json.loads(body)["max_output_tokens"] == 128
            return _reply("responses", stream=False)

    async with AsyncOpenAI(
        api_key="offline",
        base_url="https://admitted.invalid/v1",
        http_client=DefaultAsyncHttpxClient(
            transport=ConsumingTransport(), event_hooks={"request": [request_hook]}
        ),
    ) as client:
        result = await _run(
            _model("responses", client),
            streaming=False,
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
        )
    assert result.final_output == "OK"
    assert len(received) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["responses", "chat"])
@pytest.mark.parametrize("shape", ["high-first", "high-last", "nested", "escaped-nested"])
async def test_ambiguous_duplicate_json_members_never_reach_transport(monkeypatch, api, shape):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    received = []

    async def request_hook(request):
        payload = json.loads(request.content)
        key = next(
            key
            for key in ("max_output_tokens", "max_completion_tokens", "max_tokens")
            if key in payload
        )
        if shape.startswith("high-"):
            payload[key] = 999 if shape == "high-first" else 128
            last = 128 if shape == "high-first" else 999
            body = json.dumps(payload, separators=(",", ":")).encode()
            body = body[:-1] + f',"{key}":{last}}}'.encode()
        else:
            body = json.dumps(payload, separators=(",", ":")).encode()
            duplicate = b'"role":"system","role":"user"'
            if shape == "escaped-nested":
                duplicate = b'"\\u0072ole":"system","role":"user"'
            assert b'"role":"user"' in body
            body = body.replace(b'"role":"user"', duplicate, 1)
        request.stream = httpx.ByteStream(body)

    def respond(request):
        received.append(request)
        return _reply(api, stream=False)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(
            transport=httpx.MockTransport(respond), event_hooks={"request": [request_hook]}
        ),
    ) as client:
        with pytest.raises(APIConnectionError) as caught:
            await _run(
                _model(api, client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
        assert isinstance(caught.value.__cause__, PhysicalBudgetAdapterError)
    assert received == []


@pytest.mark.asyncio
async def test_duplicate_looking_text_is_ordinary_metadata(monkeypatch):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(
            transport=httpx.MockTransport(lambda _request: _reply("responses", stream=False))
        ),
    ) as client:
        result = await _run(
            _model("responses", client),
            streaming=False,
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            extra_body={"metadata": {"note": '{"same":1,"same":2}'}},
        )
    assert result.final_output == "OK"
