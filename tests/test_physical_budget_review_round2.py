"""Frozen SDK regression cases from the second physical-budget review."""

from __future__ import annotations

import asyncio
import gzip
import json
import time
import tracemalloc
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import litellm
import pytest
from agents import Agent, RunConfig, Runner
from agents.extensions.models.litellm_model import LitellmModel
from agents.models._retry_runtime import should_disable_provider_managed_retries
from agents.models.interface import ModelTracing
from agents.models.openai_responses import OpenAIResponsesWSModel
from agents.retry import ModelRetryBackoffSettings
from openai import APIConnectionError, AsyncOpenAI, DefaultAsyncHttpxClient

from lyrashield.artifacts import state as state_module
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.models import _RequestBoundTurnGuardModel
from lyrashield.policy.physical_requests import PhysicalBudgetAdapterError, _UsageEvidence
from tests.test_physical_budget_boundaries import _ByteChunks, _model, _payload, _reply, _run


@pytest.mark.asyncio
@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("api", ["responses", "chat"])
@pytest.mark.parametrize("streaming", [False, True])
async def test_digest_auth_cannot_replay_generation_under_one_quote(
    monkeypatch, api, streaming, bounded
):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    bodies = []

    def respond(request):
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(
                401,
                headers={
                    "www-authenticate": (
                        'Digest realm="fixture", nonce="nonce", qop="auth", algorithm=MD5'
                    )
                },
            )
        return _reply(api, streaming)

    http = DefaultAsyncHttpxClient(
        transport=httpx.MockTransport(respond), auth=httpx.DigestAuth("fixture", "secret")
    )
    original_auth = http.auth
    async with AsyncOpenAI(api_key="offline", http_client=http) as client:
        request = _run(
            _model(api, client),
            streaming=streaming,
            bounded=bounded,
            hooks=ReportUsageHooks(
                model="openai/gpt-6-luna", max_budget_usd=1 if bounded else None
            ),
        )
        if bounded:
            with pytest.raises((APIConnectionError, PhysicalBudgetAdapterError)):
                await request
        else:
            assert (await request).final_output == "OK"
        assert http.auth is original_auth
        assert http.follow_redirects is True
    assert len(bodies) == (1 if bounded else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("streaming", [False, True])
async def test_finite_websocket_is_rejected_before_connect_or_frame(
    monkeypatch, streaming, bounded
):
    frames = []

    class Socket:
        async def send(self, data):
            frames.append(json.loads(data))

        async def recv(self):
            return json.dumps(
                {
                    "type": "response.completed",
                    "sequence_number": 0,
                    "response": _payload("responses", usage=True),
                }
            )

        async def close(self, **_kwargs):
            pass

    connected = AsyncMock(return_value=Socket())
    monkeypatch.setattr(OpenAIResponsesWSModel, "_open_websocket_connection", connected)
    async with AsyncOpenAI(api_key="offline") as client:
        model = _RequestBoundTurnGuardModel(OpenAIResponsesWSModel("gpt-6-luna", client))
        request = _run(
            model,
            streaming=streaming,
            bounded=bounded,
            hooks=ReportUsageHooks(
                model="openai/gpt-6-luna", max_budget_usd=1 if bounded else None
            ),
            extra_body={"max_output_tokens": 400000},
        )
        if bounded:
            with pytest.raises(PhysicalBudgetAdapterError, match="WebSocket"):
                await request
        else:
            assert (await request).final_output == "OK"
    if bounded:
        assert frames == []
        connected.assert_not_called()
    else:
        assert len(frames) == 1
        assert frames[0]["max_output_tokens"] == 400000
        connected.assert_awaited_once()


def _chat_stream(*, interim: bool, final: bool):
    event = {
        "id": "c",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "gpt-6-luna",
        "choices": [],
    }
    prefix = ""
    if interim:
        prefix = (
            "data: "
            + json.dumps(
                {**event, "usage": {"prompt_tokens": 8, "completion_tokens": 0, "total_tokens": 8}}
            )
            + "\n\n"
        )
    content = _reply("chat", stream=True).content
    if final:
        final_event = (
            "data: "
            + json.dumps(
                {**event, "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}}
            )
            + "\n\n"
        )
        content = content.replace(b"data: [DONE]", final_event.encode() + b"data: [DONE]")
    return prefix.encode() + content


@pytest.mark.asyncio
@pytest.mark.parametrize("final", [False, True])
async def test_only_terminal_chat_usage_can_reconcile_a_quote(monkeypatch, final):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _m: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _m: (0, 0, 0, 4687.5))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_ByteChunks(_chat_stream(interim=True, final=final)),
        )

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model("chat", client)
        await _run(model, streaming=True, hooks=hooks)
        if final:
            await _run(model, streaming=True, hooks=hooks)
        else:
            with pytest.raises(BudgetExceededError):
                await _run(model, streaming=True, hooks=hooks)
    assert calls == (2 if final else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("stateful", [False, True])
async def test_uncapped_litellm_native_retry_suppression_is_not_a_budget(monkeypatch, stateful):
    calls = 0
    retry_flags = []

    async def complete(**_kwargs):
        nonlocal calls
        calls += 1
        retry_flags.append(should_disable_provider_managed_retries())
        if calls == 1 and not stateful:
            raise APIConnectionError(request=httpx.Request("POST", "https://offline.invalid"))
        return litellm.ModelResponse(**_payload("chat", usage=True))

    monkeypatch.setattr(litellm, "acompletion", complete)
    model = _RequestBoundTurnGuardModel(LitellmModel("openrouter/fixture", api_key="offline"))
    agent = Agent(
        name="Root",
        model=model,
        model_settings=make_model_settings(None, model_name="openrouter/fixture"),
    )
    agent.model_settings.retry = replace(
        agent.model_settings.retry,
        backoff=ModelRetryBackoffSettings(initial_delay=0, max_delay=0, jitter=False),
    )
    result = await Runner.run(
        agent,
        "offline",
        previous_response_id="prior" if stateful else None,
        run_config=RunConfig(tracing_disabled=True),
    )
    assert result.final_output == "OK"
    assert calls == (1 if stateful else 2)
    assert retry_flags == ([True] if stateful else [False, True])


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["responses", "chat"])
@pytest.mark.parametrize("streaming", [False, True])
async def test_compressed_valid_usage_is_observed_after_normal_decoding(
    monkeypatch, api, streaming
):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    raw = (
        _chat_stream(interim=False, final=True)
        if api == "chat" and streaming
        else _reply(api, streaming).content
    )
    compressed = gzip.compress(raw)

    def respond(_request):
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-type": "text/event-stream" if streaming else "application/json",
            },
            stream=_ByteChunks(compressed),
        )

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        result = await _run(
            _model(api, client),
            streaming=streaming,
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
        )
    assert result.final_output == "OK"
    usage = result.raw_responses[0].usage
    assert (usage.input_tokens, usage.output_tokens) == (8, 2)


@pytest.mark.parametrize("sse", [False, True])
def test_usage_observer_rejects_oversized_chunk_before_copy(sse):
    observer = _UsageEvidence(sse=sse)
    observer.feed(b"data: " + b"x" * 60)
    chunk = b"x" * (8 * 1024 * 1024)
    tracemalloc.start()
    baseline, _peak = tracemalloc.get_traced_memory()
    observer.feed(chunk)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak - baseline < 256 * 1024
    assert not observer.reported


def test_usage_observer_blank_lines_have_bounded_linear_work():
    observer = _UsageEvidence(sse=True)
    started = time.perf_counter()
    observer.feed(b"\n" * 262144)
    assert time.perf_counter() - started < 0.2
    assert not observer.reported


@pytest.mark.asyncio
async def test_cancelled_decoded_stream_closes_underlying_transport():
    waiting = asyncio.Event()
    closed = asyncio.Event()

    class BlockingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield (
                b"data: "
                + json.dumps(
                    {
                        "id": "c",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "gpt-6-luna",
                        "choices": [
                            {"index": 0, "delta": {"content": "OK"}, "finish_reason": None}
                        ],
                    }
                ).encode()
                + b"\n\n"
            )
            waiting.set()
            await asyncio.Event().wait()

        async def aclose(self):
            closed.set()

    def respond(_request):
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=BlockingStream()
        )

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model("chat", client)

        async def drain():
            async for _event in model.stream_response(
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
            ):
                pass

        task = asyncio.create_task(drain())
        await asyncio.wait_for(waiting.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(closed.wait(), 2)


def test_finite_identity_survives_settings_resolution_without_entering_wire_args():
    settings = make_model_settings(
        "medium", model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
    )
    resolved = settings.resolve({"temperature": 0.5})
    assert resolved._lyrashield_finite_budget is True
    assert "_lyrashield_finite_budget" not in json.dumps(resolved.to_json_dict())
    assert resolved.extra_args is None


@pytest.mark.asyncio
async def test_finite_http_keeps_resolved_auth_hooks_mount_and_endpoint(monkeypatch):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    received = []

    async def request_hook(request):
        request.headers["x-existing-hook"] = "retained"

    def sealed_default(_request):
        raise AssertionError("The resolved URL mount must remain authoritative")

    def respond(request):
        received.append(request)
        return _reply("responses", stream=False)

    resolved = httpx.MockTransport(respond)
    auth = httpx.BasicAuth("fixture", "secret")
    http = DefaultAsyncHttpxClient(
        transport=httpx.MockTransport(sealed_default),
        mounts={"https://bound.invalid": resolved},
        auth=auth,
        event_hooks={"request": [request_hook]},
    )
    async with AsyncOpenAI(
        api_key="offline", base_url="https://bound.invalid/v1", http_client=http
    ) as client:
        result = await _run(
            _model("responses", client),
            streaming=False,
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
        )
        assert result.final_output == "OK"
        assert http.auth is auth
        assert http.event_hooks["request"] == [request_hook]
    assert len(received) == 1
    request = received[0]
    assert str(request.url) == "https://bound.invalid/v1/responses"
    assert request.headers["authorization"].startswith("Basic ")
    assert request.headers["x-existing-hook"] == "retained"
    assert json.loads(request.content)["max_output_tokens"] == 128


@pytest.mark.asyncio
async def test_generation_after_final_chat_usage_requires_new_final_receipt(monkeypatch):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _m: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _m: (0, 0, 0, 4687.5))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    content = _chat_stream(interim=False, final=True).replace(
        b"data: [DONE]", _reply("chat", stream=True).content
    )
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=_ByteChunks(content)
        )

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model("chat", client)
        await _run(model, streaming=True, hooks=hooks)
        with pytest.raises(BudgetExceededError):
            await _run(model, streaming=True, hooks=hooks)
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("compressed", [False, True])
async def test_terminal_chat_reported_zero_usage_remains_evidenced(monkeypatch, compressed):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _m: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _m: (0, 0, 0, 4687.5))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    content = _chat_stream(interim=False, final=True).replace(
        b'"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10',
        b'"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0',
    )
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        headers = {"content-type": "text/event-stream"}
        if compressed:
            headers["content-encoding"] = "gzip"
        return httpx.Response(
            200,
            headers=headers,
            stream=_ByteChunks(gzip.compress(content) if compressed else content),
        )

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        for _attempt in range(2):
            await _run(_model("chat", client), streaming=True, hooks=hooks)
    assert calls == 2
    assert not hooks._agent_abandoned_floors
    assert not hooks._agent_reservations
