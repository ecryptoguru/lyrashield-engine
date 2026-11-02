"""Wire authority and session-state cases from the third budget review."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from agents import Agent, RunConfig, Runner, function_tool
from openai import APIConnectionError, AsyncOpenAI, DefaultAsyncHttpxClient
from pydantic import BaseModel

from lyrashield.artifacts import state as state_module
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.physical_requests import PhysicalBudgetAdapterError
from tests.test_physical_budget_boundaries import _ByteChunks, _model, _reply, _run
from tests.test_physical_budget_review_round2 import _chat_stream


def _sse_chunk(content):
    events = []
    for line in content.decode().splitlines():
        if not line.startswith("data: {"):
            continue
        data = line[6:]
        first, rest = data.split(",", 1)
        events.append(f"data: {first},\ndata: {rest}\n\n")
    return "".join(events).encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("fragmented", [False, True])
@pytest.mark.parametrize("shape", ["multiline", "after_done"])
async def test_only_sdk_consumed_sse_usage_can_release_quote(monkeypatch, shape, fragmented):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _m: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _m: (0, 0, 0, 4687.5))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    if shape == "multiline":
        content = _chat_stream(interim=False, final=True).replace(b"data: [DONE]\n\n", b"")
        content += _sse_chunk(_reply("chat", stream=True).content) + b"data: [DONE]\n\n"
    else:
        event = {
            "id": "c",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-6-luna",
            "choices": [],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10},
        }
        content = _chat_stream(interim=True, final=False)
        content += ("data: " + json.dumps(event) + "\n\n").encode()
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        kwargs = {"stream": _ByteChunks(content)} if fragmented else {"content": content}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, **kwargs)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model("chat", client)
        result = await _run(model, streaming=True, hooks=hooks)
        assert result.final_output == ("OKOK" if shape == "multiline" else "OK")
        assert result.raw_responses[0].usage.requests == 0
        with pytest.raises(BudgetExceededError):
            await _run(model, streaming=True, hooks=hooks)
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("seam", ["extra_body", "client_default"])
@pytest.mark.parametrize(
    "api,mutation",
    [
        ("responses", {"model": "gpt-6-sol"}),
        ("chat", {"n": 4}),
        ("responses", {"input": "x" * 200000}),
        ("chat", {"messages": [{"role": "user", "content": "x" * 200000}]}),
        ("responses", {"instructions": "x" * 200000}),
    ],
)
async def test_final_wire_charge_fields_cannot_escape_quote(monkeypatch, seam, api, mutation):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return _reply(api, stream=False)

    class DefaultBodyClient(AsyncOpenAI):
        def _build_request(self, options, *, retries_taken=0):
            request = super()._build_request(options, retries_taken=retries_taken)
            payload = {**json.loads(request.content), **mutation}
            headers = [(k, v) for k, v in request.headers.raw if k.lower() != b"content-length"]
            return httpx.Request(
                request.method,
                request.url,
                headers=headers,
                json=payload,
                extensions=request.extensions,
            )

    client_type = DefaultBodyClient if seam == "client_default" else AsyncOpenAI
    async with client_type(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        with pytest.raises((PhysicalBudgetAdapterError, APIConnectionError)) as caught:
            await _run(
                _model(api, client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
                extra_body=mutation if seam == "extra_body" else None,
            )
        assert isinstance(caught.value, PhysicalBudgetAdapterError) or isinstance(
            caught.value.__cause__, PhysicalBudgetAdapterError
        )
    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("delete", [False, True])
@pytest.mark.parametrize("bounded", [False, True])
async def test_gateway_cookie_rotation_and_deletion_survive_finite_calls(
    monkeypatch, delete, bounded
):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    received = []

    def respond(request):
        received.append(request.headers.get("cookie"))
        expected = [None, "affinity=new", None if delete else "affinity=next"]
        assert received[-1] == expected[len(received) - 1]
        response = _reply("responses", stream=False)
        if len(received) == 1:
            response.headers["set-cookie"] = "affinity=new; Path=/; Secure"
        elif len(received) == 2:
            response.headers["set-cookie"] = (
                "affinity=; Max-Age=0; Path=/; Secure"
                if delete
                else "affinity=next; Path=/; Secure"
            )
        return response

    async with AsyncOpenAI(
        api_key="offline",
        base_url="https://bound.invalid/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        for _attempt in range(3):
            await _run(
                _model("responses", client),
                streaming=False,
                bounded=bounded,
                hooks=ReportUsageHooks(
                    model="openai/gpt-6-luna", max_budget_usd=1 if bounded else None
                ),
            )
    assert len(received) == 3


@pytest.mark.asyncio
async def test_concurrent_cookie_updates_do_not_restore_stale_cookie_copies(monkeypatch):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    entered = [asyncio.Event(), asyncio.Event()]
    release = [asyncio.Event(), asyncio.Event()]
    cookies = []

    async def respond(request):
        index = len(cookies)
        cookies.append(request.headers.get("cookie"))
        response = _reply("responses", stream=False)
        if index < 2:
            entered[index].set()
            await release[index].wait()
            values = [("set-cookie", f"cookie{index}=fresh; Path=/; Secure")]
            if index == 0:
                values.append(("set-cookie", "expired=; Max-Age=0; Path=/; Secure"))
            response.headers = httpx.Headers([*response.headers.multi_items(), *values])
        return response

    async with AsyncOpenAI(
        api_key="offline",
        base_url="https://bound.invalid/v1",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        client._client.cookies.set("expired", "old", domain="bound.invalid", path="/")

        async def request():
            return await _run(
                _model("responses", client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )

        first = asyncio.create_task(request())
        await asyncio.wait_for(entered[0].wait(), 2)
        second = asyncio.create_task(request())
        await asyncio.wait_for(entered[1].wait(), 2)
        release[0].set()
        await first
        release[1].set()
        await second
        await request()
        assert "cookie0=fresh" in cookies[2] and "cookie1=fresh" in cookies[2]
        assert "expired=" not in cookies[2]
        async with AsyncOpenAI(
            api_key="other-offline",
            base_url="https://bound.invalid/v1",
            http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
        ) as other:
            await _run(
                _model("responses", other),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
        assert cookies[3] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["responses", "chat"])
async def test_normal_typed_tools_schema_and_image_input_keep_their_quoted_wire_shape(
    monkeypatch, api
):
    monkeypatch.setattr(state_module, "_global_report_state", None)

    class Answer(BaseModel):
        status: str

    @function_tool
    def lookup(query: str) -> str:
        return query

    bodies = []

    def respond(request):
        body = json.loads(request.content)
        bodies.append(body)
        response = _reply(api, stream=False)
        payload = json.loads(response.content)
        text = '{"status":"ok"}'
        if api == "responses":
            payload["output"][0]["content"][0]["text"] = text
        else:
            payload["choices"][0]["message"]["content"] = text
        return httpx.Response(200, json=payload)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        agent = Agent(
            name="Root",
            model=_model(api, client),
            tools=[lookup],
            output_type=Answer,
            model_settings=make_model_settings(
                None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
            ),
        )
        result = await Runner.run(
            agent,
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "offline"},
                        {"type": "input_image", "image_url": "data:image/png;base64,Zml4dHVyZQ=="},
                    ],
                }
            ],
            context={"agent_id": "root"},
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            run_config=RunConfig(tracing_disabled=True),
        )
    assert result.final_output.status == "ok"
    assert result.raw_responses[0].usage.total_tokens == 10
    assert len(bodies) == 1
    assert bodies[0]["tools"][0]["type"] == "function"
    assert "Zml4dHVyZQ==" in json.dumps(bodies[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("fragmented", [False, True])
@pytest.mark.parametrize("crlf", [False, True])
async def test_legal_multiline_terminal_receipt_matches_sdk(monkeypatch, fragmented, crlf):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    content = _sse_chunk(_chat_stream(interim=False, final=True)) + b"data: [DONE]\n\n"
    if crlf:
        content = content.replace(b"\n", b"\r\n")

    def respond(_request):
        kwargs = {"stream": _ByteChunks(content)} if fragmented else {"content": content}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, **kwargs)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        result = await _run(
            _model("chat", client),
            streaming=True,
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
        )
    assert result.final_output == "OK"
    assert (
        result.raw_responses[0].usage.input_tokens,
        result.raw_responses[0].usage.output_tokens,
    ) == (8, 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("n", [1, 4])
async def test_sdk_extra_args_cannot_raise_generation_multiplicity(monkeypatch, n):
    monkeypatch.setattr(state_module, "_global_report_state", None)
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return _reply("chat", stream=False)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        settings = make_model_settings(
            None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
        )
        settings.extra_args = {"n": n}
        request = Runner.run(
            Agent(name="Root", model=_model("chat", client), model_settings=settings),
            "offline",
            context={"agent_id": "root"},
            hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            run_config=RunConfig(tracing_disabled=True),
        )
        if n == 1:
            assert (await request).final_output == "OK"
        else:
            with pytest.raises(APIConnectionError) as caught:
                await request
            assert isinstance(caught.value.__cause__, PhysicalBudgetAdapterError)
    assert calls == (1 if n == 1 else 0)
