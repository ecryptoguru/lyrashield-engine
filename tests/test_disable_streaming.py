"""Tests for LLM_DISABLE_STREAMING: serve the streamed run loop without SSE.

A gateway that rejects ``stream:true`` (or delivers SSE unreliably) breaks the
SDK run loop, which only issues streamed requests. ``_NonStreamingModel`` wraps
the resolved model so each turn makes one non-streaming ``get_response`` and
replays the completed result as a single terminal stream event. A local server
that rejects streamed requests but answers non-streamed ones — including a
structured tool call — proves the wrapper works where the stock model fails.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent, Runner, function_tool
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelProvider, ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.run import RunConfig
from openai import AsyncOpenAI, BadRequestError
from openai.types.responses import (
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from lyrashield.policy import codex, loader
from lyrashield.policy.loader import load_settings
from lyrashield.policy.models import StrixProvider, _NonStreamingModel
from lyrashield.policy.settings import LlmSettings, Settings
from strix.config import models as strix_models


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


def _tool_call_completion() -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "do_thing", "arguments": '{"n": 1}'},
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


def _text_completion() -> dict[str, Any]:
    return {
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "hello from gateway"},
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }


_CAPTURED: dict[str, Any] = {}
_PAYLOAD: dict[str, dict[str, Any]] = {"value": _tool_call_completion()}


class _Handler(BaseHTTPRequestHandler):
    """A gateway that only speaks non-streaming Chat Completions."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _CAPTURED.clear()
        _CAPTURED.update(body)
        if body.get("stream"):
            payload = json.dumps(
                {"error": {"message": "streaming is not supported by this endpoint"}}
            ).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = json.dumps(_PAYLOAD["value"]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def gateway_url() -> Iterator[str]:
    _PAYLOAD["value"] = _tool_call_completion()
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _model(base_url: str) -> OpenAIChatCompletionsModel:
    client = AsyncOpenAI(api_key="tok", base_url=base_url)
    return OpenAIChatCompletionsModel(model="gw-model", openai_client=client)


def _call_kwargs() -> dict[str, Any]:
    return {
        "system_instructions": "s",
        "input": "hi",
        "model_settings": ModelSettings(),
        "tools": [],
        "output_schema": None,
        "handoffs": [],
        "tracing": ModelTracing.DISABLED,
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }


async def _drain(gen: AsyncIterator[Any]) -> list[Any]:
    return [event async for event in gen]


@pytest.mark.asyncio
async def test_stock_model_streaming_fails_on_non_streaming_gateway(gateway_url: str) -> None:
    # The stock model issues stream:true and the gateway rejects it.
    model = _model(gateway_url)
    with pytest.raises(BadRequestError, match="streaming is not supported"):
        await _drain(model.stream_response(**_call_kwargs()))
    assert _CAPTURED["stream"] is True


@pytest.mark.asyncio
async def test_wrapper_streams_tool_call_without_streaming_request(gateway_url: str) -> None:
    # The wrapper turns the streamed run-loop call into one non-streaming
    # request and replays the completed result as a terminal stream event.
    model = _NonStreamingModel(_model(gateway_url))
    events = await _drain(model.stream_response(**_call_kwargs()))

    assert _CAPTURED.get("stream") is not True
    assert len(events) == 1
    completed = events[0]
    assert isinstance(completed, ResponseCompletedEvent)

    tool_call = completed.response.output[0]
    assert isinstance(tool_call, ResponseFunctionToolCall)
    assert tool_call.name == "do_thing"
    assert json.loads(tool_call.arguments) == {"n": 1}

    assert completed.response.usage is not None
    assert completed.response.usage.total_tokens == 7


@pytest.mark.asyncio
async def test_wrapper_streams_plain_text(gateway_url: str) -> None:
    _PAYLOAD["value"] = _text_completion()
    model = _NonStreamingModel(_model(gateway_url))
    events = await _drain(model.stream_response(**_call_kwargs()))

    assert _CAPTURED.get("stream") is not True
    message = events[0].response.output[0]
    assert isinstance(message, ResponseOutputMessage)
    text = message.content[0]
    assert isinstance(text, ResponseOutputText)
    assert text.text == "hello from gateway"


@pytest.mark.asyncio
async def test_wrapper_get_response_stays_non_streaming(gateway_url: str) -> None:
    # The non-streaming path is a plain pass-through to the inner model.
    model = _NonStreamingModel(_model(gateway_url))
    response = await model.get_response(**_call_kwargs())
    assert _CAPTURED.get("stream") is not True
    tool_call = response.output[0]
    assert isinstance(tool_call, ResponseFunctionToolCall)
    assert tool_call.name == "do_thing"


_TURN_STREAM_FLAGS: list[bool] = []


class _MultiTurnHandler(BaseHTTPRequestHandler):
    """Non-streaming gateway: a tool call on turn 1, a final answer on turn 2."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _TURN_STREAM_FLAGS.append(bool(body.get("stream")))
        completion = _tool_call_completion() if len(_TURN_STREAM_FLAGS) == 1 else _text_completion()
        if len(_TURN_STREAM_FLAGS) > 1:
            completion["choices"][0]["message"]["content"] = "all done"
        payload = json.dumps(completion).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def multiturn_url() -> Iterator[str]:
    _TURN_STREAM_FLAGS.clear()
    server = HTTPServer(("127.0.0.1", 0), _MultiTurnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
async def test_run_loop_executes_tool_and_completes_without_streaming(multiturn_url: str) -> None:
    # The whole streamed agent loop runs against a non-streaming gateway: the
    # synthetic terminal event feeds the runner, which executes the tool and
    # continues the turn until a final answer.
    calls: list[int] = []

    @function_tool
    def do_thing(n: int) -> str:
        calls.append(n)
        return f"did {n}"

    class _Provider(ModelProvider):
        def get_model(self, model_name: str | None) -> Model:  # noqa: ARG002
            return _NonStreamingModel(_model(multiturn_url))

    agent = Agent(name="t", instructions="use the tool", tools=[do_thing], model="gw-model")
    result = Runner.run_streamed(
        agent, input="please", run_config=RunConfig(model_provider=_Provider())
    )
    async for _ in result.stream_events():
        pass

    assert calls == [1]  # tool executed with the streamed tool-call args
    assert result.final_output == "all done"
    assert len(_TURN_STREAM_FLAGS) == 2  # two turns, both...
    assert not any(_TURN_STREAM_FLAGS)  # ...issued as non-streaming requests


class _DummyModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


class _StalledModel(_DummyModel):
    def stream_response(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ARG002
        async def events() -> AsyncIterator[Any]:
            await asyncio.Event().wait()
            yield None

        return events()


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "LLM_STREAM_IDLE_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


def test_get_model_wraps_when_disabled(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    inner = _DummyModel()
    monkeypatch.setattr("lyrashield.policy.models.MultiProvider.get_model", lambda *_: inner)
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "true")
    load_settings()

    model = StrixProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, strix_models._TurnGuardModel)
    assert isinstance(model._inner, _NonStreamingModel)
    assert model._stream_idle_timeout == 0


def test_get_model_applies_stream_guard_by_default(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    inner = _DummyModel()
    monkeypatch.setattr("lyrashield.policy.models.MultiProvider.get_model", lambda *_: inner)
    load_settings()

    model = StrixProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, strix_models._TurnGuardModel)
    assert model._inner is inner
    assert model._stream_idle_timeout == 300


@pytest.mark.asyncio
async def test_get_model_times_out_stalled_stream_from_config(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    inner = _StalledModel()
    monkeypatch.setattr("lyrashield.policy.models.MultiProvider.get_model", lambda *_: inner)
    observed_timeouts: list[float] = []
    with_idle_timeout = strix_models._with_idle_timeout

    def record_idle_timeout(stream: Any, timeout: float) -> Any:
        observed_timeouts.append(timeout)
        return with_idle_timeout(stream, timeout)

    monkeypatch.setattr(strix_models, "_with_idle_timeout", record_idle_timeout)
    model = StrixProvider(settings=Settings(llm=LlmSettings(stream_idle_timeout=10))).get_model(
        "openai/gpt-4o-mini"
    )

    assert isinstance(model, strix_models._TurnGuardModel)
    assert model._stream_idle_timeout == 10
    stream_kwargs = _call_kwargs()
    stream_kwargs["model_settings"] = ModelSettings(extra_args={"timeout": 0.05})
    with pytest.raises(TimeoutError, match="model stream produced no event"):
        await _drain(model.stream_response(**stream_kwargs))
    assert observed_timeouts == [0.05]


def test_get_model_does_not_wrap_subscription_model(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # Subscription (ChatGPT) models stay streamed and retain the stream guard.
    monkeypatch.setattr(codex, "subscription_model", lambda *_: "gpt-5.5")
    monkeypatch.setattr(codex, "get_subscription_client", lambda: AsyncOpenAI(api_key="x"))
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "true")
    load_settings()

    model = StrixProvider().get_model("gpt-5.5")
    assert isinstance(model, strix_models._TurnGuardModel)
    assert not isinstance(model._inner, _NonStreamingModel)
