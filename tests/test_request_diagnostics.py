"""Bounded diagnostic metadata never stores model inputs or provider bodies."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from agents import Agent, Runner
from agents.model_settings import ModelSettings
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from agents.run import RunConfig
from openai import AsyncOpenAI

from lyrashield.policy.diagnostics import MAX_BYTES, DiagnosticModel, append_diagnostic
from lyrashield.policy.models import StrixProvider, _NonStreamingModel
from lyrashield.policy.settings import LlmSettings, Settings


def test_request_diagnostics_default_is_off() -> None:
    assert LlmSettings().request_diagnostics is False


def test_diagnostic_artifact_is_allowlisted_atomic_and_bounded(tmp_path) -> None:
    def append(index):
        append_diagnostic(
            tmp_path,
            {
                "request_id": f"req_{index}",
                "model": "gpt-6-sol",
                "route": "responses",
                "outcome": "completed",
                "duration_ms": index,
                "prompt": "secret content",
                "headers": {"Authorization": "secret"},
            },
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(300)))
    path = tmp_path / ".state" / "request-diagnostics.json"
    document = json.loads(path.read_text())
    assert len(document["entries"]) <= 256
    assert len(document["entries"]) + document["dropped"] == 300
    assert path.stat().st_size <= MAX_BYTES
    assert "secret" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(path.parent.glob("*.tmp"))


@pytest.mark.asyncio
async def test_cancelled_request_is_recorded_without_swallowing_cancellation(tmp_path) -> None:
    started = asyncio.Event()

    class Inner:
        async def get_response(self, *_args: Any, **_kwargs: Any):
            started.set()
            await asyncio.Event().wait()

    settings = ModelSettings(extra_args={"timeout": 1.0})
    model = DiagnosticModel(
        Inner(), model_name="openai/gpt-6-sol", route="responses", run_dir=lambda: tmp_path
    )
    task = asyncio.create_task(model.get_response(model_settings=settings, input="PRIVATE PROMPT"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    document = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())
    assert document["entries"][0]["outcome"] == "cancelled"
    assert "PRIVATE" not in json.dumps(document)
    assert settings.to_json_dict()["extra_args"] == {"timeout": 1.0}


@pytest.mark.asyncio
async def test_stream_ttft_uses_token_delta_and_keeps_usage_buckets(tmp_path) -> None:
    class Inner:
        async def stream_response(self):
            yield SimpleNamespace(type="response.created")
            yield SimpleNamespace(type="response.output_text.delta", delta="PRIVATE OUTPUT")
            yield SimpleNamespace(
                type="response.completed",
                response=SimpleNamespace(
                    id="resp_test",
                    _request_id="req_test",
                    usage=SimpleNamespace(
                        input_tokens=10,
                        output_tokens=4,
                        input_tokens_details=SimpleNamespace(cached_tokens=3),
                        output_tokens_details=SimpleNamespace(reasoning_tokens=2),
                    ),
                ),
            )

    model = DiagnosticModel(
        Inner(), model_name="openai/gpt-6-sol", route="responses", run_dir=lambda: tmp_path
    )
    events = [event async for event in model.stream_response()]
    assert len(events) == 3
    entry = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())["entries"][0]
    assert entry["tokens"] == {"input": 10, "output": 4, "cached_input": 3, "reasoning_output": 2}
    assert 0 <= entry["ttft_ms"] <= entry["duration_ms"]
    assert entry["request_id"] == "req_test"
    assert "PRIVATE" not in json.dumps(entry)


@pytest.mark.asyncio
async def test_stream_cancellation_closes_upstream_and_records_terminal_outcome(tmp_path) -> None:
    closed = []

    class Inner:
        async def stream_response(self):
            try:
                yield SimpleNamespace(type="response.created")
                await asyncio.Event().wait()
            finally:
                closed.append(True)

    model = DiagnosticModel(
        Inner(), model_name="model", route="responses", run_dir=lambda: tmp_path
    )
    stream = model.stream_response()
    await anext(stream)
    await stream.aclose()
    assert closed == [True]
    entry = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())["entries"][0]
    assert entry["outcome"] == "cancelled"
    assert "ttft_ms" not in entry


@pytest.mark.asyncio
async def test_retryable_error_is_metadata_only_and_does_not_retry(tmp_path) -> None:
    class ProviderError(RuntimeError):
        status_code = 429

    calls = []

    class Inner:
        async def get_response(self):
            calls.append(True)
            raise ProviderError("Authorization=PRIVATE SECRET BODY")

    model = DiagnosticModel(
        Inner(), model_name="model", route="responses", run_dir=lambda: tmp_path
    )
    with pytest.raises(ProviderError):
        await model.get_response()
    entry = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())["entries"][0]
    assert calls == [True]
    assert entry["retry_reason"] == "rate_limited"
    assert "PRIVATE" not in json.dumps(entry)


def test_diagnostics_scrubs_oversized_and_sensitive_fields(tmp_path) -> None:
    append_diagnostic(
        tmp_path,
        {
            "model": "x" * 1000,
            "request_id": "sk_live_1234567890abcdef",
            "outcome": "completed",
            "duration_ms": float("nan"),
            "tokens": {"input": True, "output": -1, "cached_input": 2},
        },
    )
    entry = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())["entries"][0]
    assert entry == {"outcome": "completed", "tokens": {"cached_input": 2}}


@pytest.mark.asyncio
@pytest.mark.parametrize("streamed", [False, True])
async def test_real_sdk_serialization_and_nonstreaming_fallback(tmp_path, streamed: bool) -> None:

    wire = []

    async def handle(request):
        wire.append(json.loads(request.content))
        return httpx.Response(
            200,
            headers={"x-request-id": "req_wire"},
            json={
                "id": "chatcmpl_wire",
                "object": "chat.completion",
                "created": 0,
                "model": "test-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "PRIVATE ANSWER"},
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            },
        )

    client = AsyncOpenAI(
        api_key="test", http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle))
    )
    inner = _NonStreamingModel(OpenAIChatCompletionsModel(model="test-model", openai_client=client))
    model = DiagnosticModel(
        inner, model_name="test-model", route="non_streaming", run_dir=lambda: tmp_path
    )
    settings = ModelSettings(extra_args={"timeout": 2.0})
    before = settings.to_json_dict()
    agent = Agent(name="test", model=model, model_settings=settings)
    try:
        if streamed:
            result = Runner.run_streamed(
                agent, "PRIVATE INPUT", run_config=RunConfig(tracing_disabled=True)
            )
            async for _event in result.stream_events():
                pass
        else:
            await Runner.run(agent, "PRIVATE INPUT", run_config=RunConfig(tracing_disabled=True))
    finally:
        await client.close()
    assert len(wire) == 1
    assert wire[0].get("stream") is not True
    assert settings.to_json_dict() == before
    json.dumps(before)
    document = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())
    assert len(document["entries"]) == 1
    entry = document["entries"][0]
    assert entry["outcome"] == "completed"
    # The Chat Completions adapter does not expose transport request IDs.
    assert "request_id" not in entry
    assert entry["tokens"]["input"] == 5
    assert entry["tokens"]["output"] == 3
    assert "ttft_ms" not in entry
    assert "PRIVATE" not in json.dumps(document)


def test_opt_in_provider_wraps_only_when_enabled() -> None:

    enabled = StrixProvider(
        api_key="test", settings=Settings(llm=LlmSettings(api_key="test", request_diagnostics=True))
    )
    assert isinstance(enabled.get_model("openai/gpt-6-sol"), DiagnosticModel)
    disabled = StrixProvider(
        api_key="test",
        settings=Settings(llm=LlmSettings(api_key="test", request_diagnostics=False)),
    )
    assert not isinstance(disabled.get_model("openai/gpt-6-sol"), DiagnosticModel)


@pytest.mark.asyncio
@pytest.mark.parametrize("streamed", [False, True])
async def test_real_responses_sdk_preserves_request_identity_in_fallback(
    tmp_path, streamed: bool
) -> None:
    async def handle(_request):
        return httpx.Response(
            200,
            headers={"x-request-id": "req_responses"},
            json={
                "id": "resp_wire",
                "object": "response",
                "created_at": 0,
                "model": "test-model",
                "status": "completed",
                "output": [
                    {
                        "id": "msg_wire",
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            {"type": "output_text", "text": "PRIVATE ANSWER", "annotations": []}
                        ],
                    }
                ],
                "tools": [],
                "tool_choice": "auto",
                "parallel_tool_calls": False,
                "usage": {
                    "input_tokens": 5,
                    "output_tokens": 3,
                    "total_tokens": 8,
                    "input_tokens_details": {"cached_tokens": 2},
                    "output_tokens_details": {"reasoning_tokens": 1},
                },
            },
        )

    client = AsyncOpenAI(
        api_key="test", http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle))
    )
    model = DiagnosticModel(
        _NonStreamingModel(OpenAIResponsesModel(model="test-model", openai_client=client)),
        model_name="test-model",
        route="non_streaming",
        run_dir=lambda: tmp_path,
    )
    agent = Agent(name="test", model=model)
    try:
        if streamed:
            result = Runner.run_streamed(
                agent, "PRIVATE INPUT", run_config=RunConfig(tracing_disabled=True)
            )
            async for _event in result.stream_events():
                pass
        else:
            await Runner.run(agent, "PRIVATE INPUT", run_config=RunConfig(tracing_disabled=True))
    finally:
        await client.close()
    document = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())
    entry = document["entries"][0]
    assert entry["request_id"] == "req_responses"
    assert entry["response_id"] == "resp_wire"
    assert entry["tokens"]["cached_input"] == 2
    assert entry["tokens"]["reasoning_output"] == 1
    assert "PRIVATE" not in json.dumps(document)


@pytest.mark.asyncio
async def test_real_sdk_cancellation_does_not_retry_or_lose_terminal_record(tmp_path) -> None:
    started = asyncio.Event()
    requests = []

    async def handle(_request):
        requests.append(True)
        started.set()
        await asyncio.Event().wait()

    client = AsyncOpenAI(
        api_key="test", http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle))
    )
    model = DiagnosticModel(
        OpenAIResponsesModel(model="test-model", openai_client=client),
        model_name="test-model",
        route="responses",
        run_dir=lambda: tmp_path,
    )
    task = asyncio.create_task(
        Runner.run(
            Agent(name="test", model=model),
            "PRIVATE INPUT",
            run_config=RunConfig(tracing_disabled=True),
        )
    )
    try:
        await asyncio.wait_for(started.wait(), timeout=3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
    finally:
        task.cancel()
        await client.close()
    assert requests == [True]
    document = json.loads((tmp_path / ".state" / "request-diagnostics.json").read_text())
    assert document["entries"][0]["outcome"] == "cancelled"
    assert "PRIVATE" not in json.dumps(document)


def test_byte_ceiling_evicts_before_entry_ceiling_for_maximum_fields(tmp_path) -> None:
    record = {
        "request_id": "r" * 128,
        "response_id": "s" * 128,
        "model": "m" * 128,
        "route": "p" * 128,
        "outcome": "completed",
        "duration_ms": 10**12,
        "ttft_ms": 10**12,
        "tokens": {
            "input": 10**12,
            "output": 10**12,
            "cached_input": 10**12,
            "cache_write_input": 10**12,
            "reasoning_output": 10**12,
        },
    }
    for _index in range(256):
        append_diagnostic(tmp_path, record)
    path = tmp_path / ".state" / "request-diagnostics.json"
    document = json.loads(path.read_text())
    assert path.stat().st_size <= MAX_BYTES
    assert len(document["entries"]) < 256
    assert len(document["entries"]) + document["dropped"] == 256


@pytest.mark.asyncio
async def test_request_keeps_the_run_identity_it_started_with(tmp_path) -> None:
    destination = [tmp_path / "first-run"]

    class Inner:
        async def get_response(self):
            destination[0] = tmp_path / "later-run"
            return SimpleNamespace(response_id="resp_old", usage=None)

    model = DiagnosticModel(
        Inner(), model_name="model", route="responses", run_dir=lambda: destination[0]
    )
    await model.get_response()
    assert (tmp_path / "first-run" / ".state" / "request-diagnostics.json").exists()
    assert not (tmp_path / "later-run" / ".state" / "request-diagnostics.json").exists()
