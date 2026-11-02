"""A bounded reservation must cover each physical provider submission."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import httpx
import litellm
import pytest
from agents import Agent, RunConfig, Runner
from agents.extensions.models.litellm_model import LitellmModel
from agents.items import ModelResponse
from agents.models._retry_runtime import (
    should_disable_provider_managed_retries,
    should_disable_websocket_pre_event_retries,
)
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from agents.run_internal.model_retry import get_response_with_retry, stream_response_with_retry
from agents.usage import Usage
from litellm.llms.openai.openai import OpenAIChatCompletion
from openai import APIConnectionError, APIStatusError, AsyncOpenAI, BadRequestError

from lyrashield.artifacts import dedupe
from lyrashield.artifacts import state as state_module
from lyrashield.lifecycle import compaction
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.models import _completed_stream_event
from lyrashield.triage import service


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_bounded_sdk_lost_ack_does_not_replay_under_one_reservation(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_estimate_input_tokens", lambda *_args: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (1, 0, 0, 1))
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 1)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1, max_output_tokens=600_000)
    context = SimpleNamespace(context={"agent_id": "root", "parent_id": None})
    settings = make_model_settings(
        "medium",
        model_name="openai/gpt-6-luna",
        bounded_runtime=True,
        bounded_budget=True,
        max_output_tokens=600_000,
    )
    agent = SimpleNamespace(name="Root", model="openai/gpt-6-luna", model_settings=settings)
    await hooks.on_llm_start(context, agent, None, [])
    attempts = 0

    async def physical_request() -> ModelResponse:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise APIConnectionError(
                request=httpx.Request("POST", "https://offline.invalid/responses"),
                message="synthetic loss of acknowledgement after provider acceptance",
            )
        return ModelResponse(
            output=[],
            usage=Usage(requests=1, input_tokens=8, output_tokens=2, total_tokens=10),
            response_id="second-request",
        )

    async def stream() -> Any:
        yield _completed_stream_event(await physical_request(), "gpt-6-luna")

    async def rewind() -> None:
        pass

    with pytest.raises(APIConnectionError):
        if streaming:
            async for _event in stream_response_with_retry(
                get_stream=stream,
                rewind=rewind,
                retry_settings=settings.retry,
                get_retry_advice=lambda _request: None,
                previous_response_id=None,
                conversation_id=None,
            ):
                pass
        else:
            await get_response_with_retry(
                get_response=physical_request,
                rewind=rewind,
                retry_settings=settings.retry,
                get_retry_advice=lambda _request: None,
                previous_response_id=None,
                conversation_id=None,
            )
    assert attempts == 1
    # The lost acknowledgement cannot release the conservative $0.60 quote.
    assert sum(hooks._agent_reservations.values()) == pytest.approx(0.6)
    with pytest.raises(BudgetExceededError):
        await hooks.on_llm_start(context, agent, None, [])
    assert sum(hooks._agent_abandoned_floors.values()) == pytest.approx(0.6)


@pytest.mark.asyncio
@pytest.mark.parametrize("auxiliary", ["dedupe", "triage", "compaction"])
@pytest.mark.parametrize("bounded", [False, True])
async def test_direct_native_lost_ack_has_one_physical_attempt_when_capped(
    monkeypatch: pytest.MonkeyPatch, auxiliary: str, bounded: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=0.001 if bounded else None)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    attempts = 0

    def lost_ack(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadError("synthetic acknowledgement lost after acceptance", request=request)

    async with AsyncOpenAI(
        api_key="offline-test",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(lost_ack)),
    ) as client:
        model = OpenAIResponsesModel("gpt-6-luna", openai_client=client)

        async def request() -> None:
            if auxiliary == "dedupe":
                await dedupe._request_dedupe_judgement(
                    model=model,
                    model_name="openai/gpt-6-luna",
                    model_settings=make_model_settings(None, model_name="openai/gpt-6-luna"),
                    user_msg="synthetic finding",
                )
            elif auxiliary == "triage":
                await service._request_judgement(
                    model=model,
                    model_route="openai/gpt-6-luna",
                    model_settings=make_model_settings(None, model_name="openai/gpt-6-luna"),
                    prompt="synthetic finding",
                    limits=service.TriageLimits(max_output_tokens=192),
                )
            else:
                assert (
                    await compaction._summarize(
                        "openai/gpt-6-luna",
                        "synthetic history",
                        192,
                        model_provider=SimpleNamespace(get_model=lambda _name: model),
                        settings=SimpleNamespace(
                            llm=SimpleNamespace(timeout=1, extra_headers=None)
                        ),
                    )
                    is None
                )

        if auxiliary == "compaction":
            await request()
        else:
            with pytest.raises(APIConnectionError):
                await request()
    assert attempts == (1 if bounded else 3)
    if bounded:
        assert 0 < sum(hooks._abandoned_floors.values()) < 0.001
        assert not hooks._reservations
        # A second physical request cannot reuse the unknown charge's quote.
        with pytest.raises(BudgetExceededError):
            await hooks.reserve_out_of_band_request(
                key="fallback",
                model="openai/gpt-6-luna",
                input_tokens=5000,
                max_output_tokens=512,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("api", ["responses", "chat"])
async def test_real_runner_and_native_http_cannot_replay_bounded_503(
    monkeypatch: pytest.MonkeyPatch, streaming: bool, api: str
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    attempts = 0

    def unavailable(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            503, headers={"retry-after-ms": "1"}, json={"error": {"message": "offline"}}
        )

    async with AsyncOpenAI(
        api_key="offline-test",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(unavailable)),
    ) as client:
        model = (
            OpenAIResponsesModel("gpt-6-luna", openai_client=client)
            if api == "responses"
            else OpenAIChatCompletionsModel("gpt-6-luna", openai_client=client)
        )
        settings = make_model_settings(
            None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
        )
        agent = Agent(name="Root", model=model, model_settings=settings)
        hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1, max_output_tokens=128)
        with pytest.raises(APIStatusError):
            if streaming:
                result = Runner.run_streamed(
                    agent,
                    "offline",
                    context={"agent_id": "root"},
                    hooks=hooks,
                    run_config=RunConfig(tracing_disabled=True),
                )
                async for _event in result.stream_events():
                    pass
            else:
                await Runner.run(
                    agent,
                    "offline",
                    context={"agent_id": "root"},
                    hooks=hooks,
                    run_config=RunConfig(tracing_disabled=True),
                )
    assert attempts == 1
    assert sum(hooks._agent_reservations.values()) > 0
    assert not should_disable_provider_managed_retries()
    assert not should_disable_websocket_pre_event_retries()


@pytest.mark.asyncio
@pytest.mark.parametrize("bounded", [False, True])
async def test_direct_litellm_boundary_sets_no_hidden_replay_knobs_only_for_cap(
    monkeypatch: pytest.MonkeyPatch, bounded: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1 if bounded else None)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    observed = []

    async def lost_ack(**kwargs: Any) -> Any:
        observed.append((kwargs.get("num_retries"), kwargs.get("max_retries")))
        raise APIConnectionError(request=httpx.Request("POST", "https://offline.invalid"))

    monkeypatch.setattr("litellm.acompletion", lost_ack)
    with pytest.raises(APIConnectionError):
        await dedupe._request_dedupe_judgement(
            model=LitellmModel("openai/gpt-6-luna", api_key="offline-test"),
            model_name="openai/gpt-6-luna",
            model_settings=make_model_settings(None, model_name="openai/gpt-6-luna"),
            user_msg="offline finding",
        )
    assert observed == ([(0, 0)] if bounded else [(None, None)])
    assert not should_disable_provider_managed_retries()


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_zero_retry_policy_disables_compatibility_and_websocket_replay(
    streaming: bool,
) -> None:
    settings = make_model_settings(None, model_name="openai/gpt-6-luna", bounded_budget=True)
    attempts = 0

    async def locked() -> ModelResponse:
        nonlocal attempts
        attempts += 1
        assert should_disable_provider_managed_retries()
        assert should_disable_websocket_pre_event_retries()
        raise BadRequestError(
            "conversation locked",
            response=httpx.Response(400, request=httpx.Request("POST", "https://offline.invalid")),
            body={"code": "conversation_locked"},
        )

    async def stream() -> Any:
        yield _completed_stream_event(await locked(), "gpt-6-luna")

    async def rewind() -> None:
        raise AssertionError("No compatibility rewind is allowed under one reservation")

    with pytest.raises(BadRequestError):
        if streaming:
            async for _event in stream_response_with_retry(
                get_stream=stream,
                rewind=rewind,
                retry_settings=settings.retry,
                get_retry_advice=lambda _request: None,
                previous_response_id=None,
                conversation_id=None,
            ):
                pass
        else:
            await get_response_with_retry(
                get_response=locked,
                rewind=rewind,
                retry_settings=settings.retry,
                get_retry_advice=lambda _request: None,
                previous_response_id=None,
                conversation_id=None,
            )
    assert attempts == 1
    assert not should_disable_provider_managed_retries()
    assert not should_disable_websocket_pre_event_retries()


@pytest.mark.asyncio
@pytest.mark.parametrize("bounded", [False, True])
async def test_native_503_then_success_cannot_hide_a_second_capped_attempt(
    monkeypatch: pytest.MonkeyPatch, bounded: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1 if bounded else None)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(
                503, headers={"retry-after-ms": "1"}, json={"error": {"message": "offline"}}
            )
        return httpx.Response(
            200,
            json={
                "id": "received",
                "object": "response",
                "created_at": 0,
                "model": "gpt-6-luna",
                "status": "completed",
                "output": [],
                "usage": {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10},
            },
        )

    async with AsyncOpenAI(
        api_key="offline-test",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = OpenAIResponsesModel("gpt-6-luna", openai_client=client)

        async def call() -> ModelResponse:
            return await dedupe._request_dedupe_judgement(
                model=model,
                model_name="openai/gpt-6-luna",
                model_settings=make_model_settings(
                    None, model_name="openai/gpt-6-luna", max_output_tokens=512
                ),
                user_msg="synthetic finding",
            )

        if bounded:
            with pytest.raises(APIStatusError):
                await call()
        else:
            assert (await call()).usage.total_tokens == 10
    assert len(requests) == (1 if bounded else 2)
    assert all(payload["max_output_tokens"] == 512 for payload in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("auxiliary", ["dedupe", "triage", "compaction"])
async def test_cancelled_auxiliary_holds_quote_and_resets_retry_context(
    monkeypatch: pytest.MonkeyPatch, auxiliary: str
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=0.001)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    started = asyncio.Event()
    attempts = 0

    async def accept_without_ack(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        assert should_disable_provider_managed_retries()
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("cancelled synthetic provider must not return")

    async with AsyncOpenAI(
        api_key="offline-test",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(accept_without_ack)),
    ) as client:
        model = OpenAIResponsesModel("gpt-6-luna", openai_client=client)

        async def call() -> None:
            settings = make_model_settings(
                None, model_name="openai/gpt-6-luna", max_output_tokens=192
            )
            if auxiliary == "dedupe":
                await dedupe._request_dedupe_judgement(
                    model=model,
                    model_name="openai/gpt-6-luna",
                    model_settings=settings,
                    user_msg="offline",
                )
            elif auxiliary == "triage":
                await service._request_judgement(
                    model=model,
                    model_route="openai/gpt-6-luna",
                    model_settings=settings,
                    prompt="offline",
                    limits=service.TriageLimits(max_output_tokens=192),
                )
            else:
                await compaction._summarize(
                    "openai/gpt-6-luna",
                    "offline",
                    192,
                    model_provider=SimpleNamespace(get_model=lambda _name: model),
                    settings=SimpleNamespace(llm=SimpleNamespace(timeout=30, extra_headers=None)),
                )

        caller = asyncio.create_task(call())
        await started.wait()
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
    assert attempts == 1
    assert not hooks._reservations
    assert sum(hooks._abandoned_floors.values()) > 0
    assert not should_disable_provider_managed_retries()
    assert not should_disable_websocket_pre_event_retries()
    with pytest.raises(BudgetExceededError):
        await hooks.reserve_out_of_band_request(
            key="fallback", model="openai/gpt-6-luna", input_tokens=5000, max_output_tokens=512
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_real_litellm_and_native_http_do_not_replay_capped_503(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    attempts = 0
    native_retry_settings = []

    def unavailable(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            503, headers={"retry-after-ms": "1"}, json={"error": {"message": "offline"}}
        )

    async with AsyncOpenAI(
        api_key="offline-test",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(unavailable)),
    ) as client:

        def client_factory(_self: Any, **kwargs: Any) -> AsyncOpenAI:
            native_retry_settings.append(kwargs["max_retries"])
            return client.with_options(max_retries=kwargs["max_retries"])

        monkeypatch.setattr(OpenAIChatCompletion, "_get_openai_client", client_factory)
        settings = make_model_settings(
            None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
        )
        agent = Agent(
            name="Root",
            model=LitellmModel("openai/gpt-6-luna", api_key="offline-test"),
            model_settings=settings,
        )
        hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1, max_output_tokens=128)
        with pytest.raises(litellm.ServiceUnavailableError):
            if streaming:
                result = Runner.run_streamed(
                    agent,
                    "offline",
                    hooks=hooks,
                    context={"agent_id": "root"},
                    run_config=RunConfig(tracing_disabled=True),
                )
                async for _event in result.stream_events():
                    pass
            else:
                await Runner.run(
                    agent,
                    "offline",
                    hooks=hooks,
                    context={"agent_id": "root"},
                    run_config=RunConfig(tracing_disabled=True),
                )
    assert attempts == 1
    assert native_retry_settings == [0]
    assert sum(hooks._agent_reservations.values()) > 0
    assert not should_disable_provider_managed_retries()
