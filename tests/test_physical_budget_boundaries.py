"""Wire-level finite spend boundaries, including compatibility and missing receipts."""

from __future__ import annotations

import json
from importlib import import_module
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import litellm
import pytest
from agents import Agent, RunConfig, Runner
from agents.extensions.models.litellm_model import LitellmModel
from agents.memory import SQLiteSession
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from agents.usage import Usage
from openai import APIStatusError, AsyncOpenAI, DefaultAsyncHttpxClient

from lyrashield.artifacts import dedupe
from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.interface import warmup
from lyrashield.lifecycle import execution
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.lifecycle.inputs import make_model_settings
from lyrashield.policy.models import StrixProvider, _RequestBoundTurnGuardModel
from lyrashield.policy.physical_requests import PhysicalBudgetAdapterError
from lyrashield.policy.settings import DedupeSettings, LlmSettings, Settings
from lyrashield.tools.web_search.tool import web_search
from tests.test_web_search import _clear_settings_cache, _tool_ctx


class _ByteChunks(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content

    async def __aiter__(self):
        for offset in range(0, len(self.content), 7):
            yield self.content[offset : offset + 7]


def _payload(api: str, usage: bool) -> dict[str, Any]:
    if api == "responses":
        body = {
            "id": "r",
            "object": "response",
            "created_at": 0,
            "model": "gpt-6-luna",
            "status": "completed",
            "output": [
                {
                    "id": "m",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": "OK", "annotations": []}],
                }
            ],
        }
        if usage:
            body["usage"] = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
    else:
        body = {
            "id": "c",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-6-luna",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }
            ],
        }
        if usage:
            body["usage"] = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
    return body


def _reply(api: str, stream: bool, usage: bool = True) -> httpx.Response:
    if not stream:
        return httpx.Response(200, json=_payload(api, usage))
    if api == "responses":
        events = [
            {"type": "response.completed", "response": _payload(api, usage), "sequence_number": 0}
        ]
    else:
        events = [
            {
                "id": "c",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "gpt-6-luna",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": "OK"},
                        "finish_reason": None,
                    }
                ],
            },
            {
                "id": "c",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "gpt-6-luna",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            },
        ]
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        content="".join("data: " + json.dumps(event) + "\n\n" for event in events)
        + "data: [DONE]\n\n",
    )


def _model(api: str, client: AsyncOpenAI) -> Any:
    inner = (
        OpenAIResponsesModel("gpt-6-luna", openai_client=client)
        if api == "responses"
        else OpenAIChatCompletionsModel("gpt-6-luna", openai_client=client)
    )
    return _RequestBoundTurnGuardModel(inner, max_tool_calls_per_turn=10, stream_idle_timeout=0)


async def _run(
    model: Any,
    *,
    streaming: bool,
    hooks: ReportUsageHooks,
    maximum: int = 128,
    extra_body: dict[str, Any] | None = None,
) -> Any:
    settings = make_model_settings(
        None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=maximum
    )
    if extra_body:
        settings.extra_body = extra_body
    agent = Agent(name="Root", model=model, model_settings=settings)
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
        return result
    return await Runner.run(
        agent,
        "offline",
        context={"agent_id": "root"},
        hooks=hooks,
        run_config=RunConfig(tracing_disabled=True),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_litellm_422_cannot_replay_without_output_cap(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    monkeypatch.setattr(litellm, "drop_params", True)
    monkeypatch.setattr(state_module, "_global_report_state", None)
    bodies = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        if len(bodies) == 1:
            return httpx.Response(
                422,
                json={
                    "error": {
                        "message": json.dumps(
                            {
                                "detail": [
                                    {"loc": ["body", "max_completion_tokens"], "msg": "unsupported"}
                                ]
                            }
                        )
                    }
                },
            )
        return _reply("chat", body.get("stream", False))

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _RequestBoundTurnGuardModel(
            LitellmModel("openai/gpt-6-luna", api_key="offline"),
            resolved_client=client,
            max_tool_calls_per_turn=10,
            stream_idle_timeout=0,
        )
        with pytest.raises((APIStatusError, PhysicalBudgetAdapterError)):
            await _run(
                model,
                streaming=streaming,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
    assert len(bodies) == 1
    assert bodies[0]["max_completion_tokens"] == 128
    assert litellm.drop_params is True


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize("api", ["responses", "chat"])
async def test_default_redirect_client_cannot_replay_capped_generation(
    monkeypatch: pytest.MonkeyPatch, status: int, api: str
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    bodies = []

    def respond(request: httpx.Request) -> httpx.Response:
        bodies.append((str(request.url), json.loads(request.content)))
        if len(bodies) == 1:
            return httpx.Response(status, headers={"location": "/v1/forwarded"})
        return _reply(api, stream=False)

    http = DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond))
    assert http.follow_redirects is True
    async with AsyncOpenAI(api_key="offline", http_client=http) as client:
        with pytest.raises(APIStatusError):
            await _run(
                _model(api, client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
        assert http.follow_redirects is True
    assert len(bodies) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["responses", "chat"])
@pytest.mark.parametrize("streaming", [False, True])
async def test_missing_provider_usage_keeps_main_quote(
    monkeypatch: pytest.MonkeyPatch, api: str, streaming: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_estimate_input_tokens", lambda *_args: 0)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 1)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (1, 0, 0, 1))
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _reply(api, json.loads(request.content).get("stream", False), usage=False)

    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1, max_output_tokens=600_000)
    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model(api, client)
        assert (
            await _run(model, streaming=streaming, hooks=hooks, maximum=600_000)
        ).final_output == "OK"
        with pytest.raises(BudgetExceededError):
            await _run(model, streaming=streaming, hooks=hooks, maximum=600_000)
    assert calls == 1


def test_resume_preflight_uses_selected_durable_spend(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = import_module("lyrashield.interface.main")
    monkeypatch.setattr(state_module, "run_dir_for", lambda _name: tmp_path)
    state = ReportState("selected")
    state.record_web_search_cost(1.75, query="prior", mode="turbo")
    state.save_run_data(status="running")
    monkeypatch.setattr(state_module, "_global_report_state", None)
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna", api_key="fixture"),
    )
    model = SimpleNamespace(
        get_response=AsyncMock(
            return_value=SimpleNamespace(
                usage=Usage(requests=1, input_tokens=1, output_tokens=1, total_tokens=2)
            )
        )
    )
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: model)
    )
    with pytest.raises(SystemExit):
        main._run_llm_preflight(
            SimpleNamespace(run_name="selected", resume=True, max_budget_usd=1, warm_up_usages=[]),
            deadline=None,
        )
    model.get_response.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("dispatched", [False, True])
async def test_unknown_paid_search_cannot_refund_its_quote(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, dispatched: bool
) -> None:
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_API_KEY", "offline")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", "10")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_BUDGET_USD", "0.001")
    _clear_settings_cache()
    monkeypatch.setattr(state_module, "run_dir_for", lambda _name: tmp_path)
    state = ReportState("search")
    monkeypatch.setattr(state_module, "_global_report_state", state)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=0.001)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    calls = 0

    class OfflineSearch:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> Any:
            if not dispatched:
                raise ValueError("local client setup failed before dispatch")
            return self

        async def __aexit__(self, *_args: object) -> None:
            pass

        async def post(self, *_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise httpx.ReadTimeout("accepted but acknowledgement lost")

    monkeypatch.setattr(httpx, "AsyncClient", OfflineSearch)
    args = {"query": "CVE fixture"}
    try:
        for _ in range(2):
            result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
            assert result["success"] is False
        assert calls == (1 if dispatched else 0)
        assert sum(hooks._abandoned_floors.values()) == pytest.approx(0.001 if dispatched else 0)
        assert state._web_search_reserved_cost == pytest.approx(0.001 if dispatched else 0)
        assert state.get_total_llm_cost() == 0
    finally:
        _clear_settings_cache()


@pytest.mark.asyncio
async def test_native_dedupe_missing_usage_cannot_release_persisted_success_quote(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _name: tmp_path)
    state = ReportState("missing-dedupe")
    monkeypatch.setattr(state_module, "_global_report_state", state)
    monkeypatch.setattr(hooks_module, "_estimate_out_of_band_input_tokens", lambda *_args: 0)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 1)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (1, 0, 0, 1))
    monkeypatch.setattr(dedupe, "_DEDUPE_MAX_OUTPUT_TOKENS", 600_000)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    calls = 0

    def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _reply("responses", stream=False, usage=False)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        kwargs = {
            "model": _model("responses", client),
            "model_name": "openai/gpt-6-luna",
            "model_settings": make_model_settings(
                None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=600_000
            ),
            "user_msg": "offline",
        }
        response = await dedupe._request_dedupe_judgement(**kwargs)
        assert response.usage.requests == 0
        with pytest.raises(BudgetExceededError):
            await dedupe._request_dedupe_judgement(**kwargs)
    assert calls == 1
    assert sum(hooks._abandoned_floors.values()) == pytest.approx(0.6)
    assert state.get_total_llm_cost() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("free_quote", [False, True])
async def test_native_dual_preflight_missing_usage_stops_unless_quote_is_free(
    monkeypatch: pytest.MonkeyPatch, free_quote: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(warmup, "_estimate_out_of_band_input_tokens", lambda *_args: 0)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 0)
    monkeypatch.setattr(
        hooks_module, "_model_rate_card", lambda _model: (0, 0, 0, 0 if free_quote else 9375)
    )
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna", api_key="fixture"),
        dedupe=DedupeSettings(_env_file=None, model="openai/gpt-6-luna"),
    )
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    usages = []
    calls = 0

    def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _reply("responses", stream=False, usage=False)

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        model = _model("responses", client)
        monkeypatch.setattr(
            warmup,
            "StrixProvider",
            lambda **_kwargs: SimpleNamespace(get_model=lambda _name: model),
        )
        monkeypatch.setattr(dedupe, "resolve_dedupe_model", lambda *_args, **_kwargs: model)
        if free_quote:
            await warmup.warm_up_llm(show_model_warning=False, usages=usages, max_budget_usd=1)
        else:
            with pytest.raises(SystemExit):
                await warmup.warm_up_llm(show_model_warning=False, usages=usages, max_budget_usd=1)
    assert calls == (2 if free_quote else 1)
    assert len(usages) == (2 if free_quote else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route", ["openai/gpt-6-luna", "azure/eu/gpt-6-luna", "azure_ai/gpt-6-luna", "gpt-6-luna"]
)
@pytest.mark.parametrize("api", ["responses", "chat_completions"])
@pytest.mark.parametrize("nonstream", [False, True])
async def test_admitted_native_routes_preserve_endpoint_key_and_wire_cap(
    monkeypatch: pytest.MonkeyPatch, route: str, api: str, nonstream: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None, model=route, disable_streaming=nonstream, request_diagnostics=True
        ),
    )
    provider = StrixProvider(
        settings=settings,
        api_key="bound-fixture",
        base_url="https://bound.invalid/v1",
        api_mode=api,
    )
    model = provider.get_model(route)
    native = model
    while hasattr(native, "_inner"):
        native = native._inner
    resolved = native._get_client()
    requests = []
    wire_api = "responses" if api == "responses" else "chat"

    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append((str(request.url), request.headers["authorization"], payload))
        return _reply(wire_api, payload.get("stream", False))

    offline = DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond))
    original = resolved._client
    monkeypatch.setattr(resolved, "_client", offline)
    try:
        result = await _run(
            model, streaming=True, hooks=ReportUsageHooks(model=route, max_budget_usd=1)
        )
        assert result.final_output == "OK"
    finally:
        await offline.aclose()
        await original.aclose()
    assert len(requests) == 1
    url, credential, payload = requests[0]
    assert url.startswith("https://bound.invalid/")
    assert credential == "Bearer bound-fixture"
    assert (
        payload.get(
            "max_output_tokens", payload.get("max_completion_tokens", payload.get("max_tokens"))
        )
        == 128
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize("api", ["responses", "chat"])
async def test_uncapped_native_redirect_compatibility_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, status: int, api: str
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    calls = 0

    def reply(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return (
            httpx.Response(status, headers={"location": "/v1/forwarded"})
            if calls == 1
            else _reply(api, stream=False)
        )

    async with AsyncOpenAI(
        api_key="offline", http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(reply))
    ) as client:
        result = await Runner.run(
            Agent(
                name="Root",
                model=_model(api, client),
                model_settings=make_model_settings(
                    None, model_name="openai/gpt-6-luna", max_output_tokens=128
                ),
            ),
            "offline",
            run_config=RunConfig(tracing_disabled=True),
        )
        assert result.final_output == "OK"
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
async def test_qualified_litellm_redirect_stops_before_second_generation(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    calls = 0

    def reply(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return (
            httpx.Response(status, headers={"location": "/v1/forwarded"})
            if calls == 1
            else _reply("chat", stream=json.loads(request.content).get("stream", False))
        )

    async with AsyncOpenAI(
        api_key="offline", http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(reply))
    ) as client:
        model = _RequestBoundTurnGuardModel(
            LitellmModel("openai/gpt-6-luna", api_key="offline"), resolved_client=client
        )
        with pytest.raises((APIStatusError, litellm.APIError, litellm.APIConnectionError)):
            await _run(
                model,
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("resolved", [False, True])
@pytest.mark.parametrize(
    "route", ["openrouter/fixture", "anthropic/fixture", "azure/fixture", "custom/fixture"]
)
async def test_unqualified_finite_litellm_fails_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, route: str, resolved: bool
) -> None:
    called = AsyncMock(side_effect=AssertionError("No provider call is authorized"))
    monkeypatch.setattr(litellm, "acompletion", called)
    async with AsyncOpenAI(api_key="offline") as client:
        model = _RequestBoundTurnGuardModel(
            LitellmModel(route, api_key="offline"), resolved_client=client if resolved else None
        )
        with pytest.raises(PhysicalBudgetAdapterError, match="Choose a supported native"):
            await _run(
                model,
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
            )
    called.assert_not_called()


def test_partial_resume_spend_is_not_reset_or_double_recorded(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = import_module("lyrashield.interface.main")
    monkeypatch.setattr(state_module, "run_dir_for", lambda _name: tmp_path)
    state = ReportState("partial")
    state.record_web_search_cost(0.75, query="prior", mode="turbo")
    state.save_run_data(status="running")
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(warmup, "_estimate_out_of_band_input_tokens", lambda *_args: 0)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (0, 0, 0, 9375))
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna", api_key="fixture"),
    )
    model = SimpleNamespace(get_response=AsyncMock())
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: model)
    )
    with pytest.raises(SystemExit):
        main._run_llm_preflight(
            SimpleNamespace(run_name="partial", resume=True, max_budget_usd=1, warm_up_usages=[]),
            deadline=None,
        )
    model.get_response.assert_not_called()
    restored = ReportState("partial")
    restored.hydrate_from_run_dir()
    assert restored.get_total_llm_cost() == pytest.approx(0.75)
    assert len(restored.run_record["web_search_usage"]) == 1
    assert state_module.get_global_report_state() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "usage,reported",
    [
        (Usage(), False),
        ({"requests": 1, "input_tokens": None, "output_tokens": 2}, False),
        ({"requests": 1, "input_tokens": 2}, False),
        (Usage(requests=1, input_tokens=0, output_tokens=0, total_tokens=0), True),
    ],
)
async def test_only_reported_complete_usage_can_release_a_paid_quote(
    monkeypatch: pytest.MonkeyPatch, usage: Any, reported: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 1)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (1, 0, 0, 1))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    await hooks.reserve_out_of_band_request(
        key="first", model="openai/gpt-6-luna", input_tokens=0, max_output_tokens=600_000
    )
    assert (
        await hooks.release_out_of_band_request(key="first", model="openai/gpt-6-luna", usage=usage)
        is reported
    )
    if reported:
        await hooks.reserve_out_of_band_request(
            key="next", model="openai/gpt-6-luna", input_tokens=0, max_output_tokens=600_000
        )
    else:
        with pytest.raises(BudgetExceededError):
            await hooks.reserve_out_of_band_request(
                key="next", model="openai/gpt-6-luna", input_tokens=0, max_output_tokens=600_000
            )
    assert sum(hooks._abandoned_floors.values()) == pytest.approx(0 if reported else 0.6)


def test_partial_resume_can_probe_remaining_allowance_and_record_once(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = import_module("lyrashield.interface.main")
    monkeypatch.setattr(state_module, "run_dir_for", lambda _name: tmp_path)
    state = ReportState("partial-ok")
    state.record_web_search_cost(0.75, query="prior", mode="turbo")
    state.save_run_data(status="running")
    monkeypatch.setattr(state_module, "_global_report_state", None)
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-luna", api_key="fixture"),
    )
    usage = Usage(requests=1, input_tokens=7, output_tokens=2, total_tokens=9)

    async def respond(**_kwargs: Any) -> Any:
        assert state_module.get_global_report_state().get_total_llm_cost() == pytest.approx(0.75)
        return SimpleNamespace(usage=usage)

    model = SimpleNamespace(get_response=AsyncMock(side_effect=respond))
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: model)
    )
    args = SimpleNamespace(run_name="partial-ok", resume=True, max_budget_usd=1, warm_up_usages=[])
    main._run_llm_preflight(args, deadline=None)
    model.get_response.assert_awaited_once()
    restored = ReportState("partial-ok")
    restored.hydrate_from_run_dir()
    assert restored.get_total_llm_cost() == pytest.approx(0.75)
    assert args.warm_up_usages == [(settings.llm.model, usage)]
    for route, probe_usage in args.warm_up_usages:
        restored.record_sdk_usage(
            agent_id="warmup", agent_name="warmup", model=route, usage=probe_usage
        )
    assert 0.75 < restored.get_total_llm_cost() < 0.76
    assert restored.get_total_llm_usage()["total_tokens"] == 9
    assert len(restored.run_record["web_search_usage"]) == 1
    assert state_module.get_global_report_state() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("budget,second_allowed", [(1.0, False), (1.3, True)])
async def test_image_recovery_requires_fresh_covered_admission(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, budget: float, second_allowed: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (0, 0, 0, 4687.5))
    monkeypatch.setattr(execution, "_compact_session", AsyncMock(return_value=False))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=budget)
    session = SQLiteSession("root", tmp_path / "image.db")
    await session.add_items(
        [
            {
                "type": "function_call",
                "call_id": "screenshot",
                "name": "browser",
                "arguments": "{}",
            },
            {
                "type": "function_call_output",
                "call_id": "screenshot",
                "output": [
                    {"type": "input_image", "image_url": "data:image/png;base64,Zml4dHVyZQ=="}
                ],
            },
        ]
    )
    bodies = []
    admissions = []

    def respond(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        admissions.append(sum(hooks._agent_reservations.values()))
        if len(bodies) == 1:
            return httpx.Response(400, json={"error": {"message": "does not support image input"}})
        return _reply("responses", stream=True)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        agent = Agent(
            name="Root",
            model=_model("responses", client),
            model_settings=make_model_settings(
                None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
            ),
        )
        cycle = execution._run_cycle(
            agent,
            coordinator,
            "root",
            input_data="inspect",
            run_config=RunConfig(tracing_disabled=True),
            context={"agent_id": "root", "coordinator": coordinator},
            max_turns=3,
            session=session,
            interactive=False,
            event_sink=None,
            hooks=hooks,
        )
        if second_allowed:
            result = await cycle
            assert result.final_output == "OK"
        else:
            with pytest.raises(BudgetExceededError):
                await cycle
    assert len(bodies) == (2 if second_allowed else 1)
    assert admissions == pytest.approx([0.6, 1.2] if second_allowed else [0.6])
    assert "input_image" in json.dumps(bodies[0])
    if second_allowed:
        assert "input_image" not in json.dumps(bodies[1])
        assert "image rejected by the model" in json.dumps(bodies[1])
    # A capability rejection does not establish a billing refund. Its quote
    # remains held, while a subsequent request owns a distinct admission.
    assert sum(hooks._agent_reservations.values()) + sum(
        hooks._agent_abandoned_floors.values()
    ) == pytest.approx(0.6)
    session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["prompt_tokens", "completion_tokens"])
async def test_incomplete_wire_chat_stream_usage_cannot_refund_quote(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (0, 0, 0, 4687.5))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    calls = 0

    def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        usage = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
        usage.pop(missing)
        chunk = {
            "id": "c",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-6-luna",
            "choices": [],
            "usage": usage,
        }
        content = _reply("chat", stream=True).content.replace(
            b"data: [DONE]", ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]").encode()
        )
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
    assert sum(hooks._agent_abandoned_floors.values()) == pytest.approx(0.6)


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_uncapped_litellm_422_compatibility_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    # Test-only transport injection exercises LiteLLM's original native-client
    # resolution with no credentials, global settings or runtime factory changes.
    native = import_module("litellm.llms.openai.openai")
    monkeypatch.setattr(litellm, "drop_params", True)
    bodies = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        if len(bodies) == 1:
            return httpx.Response(
                422,
                json={
                    "error": {
                        "message": json.dumps(
                            {
                                "detail": [
                                    {"loc": ["body", "max_completion_tokens"], "msg": "unsupported"}
                                ]
                            }
                        )
                    }
                },
            )
        return _reply("chat", body.get("stream", False))

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        monkeypatch.setattr(
            native.OpenAIChatCompletion, "_get_openai_client", lambda *_a, **_kw: client
        )
        agent = Agent(
            name="Root",
            model=_RequestBoundTurnGuardModel(LitellmModel("openai/gpt-6-luna", api_key="offline")),
            model_settings=make_model_settings(
                None, model_name="openai/gpt-6-luna", max_output_tokens=128
            ),
        )
        if streaming:
            result = Runner.run_streamed(
                agent, "offline", run_config=RunConfig(tracing_disabled=True)
            )
            async for _event in result.stream_events():
                pass
        else:
            result = await Runner.run(agent, "offline", run_config=RunConfig(tracing_disabled=True))
        assert result.final_output == "OK"
    assert len(bodies) == 2
    assert bodies[0]["max_completion_tokens"] == 128
    assert "max_completion_tokens" not in bodies[1]
    assert litellm.drop_params is True


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_evidenced_zero_wire_usage_can_reconcile_paid_quote(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    monkeypatch.setattr(hooks_module, "_reservation_input_rate", lambda _model: 0)
    monkeypatch.setattr(hooks_module, "_model_rate_card", lambda _model: (0, 0, 0, 4687.5))
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    calls = 0

    def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _payload("responses", usage=True)
        payload["usage"] = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        content = (
            (
                "data: "
                + json.dumps(
                    {"type": "response.completed", "response": payload, "sequence_number": 0}
                )
                + "\n\ndata: [DONE]\n\n"
            ).encode()
            if streaming
            else json.dumps(payload).encode()
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream" if streaming else "application/json"},
            stream=_ByteChunks(content),
        )

    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(respond)),
    ) as client:
        for _attempt in range(2):
            await _run(_model("responses", client), streaming=streaming, hooks=hooks)
    assert calls == 2
    assert not hooks._agent_abandoned_floors
    assert not hooks._agent_reservations


@pytest.mark.asyncio
@pytest.mark.parametrize("api,cap", [("responses", None), ("responses", 129), ("chat", 0)])
async def test_actual_wire_output_cap_cannot_be_removed_or_raised(
    monkeypatch: pytest.MonkeyPatch, api: str, cap: int | None
) -> None:
    monkeypatch.setattr(state_module, "_global_report_state", None)
    called = AsyncMock(side_effect=AssertionError("Unquoted body must not reach transport"))
    async with AsyncOpenAI(
        api_key="offline",
        http_client=DefaultAsyncHttpxClient(transport=httpx.MockTransport(called)),
    ) as client:
        with pytest.raises(Exception) as caught:
            await _run(
                _model(api, client),
                streaming=False,
                hooks=ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1),
                extra_body={
                    "max_output_tokens" if api == "responses" else "max_completion_tokens": cap
                },
            )
        assert isinstance(
            caught.value, (PhysicalBudgetAdapterError, litellm.APIConnectionError)
        ) or isinstance(caught.value.__cause__, PhysicalBudgetAdapterError)
    called.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override", ["custom_llm_provider", "fallbacks", "model_list", "context_window_fallback_dict"]
)
async def test_finite_litellm_provider_override_cannot_escape_resolved_transport(
    monkeypatch: pytest.MonkeyPatch, override: str
) -> None:
    called = AsyncMock(side_effect=AssertionError("Unqualified provider override"))
    monkeypatch.setattr(litellm, "acompletion", called)
    async with AsyncOpenAI(api_key="offline") as client:
        model = _RequestBoundTurnGuardModel(
            LitellmModel("openai/gpt-6-luna", api_key="offline"), resolved_client=client
        )
        settings = make_model_settings(
            None, model_name="openai/gpt-6-luna", bounded_budget=True, max_output_tokens=128
        )
        settings.extra_args = {override: "unqualified"}
        with pytest.raises(PhysicalBudgetAdapterError, match="Choose a supported native"):
            await Runner.run(
                Agent(name="Root", model=model, model_settings=settings),
                "offline",
                run_config=RunConfig(tracing_disabled=True),
            )
    called.assert_not_called()
