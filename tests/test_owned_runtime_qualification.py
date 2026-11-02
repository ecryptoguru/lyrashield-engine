"""Regression contracts for the owned runtime qualification fixes."""

from __future__ import annotations

import json
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from agents import Runner
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from agents.usage import Usage
from openai import AsyncOpenAI, BadRequestError

from lyrashield.artifacts import dedupe
from lyrashield.artifacts.state import ReportState
from lyrashield.interface import warmup
from lyrashield.lifecycle import execution
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError
from lyrashield.policy.models import (
    StrixProvider,
    configure_sdk_model_defaults,
    reset_sdk_model_defaults,
)
from lyrashield.policy.settings import DedupeSettings, LlmSettings, Settings


@pytest.fixture(autouse=True)
def reset_provider_defaults():
    reset_sdk_model_defaults()
    yield
    reset_sdk_model_defaults()


@pytest.mark.parametrize(
    "message,expected",
    [
        ("This model does not support image input", True),
        ("No endpoints found that support image input", True),
        ("image_url is only supported by certain models", True),
        ("unknown variant `image_url`", True),
        ("Invalid tool schema", False),
        ("Context limit exceeded counting image/vision expansion", False),
        ("Image download failed", False),
        ("Invalid image URL", False),
    ],
)
def test_only_explicit_unsupported_image_errors_allow_stripping(message, expected):
    error = BadRequestError(
        message,
        response=httpx.Response(400, request=httpx.Request("POST", "https://example.test")),
        body=None,
    )
    assert execution._is_image_rejection(error) is expected


@pytest.mark.parametrize(
    "model_name", [None, "gpt-6-sol", "openai/gpt-6-luna", "litellm/openai/gpt-6-sol"]
)
@pytest.mark.parametrize("base_url", [None, "https://proxy.example/v1"])
def test_gpt6_api_selection_does_not_depend_on_endpoint(model_name, base_url):
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None, model="openai/gpt-6-sol", api_key="fixture", api_base=base_url
        ),
    )
    configure_sdk_model_defaults(settings)
    model = StrixProvider(settings=settings).get_model(model_name)._inner
    assert isinstance(model, OpenAIResponsesModel)


def test_explicit_chat_policy_is_honored_for_custom_gpt6_endpoint():
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model="openai/gpt-6-sol",
            api_key="fixture",
            api_base="https://proxy.example/v1",
            api_mode="chat_completions",
        ),
    )
    configure_sdk_model_defaults(settings)
    model = StrixProvider(settings=settings).get_model("openai/gpt-6-luna")._inner
    assert isinstance(model, OpenAIChatCompletionsModel)


@pytest.mark.asyncio
@pytest.mark.parametrize("remaining", [12.0, 300.0])
async def test_warmup_is_short_and_bounded_by_shared_deadline(monkeypatch, remaining):
    now = [0.0]
    deadline = RunDeadline.start(remaining, clock=lambda: now[0])
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-sol", api_key="fixture", timeout=300),
    )
    response = SimpleNamespace(usage=object())
    model = SimpleNamespace(get_response=AsyncMock(return_value=response))
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: model)
    )
    original_wait_for = warmup.asyncio.wait_for
    timeouts = []

    async def wait_for(awaitable, *, timeout):
        timeouts.append(timeout)
        return await original_wait_for(awaitable, timeout=timeout)

    monkeypatch.setattr(warmup.asyncio, "wait_for", wait_for)
    usages = []
    await warmup.warm_up_llm(show_model_warning=False, usages=usages, deadline=deadline)
    assert len(timeouts) == 1
    assert 0 < timeouts[0] <= min(30.0, remaining)
    assert timeouts[0] == pytest.approx(min(30.0, remaining), abs=0.05)
    assert usages == [(settings.llm.model, response.usage)]
    assert (
        model.get_response.call_args.kwargs["model_settings"].extra_args["timeout"] == timeouts[0]
    )


@pytest.mark.asyncio
async def test_expired_deadline_never_calls_warmup_provider(monkeypatch):
    deadline = RunDeadline.start(1, clock=lambda: 2, started_at=0)
    provider = AsyncMock()
    monkeypatch.setattr(warmup, "StrixProvider", provider)
    with pytest.raises(RunDeadlineExceededError):
        await warmup.warm_up_llm(show_model_warning=False, deadline=deadline)
    provider.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("unsupported", [False, True])
async def test_image_recovery_preserves_unrelated_bad_request_evidence(monkeypatch, unsupported):

    message = "does not support image input" if unsupported else "invalid tool schema"
    failure = BadRequestError(
        message,
        response=httpx.Response(400, request=httpx.Request("POST", "https://example.test")),
        body=None,
    )

    class FailedStream:
        run_loop_exception = None

        async def stream_events(self):
            raise failure
            yield

        def cancel(self, **_kwargs):
            pass

    stream = FailedStream()
    run = Mock(return_value=stream)
    stripper = AsyncMock(side_effect=[True, False])
    monkeypatch.setattr(Runner, "run_streamed", run)
    monkeypatch.setattr(execution, "strip_all_images_from_session", stripper)
    monkeypatch.setattr(execution, "_compact_session", AsyncMock(return_value=False))
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    with pytest.raises(BadRequestError) as caught:
        await execution._run_cycle(
            object(),
            coordinator,
            "root",
            input_data="task",
            run_config=object(),
            context={},
            max_turns=5,
            session=SimpleNamespace(get_items=AsyncMock(return_value=[])),
            interactive=False,
            event_sink=None,
            hooks=None,
        )
    assert caught.value is failure
    assert run.call_count == (2 if unsupported else 1)
    assert stripper.await_count == (2 if unsupported else 0)


@pytest.mark.asyncio
async def test_dedupe_preflight_consumes_same_allowance_and_preserves_main_usage(monkeypatch):
    now = [0.0]
    deadline = RunDeadline.start(20, clock=lambda: now[0])
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(_env_file=None, model="openai/gpt-6-sol", api_key="fixture"),
        dedupe=DedupeSettings(_env_file=None, model="openai/gpt-6-luna"),
    )
    usage = object()

    async def main_response(**_kwargs):
        now[0] += 15
        return SimpleNamespace(usage=usage)

    main = SimpleNamespace(get_response=AsyncMock(side_effect=main_response))
    judge = SimpleNamespace(get_response=AsyncMock(return_value=SimpleNamespace(usage=usage)))
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: main)
    )
    monkeypatch.setattr(dedupe, "resolve_dedupe_model", lambda *_args, **_kwargs: judge)
    usages = []
    await warmup.warm_up_llm(show_model_warning=False, usages=usages, deadline=deadline)
    assert usages == [(settings.llm.model, usage), (settings.dedupe.model, usage)]
    assert judge.get_response.call_args.kwargs["model_settings"].extra_args["timeout"] == 5


@pytest.mark.asyncio
async def test_gpt6_responses_wire_preserves_output_token_limit_and_credentials():

    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None,
            model="openai/gpt-6-sol",
            api_key="fixture",
            api_base="https://proxy.example/v1",
        ),
    )
    configure_sdk_model_defaults(settings)
    model = StrixProvider(settings=settings).get_model("openai/gpt-6-luna")._inner
    original = model._client
    captured = []

    async def respond(request):
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "id": "resp_fixture",
                "object": "response",
                "created_at": 1,
                "model": "gpt-6-luna",
                "status": "completed",
                "output": [],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            },
        )

    model._client = AsyncOpenAI(
        api_key="fixture",
        base_url=original.base_url,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    try:
        await model.get_response(
            None, "OK", ModelSettings(max_tokens=73), [], None, [], ModelTracing.DISABLED
        )
    finally:
        await model._client.close()
        await original.close()
    assert len(captured) == 1
    assert str(captured[0].url) == "https://proxy.example/v1/responses"
    body = json.loads(captured[0].content)
    assert body["max_output_tokens"] == 73
    assert "max_tokens" not in body
    assert captured[0].headers["authorization"] == "Bearer fixture"


@pytest.mark.asyncio
async def test_preflight_respects_configured_output_cap(monkeypatch):
    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None, model="openai/gpt-6-sol", api_key="fixture", max_output_tokens=7
        ),
    )
    model = SimpleNamespace(get_response=AsyncMock(return_value=SimpleNamespace(usage=None)))
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: model)
    )
    await warmup.warm_up_llm(show_model_warning=False)
    assert model.get_response.call_args.kwargs["model_settings"].max_tokens == 7


def test_failed_preflight_persists_paid_usage_and_terminal_receipt(tmp_path, monkeypatch):
    main = import_module("lyrashield.interface.main")
    state = ReportState("preflight-fixture")
    state._run_dir = tmp_path
    args = SimpleNamespace(run_name="preflight-fixture", warm_up_usages=[])

    settings = Settings(
        _env_file=None,
        llm=LlmSettings(
            _env_file=None, model="openai/gpt-6-sol", api_key="fixture", max_output_tokens=7
        ),
        dedupe=DedupeSettings(_env_file=None, model="openai/gpt-6-luna"),
    )
    usage = Usage(requests=1, input_tokens=7, output_tokens=2, total_tokens=9)
    root = SimpleNamespace(get_response=AsyncMock(return_value=SimpleNamespace(usage=usage)))
    judge = SimpleNamespace(get_response=AsyncMock(side_effect=TimeoutError("judge timeout")))
    monkeypatch.setattr(warmup, "load_settings", lambda: settings)
    monkeypatch.setattr(
        warmup, "StrixProvider", lambda **_kwargs: SimpleNamespace(get_model=lambda _name: root)
    )
    monkeypatch.setattr(dedupe, "resolve_dedupe_model", lambda *_args, **_kwargs: judge)
    monkeypatch.setattr(main, "ReportState", lambda _name: state)
    with pytest.raises(SystemExit):
        main._run_llm_preflight(args, deadline=None)
    receipt = json.loads((tmp_path / "run.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["terminal_reason"] == "llm_preflight_failed"
    assert receipt["llm_usage"]["total_tokens"] == 9
    assert args.warm_up_usages == []
    assert root.get_response.call_args.kwargs["model_settings"].max_tokens == 7
    assert judge.get_response.call_args.kwargs["model_settings"].max_tokens == 7


def test_successful_preflight_leaves_usage_for_single_ui_recording(monkeypatch):
    main = import_module("lyrashield.interface.main")
    args = SimpleNamespace(run_name="preflight-fixture", warm_up_usages=[])
    usage = Usage(requests=1, input_tokens=1, output_tokens=1, total_tokens=2)

    async def successful_probe(**kwargs):
        kwargs["usages"].append(("openai/gpt-6-sol", usage))

    factory = Mock(
        side_effect=AssertionError("Successful preflight must defer ledger recording to UI")
    )
    monkeypatch.setattr(main, "warm_up_llm", successful_probe)
    monkeypatch.setattr(main, "ReportState", factory)
    main._run_llm_preflight(args, deadline=None)
    assert args.warm_up_usages == [("openai/gpt-6-sol", usage)]
    factory.assert_not_called()
