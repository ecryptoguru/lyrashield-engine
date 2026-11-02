"""Request-scoped physical submission guard for supported finite-budget SDK adapters."""

from __future__ import annotations

import copy
import json
import math
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import fields
from typing import TYPE_CHECKING, Any, cast

import httpx
from agents.model_settings import ModelSettings
from agents.models.interface import Model
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel, OpenAIResponsesWSModel
from agents.usage import Usage
from openai import AsyncOpenAI
from openai.types.responses import ResponseCompletedEvent


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


_finite_attempt: ContextVar[bool] = ContextVar("lyrashield_finite_physical_attempt", default=False)


class FiniteBudgetModelSettings(ModelSettings):
    """Owned finite admission identity, independent of SDK retry suppression."""

    _lyrashield_finite_budget = True


@contextmanager
def finite_physical_attempt(bounded: bool) -> Iterator[None]:
    token = _finite_attempt.set(bounded or _finite_attempt.get())
    try:
        yield
    finally:
        _finite_attempt.reset(token)


class PhysicalBudgetAdapterError(RuntimeError):
    """A finite request cannot be sent with provable physical/token bounds."""


class _ResolvedClientSettings(ModelSettings):
    """Keep a resolved client at runtime without exposing it in SDK trace data."""

    def to_json_dict(self) -> dict[str, Any]:
        values = {field.name: getattr(self, field.name) for field in fields(ModelSettings)}
        values["extra_args"] = {
            key: value for key, value in (self.extra_args or {}).items() if key != "client"
        }
        return ModelSettings(**values).to_json_dict()


class _UsageEvidence:
    """Bounded decoded usage evidence; only completed generation can settle.

    The observer never alters response bytes. Unknown/oversized protocols keep
    their quote, rather than manufacture a zero-cost receipt.
    """

    _MAX_FRAME_BYTES = 1_048_576
    _MAX_LINES = 4096

    def __init__(self, *, sse: bool) -> None:
        self.sse = sse
        self.buffer = bytearray()
        self.overflow = False
        self.reported = False
        self._bytes = 0
        self._lines = 0
        self._response_id: str | None = None
        self._choices: set[int] = set()
        self._finished: set[int] = set()

    def _invalidate(self) -> None:
        self.overflow = True
        self.reported = False
        self.buffer.clear()

    def _observe_choices(self, choices: list[Any]) -> bool:
        # Usage preceding later generation is provisional, even if the SDK
        # retains it as its final usage object.
        self.reported = False
        for choice in choices:
            if not isinstance(choice, dict) or type(choice.get("index")) is not int:
                self._invalidate()
                return False
            index = choice["index"]
            self._choices.add(index)
            if choice.get("finish_reason") is not None:
                self._finished.add(index)
            else:
                self._finished.discard(index)
        return True

    def _inspect(self, data: bytes | bytearray | memoryview) -> None:
        try:
            payload = json.loads(bytes(data))
        except (ValueError, UnicodeError):
            return
        if not isinstance(payload, dict):
            return
        chat = payload.get("object") in {"chat.completion", "chat.completion.chunk"}
        if self.sse and not chat:
            if payload.get("type") != "response.completed":
                self.reported = False
                return
            payload = payload.get("response")
            if not isinstance(payload, dict) or payload.get("status") != "completed":
                self.reported = False
                return
        response_id = payload.get("id")
        if isinstance(response_id, str):
            if self._response_id is not None and response_id != self._response_id:
                self._invalidate()
                return
            self._response_id = response_id
        choices = payload.get("choices")
        if (
            self.sse
            and isinstance(choices, list)
            and choices
            and not self._observe_choices(choices)
        ):
            return
        usage = payload.get("usage")
        if not isinstance(usage, dict):
            return
        keys = ("prompt_tokens", "completion_tokens") if chat else ("input_tokens", "output_tokens")
        complete = all(
            isinstance(usage.get(key), (int, float))
            and not isinstance(usage.get(key), bool)
            and math.isfinite(usage[key])
            and usage[key] >= 0
            for key in keys
        )
        self.reported = complete and (
            not self.sse or not chat or bool(self._choices and self._choices <= self._finished)
        )

    def feed(self, chunk: bytes) -> None:
        if self.overflow:
            return
        # Check before concatenating/copying an untrusted transport span.
        if len(chunk) > self._MAX_FRAME_BYTES - self._bytes:
            self._invalidate()
            return
        self._bytes += len(chunk)
        if not self.sse:
            self.buffer.extend(chunk)
            return
        position = 0
        span = memoryview(chunk)
        while position < len(chunk):
            newline = chunk.find(b"\n", position)
            if newline < 0:
                self.buffer.extend(span[position:])
                return
            self._lines += 1
            if self._lines > self._MAX_LINES:
                self._invalidate()
                return
            line: bytearray | memoryview
            if self.buffer:
                self.buffer.extend(span[position:newline])
                line = self.buffer
            else:
                line = span[position:newline]
            if bytes(line[:5]) == b"data:":
                self._inspect(line[5:])
            self.buffer.clear()
            position = newline + 1

    def finish(self) -> None:
        if not self.sse and not self.overflow:
            self._inspect(self.buffer)
        self.buffer.clear()


class _ObservedUsageResponse(httpx.Response):
    """Observe HTTPX-decoded bytes once while preserving its wire decoding."""

    def __init__(self, original: httpx.Response, evidence: _UsageEvidence) -> None:
        super().__init__(
            original.status_code,
            headers=original.headers,
            stream=original.stream,
            extensions=original.extensions,
            default_encoding=original.default_encoding,
        )
        self.evidence = evidence

    async def aiter_bytes(self, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        try:
            async for chunk in super().aiter_bytes(chunk_size):
                self.evidence.feed(chunk)
                yield chunk
            self.evidence.finish()
        finally:
            if not self.is_closed:
                await self.aclose()


class _SinglePostTransport(httpx.AsyncBaseTransport):
    def __init__(self, original: httpx.AsyncClient, maximum: int) -> None:
        self.original = original
        self.maximum = maximum
        self.sent = False
        self.usage_evidence: _UsageEvidence | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.sent:
            raise PhysicalBudgetAdapterError(
                "Finite budget blocked an unreserved provider compatibility replay."
            )
        if request.method != "POST":
            raise PhysicalBudgetAdapterError("Finite generation requires one bounded POST.")
        try:
            payload = json.loads(await request.aread())
        except (ValueError, UnicodeError) as exc:
            raise PhysicalBudgetAdapterError(
                "Cannot verify the finite generation output cap."
            ) from exc
        caps = (
            [
                payload[key]
                for key in ("max_output_tokens", "max_completion_tokens", "max_tokens")
                if key in payload
            ]
            if isinstance(payload, dict)
            else []
        )
        if not caps or any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= self.maximum
            for value in caps
        ):
            raise PhysicalBudgetAdapterError(
                "Finite generation is missing its configured hard output cap."
            )
        self.sent = True
        # Auth and redirect flow run above this counter on the scoped client.
        # Reuse the resolved URL's pool/TLS transport below those flows, so
        # every challenge-driven physical dispatch must re-enter this guard.
        transport = self.original._transport_for_url(request.url)
        response = await transport.handle_async_request(request)
        evidence = _UsageEvidence(
            sse="text/event-stream" in response.headers.get("content-type", "")
        )
        self.usage_evidence = evidence
        if response.is_stream_consumed:
            evidence.feed(response.content)
            evidence.finish()
        else:
            response = _ObservedUsageResponse(response, evidence)
        return response

    async def aclose(self) -> None:
        # This proxy does not own the provider's pooled client/transport.
        pass


@asynccontextmanager
async def _physical_call(
    model: Model, settings: ModelSettings, resolved_client: AsyncOpenAI | None = None
) -> AsyncIterator[tuple[Model, ModelSettings, _SinglePostTransport | None]]:
    finite = _finite_attempt.get() or getattr(settings, "_lyrashield_finite_budget", False) is True
    if not finite or getattr(model, "_budget_zero_cost", False) is True:
        yield model, settings, None
        return
    if isinstance(model, OpenAIResponsesWSModel):
        raise PhysicalBudgetAdapterError(
            "WebSocket generation has no qualified finite-budget frame guard. "
            "Choose the supported HTTP Responses transport."
        )
    maximum = settings.max_tokens
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0:
        raise PhysicalBudgetAdapterError(
            "Finite generation requires a positive hard output-token cap."
        )
    native = isinstance(model, (OpenAIResponsesModel, OpenAIChatCompletionsModel))
    if native:
        resolved = cast("Any", model)._get_client()
    else:
        # Lazy: native routes do not need the optional LiteLLM provider import.
        from agents.extensions.models.litellm_model import LitellmModel  # noqa: PLC0415

        if not isinstance(model, LitellmModel):
            raise PhysicalBudgetAdapterError(
                "This SDK provider adapter has no qualified finite-budget transport. "
                "Choose a supported native OpenAI/Azure route."
            )
        # LiteLLM's client argument is provider-specific. Only an existing,
        # explicitly resolved native client is qualified here. Never infer
        # credentials or replace another provider's protocol with OpenAI.
        extra_args = settings.extra_args or {}
        if not model.model.startswith("openai/") or any(
            key in extra_args
            for key in (
                "custom_llm_provider",
                "fallbacks",
                "model_list",
                "context_window_fallback_dict",
            )
        ):
            raise PhysicalBudgetAdapterError(
                "This LiteLLM route cannot prove native-client finite-budget coverage. "
                "Choose a supported native OpenAI/Azure route."
            )
        resolved = resolved_client or extra_args.get("client")
        if not isinstance(resolved, AsyncOpenAI):
            raise PhysicalBudgetAdapterError(
                "This provider adapter has no qualified finite-budget transport. "
                "Choose a supported native OpenAI/Azure route or an explicitly resolved "
                "native-client adapter; the configured budget remains enforced."
            )
    if not isinstance(resolved, AsyncOpenAI):
        raise PhysicalBudgetAdapterError(
            "The resolved provider client cannot enforce a finite budget."
        )
    original_http = resolved._client
    transport = _SinglePostTransport(original_http, maximum)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=original_http.timeout,
        headers=original_http.headers,
        cookies=original_http.cookies,
        auth=original_http.auth,
        event_hooks={key: list(value) for key, value in original_http.event_hooks.items()},
        follow_redirects=False,
    ) as proxy:
        client = resolved.with_options(http_client=proxy, max_retries=0)
        if native:
            scoped = cast("Any", copy.copy(model))
            scoped._client = client
            yield scoped, settings, transport
        else:
            values = {field.name: getattr(settings, field.name) for field in fields(ModelSettings)}
            values["extra_args"] = {**(settings.extra_args or {}), "client": client}
            yield model, _ResolvedClientSettings(**values), transport


class _PhysicalAttemptModel(Model):
    """Keep one resolved model call inside one physical generation admission."""

    _lyrashield_physical_guarded = True

    def __init__(self, inner: Model, resolved_client: AsyncOpenAI | None = None) -> None:
        self._inner = inner
        self._resolved_client = resolved_client

    async def close(self) -> None:
        await self._inner.close()

    def get_retry_advice(self, request: Any) -> Any:
        return self._inner.get_retry_advice(request)

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        settings = kwargs["model_settings"] if "model_settings" in kwargs else args[2]
        async with _physical_call(self._inner, settings, self._resolved_client) as (
            model,
            effective,
            transport,
        ):
            if "model_settings" in kwargs:
                kwargs = {**kwargs, "model_settings": effective}
            else:
                args = (*args[:2], effective, *args[3:])
            response = await model.get_response(*args, **kwargs)
            if transport is not None and not (
                transport.usage_evidence is not None and transport.usage_evidence.reported
            ):
                response.usage = Usage()
            return response

    async def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        settings = kwargs["model_settings"] if "model_settings" in kwargs else args[2]
        async with _physical_call(self._inner, settings, self._resolved_client) as (
            model,
            effective,
            transport,
        ):
            if "model_settings" in kwargs:
                kwargs = {**kwargs, "model_settings": effective}
            else:
                args = (*args[:2], effective, *args[3:])
            stream = model.stream_response(*args, **kwargs)
            try:
                async for event in stream:
                    if (
                        transport is not None
                        and isinstance(event, ResponseCompletedEvent)
                        and not (
                            transport.usage_evidence is not None
                            and transport.usage_evidence.reported
                        )
                    ):
                        event.response.usage = None
                    yield event
            finally:
                close = getattr(stream, "aclose", None)
                if callable(close):
                    await close()


def guard_physical_model(model: Any, *, resolved_client: AsyncOpenAI | None = None) -> Any:
    """Guard SDK provider models; already-owned wrappers retain their guard.

    Structural test/in-process implementations are not SDK provider adapters.
    All models resolved by the production provider factory are SDK Models and
    must qualify their finite transport before dispatch.
    """
    if (
        not isinstance(model, Model)
        or getattr(model, "_lyrashield_physical_guarded", False) is True
    ):
        return model
    if getattr(model, "_physical_passthrough", False) is True:
        scoped = cast("Any", copy.copy(model))
        scoped._inner = guard_physical_model(scoped._inner, resolved_client=resolved_client)
        scoped._lyrashield_physical_guarded = True
        return scoped
    return _PhysicalAttemptModel(model, resolved_client)
