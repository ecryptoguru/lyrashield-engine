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
from agents.models.chatcmpl_converter import Converter as ChatConverter
from agents.models.fake_id import FAKE_RESPONSES_ID
from agents.models.interface import Model
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel, OpenAIResponsesWSModel
from agents.usage import Usage
from agents.util._json import _to_dump_compatible
from openai import AsyncAzureOpenAI, AsyncOpenAI, NotGiven, Omit
from openai._streaming import SSEDecoder
from openai.types.chat.completion_create_params import CompletionCreateParamsBase
from openai.types.responses import ResponseCompletedEvent
from openai.types.responses.response_create_params import ResponseCreateParamsBase
from openai.types.responses.response_usage import InputTokensDetails


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
        self._decoder = SSEDecoder()
        self._done = False
        self._raw_counts: tuple[int | float, int | float] | None = None
        self._cache_write_known = False

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
            self._invalidate()
            return
        if not isinstance(payload, dict):
            self._invalidate()
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
        # A terminal receipt must identify itself. A prior content frame's ID
        # cannot establish the authority of an anonymous usage frame.
        if not isinstance(response_id, str) or not response_id:
            self._invalidate()
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
        if self.reported:
            self._raw_counts = (usage[keys[0]], usage[keys[1]])
            details = usage.get("prompt_tokens_details" if chat else "input_tokens_details")
            cached = details.get("cached_tokens", 0) if isinstance(details, dict) else None
            self._cache_write_known = (
                isinstance(details, dict)
                and type(details.get("cache_write_tokens")) is int
                and details["cache_write_tokens"] >= 0
                and type(cached) is int
                and cached >= 0
                and cached + details["cache_write_tokens"] <= usage[keys[0]]
            )

    def _line(self, data: bytes | bytearray | memoryview) -> bool:
        try:
            line = bytes(data).decode("utf-8").removesuffix("\r")
        except UnicodeError:
            self._invalidate()
            return True
        if "\r" in line:
            self._invalidate()
            return True
        event = self._decoder.decode(line)
        if event is None:
            return False
        if event.data.startswith("[DONE]"):
            self._done = True
            return True
        if event.event is not None and not event.event.startswith("response."):
            self._invalidate()
            return True
        self._inspect(event.data.encode("utf-8"))
        return self.overflow

    def matches(self, response: Any) -> bool:
        if not self.reported or self.overflow or self._raw_counts is None:
            return False
        usage = getattr(response, "usage", None)
        if usage is None or self._raw_counts != (
            getattr(usage, "input_tokens", None),
            getattr(usage, "output_tokens", None),
        ):
            return False
        ids = {getattr(response, "response_id", None), getattr(response, "id", None)}
        for item in getattr(response, "output", []):
            provider = getattr(item, "provider_data", None)
            if isinstance(provider, dict):
                ids.add(provider.get("response_id"))
        ids.discard(None)
        ids.discard(FAKE_RESPONSES_ID)
        matched = bool(self._response_id and ids == {self._response_id})
        if matched:
            # SDK defaults erase the distinction between omitted and explicit
            # zero cache-write usage. Preserve only that authority bit locally.
            entries = [
                usage,
                *(getattr(usage, "request_usage_entries", None) or []),
                *(getattr(usage, "_agents_sdk_request_usages", None) or []),
            ]
            for entry in entries:
                details = getattr(entry, "input_tokens_details", None)
                if details is None:
                    # Supply the DTO placeholder the SDK would otherwise create,
                    # retaining no raw fields as evidence of reported buckets.
                    details = InputTokensDetails.model_construct(
                        _fields_set=set(), cached_tokens=0, cache_write_tokens=0
                    )
                    details.__pydantic_fields_set__.clear()
                    entry.input_tokens_details = details
                cast("Any", details)._lyrashield_cache_write_known = self._cache_write_known
        return matched

    def feed(self, chunk: bytes) -> None:
        if self.overflow or self._done:
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
            stop = self._line(line)
            self.buffer.clear()
            if stop:
                return
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


# Fields that can replace the priced route, input/context/schema or response
# modality. They must match the SDK projection of the original call arguments,
# not extra_body/client defaults applied afterwards.
_QUOTED_FIELDS = (
    "model",
    "input",
    "messages",
    "instructions",
    "tools",
    "functions",
    "text",
    "response_format",
    "prompt",
    "previous_response_id",
    "conversation",
    "context_management",
    "web_search_options",
    "file_ids",
    "modalities",
    "audio",
    "prediction",
)


def _quoted_fields(
    model: Model,
    settings: ModelSettings,
    resolved: AsyncOpenAI,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    names = (
        "system_instructions",
        "input",
        "model_settings",
        "tools",
        "output_schema",
        "handoffs",
        "tracing",
    )
    call = {**dict(zip(names, args, strict=False)), **kwargs}
    clean = copy.copy(settings)
    clean.extra_args = None
    clean.extra_body = None
    inner = cast("Any", model)
    if isinstance(model, OpenAIResponsesModel):
        expected = inner._build_response_create_kwargs(
            system_instructions=call.get("system_instructions"),
            input=call["input"],
            model_settings=clean,
            tools=call.get("tools", []),
            output_schema=call.get("output_schema"),
            handoffs=call.get("handoffs", []),
            previous_response_id=call.get("previous_response_id"),
            conversation_id=call.get("conversation_id"),
            prompt=call.get("prompt"),
        )
    else:
        conversion = {
            "model": inner.model,
            "should_replay_reasoning_content": inner.should_replay_reasoning_content,
        }
        if isinstance(model, OpenAIChatCompletionsModel):
            conversion.update(
                base_url=str(resolved.base_url),
                strict_feature_validation=inner._strict_feature_validation,
            )
        else:
            # Qualified LiteLLM's exact SDK conversion flags, without executing
            # LiteLLM or inferring another provider's transport.
            conversion.update(
                base_url=inner.base_url,
                preserve_thinking_blocks=False,
                preserve_tool_output_all_content=True,
            )
        messages = ChatConverter.items_to_messages(call["input"], **conversion)
        if call.get("system_instructions"):
            messages.insert(0, {"role": "system", "content": call["system_instructions"]})
        tools = [ChatConverter.tool_to_openai(tool) for tool in call.get("tools", [])]
        tools.extend(
            ChatConverter.convert_handoff_tool(handoff) for handoff in call.get("handoffs", [])
        )
        expected = {
            "model": inner.model.removeprefix("openai/"),
            "messages": messages,
            "tools": tools,
            "response_format": ChatConverter.convert_response_format(call.get("output_schema")),
        }
    projected = {key: expected.get(key) for key in _QUOTED_FIELDS}
    projected = {
        key: None if isinstance(value, (Omit, NotGiven)) else _to_dump_compatible(value)
        for key, value in projected.items()
    }
    if not isinstance(projected["model"], str) or not projected["model"]:
        raise PhysicalBudgetAdapterError("Finite generation requires an explicit priced model.")
    return copy.deepcopy(projected)


def _validate_quoted_fields(payload: Any, expected: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise PhysicalBudgetAdapterError("Cannot verify finite generation quote fields.")
    params = (
        ResponseCreateParamsBase if expected.get("messages") is None else CompletionCreateParamsBase
    )
    if set(payload) - (set(params.__annotations__) | {"stream"}):
        raise PhysicalBudgetAdapterError(
            "Finite generation cannot qualify arbitrary routing fields."
        )
    for key, value in expected.items():
        actual = payload.get(key)
        if key in {"tools", "functions"} and not actual and not value:
            continue
        if actual != value:
            raise PhysicalBudgetAdapterError(
                f"Finite generation changed quoted {key}; "
                "raw body overrides cannot reprice a request."
            )
    for key in ("n", "best_of", "num_generations"):
        value = payload.get(key, 1)
        if type(value) is not int or value != 1:
            raise PhysicalBudgetAdapterError("Finite generation requires exactly one completion.")
    if payload.get("service_tier") not in (None, "default"):
        raise PhysicalBudgetAdapterError("Finite generation cannot change its priced service tier.")


def _unique_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhysicalBudgetAdapterError("Finite generation contains ambiguous JSON members.")
        result[key] = value
    return result


class _SinglePostTransport(httpx.AsyncBaseTransport):
    def __init__(
        self, original: httpx.AsyncClient, maximum: int, quoted: dict[str, Any], endpoint: httpx.URL
    ) -> None:
        self.original = original
        self.quoted = quoted
        self.maximum = maximum
        self.endpoint = endpoint
        self.sent = False
        self.usage_evidence: _UsageEvidence | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Body streams may execute arbitrary async callbacks. Freeze every
        # dispatch input before awaiting them, including nested extensions.
        method = request.method
        url = httpx.URL(str(request.url))
        headers = httpx.Headers(request.headers)
        extensions = copy.deepcopy(request.extensions)
        stream = request.stream
        transport = self.original._transport_for_url(url)
        if self.sent:
            raise PhysicalBudgetAdapterError(
                "Finite budget blocked an unreserved provider compatibility replay."
            )
        if method != "POST":
            raise PhysicalBudgetAdapterError("Finite generation requires one bounded POST.")
        if (
            url != self.endpoint
            or headers.get("host") != self.endpoint.netloc.decode()
            or extensions.get("sni_hostname")
            not in (
                None,
                self.endpoint.host.replace("_", "-"),
                self.endpoint.host.replace("_", "-").encode(),
            )
        ):
            raise PhysicalBudgetAdapterError("Finite generation changed its admitted endpoint.")
        if not isinstance(stream, httpx.AsyncByteStream):
            raise PhysicalBudgetAdapterError("Finite generation requires an asynchronous body.")
        body = bytearray()
        try:
            async for chunk in stream:
                if len(chunk) > 8_388_608 - len(body):
                    raise PhysicalBudgetAdapterError(
                        "Finite generation request exceeds its bounded body limit."
                    )
                body.extend(chunk)
        finally:
            await stream.aclose()
        try:
            payload = json.loads(body, object_pairs_hook=_unique_json_members)
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
        _validate_quoted_fields(payload, self.quoted)
        # The lower HTTP transport consumes stream, not Request._content.
        # Send the same immutable bytes we actually inspected, with fresh framing.
        headers.pop("content-length", None)
        headers.pop("transfer-encoding", None)
        request = httpx.Request(
            method,
            url,
            headers=headers,
            content=bytes(body),
            extensions=extensions,
        )
        self.sent = True
        # Auth and redirect flow run above this counter on the scoped client.
        # Reuse the resolved URL's pool/TLS transport below those flows, so
        # every challenge-driven physical dispatch must re-enter this guard.
        response = await transport.handle_async_request(request)
        response.request = request
        self.original.cookies.extract_cookies(response)
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


def _admitted_endpoint(
    resolved: AsyncOpenAI, original_http: httpx.AsyncClient, quoted: dict[str, Any]
) -> httpx.URL:
    resource = "/responses" if quoted.get("messages") is None else "/chat/completions"
    if isinstance(resolved, AsyncAzureOpenAI):
        if resource == "/chat/completions" and "/deployments" not in resolved.base_url.path:
            resource = f"/deployments/{quoted['model']}{resource}"
        endpoint = AsyncAzureOpenAI._prepare_url(resolved, resource)
    else:
        endpoint = AsyncOpenAI._prepare_url(resolved, resource)
    return endpoint.copy_merge_params(original_http.params).copy_merge_params(
        resolved.qs.stringify(cast("Any", resolved.default_query))
    )


@asynccontextmanager
async def _physical_call(
    model: Model,
    settings: ModelSettings,
    resolved_client: AsyncOpenAI | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
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
    quoted = _quoted_fields(model, settings, resolved, args, kwargs)
    transport = _SinglePostTransport(
        original_http, maximum, quoted, _admitted_endpoint(resolved, original_http, quoted)
    )
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
        async with _physical_call(self._inner, settings, self._resolved_client, args, kwargs) as (
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
                transport.usage_evidence is not None and transport.usage_evidence.matches(response)
            ):
                response.usage = Usage()
            return response

    async def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        settings = kwargs["model_settings"] if "model_settings" in kwargs else args[2]
        async with _physical_call(self._inner, settings, self._resolved_client, args, kwargs) as (
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
                            and transport.usage_evidence.matches(event.response)
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
