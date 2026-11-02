"""Opt-in local request metadata, isolated from customer evidence and model inputs."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import re
import stat
import threading
import time
from typing import TYPE_CHECKING, Any

from agents.models.interface import Model

from lyrashield.runtime.attachments import _is_reparse_point, _open_attachment_fd
from lyrashield.utils.redaction import redact_secrets
from strix.core.paths import runtime_state_dir
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path


logger = logging.getLogger(__name__)
MAX_ENTRIES = 256
MAX_BYTES = 131_072
_MAX_COUNTER = 2**63 - 1
_LOCK = threading.RLock()
_SAFE_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}\Z")
_UUID = re.compile(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z")
_OUTCOMES = {"completed", "error", "cancelled", "incomplete"}
_REASONS = {"rate_limited", "timeout", "connection_error", "server_error", "provider_error"}
_TOKEN_EVENTS = {
    "response.output_text.delta",
    "response.reasoning_text.delta",
    "response.reasoning_summary_text.delta",
    "response.function_call_arguments.delta",
}


def _safe_value(value: Any, *, provider_id: bool = False) -> str | None:
    if not isinstance(value, str) or _SAFE_VALUE.fullmatch(value) is None:
        return None
    if provider_id and _UUID.fullmatch(value):
        return value
    return value if redact_secrets(value) == value else None


def _bounded_number(value: Any, *, integer: bool = False) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if value < 0 or value > 10**12 or not math.isfinite(value):
        return None
    if integer:
        return value if isinstance(value, int) else None
    return round(value, 3)


def _allowlisted(record: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key in ("request_id", "response_id", "model", "route"):
        value = _safe_value(record.get(key), provider_id=key.endswith("_id"))
        if value is not None:
            clean[key] = value
    if record.get("outcome") in _OUTCOMES:
        clean["outcome"] = record["outcome"]
    if record.get("retry_reason") in _REASONS:
        clean["retry_reason"] = record["retry_reason"]
    for key in ("duration_ms", "ttft_ms"):
        number = _bounded_number(record.get(key))
        if number is not None:
            clean[key] = number
    tokens = record.get("tokens")
    if isinstance(tokens, dict):
        clean["tokens"] = {
            key: number
            for key in ("input", "output", "cached_input", "cache_write_input", "reasoning_output")
            if (number := _bounded_number(tokens.get(key), integer=True)) is not None
        }
    return clean


def _read_existing(path: Path) -> Any:
    """Bind validation/read to one no-follow, nonblocking file descriptor."""
    try:
        descriptor = _open_attachment_fd(path)
    except FileNotFoundError:
        return None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise OSError("unsafe diagnostic file")
        if opened.st_size > MAX_BYTES:
            raise ValueError("oversized diagnostics")
        payload = os.read(descriptor, MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise ValueError("diagnostics grew past the byte limit")
        return json.loads(payload)
    finally:
        os.close(descriptor)


def append_diagnostic(run_dir: Path, record: dict[str, Any]) -> None:
    """Append under a process-wide lock and atomically replace a bounded 0600 file.

    This small synchronous critical section has no cancellation points. All child
    requests in a scan share this process; separate runs use separate paths.
    Diagnostic persistence must never change the provider or lifecycle outcome.
    """
    try:
        with _LOCK:
            directory = runtime_state_dir(run_dir)
            path = directory / "request-diagnostics.json"
            if directory.is_symlink() or path.is_symlink():
                return
            directory.mkdir(parents=True, exist_ok=True)
            entries: list[dict[str, Any]] = []
            dropped = 0
            try:
                document = _read_existing(path)
                if document is not None:
                    prior = document.get("entries", [])
                    if not isinstance(prior, list):
                        raise TypeError("invalid diagnostic entries")  # noqa: TRY301
                    entries = [_allowlisted(entry) for entry in prior if isinstance(entry, dict)]
                    count = document.get("dropped", 0)
                    if isinstance(count, int) and not isinstance(count, bool):
                        dropped = min(max(count, 0), _MAX_COUNTER)
            except (ValueError, TypeError, AttributeError, RecursionError):
                dropped = 1
            entries.append(_allowlisted(record))
            if len(entries) > MAX_ENTRIES:
                dropped = min(dropped + len(entries) - MAX_ENTRIES, _MAX_COUNTER)
                entries = entries[-MAX_ENTRIES:]
            while True:
                payload = json.dumps(
                    {"version": 1, "entries": entries, "dropped": dropped},
                    separators=(",", ":"),
                    allow_nan=False,
                )
                if len(payload.encode("utf-8")) <= MAX_BYTES:
                    break
                entries.pop(0)
                dropped = min(dropped + 1, _MAX_COUNTER)
            write_secret_text(path, payload)
    except (OSError, ValueError, TypeError, OverflowError):
        # Avoid reflecting paths, record values, provider bodies, or prompts.
        logger.debug("Request diagnostics could not be persisted")


def _run_dir() -> Path | None:
    from lyrashield.artifacts.state import get_global_report_state  # noqa: PLC0415

    state = get_global_report_state()
    return state.get_run_dir() if state is not None else None


def _retry_reason(exc: BaseException) -> str:
    status = getattr(exc, "status_code", None)
    if status == 429:
        return "rate_limited"
    if isinstance(exc, TimeoutError) or type(exc).__name__ == "APITimeoutError":
        return "timeout"
    if type(exc).__name__ in {"APIConnectionError", "ConnectError", "ConnectionError"}:
        return "connection_error"
    if isinstance(status, int) and 500 <= status <= 599:
        return "server_error"
    return "provider_error"


def _field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, dict) else getattr(value, name, None)


def _response_fields(response: Any) -> dict[str, Any]:
    usage = _field(response, "usage")
    return {
        "request_id": getattr(response, "request_id", None)
        or getattr(response, "_request_id", None),
        "response_id": getattr(response, "response_id", None) or getattr(response, "id", None),
        "tokens": {
            "input": _field(usage, "input_tokens"),
            "output": _field(usage, "output_tokens"),
            "cached_input": _field(_field(usage, "input_tokens_details"), "cached_tokens"),
            "cache_write_input": _field(
                _field(usage, "input_tokens_details"), "cache_write_tokens"
            ),
            "reasoning_output": _field(_field(usage, "output_tokens_details"), "reasoning_tokens"),
        },
    }


class DiagnosticModel(Model):
    """Observe attempts without altering SDK serialization, retry policy, or input."""

    def __init__(
        self,
        inner: Model,
        *,
        model_name: str | None,
        route: str,
        run_dir: Callable[[], Path | None] = _run_dir,
    ) -> None:
        self._inner = inner
        self._model_name = model_name
        self._route = route
        self._run_dir = run_dir

    async def close(self) -> None:
        await self._inner.close()

    def get_retry_advice(self, request: Any) -> Any:
        return self._inner.get_retry_advice(request)

    def _directory(self) -> Path | None:
        try:
            return self._run_dir()
        except Exception:  # noqa: BLE001 - diagnostics cannot change a scan outcome
            return None

    def _finish(self, record: dict[str, Any], started: float, directory: Path | None) -> None:
        try:
            if directory is not None:
                append_diagnostic(
                    directory,
                    {
                        "model": self._model_name,
                        "route": self._route,
                        **record,
                        "duration_ms": (time.monotonic() - started) * 1000,
                    },
                )
        except Exception:  # noqa: BLE001 - diagnostics cannot change a scan outcome
            logger.debug("Request diagnostics unavailable")

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        started = time.monotonic()
        directory = self._directory()
        record: dict[str, Any] = {"outcome": "incomplete"}
        try:
            response = await self._inner.get_response(*args, **kwargs)
            record.update(_response_fields(response), outcome="completed")
        except asyncio.CancelledError:
            record["outcome"] = "cancelled"
            raise
        except Exception as exc:
            record.update(
                outcome="error",
                retry_reason=_retry_reason(exc),
                request_id=getattr(exc, "request_id", None),
            )
            raise
        else:
            return response
        finally:
            self._finish(record, started, directory)

    async def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        started = time.monotonic()
        directory = self._directory()
        record: dict[str, Any] = {"outcome": "incomplete"}
        stream = None
        try:
            stream = self._inner.stream_response(*args, **kwargs)
            async for event in stream:
                kind = getattr(event, "type", None)
                if (
                    kind in _TOKEN_EVENTS
                    and getattr(event, "delta", None)
                    and "ttft_ms" not in record
                ):
                    record["ttft_ms"] = (time.monotonic() - started) * 1000
                if kind in {"response.completed", "response.failed", "response.incomplete"}:
                    record.update(_response_fields(getattr(event, "response", None)))
                    record["outcome"] = {
                        "response.completed": "completed",
                        "response.failed": "error",
                        "response.incomplete": "incomplete",
                    }[kind]
                yield event
        except (asyncio.CancelledError, GeneratorExit):
            if record["outcome"] != "completed":
                record["outcome"] = "cancelled"
            raise
        except Exception as exc:
            record.update(
                outcome="error",
                retry_reason=_retry_reason(exc),
                request_id=getattr(exc, "request_id", None),
            )
            raise
        finally:
            self._finish(record, started, directory)
            close = getattr(stream, "aclose", None)
            if callable(close):
                with contextlib.suppress(Exception):
                    await close()
