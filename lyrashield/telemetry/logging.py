# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Per-scan logging setup."""

from __future__ import annotations

import contextlib
import copy
import importlib
import logging
import os
import traceback
import warnings
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, override

from lyrashield.utils.redaction import redact_text


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType


_SCAN_ID: ContextVar[str | None] = ContextVar("strix_scan_id", default=None)


def set_scan_id(scan_id: str) -> None:
    """Set the scan_id seen on every log record from this point in the task tree."""
    _SCAN_ID.set(scan_id)


class _StrixContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.scan_id = _SCAN_ID.get() or "-"
        record.agent_id = "-"
        return True


_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-7s %(scan_id)s %(agent_id)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


class _RedactingFormatter(logging.Formatter):
    """Redact credentials from scan messages and omit exception messages."""

    def format(self, record: logging.LogRecord) -> str:
        safe_record = copy.copy(record)
        safe_record.msg = redact_text(safe_record.getMessage())
        safe_record.args = ()
        safe_record.exc_text = None
        return super().format(safe_record)

    @override
    def formatException(
        self,
        exc_info: tuple[type[BaseException], BaseException, TracebackType | None]
        | tuple[None, None, None],
    ) -> str:
        exc_type, _exc_value, tb = exc_info
        if exc_type is None:
            return "Exception details unavailable."

        # Provider exception messages and response bodies can contain arbitrary
        # customer data or credentials without recognizable labels. Preserve
        # traceback locations and the exception class, but never serialize the
        # exception value or source lines into the durable scan log.
        frames: list[tuple[str, int, str]] = []
        if tb is not None:
            for frame, lineno in traceback.walk_tb(tb):
                frames.append(
                    (
                        Path(frame.f_code.co_filename).name,
                        lineno,
                        frame.f_code.co_name,
                    )
                )
                if len(frames) == 64:
                    break

        details = ["Traceback (most recent call last):"]
        details.extend(
            f'  File "{filename}", line {lineno}, in {name}' for filename, lineno, name in frames
        )
        if tb is not None and len(frames) == 64:
            details.append("  ... traceback truncated after 64 frames")
        details.append(f"{exc_type.__name__}: [exception message omitted]")
        return "\n".join(details)


# Third-party loggers that get noisy at DEBUG. Capped so the file isn't
# drowned in their internals when STRIX_DEBUG=1.
_NOISY_LIBS: tuple[str, ...] = (
    "httpx",
    "httpcore",
    "urllib3",
    "litellm",
    "openai",
    "anthropic",
)


_HANDLER_TAG = "_strix_scan_handler"


# ``openai.agents`` is the openai-agents SDK's canonical logger root.
_TRACKED_ROOTS: tuple[str, ...] = ("strix", "openai.agents", "lyrashield")

_STDOUT_QUIET_ROOTS: frozenset[str] = frozenset({"openai.agents"})


class _StdoutQuietFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            return True
        return not any(
            record.name == root or record.name.startswith(root + ".")
            for root in _STDOUT_QUIET_ROOTS
        )


def configure_dependency_logging() -> None:
    """Quiet dependency logging/warnings that obscure Strix scan logs."""
    with contextlib.suppress(Exception):
        litellm = importlib.import_module("litellm")

        litellm_logging = litellm._logging
        litellm_logging._disable_debugging()

    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("asyncio").propagate = False
    warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")


def setup_scan_logging(run_dir: Path, *, debug: bool | None = None) -> Callable[[], None]:
    """Attach scan-scoped handlers; return a teardown callable.

    Args:
        run_dir: Per-scan output directory. ``{run_dir}/strix.log`` is
            created if missing and opened append-mode (so re-runs of the
            same scan_id concatenate cleanly).
        debug: When ``True``, stderr handler runs at DEBUG instead of
            ERROR. ``None`` (default) reads ``STRIX_DEBUG`` env: ``1`` /
            ``true`` / ``yes`` / ``on`` enables debug.

    Returns:
        A no-arg callable that flushes/closes/removes the handlers this
        call attached. Idempotent — calling twice is a no-op the second
        time. Safe to call from a ``finally`` block.
    """
    configure_dependency_logging()

    if debug is None:
        debug = (os.environ.get("STRIX_DEBUG") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "strix.log"

    formatter = _RedactingFormatter(_FORMAT, datefmt=_DATEFMT)
    context_filter = _StrixContextFilter()

    file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(context_filter)
    setattr(file_handler, _HANDLER_TAG, True)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG if debug else logging.ERROR)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(context_filter)
    stream_handler.addFilter(_StdoutQuietFilter())
    setattr(stream_handler, _HANDLER_TAG, True)

    tracked_loggers = [logging.getLogger(name) for name in _TRACKED_ROOTS]
    for tracked in tracked_loggers:
        tracked.setLevel(logging.DEBUG)
        tracked.addHandler(file_handler)
        tracked.addHandler(stream_handler)
        tracked.propagate = False

    for name in _NOISY_LIBS:
        logging.getLogger(name).setLevel(logging.WARNING)

    def _teardown() -> None:
        for tracked in tracked_loggers:
            for handler in list(tracked.handlers):
                if getattr(handler, _HANDLER_TAG, False):
                    tracked.removeHandler(handler)
                    with contextlib.suppress(Exception):
                        handler.flush()
                        handler.close()

    return _teardown
