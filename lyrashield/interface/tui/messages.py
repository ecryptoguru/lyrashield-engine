"""Acknowledged, idempotent delivery from operator interfaces to the scan loop."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
import uuid
import weakref
from typing import Any, Literal


logger = logging.getLogger(__name__)
Delivery = Literal["queued", "rejected", "unknown"]
DELIVERY_TIMEOUT_SECONDS = 5.0
# Tasks are created on the scan loop. HTTP threads can read completed receipts
# under the registry lock after that loop has closed, without scheduling work.
_submissions: weakref.WeakKeyDictionary[
    Any, dict[str, tuple[tuple[str, ...], asyncio.Task[bool]]]
] = weakref.WeakKeyDictionary()
_submission_lock = threading.RLock()


async def _deliver_once(
    coordinator: Any, live_view: Any, target_agent_id: str, message: str, submission_id: str
) -> bool:
    if (
        not message.strip()
        or len(message) > 4000
        or not target_agent_id
        or len(target_agent_id) > 128
    ):
        return False
    if not submission_id or len(submission_id) > 128:
        return False

    async def accept() -> bool:
        delivered = bool(
            await coordinator.send(
                target_agent_id,
                {
                    "from": "user",
                    "content": message,
                    "type": "instruction",
                    "submission_id": submission_id,
                },
            )
        )
        if delivered:
            live_view.record_user_message(target_agent_id, message)
        return delivered

    with _submission_lock:
        submissions = _submissions.setdefault(coordinator, {})
        fingerprint = ("steer", target_agent_id, message)
        previous = submissions.get(submission_id)
        if previous is not None:
            if previous[0] != fingerprint:
                return False
            task = previous[1]
        else:
            if len(submissions) >= 4096:
                return False
            task = asyncio.create_task(accept())
            submissions[submission_id] = (fingerprint, task)
    return await asyncio.shield(task)


def read_submission_receipt(
    coordinator: Any, submission_id: str, fingerprint: tuple[str, ...]
) -> Delivery | None:
    """Read a receipt only; never enqueue or require a live scan event loop.

    Missing, pending and cancelled work cannot be promoted to acceptance. The
    registry retains at most 4096 bounded submissions per coordinator.
    """
    with _submission_lock:
        previous = _submissions.get(coordinator, {}).get(submission_id)
    if previous is None:
        return None
    if previous[0] != fingerprint:
        return "rejected"
    task = previous[1]
    if not task.done() or task.cancelled():
        return "unknown"
    try:
        return "queued" if task.result() else "rejected"
    except Exception:
        return "unknown"


async def _deliver_control_once(coordinator: Any, action: str, submission_id: str) -> bool:
    if action not in {"resume", "increase_budget"} or not submission_id or len(submission_id) > 128:
        return False
    with _submission_lock:
        submissions = _submissions.setdefault(coordinator, {})
        fingerprint = ("control", action)
        previous = submissions.get(submission_id)
        if previous is not None:
            if previous[0] != fingerprint:
                return False
            task = previous[1]
        else:
            if len(submissions) >= 4096:
                return False
            task = asyncio.create_task(coordinator.operator_control(action, submission_id))
            submissions[submission_id] = (fingerprint, task)
    return await asyncio.shield(task)


async def deliver_user_message(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    live_view: Any,
    target_agent_id: str,
    message: str,
    submission_id: str,
    timeout: float = DELIVERY_TIMEOUT_SECONDS,
) -> Delivery:
    """Await mailbox acceptance without blocking either UI or the scan loop.

    A timeout leaves delivery running. Retrying the same submission recovers its
    acknowledgement; cancelling it would make the delivery outcome ambiguous.
    """
    receipt = read_submission_receipt(
        coordinator, submission_id, ("steer", target_agent_id, message)
    )
    if receipt is not None and receipt != "unknown":
        return receipt
    if loop is None or loop.is_closed() or not loop.is_running():
        return receipt or "rejected"
    coroutine = _deliver_once(coordinator, live_view, target_agent_id, message, submission_id)
    pending: asyncio.Future[bool]
    if asyncio.get_running_loop() is loop:
        pending = asyncio.ensure_future(coroutine)
    else:
        pending = asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coroutine, loop))
    try:
        accepted = await asyncio.wait_for(asyncio.shield(pending), timeout)
    except TimeoutError:
        return "unknown"
    except asyncio.CancelledError:
        # A cancelled mailbox task is an uncertain receipt, not a request to
        # cancel its UI caller. Genuine caller cancellation must propagate.
        caller = asyncio.current_task()
        if caller is not None and caller.cancelling():
            raise
        return "unknown"
    except Exception:
        logger.exception("Operator message delivery failed")
        return "unknown"
    else:
        return "queued" if accepted else "rejected"


def send_user_message_to_agent(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    live_view: Any,
    target_agent_id: str,
    message: str,
    submission_id: str | None = None,
) -> bool:
    """Synchronous HTTP-thread bridge. Never block the scan's own event loop."""
    identifier = submission_id or uuid.uuid4().hex
    receipt = read_submission_receipt(coordinator, identifier, ("steer", target_agent_id, message))
    if receipt == "unknown":
        raise TimeoutError("delivery_unknown")
    if receipt is not None:
        return receipt == "queued"
    if loop is None or loop.is_closed() or not loop.is_running():
        return False
    try:
        current = asyncio.get_running_loop()
    except RuntimeError:
        current = None
    if current is loop:
        raise RuntimeError("Use deliver_user_message from the scan event loop")
    future = asyncio.run_coroutine_threadsafe(
        _deliver_once(coordinator, live_view, target_agent_id, message, identifier),
        loop,
    )
    try:
        return bool(future.result(timeout=DELIVERY_TIMEOUT_SECONDS))
    except concurrent.futures.TimeoutError as exc:
        raise TimeoutError("delivery_unknown") from exc


async def deliver_operator_control(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    action: str,
    submission_id: str,
) -> Delivery:
    """Submit an explicit control from an asynchronous operator interface."""
    receipt = read_submission_receipt(coordinator, submission_id, ("control", action))
    if receipt is not None and receipt != "unknown":
        return receipt
    if loop is None or loop.is_closed() or not loop.is_running():
        return receipt or "rejected"
    coroutine = _deliver_control_once(coordinator, action, submission_id)
    pending: asyncio.Future[bool]
    if asyncio.get_running_loop() is loop:
        pending = asyncio.ensure_future(coroutine)
    else:
        pending = asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coroutine, loop))
    try:
        accepted = await asyncio.wait_for(asyncio.shield(pending), DELIVERY_TIMEOUT_SECONDS)
    except TimeoutError:
        return "unknown"
    except asyncio.CancelledError:
        # A cancelled mailbox task is an uncertain receipt, not a request to
        # cancel its UI caller. Genuine caller cancellation must propagate.
        caller = asyncio.current_task()
        if caller is not None and caller.cancelling():
            raise
        return "unknown"
    except Exception:
        logger.exception("Operator control delivery failed")
        return "unknown"
    else:
        return "queued" if accepted else "rejected"


def send_operator_control(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    action: str,
    submission_id: str,
) -> bool:
    """Submit a control from an HTTP worker; never block the scan loop."""
    receipt = read_submission_receipt(coordinator, submission_id, ("control", action))
    if receipt == "unknown":
        raise TimeoutError("delivery_unknown")
    if receipt is not None:
        return receipt == "queued"
    if loop is None or loop.is_closed() or not loop.is_running():
        return False
    try:
        current = asyncio.get_running_loop()
    except RuntimeError:
        current = None
    if current is loop:
        raise RuntimeError("Use deliver_operator_control from the scan event loop")
    future = asyncio.run_coroutine_threadsafe(
        _deliver_control_once(coordinator, action, submission_id), loop
    )
    return bool(future.result(timeout=DELIVERY_TIMEOUT_SECONDS))
