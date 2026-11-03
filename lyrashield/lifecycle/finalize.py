# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Finalize scan results and release scan-scoped resources."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from collections.abc import Callable

    from lyrashield.lifecycle.scan_context import ScanPaths


logger = logging.getLogger(__name__)
SANDBOX_CLEANUP_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True, slots=True)
class FinalizeServices:
    get_global_report_state: Callable[[], Any | None]
    record_supports_evidence: Callable[[Any], bool]
    export_http_exchange_evidence: Callable[..., Any]
    set_active_hooks: Callable[[Any | None], None]
    configure_spill_writer: Callable[[Any | None], None]
    cleanup_sandbox: Callable[[str], Any]


async def finish_scan_result(
    *,
    result: Any | None,
    interactive: bool,
    scan_id: str,
    coordinator: Any,
    root_id: str,
    services: FinalizeServices,
) -> Any | None:
    """Mark incomplete terminal output and close coordinator tasks."""
    if not interactive and result is not None:
        final = getattr(result, "final_output", None)
        scan_completed = False
        if isinstance(final, str):
            try:
                parsed = json.loads(final)
            except (ValueError, TypeError):
                scan_completed = False
            else:
                scan_completed = isinstance(parsed, dict) and bool(
                    cast("dict[str, Any]", parsed).get("scan_completed")
                )
        elif isinstance(final, dict):
            scan_completed = bool(cast("dict[str, Any]", final).get("scan_completed"))
        if not scan_completed:
            report_state = services.get_global_report_state()
            if report_state is not None:
                report_state.set_terminal_reason("incomplete")
            final_type = type(cast("object", final)).__name__
            logger.error(
                "Scan %s ended without calling finish_scan. The agent "
                "emitted a text-only turn instead of a lifecycle tool call, "
                "so no executive report was written. Final output was "
                "omitted from logs (type=%s).",
                scan_id,
                final_type,
            )
    coordinator.mark_shutting_down()
    with contextlib.suppress(Exception):
        await coordinator.cancel_descendants(root_id)
    with contextlib.suppress(Exception):
        current_status = await coordinator.get_status(root_id)
        if current_status in {"running", "waiting"}:
            await coordinator.set_status(root_id, "completed")
    return result


async def cleanup_scan_resources(
    *,
    scan_id: str,
    sessions_to_close: list[Any],
    coordinator: Any,
    artifact_state: Any | None,
    bundle: dict[str, Any],
    cleanup_on_exit: bool,
    paths: ScanPaths,
    services: FinalizeServices,
) -> None:
    """Close sessions, persist evidence outcomes, and tear down scan resources."""
    try:
        services.set_active_hooks(None)
        services.configure_spill_writer(None)
        for session in sessions_to_close:
            with contextlib.suppress(Exception):
                close = getattr(session, "close", None)
                if callable(close):
                    close()
        with contextlib.suppress(Exception):
            await coordinator.maybe_snapshot()
        state = artifact_state or services.get_global_report_state()
        if state is not None and services.record_supports_evidence(state.run_record):
            from lyrashield.artifacts import evidence

            if evidence.record_supports_pending_http_evidence(state.run_record):
                try:
                    await state.reconcile_http_exchange_evidence(
                        bundle.get("caido_client"), exporter=services.export_http_exchange_evidence
                    )
                except Exception:
                    # Reconciliation owns every evidence outcome write. A
                    # stale export must not overwrite a newer durable receipt.
                    logger.exception("HTTP evidence reconciliation did not commit")
            else:
                try:
                    outcome = await asyncio.wait_for(
                        services.export_http_exchange_evidence(
                            bundle.get("caido_client"),
                            state.get_run_dir(),
                            run_record=state.run_record,
                            findings=state.vulnerability_reports,
                        ),
                        timeout=evidence.HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS,
                    )
                except Exception:
                    logger.exception("HTTP exchange evidence export failed")
                    outcome = {
                        "status": "failed",
                        "reason": "export raised before sandbox teardown",
                    }
                state.set_evidence_export_outcome(outcome)
                with contextlib.suppress(Exception):
                    state.save_run_data()
    finally:
        try:
            if cleanup_on_exit:
                logger.info("Tearing down sandbox session for scan %s", scan_id)
                cleanup_task = asyncio.create_task(_bounded_sandbox_cleanup(scan_id, services))
                cancelled = False
                while not cleanup_task.done():
                    try:
                        await asyncio.shield(cleanup_task)
                    except asyncio.CancelledError:
                        cancelled = True
                cleanup_outcome = cleanup_task.result()
                state = artifact_state or services.get_global_report_state()
                if state is not None:
                    state.set_cleanup_outcome(cleanup_outcome)
                if cancelled:
                    raise asyncio.CancelledError
        finally:
            logger.info("LyraShield scan %s done", scan_id)
            paths.teardown_logging()


async def _bounded_sandbox_cleanup(scan_id: str, services: FinalizeServices) -> Any:
    task = asyncio.create_task(services.cleanup_sandbox(scan_id))
    done, _pending = await asyncio.wait({task}, timeout=SANDBOX_CLEANUP_TIMEOUT_SECONDS)
    if task not in done:
        task.cancel()
        task.add_done_callback(_consume_cleanup_result)
        logger.error("Sandbox cleanup exceeded its deadline for scan %s", scan_id)
        return "failed"
    try:
        return task.result()
    except (asyncio.CancelledError, Exception):
        logger.exception("Sandbox cleanup failed for scan %s", scan_id)
        return "failed"


def _consume_cleanup_result(task: asyncio.Task[Any]) -> None:
    with contextlib.suppress(asyncio.CancelledError, Exception):
        task.result()
