"""Docker sandbox image verification and pull progress reporting."""

from __future__ import annotations

import contextlib
import json
import logging
import multiprocessing
import os
import re
import sys
from typing import TYPE_CHECKING, Any, cast

from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.interface.utils import check_docker_connection, image_exists
from lyrashield.lifecycle.deadline import RunDeadlineExceededError
from lyrashield.policy.loader import load_settings


if TYPE_CHECKING:
    from multiprocessing.process import BaseProcess

    from lyrashield.lifecycle.deadline import RunDeadline


logger = logging.getLogger(__name__)


def _docker_image_operation_worker(sender: Any, image: str, expected_digest: str) -> None:
    """Run blocking Docker SDK calls in a process the scan can stop."""
    client: Any = None
    pull_stream: Any = None
    outcome: tuple[str, Any] | None = None
    try:
        client = check_docker_connection()
        needs_pull = not image_exists(client, image)
        if not needs_pull and expected_digest:
            try:
                _verify_image_digest(client, image, expected_digest)
            except RuntimeError:
                logger.warning("Local image %s digest does not match; re-pulling", image)
                needs_pull = True
        if not needs_pull:
            outcome = ("complete", False)
        else:
            sender.send(("pulling", None))
            pull_stream = client.api.pull(image, stream=True, decode=True)
            for line in pull_stream:
                if not isinstance(line, dict):
                    continue
                error = line.get("error")
                if isinstance(error, str):
                    outcome = ("error", f"Docker image pull failed: {error[:2048]}")
                    break
                progress: dict[str, Any] = {}
                for key in ("status", "id", "progress"):
                    value = line.get(key)
                    if isinstance(value, str):
                        progress[key] = value[:4096]
                details = line.get("progressDetail")
                if isinstance(details, dict):
                    progress["progressDetail"] = {
                        key: value
                        for key, value in details.items()
                        if key in {"current", "total"} and isinstance(value, int)
                    }
                if len(json.dumps(progress)) > 8192:
                    outcome = ("error", "Docker image pull returned an oversized progress record")
                    break
                sender.send(("progress", progress))

            if outcome is None:
                if expected_digest:
                    _verify_image_digest(client, image, expected_digest)
                outcome = ("complete", True)
    except Exception as exc:
        outcome = ("error", f"{type(exc).__name__}: {str(exc)[:2048]}")
    finally:
        if pull_stream is not None:
            close = getattr(pull_stream, "close", None)
            if callable(close):
                with contextlib.suppress(Exception):
                    close()
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()
    if outcome is not None:
        with contextlib.suppress(Exception):
            sender.send(outcome)
    with contextlib.suppress(Exception):
        sender.close()


def _stop_docker_worker(process: BaseProcess) -> None:
    """Stop and reap the Docker child without waiting past the scan budget."""
    if process.pid is None:
        process.close()
        return
    if process.is_alive():
        with contextlib.suppress(OSError, ValueError):
            process.terminate()
        process.join(timeout=0.2)
    if process.is_alive():
        with contextlib.suppress(OSError, ValueError):
            process.kill()
        process.join(timeout=0.2)
    if process.is_alive():
        raise RuntimeError(
            f"Docker image worker pid {process.pid} remained alive after bounded termination"
        )
    process.join(timeout=0)
    process.close()


def _run_bounded_docker_operation(
    image: str,
    expected_digest: str,
    deadline: RunDeadline,
    *,
    worker: Any = _docker_image_operation_worker,
) -> bool:
    """Supervise connection, inspect and pull as one deadline-bound operation."""
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(sender, image, expected_digest))
    try:
        process.start()
    except BaseException:
        sender.close()
        receiver.close()
        _stop_docker_worker(process)
        raise
    sender.close()
    console = Console()
    status_stack = contextlib.ExitStack()
    status: Any = None
    layers_info: dict[str, str] = {}
    last_update = ""
    pulled = False
    completed = False
    try:
        while not completed:
            remaining = deadline.remaining_seconds()
            if remaining <= 0:
                raise RunDeadlineExceededError(
                    "runtime allowance exhausted during sandbox image acquisition"
                )
            if receiver.poll(min(remaining, 0.1)):
                try:
                    kind, payload = receiver.recv()
                except EOFError as exc:
                    raise RuntimeError("Docker image worker exited without a result") from exc
                if kind == "pulling":
                    console.print()
                    console.print(f"[dim]Pulling image[/] {image}")
                    console.print(
                        "[dim yellow]This only happens on first run and may take "
                        "a few minutes...[/]"
                    )
                    console.print()
                    status = status_stack.enter_context(
                        console.status("[bold cyan]Downloading image layers...", spinner="dots")
                    )
                elif kind == "progress" and status is not None:
                    last_update = process_pull_line(payload, layers_info, status, last_update)
                elif kind == "complete":
                    pulled = bool(payload)
                    completed = True
                elif kind == "error":
                    raise RuntimeError(str(payload)[:2100])
                else:
                    raise RuntimeError("Docker image worker returned an invalid response")
            elif not process.is_alive():
                raise RuntimeError(f"Docker image worker exited with status {process.exitcode}")
        process.join(timeout=min(1.0, deadline.remaining_seconds()))
        if process.is_alive():
            logger.warning("Docker image worker slow to exit after completion; stopping it")
        if pulled:
            logger.info("Docker image %s ready", image)
        return pulled
    finally:
        status_stack.close()
        receiver.close()
        _stop_docker_worker(process)


def _print_pull_failure(console: Console, image: str, error: Exception) -> None:
    error_text = Text()
    error_text.append("FAILED TO PULL IMAGE", style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(f"Could not download: {image}\n", style="white")
    error_text.append(str(error), style="dim red")

    panel = Panel(
        error_text,
        title="[bold white]LYRASHIELD",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print(panel, "\n")


def _normalize_digest(value: str) -> str:
    """Return the bare hex digest, removing repo prefix and ``sha256:``."""
    normalized = value.strip().lower()
    if "@" in normalized:
        normalized = normalized.rsplit("@", 1)[-1]
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    return normalized


def _verify_image_digest(client: Any, image: str, expected_digest: str) -> None:
    """Verify a pulled image matches an expected SHA256 digest if one is supplied."""
    try:
        pulled = client.images.get(image)
    except ImageNotFound as e:
        raise RuntimeError(f"Pulled image {image} not found for digest verification") from e

    expected = _normalize_digest(expected_digest)
    if not expected:
        raise RuntimeError(
            f"Image digest value for {image} is empty or malformed: {expected_digest!r}"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError(
            f"Image digest value for {image} is not a 64-character "
            f"SHA-256 hex string: {expected_digest!r}"
        )

    digests = cast("list[str]", pulled.attrs.get("RepoDigests") or [])
    for digest_ref in digests:
        actual = _normalize_digest(digest_ref)
        if actual and actual == expected:
            logger.info("Image digest verified for %s", image)
            return

    raise RuntimeError(
        f"Image digest verification failed for {image}: expected {expected_digest}, found {digests}"
    )


def pull_docker_image(*, deadline: RunDeadline | None = None) -> None:
    """Pull the configured sandbox image, optionally verifying ``STRIX_IMAGE_DIGEST``.

    If ``STRIX_IMAGE_DIGEST`` is set, the pulled image's ``RepoDigests`` must
    contain the expected value. The function exits on pull or verification failure.

    When ``deadline`` (the scan's shared runtime allowance) is supplied, a pull
    that would start or continue past it raises ``RunDeadlineExceededError``
    instead of silently overrunning the worker budget.
    """
    console = Console()
    image = load_settings().runtime.image
    expected_digest = os.environ.get("STRIX_IMAGE_DIGEST", "").strip()

    if deadline is not None:
        if deadline.remaining_seconds() <= 0:
            raise RunDeadlineExceededError(
                "runtime allowance exhausted before sandbox image acquisition"
            )
        try:
            pulled = _run_bounded_docker_operation(image, expected_digest, deadline)
        except (DockerException, RuntimeError) as error:
            logger.exception("Failed to acquire docker image %s", image)
            _print_pull_failure(console, image, error)
            sys.exit(1)
        if not pulled:
            logger.debug("Docker image already present locally: %s", image)
            return
        success_text = Text()
        success_text.append("Docker image ready", style="#22c55e")
        console.print(success_text)
        console.print()
        return

    client = check_docker_connection()

    needs_pull = not image_exists(client, image)
    if not needs_pull and expected_digest:
        try:
            _verify_image_digest(client, image, expected_digest)
        except RuntimeError:
            logger.warning("Local image %s digest does not match; re-pulling", image)
            needs_pull = True
        else:
            logger.debug("Docker image already present locally and digest verified: %s", image)
            return

    if not needs_pull:
        logger.debug("Docker image already present locally: %s", image)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]Pulling image[/] {image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        pull_stream: Any = None
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            # Check the shared allowance before consuming each streamed line so
            # a stalled layer fetch cannot outlive the worker's budget.
            pull_stream = client.api.pull(image, stream=True, decode=True)
            pull_iter = iter(pull_stream)
            while True:
                try:
                    line = next(pull_iter)
                except StopIteration:
                    break
                last_update = process_pull_line(line, layers_info, status, last_update)

            if expected_digest:
                _verify_image_digest(client, image, expected_digest)

        except (DockerException, RuntimeError) as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            _print_pull_failure(console, image, e)
            sys.exit(1)
        finally:
            # An abandoned pull must not leak the open response stream.
            if pull_stream is not None:
                close = getattr(pull_stream, "close", None)
                if callable(close):
                    with contextlib.suppress(Exception):
                        close()

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
    if "Pull complete" in layer_status or "Already exists" in layer_status:
        layers_info[layer_id] = "✓"
    elif "Downloading" in layer_status:
        layers_info[layer_id] = "↓"
    elif "Extracting" in layer_status:
        layers_info[layer_id] = "📦"
    elif "Waiting" in layer_status:
        layers_info[layer_id] = "⏳"
    else:
        layers_info[layer_id] = "•"


def process_pull_line(
    line: dict[str, Any], layers_info: dict[str, str], status: Any, last_update: str
) -> str:
    if "id" in line and "status" in line:
        layer_id = line["id"]
        update_layer_status(layers_info, layer_id, line["status"])

        completed = sum(1 for v in layers_info.values() if v == "✓")
        total = len(layers_info)

        if total > 0:
            update_msg = f"[bold cyan]Progress: {completed}/{total} layers complete"
            if update_msg != last_update:
                status.update(update_msg)
                return update_msg

    elif "status" in line and "id" not in line:
        global_status = line["status"]
        if "Pulling from" in global_status:
            status.update("[bold cyan]Fetching image manifest...")
        elif "Digest:" in global_status:
            status.update("[bold cyan]Verifying image...")
        elif "Status:" in global_status:
            status.update("[bold cyan]Finalizing...")

    return last_update
