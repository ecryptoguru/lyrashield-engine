"""Docker sandbox image verification and pull progress reporting."""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any, cast

from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lyrashield.interface.utils import check_docker_connection, image_exists
from lyrashield.policy.loader import load_settings


logger = logging.getLogger(__name__)


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


def pull_docker_image() -> None:
    """Pull the configured sandbox image, optionally verifying ``STRIX_IMAGE_DIGEST``.

    If ``STRIX_IMAGE_DIGEST`` is set, the pulled image's ``RepoDigests`` must
    contain the expected value. The function exits on pull or verification failure.
    """
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image
    expected_digest = os.environ.get("STRIX_IMAGE_DIGEST", "").strip()

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
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

            if expected_digest:
                _verify_image_digest(client, image, expected_digest)

        except (DockerException, RuntimeError) as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]LYRASHIELD",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

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
