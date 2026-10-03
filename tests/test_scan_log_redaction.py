from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from openai import APIError

from lyrashield.telemetry.logging import setup_scan_logging


if TYPE_CHECKING:
    from pathlib import Path


def _raise_provider_error(message: str) -> None:
    raise RuntimeError(message)


def _raise_openai_error(message: str) -> None:
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    raise APIError(message, request, body={"error": {"message": message}})


def test_scan_log_redacts_provider_credentials_from_messages_and_exceptions(
    tmp_path: Path,
) -> None:
    credential_value = "provider-secret-token-123456"
    run_dir = tmp_path / "scan"
    teardown = setup_scan_logging(run_dir)
    logger = logging.getLogger("strix.telemetry.redaction-regression")

    try:
        logger.error("Provider rejected Authorization: Bearer %s", credential_value)
        try:
            _raise_provider_error(f"request failed with Bearer {credential_value}")
        except RuntimeError:
            logger.exception("Provider request failed")
    finally:
        teardown()

    contents = (run_dir / "strix.log").read_text(encoding="utf-8")
    assert credential_value not in contents
    assert "[TOKEN]" in contents


def test_scan_log_does_not_emit_unlabelled_provider_exception_data(
    tmp_path: Path,
) -> None:
    response_marker = "cobalt-monsoon-7f3a"
    run_dir = tmp_path / "scan"
    teardown = setup_scan_logging(run_dir)
    logger = logging.getLogger("strix.telemetry.unlabelled-redaction-regression")

    try:
        try:
            _raise_provider_error(f"request rejected with {response_marker}")
        except RuntimeError:
            logger.exception("Provider request failed")
    finally:
        teardown()

    contents = (run_dir / "strix.log").read_text(encoding="utf-8")
    assert response_marker not in contents
    assert "RuntimeError" in contents
    assert "_raise_provider_error" in contents


def test_scan_log_omits_unlabelled_openai_error_message(
    tmp_path: Path,
) -> None:
    response_marker = "cobalt-monsoon-7f3a"
    run_dir = tmp_path / "scan"
    teardown = setup_scan_logging(run_dir)
    logger = logging.getLogger("strix.telemetry.openai-redaction-regression")

    try:
        try:
            _raise_openai_error(f"request rejected with {response_marker}")
        except APIError:
            logger.exception("Provider request failed")
    finally:
        teardown()

    contents = (run_dir / "strix.log").read_text(encoding="utf-8")
    assert response_marker not in contents
    assert "APIError" in contents
    assert "test_scan_log_omits_unlabelled_openai_error_message" in contents


def test_scan_log_captures_and_redacts_lyrashield_namespace(tmp_path: Path) -> None:
    credential_value = "lyrashield-provider-secret-123456"
    response_marker = "lyrashield-private-response-7f3a"
    run_dir = tmp_path / "scan"
    teardown = setup_scan_logging(run_dir)
    logger = logging.getLogger("lyrashield.lifecycle.execution.redaction-regression")

    try:
        logger.warning("Provider returned token=%s", credential_value)
        try:
            _raise_provider_error(f"request rejected with {response_marker}")
        except RuntimeError:
            logger.exception("Provider request failed")
    finally:
        teardown()

    contents = (run_dir / "strix.log").read_text(encoding="utf-8")
    assert credential_value not in contents
    assert response_marker not in contents
    assert "[SECRET]" in contents
    assert "RuntimeError: [exception message omitted]" in contents
