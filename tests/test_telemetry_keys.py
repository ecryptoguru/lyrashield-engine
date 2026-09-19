# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for telemetry key externalization and lazy env var reads."""

from __future__ import annotations

import importlib
from pathlib import Path
from unittest.mock import patch

import pytest

import strix.skills as skills_mod
from lyrashield.policy import loader
from lyrashield.telemetry import posthog, scarf


@pytest.fixture(autouse=True)
def _telemetry_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")


def test_posthog_skips_when_api_key_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Posthog should silently skip when no API key is set."""
    monkeypatch.delenv("STRIX_POSTHOG_API_KEY", raising=False)
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    importlib.reload(posthog)
    try:
        result = posthog._send("test_event", {"key": "value"})
        assert result is False
    finally:
        monkeypatch.setenv("STRIX_TELEMETRY", "0")
        importlib.reload(posthog)


def test_posthog_reads_api_key_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    """Posthog should read the API key at call time, not import time."""
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    monkeypatch.setenv("STRIX_POSTHOG_API_KEY", "phc_test_key_123")
    importlib.reload(posthog)
    try:
        assert posthog._posthog_api_key() == "phc_test_key_123"
        assert posthog._posthog_host() == "https://us.i.posthog.com"

        monkeypatch.setenv("STRIX_POSTHOG_API_KEY", "phc_changed_key")
        assert posthog._posthog_api_key() == "phc_changed_key"
    finally:
        monkeypatch.setenv("STRIX_TELEMETRY", "0")
        monkeypatch.delenv("STRIX_POSTHOG_API_KEY", raising=False)
        importlib.reload(posthog)


def test_posthog_reads_host_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    """Posthog host should be read at call time."""
    monkeypatch.setenv("STRIX_POSTHOG_HOST", "https://custom.posthog.example")
    assert posthog._posthog_host() == "https://custom.posthog.example"
    monkeypatch.delenv("STRIX_POSTHOG_HOST", raising=False)
    assert posthog._posthog_host() == "https://us.i.posthog.com"


def test_scarf_skips_when_endpoint_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scarf should silently skip when no endpoint is set."""
    monkeypatch.delenv("STRIX_SCARF_ENDPOINT", raising=False)
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    importlib.reload(scarf)
    try:
        result = scarf._send("test_event", {"key": "value"})
        assert result is False
    finally:
        monkeypatch.setenv("STRIX_TELEMETRY", "0")
        importlib.reload(scarf)


def test_scarf_reads_endpoint_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scarf endpoint should be read at call time, not import time."""
    monkeypatch.setenv("STRIX_SCARF_ENDPOINT", "https://custom.scarf.example")
    assert scarf._scarf_endpoint() == "https://custom.scarf.example"

    monkeypatch.setenv("STRIX_SCARF_ENDPOINT", "https://changed.scarf.example")
    assert scarf._scarf_endpoint() == "https://changed.scarf.example"

    monkeypatch.delenv("STRIX_SCARF_ENDPOINT", raising=False)
    assert scarf._scarf_endpoint() == ""


def test_skills_track_only_records_names_no_beacon(monkeypatch: pytest.MonkeyPatch) -> None:
    """Upstream v1.6.2 dropped the per-load beacon: _track_skill_loaded only
    records names for the end-of-run report, so it must never spawn a thread or
    hit the network regardless of the telemetry toggle."""
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    loader._cached = None

    with (
        patch("strix.telemetry.posthog._send") as posthog_send,
        patch("strix.telemetry.scarf._send") as scarf_send,
    ):
        skills_mod._track_skill_loaded("test-skill", Path("/fake/skills/test.md"))
        assert "custom" in skills_mod.get_loaded_skill_names()
        posthog_send.assert_not_called()
        scarf_send.assert_not_called()
