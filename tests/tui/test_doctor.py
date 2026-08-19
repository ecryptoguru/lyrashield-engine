# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the doctor diagnostics module."""

from __future__ import annotations

from pathlib import Path

import pytest

from lyrashield.tui.byok_config import ByokConfig, ChatGptConfig, Provider
from lyrashield.tui.doctor import (
    DoctorReport,
    FREE_ALTERNATIVES,
    check_byok,
    check_license_cache,
    detect_runtime,
    format_report,
    run_doctor,
)


def test_free_alternatives_include_podman_rancher_colima() -> None:
    names = {a["name"] for a in FREE_ALTERNATIVES}
    assert "Podman Desktop" in names
    assert "Rancher Desktop" in names
    assert "Colima" in names


def test_detect_runtime_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lyrashield.tui.doctor._probe_unix_socket", lambda p, timeout=2.0: False)
    monkeypatch.setattr("lyrashield.tui.doctor._probe_tcp_host", lambda h, timeout=2.0: False)
    result = detect_runtime({"DOCKER_HOST": "unix:///nonexistent.sock"})
    assert result.ok is False
    assert "Podman" in result.remediation or "Rancher" in result.remediation


def test_detect_runtime_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lyrashield.tui.doctor._probe_unix_socket", lambda p, timeout=2.0: True)
    monkeypatch.setattr("lyrashield.tui.doctor._docker_version_handshake", lambda e: "1.2.3")
    result = detect_runtime({"DOCKER_HOST": "unix:///var/run/docker.sock"})
    assert result.ok is True
    assert "1.2.3" in result.detail


def test_check_byok_unconfigured() -> None:
    result = check_byok(ByokConfig())
    assert result.ok is False


def test_check_byok_chatgpt_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lyrashield.tui.byok_config.validate_chatgpt_credential", lambda: False)
    cfg = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    result = check_byok(cfg)
    assert result.ok is False


def test_check_license_cache_missing(tmp_path: Path) -> None:
    result = check_license_cache(tmp_path / "nope.cache")
    assert result.ok is False


def test_check_license_cache_present(tmp_path: Path) -> None:
    path = tmp_path / "license.cache"
    path.write_bytes(b"x" * 128)  # >= 64 bytes
    result = check_license_cache(path)
    assert result.ok is True


def test_run_doctor_aggregates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lyrashield.tui.doctor.detect_runtime",
        lambda env=None: __import__("lyrashield.tui.doctor", fromlist=["CheckResult"]).CheckResult(
            "docker-runtime", True, "ok"
        ),
    )
    monkeypatch.setattr(
        "lyrashield.tui.doctor.check_byok",
        lambda c: __import__("lyrashield.tui.doctor", fromlist=["CheckResult"]).CheckResult(
            "byok-credential", True, "ok"
        ),
    )
    monkeypatch.setattr(
        "lyrashield.tui.doctor.check_license_cache",
        lambda p=None: __import__("lyrashield.tui.doctor", fromlist=["CheckResult"]).CheckResult(
            "license-cache", True, "ok"
        ),
    )
    report = run_doctor(skip_smoke=True)
    assert report.all_ok is True
    assert len(report.checks) == 3


def test_format_report_renders() -> None:
    report = DoctorReport()
    from lyrashield.tui.doctor import CheckResult

    report.add(CheckResult("x", True, "ok"))
    text = format_report(report)
    assert "[OK]" in text
    assert "All checks passed." in text
