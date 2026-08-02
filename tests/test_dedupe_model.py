"""Tests for the dedicated deduplication model configuration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from strix.config import loader
from strix.config.settings import DedupeSettings
from strix.core import hooks as hooks_module
from strix.report import dedupe as dedupe_module
from strix.report.dedupe import (
    _MAX_EXISTING_REPORTS_CHARS,
    _bound_existing_reports,
    _dedupe_model_settings,
    _extract_balanced_json,
    _parse_dedupe_response,
)


def test_dedupe_key_sent_per_call_not_via_global_env() -> None:
    dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap", DEDUPE_LLM_API_KEY="dedupe-key")
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    # The key rides on the request, so a shared-provider main key can't clobber
    # it (and vice versa) through the global provider env var.
    assert (settings.extra_args or {})["api_key"] == "dedupe-key"


def test_dedupe_settings_omit_api_key_when_unset() -> None:
    dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap")
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert "api_key" not in (settings.extra_args or {})
    assert "api_base" not in (settings.extra_args or {})


def test_dedupe_endpoint_sent_per_call() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="openai/cheap",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    settings = _dedupe_model_settings(dedupe, "openai/cheap", 300)
    # A distinct dedupe endpoint rides on the request instead of the
    # process-wide base URL, so it can't clobber the main model's endpoint.
    assert (settings.extra_args or {})["api_base"] == "https://dedupe.example/v1"
    assert (settings.extra_args or {})["api_key"] == "dedupe-key"


def test_dedicated_dedupe_model_uses_own_headers_not_main() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_EXTRA_HEADERS={"X-Dedupe": "yes"},
    )
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert settings.extra_headers == {"X-Dedupe": "yes"}


def test_dedicated_dedupe_model_gets_no_main_headers_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Main": "secret"}))
    loader._cached = None
    try:
        dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap")
        settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
        assert settings.extra_headers is None
    finally:
        loader._cached = None


def test_fallback_dedupe_inherits_main_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Main": "svc"}))
    loader._cached = None
    try:
        settings = _dedupe_model_settings(DedupeSettings(), "openai/main-model", 300)
        assert settings.extra_headers == {"X-Main": "svc"}
    finally:
        loader._cached = None


def test_dedupe_defaults_are_empty() -> None:
    settings = DedupeSettings()
    assert settings.model is None
    assert settings.reasoning_effort is None
    assert settings.api_key is None


def test_dedupe_model_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DEDUPE_MODEL", "deepseek/deepseek-v4-flash")
    monkeypatch.setenv("STRIX_DEDUPE_REASONING_EFFORT", "low")

    settings = DedupeSettings()

    assert settings.model == "deepseek/deepseek-v4-flash"
    assert settings.reasoning_effort == "low"


def test_config_file_loads_dedupe_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("STRIX_LLM", "STRIX_DEDUPE_MODEL", "STRIX_DEDUPE_REASONING_EFFORT"):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM": "openai/root",
                    "STRIX_DEDUPE_MODEL": "deepseek/cheap",
                    "STRIX_DEDUPE_REASONING_EFFORT": "minimal",
                }
            }
        ),
        encoding="utf-8",
    )
    loader._cached = None
    loader._override = path
    try:
        settings = loader.load_settings()
    finally:
        loader._cached = None
        loader._override = None

    assert settings.dedupe.model == "deepseek/cheap"
    assert settings.dedupe.reasoning_effort == "minimal"
    # Main model stays independent of the dedupe override.
    assert settings.llm.model == "openai/root"


def test_bound_existing_reports_keeps_small_lists_intact() -> None:
    reports = [{"id": f"vuln-{i}", "title": "x" * 100} for i in range(50)]
    assert _bound_existing_reports(reports) == reports


def test_bound_existing_reports_drops_oldest_beyond_budget() -> None:
    big = "x" * 8000
    reports = [{"id": f"vuln-{i:04d}", "description": big} for i in range(100)]
    bounded = _bound_existing_reports(reports)
    assert 0 < len(bounded) < len(reports)
    # Newest reports are retained, in original order.
    assert bounded == reports[len(reports) - len(bounded) :]
    assert sum(len(json.dumps(r)) for r in bounded) <= _MAX_EXISTING_REPORTS_CHARS


def test_bound_existing_reports_truncates_an_oversized_newest_report() -> None:
    oversized = {"id": "vuln-big", "description": "x" * (_MAX_EXISTING_REPORTS_CHARS + 1)}
    bounded = _bound_existing_reports([{"id": "vuln-old"}, oversized])
    assert len(bounded) == 1
    kept = bounded[0]
    # Identity is preserved, the payload is not.
    assert kept["id"] == "vuln-big"
    assert kept["description"].endswith("...[truncated]")
    assert len(json.dumps(kept, indent=2)) <= _MAX_EXISTING_REPORTS_CHARS


def test_bound_existing_reports_encoded_payload_never_exceeds_the_cap() -> None:
    """The transmitted payload is indented, so the cap must hold against that form."""
    reports = [{"id": f"vuln-{i:04d}", "description": "x" * 8000} for i in range(200)]
    bounded = _bound_existing_reports(reports)
    assert len(json.dumps(bounded, indent=2)) <= _MAX_EXISTING_REPORTS_CHARS


def test_bound_existing_reports_drops_a_report_whose_identity_alone_overflows() -> None:
    unshrinkable = {"id": "x" * (_MAX_EXISTING_REPORTS_CHARS + 1)}
    assert _bound_existing_reports([unshrinkable]) == []


@pytest.mark.asyncio
async def test_dedupe_call_reserves_and_releases_against_the_scan_budget() -> None:
    """The dedupe model call is metered, so it must reserve like any agent request."""
    events: list[str] = []

    class _Hooks:
        async def reserve_out_of_band_request(self, **kwargs: object) -> None:
            events.append(f"reserve:{kwargs['key']}")

        async def release_out_of_band_request(self, **kwargs: object) -> None:
            events.append(f"release:{kwargs['key']}")

    async def _fake_get_response(**_kwargs: object) -> SimpleNamespace:
        events.append("request")
        return SimpleNamespace(usage=None)

    hooks_module.set_active_hooks(cast("Any", _Hooks()))
    try:
        response = await dedupe_module._request_dedupe_judgement(
            model=SimpleNamespace(get_response=_fake_get_response),
            model_name="gpt-5.6-luna",
            model_settings=cast("Any", None),
            user_msg="compare",
        )
    finally:
        hooks_module.set_active_hooks(None)

    assert response is not None
    assert [e.split(":")[0] for e in events] == ["reserve", "request", "release"]


@pytest.mark.asyncio
async def test_dedupe_releases_its_reservation_when_the_request_fails() -> None:
    """A provider error must not strand the reservation for the rest of the scan."""
    events: list[str] = []

    class _Hooks:
        async def reserve_out_of_band_request(self, **_kwargs: object) -> None:
            events.append("reserve")

        async def release_out_of_band_request(self, **_kwargs: object) -> None:
            events.append("release")

    async def _boom(**_kwargs: object) -> None:
        raise RuntimeError("provider exploded")

    hooks_module.set_active_hooks(cast("Any", _Hooks()))
    try:
        with pytest.raises(RuntimeError, match="provider exploded"):
            await dedupe_module._request_dedupe_judgement(
                model=SimpleNamespace(get_response=_boom),
                model_name="gpt-5.6-luna",
                model_settings=cast("Any", None),
                user_msg="compare",
            )
    finally:
        hooks_module.set_active_hooks(None)

    assert events == ["reserve", "release"]


@pytest.mark.asyncio
async def test_dedupe_works_without_active_hooks() -> None:
    """Dedupe outside a scan (no registered hooks) must not crash."""
    assert hooks_module.get_active_hooks() is None

    async def _fake_get_response(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(usage=None)

    response = await dedupe_module._request_dedupe_judgement(
        model=SimpleNamespace(get_response=_fake_get_response),
        model_name="gpt-5.6-luna",
        model_settings=cast("Any", None),
        user_msg="compare",
    )
    assert response is not None


def test_runner_clears_active_hooks_on_every_exit_path() -> None:
    """A stale hooks registration would let a later scan reserve against a dead budget."""
    runner = Path("strix/core/runner.py").read_text(encoding="utf-8")
    assert "set_active_hooks(hooks)" in runner
    # The clear must live in the `finally` so it runs on success, failure, and cancel.
    finally_block = runner.split("\n    finally:\n", 1)[1]
    assert "set_active_hooks(None)" in finally_block


def test_extract_balanced_json_handles_fences_and_nesting() -> None:
    cases = [
        ('{"is_duplicate": true, "confidence": 0.9}', '{"is_duplicate": true, "confidence": 0.9}'),
        ('```json\n{"is_duplicate": true}\n```', '{"is_duplicate": true}'),
        (
            'Here is the result: {"is_duplicate": true, "reason": "same"}',
            '{"is_duplicate": true, "reason": "same"}',
        ),
        (
            json.dumps({"is_duplicate": True, "reason": 'has a { brace and " escaped quote'}),
            json.dumps({"is_duplicate": True, "reason": 'has a { brace and " escaped quote'}),
        ),
        (
            '{"outer": {"inner": 1}}',
            '{"outer": {"inner": 1}}',
        ),
    ]
    for raw, expected in cases:
        assert _extract_balanced_json(raw) == expected


def test_extract_balanced_json_rejects_missing_object() -> None:
    with pytest.raises(ValueError, match="No JSON object found"):
        _extract_balanced_json("just prose")


def test_extract_balanced_json_rejects_unbalanced_object() -> None:
    with pytest.raises(ValueError, match="No balanced JSON object found"):
        _extract_balanced_json('{"is_duplicate": true')


def test_parse_dedupe_response_coerces_fields_and_truncates() -> None:
    payload = json.dumps(
        {
            "is_duplicate": True,
            "duplicate_id": "x" * 100,
            "confidence": "bad",
            "reason": "y" * 1000,
        }
    )
    parsed = _parse_dedupe_response(payload)
    assert parsed["is_duplicate"] is True
    assert len(parsed["duplicate_id"]) <= 64
    assert parsed["confidence"] == 0.0
    assert len(parsed["reason"]) <= 500
