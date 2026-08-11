# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the Parallel Search web_search tool and WebSearchSettings."""

from __future__ import annotations

import json
import os
from typing import Any, Self

import httpx
import pytest
from agents.tool_context import ToolContext

from lyrashield.artifacts.state import ReportState, set_global_report_state
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.policy import loader as config_loader
from lyrashield.policy.loader import load_settings
from lyrashield.tools.web_search.tool import (
    _build_objective,
    _estimate_cost,
    _query_to_keywords,
    _redact_query,
    _target_hosts_from_report,
    _validate_web_search_call,
    web_search,
)


def _clear_settings_cache() -> None:
    config_loader._cached = None


def _reload_settings() -> Any:
    _clear_settings_cache()
    return load_settings()


def _tool_ctx(args: dict[str, Any]) -> ToolContext:
    """Build a minimal ToolContext for invoking the web_search FunctionTool."""
    payload = json.dumps(args)
    return ToolContext(
        context={},
        tool_name="web_search",
        tool_call_id="test-call",
        tool_arguments=payload,
    )


def test_web_search_settings_defaults() -> None:
    """WebSearchSettings should default to disabled and sensible caps."""
    settings = _reload_settings()
    assert settings.web_search.enabled is False
    assert settings.web_search.api_key is None
    assert settings.web_search.api_base is None
    assert settings.web_search.mode == "turbo"
    assert settings.web_search.max_results == 5
    assert settings.web_search.max_calls_per_scan == 50
    assert settings.web_search.budget_usd == 1.0
    assert settings.web_search.turbo_cost_per_call == 0.001


def test_web_search_env_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    """LYRASHIELD_* and PARALLEL_API_KEY aliases resolve correctly."""
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("PARALLEL_API_KEY", "pk_test")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MODE", "advanced")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", "10")

    settings = _reload_settings()
    assert settings.web_search.enabled is True
    assert settings.web_search.api_key == "pk_test"
    assert settings.web_search.mode == "advanced"
    assert settings.web_search.max_calls_per_scan == 10


def test_web_search_env_aliases_product_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker passes LYRASHIELD_WEB_SEARCH_API_KEY, not the upstream PARALLEL_API_KEY."""
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_ENABLED", "1")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_API_KEY", "lyra-product-key")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_PROVIDER", "parallel")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MODE", "basic")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_RESULTS", "7")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_CHARS_TOTAL", "2500")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", "5")
    monkeypatch.setenv("LYRASHIELD_WEB_SEARCH_BUDGET_USD", "2.5")

    settings = _reload_settings()
    assert settings.web_search.enabled is True
    assert settings.web_search.api_key == "lyra-product-key"
    assert settings.web_search.provider == "parallel"
    assert settings.web_search.mode == "basic"
    assert settings.web_search.max_results == 7
    assert settings.web_search.max_chars_total == 2500
    assert settings.web_search.max_calls_per_scan == 5
    assert settings.web_search.budget_usd == 2.5


def test_redact_query_handles_sensitive_patterns() -> None:
    """Redactor should strip credentials, PII, and URLs without breaking topic intent."""
    query = (
        "Find CVEs for service at https://api.target.com/v1/users "
        "using api_key=sk-1234567890abcdef "
        "and contact alice@example.com; uuid 550e8400-e29b-41d4-a716-446655440000 "
        "ip 192.168.1.1 token abcdef1234567890abcdef1234567890"
    )
    redacted = _redact_query(query, "cve", None)
    assert "https://api.target.com" not in redacted
    assert "[URL]" in redacted
    assert "sk-1234567890abcdef" not in redacted
    assert "[SECRET]" in redacted
    assert "alice@example.com" not in redacted
    assert "[EMAIL]" in redacted
    assert "550e8400-e29b-41d4-a716-446655440000" not in redacted
    assert "[UUID]" in redacted
    assert "192.168.1.1" not in redacted
    assert "[IP]" in redacted
    assert "abcdef1234567890abcdef1234567890" not in redacted
    assert "[SECRET]" in redacted


def test_redact_query_preserves_public_endpoints_domain() -> None:
    """Public-endpoints topic should keep bare hostnames while still redacting secrets."""
    query = "Find public API docs for example.com and token=secret123"
    redacted = _redact_query(query, "public-endpoints", None)
    assert "example.com" in redacted
    assert "secret123" not in redacted


def test_redact_query_replaces_target_hosts() -> None:
    """Known target hostnames should be replaced for non-public-endpoints queries."""
    query = "CVEs for django on target.example.com"
    redacted = _redact_query(query, "cve", {"target.example.com"})
    assert "target.example.com" not in redacted
    assert "[TARGET]" in redacted
    assert "django" in redacted


def test_query_to_keywords_uses_provided_keywords() -> None:
    """If keywords are given, use them directly (trimmed and capped)."""
    assert _query_to_keywords("", "cve", ["foo", "bar", "  baz  "]) == ["foo", "bar", "baz"]


def test_query_to_keywords_derives_from_query() -> None:
    """Without keywords, derive 2 short search queries from the redacted query."""
    query = "Find latest CVE for Next.js authentication bypass"
    keywords = _query_to_keywords(query, "cve", None)
    assert keywords
    assert all(len(k.split()) <= 6 for k in keywords)
    assert any("Next" in k or "next" in k for k in keywords)


def test_build_objective_prefixes_by_topic() -> None:
    """Objectives use a topic-appropriate prefix."""
    assert _build_objective("cve", "django 4.2") == (
        "Find public CVEs and security advisories for django 4.2"
    )
    assert _build_objective("version", "django") == (
        "Find the latest stable version and release notes for django"
    )


def test_estimate_cost_per_mode() -> None:
    """Cost estimates should follow the configured per-mode price."""

    class FakeSettings:
        turbo_cost_per_call = 0.001
        basic_cost_per_call = 0.005
        advanced_cost_per_call = 0.005

    assert _estimate_cost("turbo", FakeSettings()) == 0.001
    assert _estimate_cost("basic", FakeSettings()) == 0.005
    assert _estimate_cost("advanced", FakeSettings()) == 0.005


def test_target_hosts_from_report() -> None:
    """Target hosts are extracted from string targets and dict target records."""
    report_state = ReportState(run_name="test")
    report_state.set_scan_config(
        {
            "targets": [
                "https://target.example.com/path",
                {"target": "other.test", "host": "ignored"},
            ],
        }
    )
    set_global_report_state(report_state)

    hosts = _target_hosts_from_report()
    assert hosts is not None
    assert "target.example.com" in hosts
    assert "other.test" in hosts

    set_global_report_state(None)


@pytest.mark.asyncio
async def test_web_search_disabled() -> None:
    """When disabled, web_search returns a clear message and never calls the API."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "0"

    args = {"query": "Find CVEs for django"}
    result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert result["success"] is False
    assert "disabled" in result["message"].lower()

    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]


@pytest.mark.asyncio
async def test_web_search_missing_api_key() -> None:
    """An enabled tool with no API key should return a configuration error."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "1"

    args = {"query": "Find CVEs for django"}
    result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert result["success"] is False
    assert "api key" in result["message"].lower() or "not configured" in result["message"].lower()

    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]


def test_validate_web_search_call_invalid_topic() -> None:
    """Invalid topic is rejected by the guard validator."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "1"
    os.environ["PARALLEL_API_KEY"] = "pk_test"
    settings = load_settings()
    error = _validate_web_search_call(settings.web_search, "not_a_topic", None)
    assert error is not None
    assert "invalid topic" in error.lower()
    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]
    del os.environ["PARALLEL_API_KEY"]


@pytest.mark.asyncio
async def test_web_search_call_count_cap() -> None:
    """Respect max_calls_per_scan from web search settings."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "1"
    os.environ["PARALLEL_API_KEY"] = "pk_test"
    os.environ["LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN"] = "1"

    report_state = ReportState(run_name="test")
    report_state.record_web_search_cost(0.001, query="first", mode="turbo")
    set_global_report_state(report_state)

    args = {"query": "Find CVEs for django"}
    result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert result["success"] is False
    assert "limit reached" in result["message"].lower()

    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]
    del os.environ["PARALLEL_API_KEY"]
    del os.environ["LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN"]
    set_global_report_state(None)


@pytest.mark.asyncio
async def test_web_search_hits_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful Parallel Search call returns summarized results."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "1"
    os.environ["PARALLEL_API_KEY"] = "pk_test"
    os.environ["LYRASHIELD_WEB_SEARCH_MODE"] = "turbo"
    os.environ["LYRASHIELD_WEB_SEARCH_MAX_RESULTS"] = "2"

    report_state = ReportState(run_name="test")
    set_global_report_state(report_state)

    class FakeResponse:
        def json(self) -> dict[str, Any]:
            return {
                "results": [
                    {
                        "title": "CVE-2024-1234",
                        "url": "https://example.com/cve",
                        "excerpts": ["Django 4.2 has a vulnerability."],
                    },
                    {
                        "title": "Advisory",
                        "url": "https://example.com/advisory",
                        "excerpts": ["Patch available."],
                    },
                ],
            }

        def raise_for_status(self) -> None:
            pass

    class FakeClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, *_: object, **__: object) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

    args = {"query": "Find CVEs for Django 4.2"}
    result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert result["success"] is True
    assert "CVE-2024-1234" in result["content"]
    assert "example.com/cve" in result["content"]
    assert result["mode"] == "turbo"

    count, cost = report_state.get_web_search_stats()
    assert count == 1
    assert cost > 0

    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]
    del os.environ["PARALLEL_API_KEY"]
    del os.environ["LYRASHIELD_WEB_SEARCH_MODE"]
    del os.environ["LYRASHIELD_WEB_SEARCH_MAX_RESULTS"]
    set_global_report_state(None)


@pytest.mark.asyncio
async def test_web_search_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP failures from Parallel should be surfaced as a failed tool result."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "1"
    os.environ["PARALLEL_API_KEY"] = "pk_test"

    class FakeClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, *_: object, **__: object) -> None:
            raise httpx.HTTPError("connection refused")

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

    args = {"query": "Find CVEs"}
    result = json.loads(await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args)))
    assert result["success"] is False
    assert "failed" in result["message"].lower()

    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]
    del os.environ["PARALLEL_API_KEY"]


@pytest.mark.asyncio
async def test_reserve_web_search_call_enforces_budget() -> None:
    """Reserve and release should respect max_budget_usd."""
    hooks = ReportUsageHooks(model="openai/gpt-5.6-luna", max_budget_usd=0.001)
    key = "test:ws"
    await hooks.reserve_web_search_call(key=key, estimated_cost=0.001)

    with pytest.raises(BudgetExceededError):
        await hooks.reserve_web_search_call(key=f"{key}:2", estimated_cost=0.002)

    await hooks.release_web_search_call(key=key, actual_cost=0.001)


@pytest.mark.asyncio
async def test_web_search_payload_includes_advanced_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The API payload should nest max_results under advanced_settings."""
    _clear_settings_cache()
    os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"] = "1"
    os.environ["PARALLEL_API_KEY"] = "pk_test"
    os.environ["LYRASHIELD_WEB_SEARCH_MODE"] = "turbo"
    os.environ["LYRASHIELD_WEB_SEARCH_MAX_RESULTS"] = "3"

    report_state = ReportState(run_name="test")
    set_global_report_state(report_state)

    captured_payload: dict[str, Any] = {}

    class FakeResponse:
        def json(self) -> dict[str, Any]:
            return {"results": []}

        def raise_for_status(self) -> None:
            pass

    class FakeClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, _url: str, *, json: dict[str, Any], **_: object) -> FakeResponse:
            captured_payload.update(json)
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

    args = {"query": "Find CVEs for Django 4.2"}
    await web_search.on_invoke_tool(_tool_ctx(args), json.dumps(args))

    assert "advanced_settings" in captured_payload
    assert captured_payload["advanced_settings"]["max_results"] == 3
    assert "max_results" not in captured_payload or captured_payload.get("max_results") is None

    del os.environ["LYRASHIELD_WEB_SEARCH_ENABLED"]
    del os.environ["PARALLEL_API_KEY"]
    del os.environ["LYRASHIELD_WEB_SEARCH_MODE"]
    del os.environ["LYRASHIELD_WEB_SEARCH_MAX_RESULTS"]
    set_global_report_state(None)
