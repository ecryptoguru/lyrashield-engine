"""Headless checks for Local setup and scan controls."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Input, Select, Static

from lyrashield.tui.app import LyraShieldLocalApp
from lyrashield.tui.byok_config import ByokConfig, ChatGptConfig, Provider
from lyrashield.tui.results_store import ResultsStore, ResultsStoreKeyError
from lyrashield.tui.scan_flow import ScanResult


def test_invalid_budget_and_duplicate_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from lyrashield.tui import app as tui_app

    calls = 0
    release = asyncio.Event()

    async def fake_scan(*_args: object, **_kwargs: object) -> ScanResult:
        nonlocal calls
        calls += 1
        await release.wait()
        return ScanResult("r1", 0, "", "", 0.1)

    monkeypatch.setattr(tui_app, "run_scan", fake_scan)
    config = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    app = LyraShieldLocalApp(config, ResultsStore(tmp_path / "results.db"))

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one("#target", Input).value = "https://example.com"
            budget = app.query_one("#max-budget", Input)
            for value in ("abc", "0", "-1", "nan", "inf"):
                budget.value = value
                app._run_scan()
                assert calls == 0
                assert "positive finite" in str(app.query_one("#progress", Static).render())
            budget.value = "1"
            app._run_scan()
            app._run_scan()
            await pilot.pause()
            assert calls == 1
            release.set()
            await pilot.pause()

    asyncio.run(exercise())


def test_setup_requires_auth_and_azure_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lyrashield.tui import app as tui_app

    monkeypatch.setattr(tui_app, "validate_chatgpt_credential", lambda: False)
    saved = []
    monkeypatch.setattr(tui_app, "save_config", lambda config: saved.append(config.provider))
    app = LyraShieldLocalApp(ByokConfig(), ResultsStore(tmp_path / "results.db"))

    async def exercise() -> None:
        async with app.run_test(size=(120, 45)) as pilot:
            await app._on_save_byok(None)  # type: ignore[arg-type]
            assert saved == []
            assert "Sign in first" in str(app.query_one("#byok-status", Static).render())
            app.query_one("#provider", Select).value = Provider.AZURE_OPENAI.value
            await app._on_save_byok(None)  # type: ignore[arg-type]
            assert saved == []
            app.query_one("#azure-endpoint", Input).value = "https://example.openai.azure.com"
            app.query_one("#azure-deployment", Input).value = "dep"
            app.query_one("#azure-key", Input).value = "synthetic-key"
            await app._on_save_byok(None)  # type: ignore[arg-type]
            assert saved == [Provider.AZURE_OPENAI]
            assert app.config.is_configured()
            await pilot.pause()

    asyncio.run(exercise())


def test_results_key_failures_show_in_findings_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ResultsStore(tmp_path / "results.db")
    app = LyraShieldLocalApp(ByokConfig(), store)

    def key_error(*_args: object) -> None:
        raise ResultsStoreKeyError("Local keychain is unavailable")

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)):
            monkeypatch.setattr(store, "list_findings", key_error)
            app._render_findings("r1")
            assert "Findings unavailable" in str(app.query_one("#findings", Static).render())

            monkeypatch.setattr(store, "list_findings", lambda _run_id: [])
            monkeypatch.setattr(store, "get_run", key_error)
            app._render_findings("r1")
            assert "Findings unavailable" in str(app.query_one("#findings", Static).render())

            monkeypatch.setattr(store, "list_runs", key_error)
            app._export("sarif")
            assert "Export failed" in str(app.query_one("#progress", Static).render())

    asyncio.run(exercise())
