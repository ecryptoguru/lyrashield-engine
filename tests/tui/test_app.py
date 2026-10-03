"""Headless checks for Local setup and scan controls."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from textual.widgets import Input, Select, Static

from lyrashield.tui.app import LyraShieldLocalApp
from lyrashield.tui.byok_config import (
    AzureConfig,
    ByokConfig,
    ByokConfigError,
    ChatGptConfig,
    Provider,
)
from lyrashield.tui.results_store import FindingRecord, ResultsStore, ResultsStoreKeyError
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


def test_malformed_saved_byok_keeps_tui_open_with_recovery_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lyrashield.tui import app as tui_app

    def malformed_config():
        raise ByokConfigError("The saved BYOK setup is malformed; re-enter setup.")

    monkeypatch.setattr(tui_app, "load_config", malformed_config)
    app = LyraShieldLocalApp(store=ResultsStore(tmp_path / "results.db"))

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)):
            message = str(app.query_one("#byok-status", Static).render())
            assert "saved BYOK setup is malformed" in message
            assert "re-enter setup" in message

    asyncio.run(exercise())


def test_missing_saved_azure_key_keeps_endpoint_and_shows_recovery_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lyrashield.tui import app as tui_app

    monkeypatch.setattr(
        tui_app,
        "load_config",
        lambda: ByokConfig(
            provider=Provider.AZURE_OPENAI,
            azure=AzureConfig(endpoint="https://example.openai.azure.com", deployment="prod"),
        ),
    )
    app = LyraShieldLocalApp(store=ResultsStore(tmp_path / "results.db"))

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)):
            message = str(app.query_one("#byok-status", Static).render())
            assert "saved Azure key is unavailable" in message
            assert "enter it again" in message
            assert app.config.azure.endpoint == "https://example.openai.azure.com"

    asyncio.run(exercise())


def test_setup_requires_new_key_before_switching_azure_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lyrashield.tui import byok_config

    keyring = {}

    def fake_get(service: str, key: str) -> str | None:
        return keyring.get(f"{service}:{key}")

    def fake_set(service: str, key: str, value: str) -> bool:
        keyring[f"{service}:{key}"] = value
        return True

    def fake_delete(service: str, key: str) -> bool:
        keyring.pop(f"{service}:{key}", None)
        return True

    monkeypatch.setattr(byok_config, "keyring_get", fake_get)
    monkeypatch.setattr(byok_config, "keyring_set", fake_set)
    monkeypatch.setattr(byok_config, "keyring_delete", fake_delete)
    byok_config.save_config(
        ByokConfig(
            provider=Provider.AZURE_OPENAI,
            azure=AzureConfig(
                api_key="old-endpoint-key",
                endpoint="https://old.example",
                deployment="production",
            ),
        )
    )
    saved_blob = keyring[f"{byok_config.KEYCHAIN_SERVICE}:{byok_config.CONFIG_KEY}"]
    old_key_id = json.loads(saved_blob)["azure"]["key_id"]
    app = LyraShieldLocalApp(store=ResultsStore(tmp_path / "results.db"))

    async def exercise() -> None:
        async with app.run_test(size=(100, 35)):
            app.query_one("#provider", Select).value = Provider.AZURE_OPENAI.value
            app.query_one("#azure-endpoint", Input).value = "https://new.example/"
            app.query_one("#azure-deployment", Input).value = "replacement"
            await app._on_save_byok(None)  # type: ignore[arg-type]

            message = str(app.query_one("#byok-status", Static).render())
            assert "endpoint change requires entering the API key" in message
            assert keyring[f"{byok_config.KEYCHAIN_SERVICE}:{byok_config.CONFIG_KEY}"] == saved_blob
            assert keyring[f"{byok_config.KEYCHAIN_SERVICE}:{old_key_id}"] == "old-endpoint-key"
            assert app.config.azure.endpoint == "https://old.example"

            app.query_one("#azure-key", Input).value = "new-endpoint-key"
            await app._on_save_byok(None)  # type: ignore[arg-type]

            loaded = byok_config.load_config()
            assert loaded.azure.endpoint == "https://new.example/"
            assert loaded.azure.api_key == "new-endpoint-key"
            assert old_key_id not in keyring

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


def test_untrusted_finding_title_is_rendered_as_plain_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ResultsStore(tmp_path / "results.db")
    monkeypatch.setattr(
        store,
        "list_findings",
        lambda _run_id: [
            FindingRecord(
                finding_id="f1",
                run_id="r1",
                severity="HIGH",
                title="[red]owned title[/]",
                payload={},
            )
        ],
    )
    app = LyraShieldLocalApp(ByokConfig(), store)

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)):
            app._render_findings("r1")
            rendered = app.query_one("#findings", Static).render()
            assert "[red]owned title[/]" in rendered.plain
            title_start = rendered.plain.index("[red]owned title[/]")
            assert all(not (span.start <= title_start < span.end) for span in rendered.spans)

    asyncio.run(exercise())
