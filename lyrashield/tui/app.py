# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""LyraShield Local — main TUI entry point.

A Textual-based terminal UI that shells into the existing engine CLI. Flows:

1. pick a target (repo path/URL)
2. pick a scan mode (SAFE/QUICK/STANDARD/DEEP/CUSTOM — all available locally,
   no Cloud-style depth gating, no agent-minute metering)
3. connect BYOK (ChatGPT subscription OAuth or Azure OpenAI;
   local/self-hosted marked "experimental / coming")
4. run with streamed progress
5. view findings + fix suggestions
6. export SARIF/report

No engine thin-fork expansion — the TUI shells into the existing adapter.
Azure credentials live in the OS keychain; ChatGPT OAuth uses the engine's
owner-only auth store. Results persist in the local encrypted SQLite store. No benchmark/coverage claims, no money-back
language, no upstream-engine naming.
"""

from __future__ import annotations

import asyncio
import logging
import math
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.panel import Panel
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Select, Static

from lyrashield.tui.byok_config import (
    LAUNCH_PROVIDERS,
    SCAN_MODES,
    ByokConfig,
    Provider,
    load_config,
    provider_label,
    save_config,
    validate_chatgpt_credential,
)
from lyrashield.tui.doctor import format_report, run_doctor
from lyrashield.tui.results_store import ResultsStore, ResultsStoreKeyError
from lyrashield.tui.scan_flow import ScanRequest, export_report, export_sarif, run_scan


if TYPE_CHECKING:
    pass


logger = logging.getLogger(__name__)


APP_TITLE = "LyraShield Local"
EDITION_LABEL = "LyraShield Desktop — Local edition"


class LyraShieldLocalApp(App[None]):
    """LyraShield Local TUI — guided scan flow."""

    TITLE = APP_TITLE
    CSS = """
    Screen {
        layout: vertical;
        padding: 1 2;
    }
    #main { layers: setup run results; }
    .panel { border: round $primary; padding: 1 2; margin: 1 0; }
    .hidden { display: none; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "doctor", "Doctor"),
        Binding("r", "run_scan", "Run scan"),
    ]

    # ---- state ----------------------------------------------------------
    config: ByokConfig
    store: ResultsStore

    # ---- lifecycle ------------------------------------------------------

    def __init__(self, config: ByokConfig | None = None, store: ResultsStore | None = None) -> None:
        super().__init__()
        self._startup_error = ""
        try:
            self.config = config if config is not None else load_config()
        except ResultsStoreKeyError:
            self.config = ByokConfig()
            self._startup_error = "Local keychain is unavailable; BYOK setup cannot be loaded."
        self.store = store or ResultsStore()
        self._scan_task: asyncio.Task[None] | None = None
        self._doctor_task: asyncio.Task[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static(
                Panel(Text(f"{APP_TITLE} — guided scan", style="bold cyan"), title=EDITION_LABEL)
            ),
            self._setup_panel(),
            self._run_panel(),
            self._results_panel(),
            id="main",
        )
        yield Footer()

    def _setup_panel(self) -> Vertical:
        return Vertical(
            Static("1. Point at a project", classes="panel"),
            Static("Target (repo path or URL):"),
            Input(placeholder="/path/to/repo or https://github.com/you/repo", id="target"),
            Static("2. Pick a scan mode (all depths available locally):"),
            Select(
                [(mode, mode) for mode in SCAN_MODES],
                value="STANDARD",
                id="scan-mode",
            ),
            Static("3. Connect AI (BYOK):"),
            Select(
                [(provider_label(p), p.value) for p in LAUNCH_PROVIDERS],
                value=self.config.provider.value,
                id="provider",
            ),
            Static("ChatGPT: sign in with `lyrashield auth login chatgpt` before saving."),
            Input(placeholder="https://your-resource.openai.azure.com", id="azure-endpoint"),
            Input(placeholder="Azure deployment name", id="azure-deployment"),
            Input(
                placeholder="Azure API key (leave blank to keep saved key)",
                password=True,
                id="azure-key",
            ),
            Static("Local / self-hosted models: experimental / coming", classes="hidden"),
            Button("Save BYOK setup", id="save-byok"),
            Static(self._startup_error, id="byok-status"),
            classes="panel",
            id="setup",
        )

    def _run_panel(self) -> Vertical:
        return Vertical(
            Static("4. Run scan", classes="panel"),
            Horizontal(
                Button("Run scan", id="run", variant="success"),
                Button("Cancel", id="cancel", disabled=True),
                Button("Doctor", id="doctor", variant="default"),
                id="run-buttons",
            ),
            Static("Max budget (USD, optional):"),
            Input(placeholder="e.g. 5.0", id="max-budget"),
            VerticalScroll(Static("", id="progress"), id="progress-scroll"),
            classes="panel",
            id="run-panel",
        )

    def _results_panel(self) -> Vertical:
        return Vertical(
            Static("5. Findings + fix suggestions", classes="panel"),
            VerticalScroll(
                Static("No findings yet — run a scan.", id="findings"), id="findings-scroll"
            ),
            Horizontal(
                Button("Export SARIF", id="export-sarif", variant="primary"),
                Button("Export report", id="export-report", variant="primary"),
                id="export-buttons",
            ),
            classes="panel",
            id="results",
        )

    # ---- actions --------------------------------------------------------

    def action_doctor(self) -> None:
        self._run_doctor()

    def action_run_scan(self) -> None:
        self._run_scan()

    # ---- handlers -------------------------------------------------------

    @on(Button.Pressed, "#save-byok")
    async def _on_save_byok(self, _event: Button.Pressed) -> None:
        select = self.query_one("#provider", Select)
        value = str(select.value)
        try:
            self.config.provider = Provider(value)
        except ValueError:
            self.query_one("#byok-status", Static).update("[red]Select a supported provider.[/]")
            return
        status = self.query_one("#byok-status", Static)
        if self.config.provider == Provider.CHATGPT_OAUTH:
            status.update("Checking ChatGPT sign-in…")
            self.config.chatgpt.enabled = await asyncio.to_thread(validate_chatgpt_credential)
            if not self.config.chatgpt.enabled:
                status.update("[red]Sign in first: `lyrashield auth login chatgpt`[/]")
                return
        else:
            self.config.azure.endpoint = (
                self.query_one("#azure-endpoint", Input).value.strip() or self.config.azure.endpoint
            )
            self.config.azure.deployment = (
                self.query_one("#azure-deployment", Input).value.strip()
                or self.config.azure.deployment
            )
            self.config.azure.api_key = (
                self.query_one("#azure-key", Input).value.strip() or self.config.azure.api_key
            )
            if not self.config.azure.is_complete():
                status.update("[red]Enter an Azure endpoint, deployment and API key.[/]")
                return
        try:
            save_config(self.config)
        except Exception as exc:  # noqa: BLE001
            status.update(f"[red]BYOK setup could not be saved: {exc}[/]")
            return
        status.update(f"BYOK setup saved: {provider_label(self.config.provider)}")

    @on(Button.Pressed, "#doctor")
    def _on_doctor(self, _event: Button.Pressed) -> None:
        self._run_doctor()

    @on(Button.Pressed, "#run")
    def _on_run(self, _event: Button.Pressed) -> None:
        self._run_scan()

    @on(Button.Pressed, "#cancel")
    def _on_cancel(self, _event: Button.Pressed) -> None:
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()

    @on(Button.Pressed, "#export-sarif")
    def _on_export_sarif(self, _event: Button.Pressed) -> None:
        self._export("sarif")

    @on(Button.Pressed, "#export-report")
    def _on_export_report(self, _event: Button.Pressed) -> None:
        self._export("report")

    # ---- internals ------------------------------------------------------

    def _run_doctor(self) -> None:
        if self._doctor_task and not self._doctor_task.done():
            return

        async def check() -> None:
            report = await asyncio.to_thread(run_doctor, self.config, skip_smoke=True)
            self.query_one("#progress", Static).update(format_report(report))

        self._doctor_task = asyncio.create_task(check())

    def _run_scan(self) -> None:
        if self._scan_task and not self._scan_task.done():
            return
        if not self.config.is_configured():
            self.query_one("#progress", Static).update(
                "[red]Complete BYOK setup before scanning.[/]"
            )
            return
        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.query_one("#progress", Static).update("[red]Enter a target first.[/]")
            return
        mode = str(self.query_one("#scan-mode", Select).value)
        budget_str = self.query_one("#max-budget", Input).value.strip()
        try:
            budget = float(budget_str) if budget_str else None
        except ValueError:
            budget = None
            invalid_budget = True
        else:
            invalid_budget = budget is not None and (not math.isfinite(budget) or budget <= 0)
        if invalid_budget:
            self.query_one("#progress", Static).update(
                "[red]Budget must be a positive finite number.[/]"
            )
            self.query_one("#max-budget", Input).focus()
            return
        req = ScanRequest(target=target, scan_mode=mode, max_budget_usd=budget)
        self.query_one("#progress", Static).update("[cyan]Starting scan…[/]")
        self.query_one("#run", Button).disabled = True
        self.query_one("#cancel", Button).disabled = False
        self._scan_task = asyncio.create_task(self._scan_async(req))

    async def _scan_async(self, req: ScanRequest) -> None:
        progress = self.query_one("#progress", Static)

        async def on_progress(p: Any) -> None:
            progress.update(f"[{p.stream}] {p.line}")

        try:
            result = await run_scan(req, self.config, self.store, on_progress=on_progress)
        except asyncio.CancelledError:
            progress.update("[yellow]Scan cancelled. Check engine receipt for cleanup status.[/]")
            return
        except FileNotFoundError:
            progress.update("[red]`lyrashield` CLI not found. Install the engine.[/]")
            return
        except Exception as exc:  # noqa: BLE001
            progress.update(f"[red]Scan failed: {exc}[/]")
            return

        else:
            color = "green" if result.status == "completed" else "yellow"
            progress.update(
                f"[{color}]Scan {result.status} (exit {result.returncode}) in {result.elapsed_s:.1f}s[/]"
            )
            self._render_findings(result.run_id)
        finally:
            self.query_one("#run", Button).disabled = False
            self.query_one("#cancel", Button).disabled = True

    def _render_findings(self, run_id: str) -> None:
        view = self.query_one("#findings", Static)
        try:
            findings = self.store.list_findings(run_id)
            run = self.store.get_run(run_id) if not findings else None
        except ResultsStoreKeyError as exc:
            view.update(f"[red]Findings unavailable: {exc}[/]")
            return
        if not findings:
            view.update(
                "No findings recorded."
                if run and run.status == "completed"
                else "Scan incomplete; findings may be unavailable."
            )
            return
        lines = [f"Run {run_id} — {len(findings)} finding(s):", ""]
        for f in findings:
            lines.append(f"[{f.severity}] {f.title}")
        view.update("\n".join(lines))

    def _export(self, kind: str) -> None:
        try:
            runs = self.store.list_runs()
            if not runs:
                self.query_one("#progress", Static).update("[red]No runs to export.[/]")
                return
            run_id = runs[0].run_id
            dest_dir = Path.home() / ".lyrashield" / "local" / "exports"
            if kind == "sarif":
                dest = dest_dir / f"{run_id}.sarif"
                export_sarif(run_id, self.store, dest)
            else:
                dest = dest_dir / f"{run_id}.md"
                export_report(run_id, self.store, dest)
        except (OSError, ValueError, RuntimeError) as exc:
            self.query_one("#progress", Static).update(f"[red]Export failed: {exc}[/]")
            return
        self.query_one("#progress", Static).update(f"[green]Exported {kind} to {dest}[/]")

    def on_unmount(self) -> None:
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
        if self._doctor_task and not self._doctor_task.done():
            self._doctor_task.cancel()


def run_tui() -> None:
    """Entry point for ``lyrashield-local`` TUI."""
    app = LyraShieldLocalApp()
    app.run()
