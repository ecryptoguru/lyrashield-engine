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
Credentials live in the OS keychain, never plaintext. Results persist in the
local encrypted SQLite store. No benchmark/coverage claims, no money-back
language, no upstream-engine naming.
"""

from __future__ import annotations

import asyncio
import logging
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
)
from lyrashield.tui.doctor import format_report, run_doctor
from lyrashield.tui.results_store import ResultsStore
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
        self.config = config or load_config()
        self.store = store or ResultsStore()

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
            Static("Local / self-hosted models: experimental / coming", classes="hidden"),
            Button("Save BYOK setup", id="save-byok"),
            Static("", id="byok-status"),
            classes="panel",
            id="setup",
        )

    def _run_panel(self) -> Vertical:
        return Vertical(
            Static("4. Run scan", classes="panel"),
            Horizontal(
                Button("Run scan", id="run", variant="success"),
                Button("Doctor", id="doctor", variant="default"),
                id="run-buttons",
            ),
            Static("Max budget (USD, optional):"),
            Input(placeholder="e.g. 5.0", id="max-budget"),
            VerticalScroll(Static("", id="progress"), id="progress-scroll"),
            classes="panel",
            id="run",
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
    def _on_save_byok(self, _event: Button.Pressed) -> None:
        select = self.query_one("#provider", Select)
        value = str(select.value)
        try:
            self.config.provider = Provider(value)
        except ValueError:
            self.config.provider = Provider.CHATGPT_OAUTH
        save_config(self.config)
        self.query_one("#byok-status", Static).update(
            f"BYOK setup saved: {provider_label(self.config.provider)}",
        )

    @on(Button.Pressed, "#doctor")
    def _on_doctor(self, _event: Button.Pressed) -> None:
        self._run_doctor()

    @on(Button.Pressed, "#run")
    def _on_run(self, _event: Button.Pressed) -> None:
        self._run_scan()

    @on(Button.Pressed, "#export-sarif")
    def _on_export_sarif(self, _event: Button.Pressed) -> None:
        self._export("sarif")

    @on(Button.Pressed, "#export-report")
    def _on_export_report(self, _event: Button.Pressed) -> None:
        self._export("report")

    # ---- internals ------------------------------------------------------

    def _run_doctor(self) -> None:
        report = run_doctor(self.config, skip_smoke=True)
        self.query_one("#progress", Static).update(format_report(report))

    def _run_scan(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.query_one("#progress", Static).update("[red]Enter a target first.[/]")
            return
        mode = str(self.query_one("#scan-mode", Select).value)
        budget_str = self.query_one("#max-budget", Input).value.strip()
        budget = float(budget_str) if budget_str else None
        req = ScanRequest(target=target, scan_mode=mode, max_budget_usd=budget)
        self.query_one("#progress", Static).update("[cyan]Starting scan…[/]")
        self._scan_task = asyncio.create_task(self._scan_async(req))

    async def _scan_async(self, req: ScanRequest) -> None:
        progress = self.query_one("#progress", Static)

        async def on_progress(p: Any) -> None:
            progress.update(f"[{p.stream}] {p.line}")

        try:
            result = await run_scan(req, self.config, self.store, on_progress=on_progress)
        except FileNotFoundError:
            progress.update("[red]`lyrashield` CLI not found. Install the engine.[/]")
            return
        except Exception as exc:  # noqa: BLE001
            progress.update(f"[red]Scan failed: {exc}[/]")
            return

        status = "completed" if result.returncode == 0 else f"exit {result.returncode}"
        progress.update(f"[green]Scan {status} in {result.elapsed_s:.1f}s[/]")
        self._render_findings(result.run_id)

    def _render_findings(self, run_id: str) -> None:
        findings = self.store.list_findings(run_id)
        view = self.query_one("#findings", Static)
        if not findings:
            view.update("Scan complete. No findings ingested yet — see the engine report.")
            return
        lines = [f"Run {run_id} — {len(findings)} finding(s):", ""]
        for f in findings:
            lines.append(f"[{f.severity}] {f.title}")
        view.update("\n".join(lines))

    def _export(self, kind: str) -> None:
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
        self.query_one("#progress", Static).update(f"[green]Exported {kind} to {dest}[/]")


def run_tui() -> None:
    """Entry point for ``lyrashield-local`` TUI."""
    app = LyraShieldLocalApp()
    app.run()
