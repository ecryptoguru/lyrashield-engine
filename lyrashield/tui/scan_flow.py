# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Scan execution flow for LyraShield Local.

Shells into the existing engine CLI (``lyrashield``) — no engine
reimplementation. Reuses the engine's run contract: ``--max-budget``, scan
modes, ``run.json``, SARIF, and reports. The TUI streams stdout/stderr for
progress and persists results into the local encrypted results store.

All scan depths (SAFE/QUICK/STANDARD/DEEP/CUSTOM) are available locally; there
is no Cloud-style depth gating and no agent-minute metering in Local mode.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lyrashield.tui.byok_config import ByokConfig, engine_mode_for
from lyrashield.tui.results_store import FindingRecord, ResultsStore, new_run_id


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence


logger = logging.getLogger(__name__)


# Engine CLI binary name. Resolved from PATH; never a hardcoded absolute path.
ENGINE_CLI = "lyrashield"


@dataclass
class ScanRequest:
    target: str
    scan_mode: str = "STANDARD"
    max_budget_usd: float | None = None
    max_turns: int | None = None
    instruction: str | None = None
    run_name: str | None = None
    extra_args: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class ScanProgress:
    stream: str  # "stdout" | "stderr"
    line: str
    elapsed_s: float


@dataclass
class ScanResult:
    run_id: str
    returncode: int
    stdout: str
    stderr: str
    elapsed_s: float
    run_dir: Path | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)


def build_argv(req: ScanRequest, config: ByokConfig) -> list[str]:
    """Build the engine CLI argv for a scan request."""
    argv: list[str] = [ENGINE_CLI]
    argv += ["--target", req.target]
    argv += ["--scan-mode", engine_mode_for(req.scan_mode)]
    argv += ["--non-interactive"]
    if req.max_budget_usd is not None:
        argv += ["--max-budget", str(req.max_budget_usd)]
    if req.max_turns is not None:
        argv += ["--max-turns", str(req.max_turns)]
    if req.instruction:
        argv += ["--instruction", req.instruction]
    if req.run_name:
        argv += ["--run-name", req.run_name]
    argv += list(req.extra_args)
    return argv


def build_env(config: ByokConfig, base_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the env for the engine CLI subprocess from BYOK config."""
    env = dict(base_env) if base_env is not None else dict(os.environ)
    env.update(config.to_env())
    return env


async def _stream(proc: asyncio.subprocess.Process, stream_name: str) -> tuple[str, list[str]]:
    stream = proc.stdout if stream_name == "stdout" else proc.stderr
    lines: list[str] = []
    chunks: list[str] = []
    assert stream is not None
    while True:
        line_bytes = await stream.readline()
        if not line_bytes:
            break
        line = line_bytes.decode(errors="replace").rstrip()
        lines.append(line)
        chunks.append(line + "\n")
    return "".join(chunks), lines


async def run_scan(
    req: ScanRequest,
    config: ByokConfig,
    store: ResultsStore | None = None,
    on_progress: Any | None = None,
    base_env: Mapping[str, str] | None = None,
) -> ScanResult:
    """Run a scan by shelling into the engine CLI, streaming progress.

    ``on_progress`` is an optional async callable invoked with each
    ``ScanProgress`` event. Results are persisted to ``store`` if provided.
    """
    argv = build_argv(req, config)
    env = build_env(config, base_env)
    run_id = req.run_name or new_run_id()
    start = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    # Stream both pipes concurrently.
    async def _pipe(name: str) -> tuple[str, list[str]]:
        return await _stream(proc, name)

    stdout_task = asyncio.create_task(_pipe("stdout"))
    stderr_task = asyncio.create_task(_pipe("stderr"))

    # If a progress callback is supplied, poll running lines while the process
    # runs. The full line buffers are awaited above; the progress callback
    # receives lines as they're read by awaiting the tasks in a loop.
    if on_progress is not None:
        # Simplest correct approach: await tasks then emit all lines. A
        # real-time streaming variant would read char-by-char; for the TUI we
        # emit the captured lines with elapsed timestamps.
        pass

    stdout, stdout_lines = await stdout_task
    stderr, stderr_lines = await stderr_task
    returncode = await proc.wait()
    elapsed = time.monotonic() - start

    if on_progress is not None:
        for line in stdout_lines:
            await _maybe_call(
                on_progress, ScanProgress(stream="stdout", line=line, elapsed_s=elapsed)
            )
        for line in stderr_lines:
            await _maybe_call(
                on_progress, ScanProgress(stream="stderr", line=line, elapsed_s=elapsed)
            )

    result = ScanResult(
        run_id=run_id,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        elapsed_s=elapsed,
    )

    if store is not None:
        _persist_run(store, req, config, result)

    return result


async def _maybe_call(cb: Any, progress: ScanProgress) -> None:
    res = cb(progress)
    if asyncio.iscoroutine(res):
        await res


def _persist_run(
    store: ResultsStore,
    req: ScanRequest,
    config: ByokConfig,
    result: ScanResult,
) -> None:
    """Persist the run + any parseable findings into the encrypted store."""
    from lyrashield.tui.results_store import RunRecord  # noqa: PLC0415

    status = "completed" if result.returncode == 0 else "failed"
    payload: dict[str, Any] = {
        "returncode": result.returncode,
        "elapsed_s": result.elapsed_s,
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
        "scan_mode": req.scan_mode,
        "target": req.target,
        "provider": config.provider.value,
    }
    store.save_run(
        RunRecord(
            run_id=result.run_id,
            target=req.target,
            scan_mode=req.scan_mode,
            provider=config.provider.value,
            created_at=int(time.time()),
            status=status,
            payload=payload,
        )
    )

    # Parse SARIF findings if a report path is known. The engine writes
    # artifacts under its run dir; the TUI does not assume a fixed location,
    # so findings ingestion is best-effort.
    for finding in _parse_sarif_findings(result):
        store.save_finding(finding)


def _parse_sarif_findings(result: ScanResult) -> list[FindingRecord]:
    """Best-effort SARIF parse from stdout. The engine CLI emits report paths."""
    # The engine writes SARIF to its run dir; the TUI does not re-implement
    # report discovery. This is a forward-compat hook for the desktop shell,
    # which knows the run dir. Return empty for now.
    return []


def export_sarif(run_id: str, store: ResultsStore, dest: Path) -> Path:
    """Export a SARIF document for a stored run. The engine already writes
    SARIF; this is a convenience that copies/serializes the stored payload.
    """
    run = store.get_run(run_id)
    if run is None:
        msg = f"Run {run_id} not found in local store"
        raise KeyError(msg)
    import json  # noqa: PLC0415

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LyraShield Local",
                        "informationUri": "https://lyrashieldai.com",
                    }
                },
                "results": [
                    {
                        "ruleId": f.payload.get("ruleId", "LYRASHIELD"),
                        "level": f.severity.lower()
                        if f.severity in ("HIGH", "MEDIUM", "LOW")
                        else "warning",
                        "message": {"text": f.title},
                        "locations": f.payload.get("locations", []),
                    }
                    for f in store.list_findings(run_id)
                ],
            }
        ],
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return dest


def export_report(run_id: str, store: ResultsStore, dest: Path) -> Path:
    """Export a plain-language Markdown report for a stored run."""
    run = store.get_run(run_id)
    if run is None:
        msg = f"Run {run_id} not found in local store"
        raise KeyError(msg)
    findings = store.list_findings(run_id)
    lines = [
        f"# LyraShield Local — Scan Report",
        "",
        f"- **Run ID:** {run.run_id}",
        f"- **Target:** {run.target}",
        f"- **Scan mode:** {run.scan_mode}",
        f"- **Provider:** {run.provider}",
        f"- **Status:** {run.status}",
        f"- **Findings:** {len(findings)}",
        "",
        "## Findings",
        "",
    ]
    for f in findings:
        lines += [
            f"### [{f.severity}] {f.title}",
            "",
            f.payload.get("description", ""),
            "",
        ]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines), encoding="utf-8")
    return dest
