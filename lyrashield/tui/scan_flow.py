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
import json
import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lyrashield.artifacts.sarif import _sarif_level
from lyrashield.artifacts.state import validate_run_record
from lyrashield.tui.byok_config import ByokConfig, Provider, engine_mode_for
from lyrashield.tui.results_store import FindingRecord, ResultsStore, new_run_id
from strix.core.paths import run_dir_for


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence


logger = logging.getLogger(__name__)


# Engine CLI binary name. Resolved from PATH; never a hardcoded absolute path.
ENGINE_CLI = "lyrashield"

_INHERITED_MODEL_CONNECTION_VARS = (
    "STRIX_LLM",
    "LYRASHIELD_LLM",
    "STRIX_DELEGATE_LLM",
    "LYRASHIELD_DELEGATE_LLM",
    "STRIX_DEDUPE_MODEL",
    "LYRASHIELD_DEDUPE_MODEL",
    "LLM_API_KEY",
    "LLM_API_BASE",
    "LLM_API_VERSION",
    "OPENAI_API_KEY",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_BASE",
    "AZURE_OPENAI_API_VERSION",
    "AZURE_AI_API_KEY",
    "AZURE_AI_API_BASE",
    "AZURE_API_BASE",
    "AZURE_AI_API_BASE",
    "AZURE_API_VERSION",
    "AZURE_AI_API_VERSION",
    "DEDUPE_LLM_API_KEY",
    "DEDUPE_LLM_API_BASE",
)


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
    status: str = "incomplete"
    terminal_reason: str | None = None


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
    for name in _INHERITED_MODEL_CONNECTION_VARS:
        env.pop(name, None)
    env.update(config.to_env())
    if config.provider == Provider.AZURE_OPENAI:
        env["LLM_API_KEY"] = config.azure.api_key
        env["LLM_API_BASE"] = config.azure.endpoint
        env["LLM_API_VERSION"] = config.azure.api_version
    return env


async def _stream(
    proc: asyncio.subprocess.Process, stream_name: str, start: float, on_progress: Any | None
) -> str:
    stream = proc.stdout if stream_name == "stdout" else proc.stderr
    tail = b""
    pending = b""
    assert stream is not None
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        tail = (tail + chunk)[-4000:]
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            if on_progress is not None:
                await _maybe_call(
                    on_progress,
                    ScanProgress(
                        stream_name, line[-4000:].decode(errors="replace"), time.monotonic() - start
                    ),
                )
        if len(pending) > 4000:
            pending = pending[-4000:]
    if pending and on_progress is not None:
        await _maybe_call(
            on_progress,
            ScanProgress(stream_name, pending.decode(errors="replace"), time.monotonic() - start),
        )
    return tail.decode(errors="replace")


async def _stop_child(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        await proc.wait()
        return
    try:
        proc.send_signal(signal.SIGINT)
        await asyncio.wait_for(proc.wait(), timeout=3)
    except (TimeoutError, ProcessLookupError):
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except TimeoutError:
                proc.kill()
                await proc.wait()


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
    run_id = req.run_name or new_run_id()
    argv = build_argv(replace(req, run_name=run_id), config)
    env = build_env(config, base_env)
    launch_cwd = Path.cwd().resolve()
    start = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    readers = [
        asyncio.create_task(_stream(proc, name, start, on_progress))
        for name in ("stdout", "stderr")
    ]
    try:
        stdout, stderr = await asyncio.gather(*readers)
        returncode = await proc.wait()
    except BaseException:
        await asyncio.shield(_stop_child(proc))
        for reader in readers:
            reader.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        raise
    elapsed = time.monotonic() - start
    run_dir = run_dir_for(run_id, cwd=launch_cwd)
    receipt = _read_receipt(run_dir, run_id)
    status = _scan_status(receipt, returncode)
    try:
        findings = _read_findings(run_dir) if receipt is not None else []
    except (OSError, ValueError, TypeError):
        findings = []
        status = "incomplete"
    if status == "completed" and not (run_dir / "vulnerabilities.json").is_file():
        status = "incomplete"

    result = ScanResult(
        run_id=run_id,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        elapsed_s=elapsed,
        run_dir=run_dir if receipt is not None else None,
        findings=findings,
        status=status,
        terminal_reason=receipt.get("terminal_reason") if receipt else None,
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

    payload: dict[str, Any] = {
        "returncode": result.returncode,
        "elapsed_s": result.elapsed_s,
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
        "scan_mode": req.scan_mode,
        "target": req.target,
        "provider": config.provider.value,
        "run_dir": str(result.run_dir) if result.run_dir else None,
        "terminal_reason": result.terminal_reason,
    }
    findings = [
        FindingRecord(
            finding_id=str(finding.get("id") or f"vuln-{index + 1}"),
            run_id=result.run_id,
            severity=str(finding.get("severity") or "UNKNOWN").upper(),
            title=str(finding.get("title") or "Untitled finding"),
            payload=finding,
        )
        for index, finding in enumerate(result.findings)
    ]
    store.save_scan(
        RunRecord(
            run_id=result.run_id,
            target=req.target,
            scan_mode=req.scan_mode,
            provider=config.provider.value,
            created_at=int(time.time()),
            status=result.status,
            payload=payload,
        ),
        findings,
    )


def _read_receipt(run_dir: Path, run_id: str) -> dict[str, Any] | None:
    try:
        record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        not isinstance(record, dict)
        or record.get("run_name") != run_id
        or record.get("run_id") != run_id
    ):
        return None
    try:
        validate_run_record(record)
    except RuntimeError:
        return None
    return record


def _scan_status(receipt: dict[str, Any] | None, returncode: int) -> str:
    if receipt is None:
        return "incomplete"
    if receipt.get("receipt_persisted") is False:
        return "incomplete"
    if receipt.get("status") == "completed" and returncode in (0, 2):
        return "completed"
    if receipt.get("terminal_reason") == "no_change" and returncode == 0:
        return "no_change"
    return "partial" if receipt.get("status") in ("running", "stopped") else "failed"


def _read_findings(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "vulnerabilities.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("Canonical findings artifact is invalid")
    return data


def export_sarif(run_id: str, store: ResultsStore, dest: Path) -> Path:
    """Export a SARIF document for a stored run. The engine already writes
    SARIF; this is a convenience that copies/serializes the stored payload.
    """
    run = store.get_run(run_id)
    if run is None:
        msg = f"Run {run_id} not found in local store"
        raise KeyError(msg)
    run_dir = run.payload.get("run_dir")
    if run_dir:
        source = Path(run_dir) / "findings.sarif"
        if source.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
            return dest
        raise FileNotFoundError(f"Canonical SARIF is unavailable for run {run_id}")

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
                        "level": _sarif_level(f.severity),
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
    run_dir = run.payload.get("run_dir")
    if run_dir:
        source = Path(run_dir) / "penetration_test_report.md"
        if source.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
            return dest
        raise FileNotFoundError(f"Canonical report is unavailable for run {run_id}")
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
