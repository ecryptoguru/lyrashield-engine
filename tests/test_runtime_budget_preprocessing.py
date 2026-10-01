"""The non-interactive runtime allowance covers preprocessing (E1.1).

Image pull and repository acquisition consume the same monotonic deadline the
scan lifecycle enforces — a slow pull or clone can no longer let the actual
model work start after the worker's budget has already been spent.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from lyrashield.artifacts.state import get_global_report_state, set_global_report_state
from lyrashield.interface import cli as cli_module
from lyrashield.interface import image_pull, repo_clone, source_acquisition
from lyrashield.lifecycle.deadline import RunDeadline, RunDeadlineExceededError


cli_main = import_module("lyrashield.interface.main")


def _scan_args(**overrides: Any) -> SimpleNamespace:
    args = SimpleNamespace(
        run_name="scan-test",
        targets_info=[{"original": "example.test"}],
        instruction=None,
        diff_scope={"active": False},
        local_sources=[],
        scope_mode="auto",
        diff_base=None,
        user_explicit_instruction=None,
        scan_mode="quick",
        non_interactive=True,
        interactive=False,
        max_budget_usd=1.0,
        runtime_budget_seconds=90.0,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def _run_cli_patches(report_state: Any, run_scan: Any, cleanup: Any) -> list[Any]:
    return [
        patch.object(cli_module, "ReportState", return_value=report_state),
        patch.object(cli_module, "set_global_report_state"),
        patch.object(cli_module, "_resolve_sandbox_image", return_value="img@sha256:test"),
        patch.object(cli_module, "run_strix_scan", new=run_scan),
        patch.object(cli_module.session_manager, "cleanup", new=cleanup),
        patch.object(cli_module, "Live", side_effect=AssertionError("Live must not be created")),
        patch.object(cli_module.atexit, "register"),
        patch.object(cli_module.signal, "signal"),
    ]


def _stub_scan_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("validate_environment", "check_docker_installed"):
        monkeypatch.setattr(cli_main, name, Mock())
    monkeypatch.setattr(cli_main, "warm_up_llm", AsyncMock())
    monkeypatch.setattr(cli_main, "posthog", Mock())
    monkeypatch.setattr(cli_main, "scarf", Mock())
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(
            llm=SimpleNamespace(model="openai/gpt-6-sol"),
            runtime=SimpleNamespace(max_local_copy_mb=1024, backend="docker", image="img"),
        ),
    )


@pytest.mark.asyncio
async def test_run_cli_reuses_the_deadline_created_before_acquisition() -> None:
    """The deadline attached by main() is reused verbatim — never reset."""
    now = [40.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)
    args = _scan_args(run_deadline=deadline)
    report_state = MagicMock()
    report_state.final_scan_result = None
    run_scan = AsyncMock()
    cleanup = AsyncMock(return_value="removed")

    with contextlib.ExitStack() as stack:
        for patcher in _run_cli_patches(report_state, run_scan, cleanup):
            stack.enter_context(patcher)
        await cli_module.run_cli(args)

    coordinator = run_scan.call_args.kwargs["coordinator"]
    # The lifecycle runs on the same deadline object acquisition consumed.
    assert coordinator.run_deadline is deadline
    assert deadline.remaining_seconds() == 50.0


@pytest.mark.asyncio
async def test_run_cli_without_an_attached_deadline_starts_its_own() -> None:
    """Direct run_cli callers that skipped main() still get a fresh deadline."""
    args = _scan_args()
    assert not hasattr(args, "run_deadline")
    report_state = MagicMock()
    report_state.final_scan_result = None
    run_scan = AsyncMock()
    cleanup = AsyncMock(return_value="removed")

    with contextlib.ExitStack() as stack:
        for patcher in _run_cli_patches(report_state, run_scan, cleanup):
            stack.enter_context(patcher)
        await cli_module.run_cli(args)

    coordinator = run_scan.call_args.kwargs["coordinator"]
    assert coordinator.run_deadline is not None
    assert coordinator.run_deadline.remaining_seconds() > 0


@pytest.mark.asyncio
async def test_run_cli_makes_no_provider_request_once_the_allowance_is_gone() -> None:
    """An exhausted allowance skips model work; cleanup still runs."""
    now = [120.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)
    args = _scan_args(run_deadline=deadline)
    report_state = MagicMock()
    report_state.final_scan_result = None
    run_scan = AsyncMock()
    cleanup = AsyncMock(return_value="removed")

    with contextlib.ExitStack() as stack:
        for patcher in _run_cli_patches(report_state, run_scan, cleanup):
            stack.enter_context(patcher)
        await cli_module.run_cli(args)

    # The lifecycle coroutine is never even invoked past the deadline.
    run_scan.assert_not_called()
    report_state.set_terminal_reason.assert_called_once_with("runtime_deadline")
    cleanup.assert_awaited_once_with("scan-test")
    assert report_state.set_cleanup_outcome.call_args.args == ("removed",)


# ---------------------------------------------------------------------------
# main(): one deadline spans pull, acquisition, and the scan itself
# ---------------------------------------------------------------------------


def test_preprocessing_consumes_the_shared_scan_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """40s of preprocessing on a 90s allowance leaves the scan 50s.

    The simulated scan files a finding, hits the deadline, and the terminal
    artifact stays honest (``stopped``/``runtime_deadline``, never
    ``completed``) while the finding survives — all inside the worker's 120s
    budget. Fake monotonic time; nothing sleeps.
    """
    now = [0.0]
    observed: dict[str, Any] = {}

    source = tmp_path / "app"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    def pull_image(*, deadline: RunDeadline | None = None) -> None:
        observed["pull_deadline"] = deadline
        now[0] += 40.0  # image pull consumed 40 seconds of the allowance

    async def scan_files_finding_then_hits_deadline(*_a: Any, **kwargs: Any) -> None:
        observed["scan_deadline"] = kwargs["coordinator"].run_deadline
        state = get_global_report_state()
        state.add_vulnerability_report(
            title="Reflected XSS",
            severity="high",
            target="https://example.test",
            description="reflected payload executes",
        )
        # The lifecycle refuses the next model start at the deadline.
        now[0] = 95.0
        raise RunDeadlineExceededError("scan runtime deadline reached")

    _stub_scan_environment(monkeypatch)
    monkeypatch.setattr(cli_main, "pull_docker_image", pull_image)
    monkeypatch.setattr(cli_module, "run_strix_scan", scan_files_finding_then_hits_deadline)
    monkeypatch.setattr(cli_module, "_resolve_sandbox_image", lambda: "img@sha256:test")
    monkeypatch.setattr(cli_module.session_manager, "cleanup", AsyncMock(return_value="removed"))
    monkeypatch.setattr(cli_module.atexit, "register", Mock())
    monkeypatch.setattr(cli_module.signal, "signal", Mock())
    monkeypatch.setattr("lyrashield.artifacts.state_findings.posthog", Mock())
    monkeypatch.setattr("lyrashield.artifacts.state_findings.scarf", Mock())

    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    monkeypatch.chdir(runs_root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(source),
            "--target-type",
            "local_code",
            "--scope-mode",
            "full",
            "--run-name",
            "budgeted",
            "-n",
            "--runtime-budget-seconds",
            "90",
        ],
    )

    try:
        with pytest.raises(SystemExit) as exc_info:
            cli_main.main(entry_monotonic=0.0, monotonic=lambda: now[0])
    finally:
        set_global_report_state(None)

    # runtime_deadline with a persisted finding maps to worker exit code 2.
    assert exc_info.value.code == 2

    # Same deadline identity before and after acquisition.
    assert observed["pull_deadline"] is observed["scan_deadline"]
    deadline = observed["scan_deadline"]
    assert isinstance(deadline, RunDeadline)
    assert deadline.remaining_seconds() == 0.0

    # Engine work ended at 95s — inside the 120s worker budget — and no real
    # time was spent (the clock is fake).
    assert now[0] == 95.0
    assert now[0] < 120.0

    run_dir = runs_root / "strix_runs" / "budgeted"
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert record["status"] == "stopped"
    assert record["terminal_reason"] == "runtime_deadline"
    assert record["run_name"] == "budgeted"

    # The filed finding survives the bounded termination.
    vulnerabilities = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert [v["id"] for v in vulnerabilities] == ["vuln-0001"]
    assert vulnerabilities[0]["title"] == "Reflected XSS"


def test_acquisition_exhaustion_writes_a_bounded_terminal_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pull consumes the whole allowance: no scan, honest stopped receipt."""
    now = [0.0]
    source = tmp_path / "app"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    def pull_image(*, deadline: RunDeadline | None = None) -> None:
        assert deadline is not None
        now[0] = 95.0  # acquisition outlived the 90s allowance

    run_cli = AsyncMock()
    _stub_scan_environment(monkeypatch)
    monkeypatch.setattr(cli_main, "pull_docker_image", pull_image)
    monkeypatch.setattr(cli_main, "run_cli", run_cli)

    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    monkeypatch.chdir(runs_root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(source),
            "--target-type",
            "local_code",
            "--scope-mode",
            "full",
            "--run-name",
            "exhausted",
            "-n",
            "--runtime-budget-seconds",
            "90",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli_main.main(entry_monotonic=0.0, monotonic=lambda: now[0])

    # runtime_deadline without findings -> worker exit code 5.
    assert exc_info.value.code == 5
    run_cli.assert_not_called()

    record = json.loads(
        (runs_root / "strix_runs" / "exhausted" / "run.json").read_text(encoding="utf-8")
    )
    assert record["status"] == "stopped"
    assert record["phase"] == "stopped"
    assert record["terminal_reason"] == "runtime_deadline"
    assert record["end_time"]
    assert record["run_name"] == "exhausted"
    # No model work ran; no coverage is claimed.
    assert record["llm_usage"]["requests"] == 0


def test_acquisition_exhaustion_preserves_persisted_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings already on disk survive and keep the findings exit code."""
    now = [0.0]
    source = tmp_path / "app"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    runs_root = tmp_path / "runs"
    run_dir = runs_root / "strix_runs" / "resume-exhausted"
    run_dir.mkdir(parents=True)
    findings = [
        {"id": "vuln-0001", "title": "SSRF", "severity": "high", "timestamp": "t"},
    ]
    (run_dir / "vulnerabilities.json").write_text(json.dumps(findings), encoding="utf-8")

    def pull_image(*, deadline: RunDeadline | None = None) -> None:
        assert deadline is not None
        now[0] = 200.0

    run_cli = AsyncMock()
    _stub_scan_environment(monkeypatch)
    monkeypatch.setattr(cli_main, "pull_docker_image", pull_image)
    monkeypatch.setattr(cli_main, "run_cli", run_cli)
    monkeypatch.chdir(runs_root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(source),
            "--target-type",
            "local_code",
            "--scope-mode",
            "full",
            "--run-name",
            "resume-exhausted",
            "-n",
            "--runtime-budget-seconds",
            "90",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli_main.main(entry_monotonic=0.0, monotonic=lambda: now[0])

    assert exc_info.value.code == 2
    run_cli.assert_not_called()

    # The already-persisted findings are untouched.
    assert json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8")) == findings
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert record["status"] == "stopped"
    assert record["terminal_reason"] == "runtime_deadline"


def test_interactive_scan_never_creates_a_run_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Interactive runs stay outside the non-interactive deadline path."""
    source = tmp_path / "app"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    captured: dict[str, Any] = {}

    async def fake_tui(args: Any) -> None:
        captured["deadline"] = getattr(args, "run_deadline", "unset")

    _stub_scan_environment(monkeypatch)
    monkeypatch.setattr(cli_main, "pull_docker_image", Mock())
    monkeypatch.setattr(cli_main, "run_tui", fake_tui)
    monkeypatch.setattr(cli_main, "_persist_run_record", Mock())
    monkeypatch.setattr(cli_main, "get_global_report_state", lambda: None)

    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    monkeypatch.chdir(runs_root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(source),
            "--target-type",
            "local_code",
            "--scope-mode",
            "full",
            "--run-name",
            "interactive1",
        ],
    )

    cli_main.main(entry_monotonic=0.0, monotonic=lambda: 9999.0)

    assert captured["deadline"] is None


# ---------------------------------------------------------------------------
# Acquisition helpers bound their waits by the remaining allowance
# ---------------------------------------------------------------------------


def _fake_subprocess(run: Any) -> SimpleNamespace:
    return SimpleNamespace(
        run=run,
        TimeoutExpired=subprocess.TimeoutExpired,
        CalledProcessError=subprocess.CalledProcessError,
        SubprocessError=subprocess.SubprocessError,
        CompletedProcess=subprocess.CompletedProcess,
    )


def test_clone_timeout_is_bounded_by_the_remaining_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [30.0]
    deadline = RunDeadline.start(60.0, clock=lambda: now[0], started_at=0.0)
    calls: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(repo_clone, "subprocess", _fake_subprocess(fake_run))
    monkeypatch.setattr(source_acquisition.tempfile, "gettempdir", lambda: str(tmp_path))

    path = source_acquisition.clone_repository(
        "https://github.com/org/repo", "bounded-clone", deadline=deadline
    )

    assert Path(path).name == "repo"
    # min(_GIT_CLONE_TIMEOUT_SECONDS, remaining) — never the bare 900s cap.
    assert calls[0]["timeout"] == 30.0


def test_clone_refuses_to_spawn_git_once_the_budget_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [95.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)
    calls: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(repo_clone, "subprocess", _fake_subprocess(fake_run))
    monkeypatch.setattr(source_acquisition.tempfile, "gettempdir", lambda: str(tmp_path))

    with pytest.raises(RunDeadlineExceededError):
        source_acquisition.clone_repository(
            "https://github.com/org/repo", "gone-clone", deadline=deadline
        )

    # No git subprocess was ever spawned past the deadline.
    assert calls == []


def test_clone_subprocess_timeout_maps_to_the_deadline_when_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [10.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        now[0] = 200.0  # the wait outlived the allowance
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

    monkeypatch.setattr(repo_clone, "subprocess", _fake_subprocess(fake_run))
    monkeypatch.setattr(source_acquisition.tempfile, "gettempdir", lambda: str(tmp_path))

    with pytest.raises(RunDeadlineExceededError):
        source_acquisition.clone_repository(
            "https://github.com/org/repo", "timeout-clone", deadline=deadline
        )


def test_clone_subprocess_timeout_without_budget_left_behaves_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timeout inside the allowance stays an ordinary clone failure."""
    now = [10.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

    monkeypatch.setattr(repo_clone, "subprocess", _fake_subprocess(fake_run))
    monkeypatch.setattr(source_acquisition.tempfile, "gettempdir", lambda: str(tmp_path))

    with pytest.raises(SystemExit) as exc_info:
        source_acquisition.clone_repository(
            "https://github.com/org/repo", "plain-timeout", deadline=deadline
        )
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Image pull is bounded by the same deadline
# ---------------------------------------------------------------------------


def _patch_pull_client(monkeypatch: pytest.MonkeyPatch, pull_stream: Any) -> MagicMock:
    client = MagicMock()
    client.api.pull = pull_stream
    monkeypatch.setattr(image_pull, "check_docker_connection", lambda: client)
    monkeypatch.setattr(image_pull, "image_exists", lambda *_a, **_k: False)
    monkeypatch.setattr(
        image_pull,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(image="sandbox:img")),
    )
    monkeypatch.delenv("STRIX_IMAGE_DIGEST", raising=False)
    return client


def test_image_pull_stops_streaming_once_the_deadline_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)

    def stream(*_a: Any, **_k: Any) -> Any:
        yield {"status": "Pulling from lyrashield/sandbox"}
        now[0] = 120.0  # the layer fetch outlived the allowance
        yield {"status": "Digest: sha256:abc"}

    _patch_pull_client(monkeypatch, lambda *_a, **_k: stream())

    with pytest.raises(RunDeadlineExceededError):
        image_pull.pull_docker_image(deadline=deadline)


def test_image_pull_with_no_remaining_allowance_never_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [95.0]
    deadline = RunDeadline.start(90.0, clock=lambda: now[0], started_at=0.0)
    pull = Mock()

    _patch_pull_client(monkeypatch, pull)

    with pytest.raises(RunDeadlineExceededError):
        image_pull.pull_docker_image(deadline=deadline)

    pull.assert_not_called()
