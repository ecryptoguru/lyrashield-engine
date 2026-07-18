from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-worker-contract.sh"
REQUIRED_FLAGS = "--non-interactive --target --scan-mode --instruction --max-budget-usd"


def executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def make_fake_app(tmp_path: Path) -> tuple[Path, Path, Path]:
    app = tmp_path / "app"
    bin_dir = tmp_path / "bin"
    app.mkdir()
    bin_dir.mkdir()
    (app / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")
    for relative in (
        "apps/worker/src/engine/command-builder.test.ts",
        "apps/worker/src/engine/output-parser.test.ts",
    ):
        target = app / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("// fixture\n", encoding="utf-8")
    args_file = tmp_path / "pnpm.args"
    executable(bin_dir / "corepack", "exit 0")
    executable(bin_dir / "pnpm", f"printf '%s\\n' \"$*\" >> '{args_file}'")
    return app, bin_dir, args_file


def run_contract(
    app: Path, bin_dir: Path, tmp_path: Path, *, help_text: str
) -> subprocess.CompletedProcess[str]:
    cli = executable(tmp_path / "lyrashield", f"printf '%s\\n' '{help_text}'")
    return subprocess.run(  # noqa: S603
        [str(SCRIPT), str(app)],
        check=False,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "LYRASHIELD_BIN": str(cli),
        },
    )


def test_rejects_help_without_required_flag(tmp_path: Path) -> None:
    app, bin_dir, _ = make_fake_app(tmp_path)
    result = run_contract(app, bin_dir, tmp_path, help_text="--target --scan-mode")
    assert result.returncode != 0
    assert "--non-interactive" in result.stderr


def test_runs_focused_worker_tests(tmp_path: Path) -> None:
    app, bin_dir, args_file = make_fake_app(tmp_path)
    result = run_contract(app, bin_dir, tmp_path, help_text=REQUIRED_FLAGS)
    assert result.returncode == 0, result.stderr
    calls = args_file.read_text(encoding="utf-8")
    assert "install --frozen-lockfile" in calls
    assert "command-builder.test.ts" in calls
    assert "output-parser.test.ts" in calls


def test_rejects_checkout_without_worker_contract_tests(tmp_path: Path) -> None:
    app, bin_dir, _ = make_fake_app(tmp_path)
    (app / "apps/worker/src/engine/output-parser.test.ts").unlink()
    result = run_contract(app, bin_dir, tmp_path, help_text=REQUIRED_FLAGS)
    assert result.returncode != 0
    assert "output-parser.test.ts" in result.stderr
