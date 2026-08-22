from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-worker-contract.sh"
PIN_FILE = ROOT / ".lyrashield-worker-pin"
TESTS_FILE = ROOT / "scripts" / "worker-contract-tests.txt"
REQUIRED_FLAGS = "--non-interactive --target --scan-mode --instruction --max-budget-usd"

# The declared contract-test list lives in scripts/worker-contract-tests.txt so
# this test and the shell gate consume one source of truth (I17); the canonical
# scan-profile test cannot be silently omitted from either.
CONTRACT_TESTS = tuple(
    line.strip() for line in TESTS_FILE.read_text(encoding="utf-8").splitlines() if line.strip()
)

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "ci",
    "GIT_COMMITTER_NAME": "ci",
    "GIT_AUTHOR_EMAIL": "ci@example.com",
    "GIT_COMMITTER_EMAIL": "ci@example.com",
    "EMAIL": "ci@example.com",
}


def executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def make_fake_app(tmp_path: Path) -> tuple[Path, str]:
    """A git-committed app fixture carrying every declared contract test."""
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")
    for relative in CONTRACT_TESTS:
        target = app / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("// fixture\n", encoding="utf-8")
    git = shutil.which("git") or "git"
    subprocess.run([git, "init", "-q"], cwd=app, check=True, env=_GIT_ENV)  # noqa: S603
    subprocess.run([git, "add", "."], cwd=app, check=True, env=_GIT_ENV)  # noqa: S603
    subprocess.run([git, "commit", "-q", "-m", "fixture"], cwd=app, check=True, env=_GIT_ENV)  # noqa: S603
    head = subprocess.run(  # noqa: S603 - resolved git, fixture path
        [git, "rev-parse", "HEAD"], cwd=app, check=True, capture_output=True, text=True
    ).stdout.strip()
    return app, head


def make_gate_root(tmp_path: Path, pinned_sha: str) -> tuple[Path, Path]:
    """Copy the real gate into a fixture repo root with a controllable pin."""
    gate_root = tmp_path / "gate-root"
    (gate_root / "scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT, gate_root / "scripts" / "verify-worker-contract.sh")
    shutil.copy2(TESTS_FILE, gate_root / "scripts" / "worker-contract-tests.txt")
    (gate_root / ".lyrashield-worker-pin").write_text(pinned_sha + "\n", encoding="utf-8")
    return gate_root, gate_root / "scripts" / "verify-worker-contract.sh"


def run_contract(
    gate_script: Path, app: Path, tmp_path: Path, *, help_text: str
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    args_file = tmp_path / "pnpm.args"
    executable(
        bin_dir / "corepack",
        (
            '[[ "${1:-}" == "pnpm" ]] || { echo "global corepack mutation" >&2; exit 42; }; '
            f"shift; printf '%s\\n' \"$*\" >> '{args_file}'"
        ),
    )
    executable(bin_dir / "pnpm", 'echo "unpinned pnpm invocation" >&2; exit 43')
    cli = executable(tmp_path / "lyrashield", f"printf '%s\\n' '{help_text}'")
    return subprocess.run(  # noqa: S603
        [str(gate_script), str(app)],
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
    app, head = make_fake_app(tmp_path)
    _gate_root, gate_script = make_gate_root(tmp_path, head)
    result = run_contract(gate_script, app, tmp_path, help_text="--target --scan-mode")
    assert result.returncode != 0
    assert "--non-interactive" in result.stderr


def test_runs_focused_worker_tests_without_global_corepack_mutation(tmp_path: Path) -> None:
    app, head = make_fake_app(tmp_path)
    _gate_root, gate_script = make_gate_root(tmp_path, head)
    result = run_contract(gate_script, app, tmp_path, help_text=REQUIRED_FLAGS)
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "pnpm.args").read_text(encoding="utf-8")
    assert "install --frozen-lockfile" in calls
    assert "command-builder.test.ts" in calls
    assert "scan-profile.test.ts" in calls


def test_missing_declared_contract_test_fails_gate(tmp_path: Path) -> None:
    app, _head = make_fake_app(tmp_path)
    missing = CONTRACT_TESTS[0]
    (app / missing).unlink()
    git = shutil.which("git") or "git"
    subprocess.run([git, "add", "-A"], cwd=app, check=True, env=_GIT_ENV)  # noqa: S603
    subprocess.run([git, "commit", "-q", "-m", "drop test"], cwd=app, check=True, env=_GIT_ENV)  # noqa: S603
    head = subprocess.run(  # noqa: S603 - resolved git, fixture path
        [git, "rev-parse", "HEAD"], cwd=app, check=True, capture_output=True, text=True
    ).stdout.strip()
    _gate_root, gate_script = make_gate_root(tmp_path, head)
    result = run_contract(gate_script, app, tmp_path, help_text=REQUIRED_FLAGS)
    assert result.returncode != 0
    assert missing in result.stderr


def test_wrong_consumer_sha_fails_before_running_tests(tmp_path: Path) -> None:
    app, head = make_fake_app(tmp_path)
    wrong = "0" * 40 if not head.startswith("0") else "1" * 40
    gate_root, gate_script = make_gate_root(tmp_path, wrong)
    result = run_contract(gate_script, app, gate_root, help_text=REQUIRED_FLAGS)
    assert result.returncode != 0
    assert "revision mismatch" in result.stderr
    # The gate failed before invoking any consumer tooling.
    assert not (tmp_path / "pnpm.args").exists()


def test_dirty_consumer_checkout_fails(tmp_path: Path) -> None:
    app, head = make_fake_app(tmp_path)
    (app / "package.json").write_text('{"name":"dirty"}\n', encoding="utf-8")
    gate_root, gate_script = make_gate_root(tmp_path, head)
    result = run_contract(gate_script, app, gate_root, help_text=REQUIRED_FLAGS)
    assert result.returncode != 0
    assert "local modifications" in result.stderr


def test_canonical_scan_profile_test_cannot_be_omitted(tmp_path: Path) -> None:
    """The one declared list feeds both gates; the canonical scan-profile
    test is a member and every declared test exists in a faithful checkout."""
    assert "packages/types/src/scan-profile.test.ts" in CONTRACT_TESTS
    app, _ = make_fake_app(tmp_path)
    for relative in CONTRACT_TESTS:
        assert (app / relative).is_file(), relative


def test_real_pin_is_a_sha() -> None:
    pin = PIN_FILE.read_text(encoding="utf-8").strip()
    assert len(pin) == 40 and all(c in "0123456789abcdef" for c in pin)


def test_untracked_nested_engine_checkout_does_not_fail_gate(tmp_path: Path) -> None:
    """E6: an untracked nested lyrashield-engine/ checkout inside the app
    checkout must NOT cause the gate to fail. The gate should only reject
    tracked modifications, not untracked files used by app deployment."""
    app, head = make_fake_app(tmp_path)
    # Simulate an untracked nested engine checkout (used by app deployment).
    nested = app / "lyrashield-engine"
    nested.mkdir(exist_ok=True)
    (nested / "README.md").write_text("untracked nested checkout\n", encoding="utf-8")
    (nested / "lyrashield").mkdir(exist_ok=True)
    (nested / "lyrashield" / "__init__.py").write_text("", encoding="utf-8")
    _gate_root, gate_script = make_gate_root(tmp_path, head)
    result = run_contract(gate_script, app, tmp_path, help_text=REQUIRED_FLAGS)
    assert result.returncode == 0, f"gate failed with untracked nested checkout: {result.stderr}"
