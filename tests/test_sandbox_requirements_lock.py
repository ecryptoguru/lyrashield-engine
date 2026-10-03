"""Reproducibility and platform coverage for the sandbox dependency lock."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "containers" / "requirements.in"
LOCK = ROOT / "containers" / "python-requirements.txt"
OVERRIDES = ROOT / "containers" / "pyjwt-override.txt"


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _packages(text: str) -> set[tuple[str, str]]:
    return {
        (_normalize(match.group(1)), match.group(2))
        for match in re.finditer(r"(?m)^([A-Za-z0-9_.-]+)==([^\\\s]+)", text)
    }


def _compile_args(output: Path, *platform_args: str) -> list[str]:
    args = [
        "uv",
        "pip",
        "compile",
        str(INPUT.relative_to(ROOT)),
        "--generate-hashes",
        "--no-header",
        "--no-annotate",
        "--upgrade-package",
        "pyjwt",
        "--overrides",
        str(OVERRIDES.relative_to(ROOT)),
        "--output-file",
        str(output),
    ]
    if platform_args:
        args.extend(platform_args)
    else:
        args.append("--universal")
    return args


def test_sandbox_lock_pins_direct_inputs_and_hashes_every_distribution() -> None:
    lock_text = LOCK.read_text(encoding="utf-8")
    lock_entries = list(re.finditer(r"(?m)^([A-Za-z0-9_.-]+)==[^\\\s]+", lock_text))
    assert lock_entries

    locked_names: set[str] = set()
    for index, match in enumerate(lock_entries):
        end = lock_entries[index + 1].start() if index + 1 < len(lock_entries) else len(lock_text)
        stanza = lock_text[match.start() : end]
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", stanza), match.group(1)
        locked_names.add(_normalize(match.group(1)))

    direct_names = {
        _normalize(name)
        for name in re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", INPUT.read_text(encoding="utf-8"))
    }
    assert direct_names <= locked_names


def test_sandbox_lock_reproduces_from_current_input(tmp_path: Path) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv is required to regenerate the sandbox lock")

    output = tmp_path / "python-requirements.txt"
    shutil.copyfile(LOCK, output)
    subprocess.run(  # noqa: S603 - fixed uv command compiles tracked requirement files
        _compile_args(output),
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    # The tracked file keeps its explanatory three-line header; uv writes only
    # the generated hash-locked distribution stanzas.
    generated_lock = "\n".join(LOCK.read_text(encoding="utf-8").splitlines()[3:]) + "\n"
    assert output.read_text(encoding="utf-8") == generated_lock


def test_sandbox_lock_resolves_the_same_packages_for_both_linux_architectures(
    tmp_path: Path,
) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv is required to resolve sandbox architecture targets")

    resolved: list[set[tuple[str, str]]] = []
    for platform in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
        output = tmp_path / f"{platform}.txt"
        shutil.copyfile(LOCK, output)
        subprocess.run(  # noqa: S603 - fixed uv command resolves the declared sandbox targets
            _compile_args(
                output,
                "--python-version",
                "3.13",
                "--python-platform",
                platform,
            ),
            check=True,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        resolved.append(_packages(output.read_text(encoding="utf-8")))

    locked = _packages(LOCK.read_text(encoding="utf-8"))
    assert resolved[0] == resolved[1]
    assert resolved[0] <= locked


def test_guarded_caido_module_imports_with_the_engine_dependency_environment() -> None:
    env = os.environ.copy()
    proxy_path = str(ROOT / "lyrashield" / "tools" / "proxy")
    env["PYTHONPATH"] = os.pathsep.join(
        path for path in (proxy_path, env.get("PYTHONPATH", "")) if path
    )
    subprocess.run(
        [sys.executable, "-c", "import caido_api"],
        check=True,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
