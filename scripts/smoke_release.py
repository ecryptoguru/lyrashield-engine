# ruff: noqa: INP001
"""Smoke-test a packaged LyraShield engine binary without starting its TUI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    binary = Path(sys.argv[1])
    expected = f"lyrashield {sys.argv[2]}"

    try:
        result = subprocess.run(  # noqa: S603 - the build supplies its own binary path
            [binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Binary smoke test failed: {error}", file=sys.stderr)  # noqa: T201
        return 1

    actual = result.stdout.strip()
    if result.returncode != 0 or actual != expected:
        print(  # noqa: T201
            f"Binary smoke test failed: expected {expected!r}, got {actual!r} "
            f"(exit {result.returncode})",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
