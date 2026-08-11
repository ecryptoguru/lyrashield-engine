# ruff: noqa: INP001
"""Smoke-test a packaged LyraShield engine binary without starting its TUI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    binary = Path(sys.argv[1])
    expected = f"lyrashield {sys.argv[2]}"

    checks = [(["--version"], expected, True), (["--help"], "--scope-mode", False)]
    for args, expected_output, exact in checks:
        try:
            result = subprocess.run(  # noqa: S603 - the build supplies its own binary path
                [binary, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"Binary smoke test failed for {args}: {error}", file=sys.stderr)  # noqa: T201
            return 1

        actual = result.stdout.strip()
        matched = actual == expected_output if exact else expected_output in actual
        if result.returncode != 0 or not matched:
            print(  # noqa: T201
                f"Binary smoke test failed for {args}: expected {expected_output!r}, "
                f"got {actual!r} (exit {result.returncode})",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
