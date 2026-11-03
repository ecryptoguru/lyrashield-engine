# ruff: noqa: INP001
"""Exercise the packaged financial backend without a provider or Docker."""

from __future__ import annotations

import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread


def check_budget_boundary(binary: Path) -> None:
    """A tiny unfunded request must persist its ceiling across fresh processes."""
    requests: list[str] = []

    class DenyProvider(BaseHTTPRequestHandler):
        def parse_request(self) -> bool:
            parsed = super().parse_request()
            if parsed:
                requests.append(self.command)
            return parsed

        def do_POST(self) -> None:
            self.send_error(503)

        def log_message(self, _format: str, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), DenyProvider)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TemporaryDirectory(prefix="lyra-budget-package-") as temporary:
            # macOS's default temporary path includes /var, an alias deliberately
            # refused by financial no-follow I/O. Use its real directory.
            root = Path(temporary).resolve()
            source, output = root / "input.json", root / "output.json"
            source.write_text(
                json.dumps(
                    {
                        "schemaVersion": "ai-security-triage-input/1.0",
                        "commitSha": "a" * 40,
                        "detectorVersion": "package-control/1",
                        "ruleVersion": "rules/1",
                        "candidates": [
                            {
                                "findingIdentity": "b" * 64,
                                "controlId": "AI-01",
                                "ruleId": "package-control",
                                "severity": "MEDIUM",
                                "selectionReason": "MEDIUM_SEVERITY",
                                "evidenceChecksum": "b" * 64,
                                "evidenceExcerpt": "Offline package control",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            # Never carry the invoking operator's credentials or configuration.
            env = {
                k: v
                for k, v in os.environ.items()
                if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}
            }
            env.update(
                {
                    "HOME": str(root),
                    "USERPROFILE": str(root),
                    "TEMP": str(root),
                    "TMP": str(root),
                    "TMPDIR": str(root),
                    "LYRASHIELD_LLM": "openai/gpt-6-luna",
                    "LYRASHIELD_LUNA_LLM": "openai/gpt-6-luna",
                    "LLM_API_KEY": "offline-package-control",
                    "LLM_API_BASE": f"http://127.0.0.1:{server.server_port}/v1",
                    "LLM_API_MODE": "responses",
                    "OPENAI_AGENTS_DISABLE_TRACING": "1",
                    "LYRASHIELD_TELEMETRY": "0",
                }
            )
            args = [
                str(binary.resolve()),
                "ai-security-triage",
                "--input",
                str(source),
                "--output",
                str(output),
                "--enabled",
            ]
            previous_guard = None
            for allowance in (["--max-budget-usd", "0.000000001"], []):
                output.unlink(missing_ok=True)
                result = subprocess.run(  # noqa: S603 - caller supplies the built artifact
                    [*args, *allowance],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode:
                    raise RuntimeError(
                        f"Packaged budget control failed (exit {result.returncode}): "
                        + result.stderr[-4000:]
                    )
                artifact = json.loads(output.read_text(encoding="utf-8"))
                if (
                    artifact["status"] != "BUDGET_STOPPED"
                    or artifact["terminalReason"] != "TRIAGE_BUDGET_EXHAUSTED"
                    or artifact["llmUsage"]["requests"] != 0
                    or artifact["results"] != []
                    or requests
                ):
                    raise RuntimeError("Packaged budget control reached provider or lost its cap")
                records = list(root.rglob("run.json"))
                if len(records) != 1:
                    raise RuntimeError("Packaged budget control did not persist one run")
                record = json.loads(records[0].read_text(encoding="utf-8"))
                guard = record["_finite_budget_guard"]
                if (
                    guard["limit_units"] != 10
                    or guard["known_floor_units"] != 0
                    or guard["pending"] != []
                    or not (records[0].parent / ".finite-budget-activated").is_file()
                    or (previous_guard is not None and guard != previous_guard)
                ):
                    raise RuntimeError("Packaged budget state changed across a cold process")
                previous_guard = guard
            # A broken activation pair must never be treated as a new unlimited
            # run by another copy of the packaged CLI.
            before = records[0].read_bytes()
            (records[0].parent / ".finite-budget-activated").unlink()
            output.unlink()
            result = subprocess.run(  # noqa: S603 - same built artifact and fixed arguments
                args,
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if (
                result.returncode == 0
                or requests
                or output.exists()
                or (records[0].parent / ".finite-budget-activated").exists()
                or records[0].read_bytes() != before
            ):
                raise RuntimeError("Packaged resume accepted a broken financial activation pair")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
