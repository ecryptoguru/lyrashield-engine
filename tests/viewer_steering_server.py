"""Capability-protected synthetic live run for steering browser acceptance tests."""

from __future__ import annotations

import json
import signal
import tempfile
import threading
from pathlib import Path

from lyrashield.interface.viewer.server import authorized_url, serve


def main() -> None:
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    with tempfile.TemporaryDirectory(prefix="viewer-steering-") as directory:
        root = Path(directory)
        for stored in ("current-directory", "past-directory"):
            run = root / stored
            (run / ".state").mkdir(parents=True)
            (run / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": stored,
                        "run_name": stored,
                        "status": "running",
                        "scan_mode": "quick",
                        "targets_info": [],
                    }
                ),
                encoding="utf-8",
            )
            (run / "vulnerabilities.json").write_text("[]", encoding="utf-8")
            (run / "report.md").write_text("# Synthetic report", encoding="utf-8")
            (run / ".state" / "agents.json").write_text(
                json.dumps(
                    {
                        "statuses": {"root": "budget_paused"},
                        "names": {"root": "Root agent"},
                        "parent_of": {"root": None},
                        "metadata": {},
                    }
                ),
                encoding="utf-8",
            )
        budget = {
            "increment_usd": 1.2,
            "limit_usd": 1.2,
            "spent_usd": 1.2,
            "paused": True,
            "resume_requires_increase": True,
        }

        def steer(_agent_id: str, _message: str, _submission_id: str) -> bool:
            return True

        def control(action: str, _submission_id: str) -> bool:
            if action == "increase_budget":
                budget["limit_usd"] = 2.4
                budget["resume_requires_increase"] = False
            elif budget["resume_requires_increase"]:
                return False
            else:
                budget["paused"] = False
            return True

        server, url, token = serve(
            root / "current-directory",
            open_browser=False,
            steer_handler=steer,
            control_handler=control,
            control_state_handler=lambda: dict(budget),
        )
        try:
            print(json.dumps({"url": authorized_url(url, token)}), flush=True)  # noqa: T201
            stopped.wait()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
