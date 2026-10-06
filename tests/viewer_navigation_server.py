"""Synthetic, capability-protected viewer fixture for browser navigation tests."""

from __future__ import annotations

import json
import signal
import tempfile
import threading
from pathlib import Path

from lyrashield.interface.viewer import auth
from lyrashield.interface.viewer.server import authorized_url, serve


def main() -> None:
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    auth.is_verified = lambda: False
    auth.read_auth = lambda: None
    with tempfile.TemporaryDirectory(prefix="viewer-navigation-") as directory:
        root = Path(directory)
        for stored, display in [
            ("current-directory", "Current friendly name"),
            ("past-directory", "Past friendly name"),
        ]:
            run = root / stored
            (run / ".state").mkdir(parents=True)
            (run / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": stored,
                        "run_name": display,
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
                json.dumps({"statuses": {}, "names": {}, "parent_of": {}}), encoding="utf-8"
            )
        server, url, token = serve(root / "current-directory", open_browser=False)
        try:
            print(json.dumps({"url": authorized_url(url, token)}), flush=True)  # noqa: T201 - test startup protocol
            stopped.wait()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
