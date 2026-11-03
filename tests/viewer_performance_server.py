"""Synthetic large-run fixture; no provider, external calls or operator actions."""

from __future__ import annotations

import argparse
import json
import signal
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from lyrashield.interface.viewer import server as viewer_server
from lyrashield.interface.viewer.transcript import build_run_state
from lyrashield.interface.viewer.transcript_window import build_transcript_window


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages", type=int, default=10000)
    parser.add_argument("--static", type=Path)
    args = parser.parse_args()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    with tempfile.TemporaryDirectory(prefix="viewer-perf-") as directory:
        run = Path(directory)
        (run / ".state").mkdir()
        (run / "run.json").write_text(
            json.dumps(
                {
                    "run_id": "performance",
                    "run_name": "Synthetic large run",
                    "status": "running",
                    "targets_info": [],
                }
            )
        )
        (run / "vulnerabilities.json").write_text("[]")
        (run / ".state/agents.json").write_text(
            json.dumps(
                {
                    "statuses": {"root": "running"},
                    "names": {"root": "Root"},
                    "parent_of": {"root": None},
                }
            )
        )
        with sqlite3.connect(run / ".state/agents.db") as conn:
            conn.execute(
                "create table agent_messages(id integer primary key, session_id text, "
                "message_data text, created_at text)"
            )
            conn.executemany(
                "insert into agent_messages(session_id,message_data,created_at) "
                "values ('root',?,'2026-01-01T00:00:00Z')",
                [
                    (
                        json.dumps(
                            {
                                "role": "assistant",
                                "content": f"Message {i}: " + "synthetic text " * 50,
                            }
                        ),
                    )
                    for i in range(args.messages)
                ],
            )
        metrics = {}
        for name, project in [
            ("full", build_run_state),
            ("window", build_transcript_window),
            ("summary", lambda run: build_transcript_window(run, summary_only=True)),
        ]:
            timings = []
            for _ in range(3):
                start = time.perf_counter()
                state = project(run)
                timings.append(round((time.perf_counter() - start) * 1000, 2))
            metrics[name] = {
                "projection_ms": timings,
                "bytes": len(json.dumps(state).encode()),
                "events": len(state["events"]),
            }
        if args.static:
            viewer_server.bundle_dir = lambda: args.static
        server, url, token = viewer_server.serve(run, open_browser=False)
        try:
            print(  # noqa: T201 - fixture startup protocol
                json.dumps({"url": viewer_server.authorized_url(url, token), "metrics": metrics}),
                flush=True,
            )
            stopped.wait()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
