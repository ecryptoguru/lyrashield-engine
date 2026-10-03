"""Behavior and drift-report coverage for owned and upstream twins."""

from __future__ import annotations

import csv
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from strix.interface.tui.history import load_session_history


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_upstream_history_loader_reads_session_db_read_only(tmp_path: Path) -> None:
    state_dir = tmp_path / ".state"
    state_dir.mkdir()
    agents_db = state_dir / "agents.db"
    with sqlite3.connect(agents_db) as conn:
        conn.execute(
            "create table agent_messages (id integer primary key, session_id text, "
            "message_data text, created_at text)"
        )
        conn.executemany(
            "insert into agent_messages (session_id, message_data, created_at) values (?, ?, ?) ",
            [
                ("root", json.dumps({"type": "message", "text": "first"}), "2026-01-01T00:00:00Z"),
                (
                    "other",
                    json.dumps({"type": "message", "text": "hidden"}),
                    "2026-01-01T00:00:01Z",
                ),
                ("root", "not-json", "2026-01-01T00:00:02Z"),
            ],
        )

    assert load_session_history(tmp_path, ["root"]) == [
        ("root", {"type": "message", "text": "first"}, "2026-01-01T00:00:00+00:00")
    ]


def test_twin_report_is_sorted_and_drift_never_fails(tmp_path: Path) -> None:
    owned = tmp_path / "lyrashield"
    upstream = tmp_path / "strix"
    owned.mkdir()
    upstream.mkdir()
    for root in (owned, upstream):
        (root / "nested").mkdir()
    (owned / "z.py").write_text("same\n", encoding="utf-8")
    (upstream / "z.py").write_text("same\n", encoding="utf-8")
    (owned / "nested" / "a.py").write_text("same\nowned\n", encoding="utf-8")
    (upstream / "nested" / "a.py").write_text("same\nupstream\n", encoding="utf-8")
    (owned / "only.py").write_text("no twin\n", encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - fixed local interpreter and script
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "report_twin_drift.py"),
            "--root",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = list(csv.DictReader(result.stdout.splitlines()))
    assert rows == [
        {
            "owned": "lyrashield/nested/a.py",
            "upstream": "strix/nested/a.py",
            "byte_identical": "no",
            "matching_lines": "1",
            "owned_lines": "2",
            "upstream_lines": "2",
        },
        {
            "owned": "lyrashield/z.py",
            "upstream": "strix/z.py",
            "byte_identical": "yes",
            "matching_lines": "1",
            "owned_lines": "1",
            "upstream_lines": "1",
        },
    ]
