"""Window transport preserves the shared projection without unbounded payloads."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest

from lyrashield.interface.viewer.server import serve
from lyrashield.interface.viewer.transcript import build_run_state
from lyrashield.interface.viewer.transcript_window import MAX_EVENT_BYTES, build_transcript_window


if TYPE_CHECKING:
    from pathlib import Path


def _history(tmp_path: Path, count: int = 350) -> Path:
    run = tmp_path / "run"
    (run / ".state").mkdir(parents=True)
    (run / "run.json").write_text(json.dumps({"status": "running"}))
    (run / ".state/agents.json").write_text(
        json.dumps(
            {
                "statuses": {"root": "running", "child": "running"},
                "names": {"root": "Root", "child": "Child"},
                "parent_of": {"root": None, "child": "root"},
            }
        )
    )
    with sqlite3.connect(run / ".state/agents.db") as conn:
        conn.execute(
            "create table agent_messages (id integer primary key, session_id text, "
            "message_data text, created_at text)"
        )
        conn.executemany(
            "insert into agent_messages(session_id,message_data,created_at) values (?,?,?)",
            [
                (
                    "root",
                    json.dumps({"role": "assistant", "content": f"event {i}"}),
                    "2026-01-01T00:00:00Z",
                )
                for i in range(count)
            ],
        )
    return run


def test_window_pages_preserve_all_ids_across_other_agent_and_late_timestamp_append(
    tmp_path: Path,
) -> None:
    run = _history(tmp_path)
    latest = build_transcript_window(run)
    assert len(latest["events"]) == 100
    assert latest["agent_summaries"]["root"]["message_count"] == 350
    original_ids = [event["id"] for event in latest["events"]]
    cursor = latest["older_cursors"]["root"]
    with sqlite3.connect(run / ".state/agents.db") as conn:
        conn.executemany(
            "insert into agent_messages(session_id,message_data,created_at) values (?,?,?)",
            [
                (
                    "child",
                    json.dumps({"role": "assistant", "content": "other agent"}),
                    "2020-01-01T00:00:00Z",
                ),
                (
                    "root",
                    json.dumps({"role": "assistant", "content": "late timestamp"}),
                    "2010-01-01T00:00:00Z",
                ),
            ],
        )
    after = build_transcript_window(run)
    assert [event["id"] for event in after["events"] if event["agent_id"] == "root"][
        :-1
    ] == original_ids[1:]
    ids = set(original_ids)
    while cursor:
        older = build_transcript_window(run, agent_id="root", before=cursor)
        assert all(event["agent_id"] == "root" for event in older["events"])
        page_ids = {event["id"] for event in older["events"]}
        assert not ids & page_ids
        ids |= page_ids
        cursor = older["older_cursors"]["root"]
    assert len(ids) == 350
    with pytest.raises(ValueError, match="cursor"):
        build_transcript_window(run, agent_id="child", before=original_ids[0])


def test_projection_preserves_tool_results_and_initial_user_semantics(tmp_path: Path) -> None:
    run = _history(tmp_path, 0)
    messages = [
        {"role": "user", "content": "initial task"},
        {
            "type": "function_call",
            "call_id": "a",
            "name": "exec_command",
            "arguments": '{"cmd":"pwd"}',
        },
        {
            "type": "function_call_output",
            "call_id": "a",
            "output": '{"success":true,"output":"/tmp"}',
        },
        {"role": "user", "content": "real steering"},
    ]
    with sqlite3.connect(run / ".state/agents.db") as conn:
        conn.executemany(
            "insert into agent_messages(session_id,message_data,created_at) "
            "values ('root',?,'2026-01-01T00:00:00Z')",
            [(json.dumps(item),) for item in messages],
        )
    full = build_run_state(run)
    window = build_transcript_window(run, limit=2)
    assert window["events"][0]["data"]["result"] == full["events"][1]["data"]["result"]
    assert window["events"][-1]["data"]["content"] == "real steering"
    assert not window["events"][-1]["data"].get("viewer_initial_input")
    oldest = build_transcript_window(run, agent_id="root", before=window["older_cursors"]["root"])
    assert oldest["events"][0]["data"]["viewer_initial_input"] is True
    assert len(full["events"]) == 3
    assert "windowed" not in full


def test_large_unicode_event_is_bounded_without_mutating_original_artifact(tmp_path: Path) -> None:
    run = _history(tmp_path, 0)
    content = "🤗" * 100_000
    with sqlite3.connect(run / ".state/agents.db") as conn:
        conn.execute(
            "insert into agent_messages(session_id,message_data,created_at) "
            "values ('root',?,'2026-01-01T00:00:00Z')",
            (json.dumps({"role": "assistant", "content": content}),),
        )
    event = build_transcript_window(run)["events"][0]
    assert event["data"]["viewer_truncated"] is True
    assert event["data"]["content"].startswith("🤗")
    assert len(json.dumps(event).encode()) <= MAX_EVENT_BYTES
    assert build_run_state(run)["events"][0]["data"]["content"] == content


def test_window_cache_observes_uncheckpointed_wal_and_agent_updates(tmp_path: Path) -> None:
    run = _history(tmp_path, 1)
    first = build_transcript_window(run)
    with sqlite3.connect(run / ".state/agents.db") as writer:
        writer.execute("pragma journal_mode=wal")
        writer.execute(
            "insert into agent_messages(session_id,message_data,created_at) "
            "values ('root',?,'2020-01-01T00:00:00Z')",
            (json.dumps({"role": "assistant", "content": "committed WAL activity"}),),
        )
        writer.commit()
        second = build_transcript_window(run)
        assert len(second["events"]) == 2
        assert second["events"][0]["id"] == first["events"][0]["id"]
        assert second["events"][1]["data"]["content"] == "committed WAL activity"
    path = run / ".state/agents.json"
    metadata = json.loads(path.read_text())
    metadata["statuses"]["root"] = "completed"
    path.write_text(json.dumps(metadata))
    assert build_transcript_window(run)["agents"][0]["status"] == "completed"
    summary = build_transcript_window(run, summary_only=True)
    assert summary["events"] == []
    assert summary["agent_summaries"]["root"]["message_count"] == 2


def test_window_http_preserves_session_and_legacy_endpoint_contract(tmp_path: Path) -> None:
    run = _history(tmp_path)
    server, url, token = serve(run, open_browser=False)
    headers = {"Cookie": f"strix_viewer_session_{urlsplit(url).port}={token}"}
    try:
        for path, expected in [("/api/transcript?limit=100", 403)]:
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(url + path)  # noqa: S310 - local fixture URL
            assert error.value.code == expected
        for query in ["limit=0", "limit=201", "limit=oops", "limit=100&agent=child&before=row_1_0"]:
            with pytest.raises(urllib.error.HTTPError) as error:
                request = urllib.request.Request(  # noqa: S310 - local fixture
                    url + "/api/transcript?" + query, headers=headers
                )
                urllib.request.urlopen(request)  # noqa: S310 - local fixture
            assert error.value.code == 400
        for suffix, count in [
            ("", 350),
            ("?limit=100&agent=root", 100),
            ("?limit=100&summary=1", 0),
        ]:
            request = urllib.request.Request(  # noqa: S310 - local fixture
                url + "/api/transcript" + suffix, headers=headers
            )
            with urllib.request.urlopen(request) as response:  # noqa: S310 - local fixture
                payload = json.load(response)
            assert len(payload["events"]) == count
    finally:
        server.shutdown()
        server.server_close()
