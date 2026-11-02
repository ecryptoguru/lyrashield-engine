"""Bounded viewer transport over the TUI's existing event projection.

The legacy full transcript/TUI reader remains unchanged. Source SQLite row IDs
anchor event identity independently of timestamps, other agents and page size.
"""

from __future__ import annotations

import json
import sqlite3
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from lyrashield.interface.tui.live_view import TuiLiveView
from lyrashield.interface.viewer.transcript import _guard_transcript_state_inputs
from strix.core.paths import runtime_state_dir
from strix.interface.tui.history import _sqlite_timestamp_to_iso


if TYPE_CHECKING:
    from pathlib import Path


MAX_EVENT_BYTES = 24_000


def _bounded_event(event: dict[str, Any]) -> dict[str, Any]:
    if len(json.dumps(event).encode()) <= MAX_EVENT_BYTES:
        return event
    data = event["data"]
    # Bound UTF-8 bytes too: arbitrary Unicode can use four bytes per character.
    preview = json.dumps(data, ensure_ascii=False).encode()[:4000].decode("utf-8", errors="ignore")
    bounded: dict[str, Any]
    if event["type"] == "chat":
        preview = str(data.get("content", "")).encode()[:4000].decode("utf-8", errors="ignore")
        bounded = {"role": str(data.get("role", "assistant"))[:40], "content": preview}
    else:
        bounded = {
            "tool_name": str(data.get("tool_name", "tool"))[:100],
            "status": str(data.get("status", "completed"))[:40],
            "args": {"__raw": preview},
        }
    return {
        **event,
        "timestamp": str(event.get("timestamp", ""))[:128],
        "data": {
            **bounded,
            "viewer_truncated": True,
            "viewer_initial_input": data.get("viewer_initial_input", False),
        },
    }


def build_transcript_window(
    run_dir: Path,
    *,
    limit: int = 100,
    agent_id: str | None = None,
    before: str | None = None,
    summary_only: bool = False,
) -> dict[str, Any]:
    """Project history, return a bounded recent window per agent or older page.

    Projection CPU on changed artifacts is proportional to history. Unchanged
    projections are reused in memory; transport and DOM bounds are independent
    of TUI semantics and no persistent index or artifact mutation is introduced.
    """
    if (
        not 1 <= limit <= 200
        or (agent_id and len(agent_id) > 128)
        or (before and len(before) > 128)
    ):
        raise ValueError("Invalid transcript window")
    _guard_transcript_state_inputs(run_dir)
    state_dir = runtime_state_dir(run_dir)
    signature = tuple(
        _artifact_signature(state_dir / name)
        for name in ("agents.json", "agents.db", "agents.db-wal")
    )
    agents, grouped, summaries = _project_history(run_dir, signature)
    cursors: dict[str, str | None] = {}
    events: list[dict[str, Any]] = []
    if before and (not agent_id or not any(e["id"] == before for e in grouped.get(agent_id, []))):
        raise ValueError("Unknown transcript cursor")
    for aid, agent_events in grouped.items():
        if agent_id and aid != agent_id:
            continue
        end = (
            next(
                (i for i, event in enumerate(agent_events) if event["id"] == before),
                len(agent_events),
            )
            if before
            else len(agent_events)
        )
        start = max(0, end - limit)
        page = agent_events[start:end]
        cursors[aid] = page[0]["id"] if start and page else None
        if not summary_only:
            events.extend(_bounded_event(event) for event in page)
    return {
        "agents": agents,
        "events": events,
        "windowed": True,
        "older_cursors": cursors,
        "agent_summaries": summaries,
    }


@lru_cache(maxsize=2)
def _project_history(
    run_dir: Path, _signature: tuple[tuple[int, int, int] | None, ...]
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """Reuse at most two unchanged run projections across graph/page readers."""
    state_dir = runtime_state_dir(run_dir)
    agents_path = state_dir / "agents.json"
    metadata = json.loads(agents_path.read_text()) if agents_path.exists() else {}
    view = TuiLiveView()
    for aid, status in (metadata.get("statuses") or {}).items():
        if not isinstance(aid, str) or len(aid) > 128:
            raise ValueError("Invalid recorded agent identity")
        view.upsert_agent(
            aid,
            name=(metadata.get("names") or {}).get(aid, aid),
            parent_id=(metadata.get("parent_of") or {}).get(aid),
            status=str(status),
        )
    database = state_dir / "agents.db"
    if database.exists() and view.agents:
        with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as conn:
            rows = conn.execute(
                "select id, session_id, message_data, created_at from agent_messages order by id"
            )
            for row_id, aid, raw, created_at in rows:
                if aid not in view.agents:
                    continue
                try:
                    item = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(item, dict):
                    continue
                previous = len(view.events)
                view._ingest_session_history_item(
                    aid, item, timestamp=_sqlite_timestamp_to_iso(created_at)
                )
                for ordinal, event in enumerate(view.events[previous:]):
                    event["id"] = f"row_{row_id}_{ordinal}"
    grouped: dict[str, list[dict[str, Any]]] = {aid: [] for aid in view.agents}
    summaries: dict[str, dict[str, Any]] = {
        aid: {"tool_count": 0, "message_count": 0, "task": ""} for aid in view.agents
    }
    tasks: dict[str, str] = {}
    seen_input: set[str] = set()
    for event in view.events:
        aid = event["agent_id"]
        data = event["data"]
        if event["type"] == "tool":
            summaries[aid]["tool_count"] += 1
            if data.get("tool_name") == "create_agent":
                args = data.get("args")
                if isinstance(args, dict) and isinstance(args.get("name"), str):
                    tasks[args["name"]] = str(args.get("task", ""))[:4000]
        elif data.get("role") in {"user", "human"}:
            if (
                not str(data.get("content", "")).startswith("[Message from ")
                and aid not in seen_input
            ):
                data["viewer_initial_input"] = True
                seen_input.add(aid)
        else:
            summaries[aid]["message_count"] += 1
        grouped[aid].append(event)
    for aid, agent in view.agents.items():
        summaries[aid]["task"] = tasks.get(agent["name"], "")
    return list(view.agents.values()), grouped, summaries


def _artifact_signature(path: Path) -> tuple[int, int, int] | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return stat.st_ino, stat.st_mtime_ns, stat.st_size
