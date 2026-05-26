"""SDK session helpers for Strix agents."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from agents.memory import SQLiteSession


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteSession(session_id=agent_id, db_path=path)


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"


async def strip_latest_image_from_session(session: Session) -> bool:
    items = await session.get_items()
    if not items:
        return False
    latest = items[-1]
    if not isinstance(latest, dict) or latest.get("type") != "function_call_output":
        return False
    output = latest.get("output")
    if not isinstance(output, list):
        return False
    if not any(isinstance(b, dict) and b.get("type") == "input_image" for b in output):
        return False
    await session.pop_item()
    await session.add_items(
        cast(
            "list[TResponseInputItem]",
            [
                {
                    "type": "function_call_output",
                    "call_id": latest.get("call_id"),
                    "output": [{"type": "input_text", "text": _IMAGE_REJECTED_TEXT}],
                },
            ],
        ),
    )
    return True
