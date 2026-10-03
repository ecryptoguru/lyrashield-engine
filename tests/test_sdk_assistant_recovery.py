"""Persisted SDK message compatibility for content-filter recovery."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents import Agent
from agents.items import MessageOutputItem, TResponseInputItem
from agents.memory import SQLiteSession
from openai.types.responses import ResponseOutputMessage, ResponseOutputRefusal, ResponseOutputText
from openai.types.responses.response_output_text import AnnotationFileCitation

from lyrashield.lifecycle.sessions import sanitize_session_secrets


if TYPE_CHECKING:
    from pathlib import Path


def _sdk_assistant(text: str) -> dict[str, Any]:
    message = ResponseOutputMessage(
        id="msg-recovery",
        type="message",
        role="assistant",
        status="completed",
        content=[
            ResponseOutputText(
                type="output_text",
                text=text,
                annotations=[
                    AnnotationFileCitation(
                        type="file_citation",
                        file_id="file-evidence",
                        filename="evidence.txt",
                        index=0,
                    )
                ],
                logprobs=[],
            ),
            ResponseOutputRefusal(type="refusal", refusal="Preserve this nontext sibling"),
        ],
    )
    return cast(
        "dict[str, Any]",
        MessageOutputItem(agent=Agent(name="recovery"), raw_item=message).to_input_item(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("omit_type", [False, True])
async def test_recovery_preserves_sdk_assistant_siblings_and_metadata(
    tmp_path: Path, omit_type: bool
) -> None:
    item = _sdk_assistant("Captured api_key=sk-1234567890abcdef")
    if omit_type:
        item.pop("type")
    expected = deepcopy(item)
    expected["content"][0]["text"] = "Captured [SECRET]"
    session = SQLiteSession("assistant", tmp_path / "session.db")
    try:
        await session.add_items([cast("TResponseInputItem", item)])
        assert await sanitize_session_secrets(session) is True
        assert await session.get_items() == [expected]
        # The already-redacted SDK message is a no-change recovery on retry.
        assert await sanitize_session_secrets(session) is False
        assert await session.get_items() == [expected]
    finally:
        session.close()


@pytest.mark.asyncio
async def test_recovery_preserves_user_secret_and_clean_sdk_assistant(tmp_path: Path) -> None:
    items = [
        _sdk_assistant("Public scan evidence"),
        {"role": "user", "content": "Authorized input api_key=sk-1234567890abcdef"},
    ]
    session = SQLiteSession("user-policy", tmp_path / "session.db")
    try:
        await session.add_items(cast("list[TResponseInputItem]", items))
        assert await sanitize_session_secrets(session) is False
        assert await session.get_items() == items
    finally:
        session.close()
