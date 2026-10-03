from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from agents.tool_context import ToolContext

from lyrashield.tools.todo import tools as todo_tools


def _context(agent_id: str = "agent-1", tool_name: str = "create_todo") -> ToolContext[Any]:
    return ToolContext(
        context={"agent_id": agent_id},
        tool_name=tool_name,
        tool_call_id="test-call",
        tool_arguments="{}",
    )


@pytest.mark.asyncio
async def test_unreadable_todo_store_blocks_mutation_without_replacing_file(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / ".state"
    state_dir.mkdir()
    path = state_dir / "todos.json"
    original = b"{truncated json"
    path.write_bytes(original)
    todo_tools.hydrate_todos_from_disk(state_dir)

    result = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"new task"}]'})
        )
    )

    assert result["success"] is False
    assert path.read_bytes() == original


@pytest.mark.asyncio
async def test_failed_todo_persist_does_not_report_or_keep_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / ".state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"durable task"}]'})
        )
    )
    todo_id = created["created"][0]["todo_id"]
    path = state_dir / "todos.json"
    original_bytes = path.read_bytes()
    original_replace = Path.replace

    def fail_target_replace(self: Path, target: Path) -> Path:
        if Path(target) == path:
            raise OSError("injected todo write failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_target_replace)
    result = json.loads(
        await todo_tools.mark_todo_done.on_invoke_tool(
            _context(tool_name="mark_todo_done"), json.dumps({"todo_ids": json.dumps([todo_id])})
        )
    )

    assert result["success"] is False
    assert json.loads(path.read_bytes())["agent-1"][todo_id]["status"] == "pending"
    assert path.read_bytes() == original_bytes


@pytest.mark.asyncio
async def test_invalid_bulk_update_does_not_persist_partial_changes(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / ".state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(),
            json.dumps({"todos": '[{"title":"first"},{"title":"second"}]'}),
        )
    )
    first_id, second_id = [item["todo_id"] for item in created["created"]]

    result = json.loads(
        await todo_tools.update_todo.on_invoke_tool(
            _context(tool_name="update_todo"),
            json.dumps(
                {
                    "updates": json.dumps(
                        [
                            {
                                "todo_id": first_id,
                                "title": "must not partially save",
                                "status": "invalid",
                            },
                            {"todo_id": second_id, "status": "in_progress"},
                        ]
                    )
                }
            ),
        )
    )

    assert result["success"] is False
    persisted = json.loads((state_dir / "todos.json").read_text(encoding="utf-8"))
    assert persisted["agent-1"][first_id]["title"] == "first"
    assert persisted["agent-1"][second_id]["status"] == "pending"
    assert todo_tools._todos_storage["agent-1"][first_id]["title"] == "first"
    assert todo_tools._todos_storage["agent-1"][second_id]["status"] == "pending"


@pytest.mark.asyncio
async def test_create_validates_the_full_batch_before_mutating(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    todo_tools.hydrate_todos_from_disk(state_dir)

    result = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(),
            json.dumps(
                {
                    "todos": json.dumps(
                        [
                            {"title": "valid first"},
                            {"title": "invalid second", "priority": "urgent"},
                        ]
                    )
                }
            ),
        )
    )

    assert result["success"] is False
    assert todo_tools._todos_storage == {}
    assert not (state_dir / "todos.json").exists()


@pytest.mark.asyncio
async def test_update_rejects_a_partially_valid_batch_without_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"original"}]'})
        )
    )
    todo_id = created["created"][0]["todo_id"]
    store_before = deepcopy(todo_tools._todos_storage)
    path = state_dir / "todos.json"
    disk_before = path.read_bytes()

    result = json.loads(
        await todo_tools.update_todo.on_invoke_tool(
            _context(tool_name="update_todo"),
            json.dumps(
                {
                    "updates": json.dumps(
                        [
                            {"todo_id": todo_id, "title": "changed"},
                            {"todo_id": todo_id, "status": "finished"},
                        ]
                    )
                }
            ),
        )
    )

    assert result["success"] is False
    assert "Invalid status" in result["error"]
    assert todo_tools._todos_storage == store_before
    assert path.read_bytes() == disk_before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "result_key"),
    [
        ("update_todo", {"updates": '[{"todo_id":"missing","title":"x"}]'}, "updated"),
        ("mark_todo_done", {"todo_ids": '["missing"]'}, "marked"),
        ("mark_todo_pending", {"todo_ids": '["missing"]'}, "marked"),
        ("delete_todo", {"todo_ids": '["missing"]'}, "deleted"),
    ],
)
async def test_missing_id_batches_do_not_create_state(
    tmp_path: Path, tool_name: str, arguments: dict[str, str], result_key: str
) -> None:
    state_dir = tmp_path / "state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    before = deepcopy(todo_tools._todos_storage)
    tool = getattr(todo_tools, tool_name)

    result = json.loads(
        await tool.on_invoke_tool(
            _context(agent_id="missing-agent", tool_name=tool_name), json.dumps(arguments)
        )
    )

    assert result["success"] is False
    assert result[result_key] == []
    assert todo_tools._todos_storage == before == {}
    assert not (state_dir / "todos.json").exists()


@pytest.mark.asyncio
async def test_successful_update_is_durable_before_success_returns(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"before"}]'})
        )
    )
    todo_id = created["created"][0]["todo_id"]

    result = json.loads(
        await todo_tools.update_todo.on_invoke_tool(
            _context(tool_name="update_todo"),
            json.dumps({"updates": json.dumps([{"todo_id": todo_id, "title": "durable"}])}),
        )
    )

    assert result["success"] is True
    persisted = json.loads((state_dir / "todos.json").read_text(encoding="utf-8"))
    assert persisted["agent-1"][todo_id]["title"] == "durable"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["read", "malformed"])
async def test_failed_todo_hydration_blocks_mutation_without_overwriting_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    state_dir = tmp_path / "state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"preserve"}]'})
        )
    )
    path = state_dir / "todos.json"
    valid_bytes = path.read_bytes()
    if failure == "read":
        original_read = Path.read_text

        def fail_todo_read(self: Path, *args: Any, **kwargs: Any) -> str:
            if self == path:
                raise OSError("injected read failure")
            return original_read(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", fail_todo_read)
    else:
        path.write_bytes(b"{ malformed todos")
    disk_before = path.read_bytes()

    todo_tools.hydrate_todos_from_disk(state_dir)
    result = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"must not replace prior state"}]'})
        )
    )

    assert result["success"] is False
    assert todo_tools._todos_storage == {}
    assert path.read_bytes() == disk_before

    if failure == "read":
        monkeypatch.setattr(Path, "read_text", original_read)
    else:
        path.write_bytes(valid_bytes)
    todo_tools.hydrate_todos_from_disk(state_dir)
    assert todo_tools._todos_storage["agent-1"][created["created"][0]["todo_id"]]["title"] == (
        "preserve"
    )


@pytest.mark.asyncio
async def test_todo_state_is_isolated_between_fresh_and_resumed_runs(tmp_path: Path) -> None:
    original_run = tmp_path / "original" / "state"
    fresh_run = tmp_path / "fresh" / "state"
    todo_tools.hydrate_todos_from_disk(original_run)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"resume me"}]'})
        )
    )
    todo_id = created["created"][0]["todo_id"]

    todo_tools.hydrate_todos_from_disk(fresh_run)
    assert todo_tools._todos_storage == {}
    todo_tools.hydrate_todos_from_disk(original_run)
    assert todo_tools._todos_storage["agent-1"][todo_id]["title"] == "resume me"
    todo_tools.hydrate_todos_from_disk(fresh_run)
    assert todo_tools._todos_storage == {}


@pytest.mark.asyncio
async def test_malformed_nested_todo_record_fails_closed_without_overwriting(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    path = state_dir / "todos.json"
    corrupt = json.dumps(
        {
            "agent-1": {
                "saved": {
                    "title": "saved task",
                    "description": "",
                    "priority": "normal",
                    "status": "pending",
                }
            },
            "malformed-agent": ["not", "a", "todo mapping"],
        }
    ).encode()
    path.write_bytes(corrupt)
    todo_tools.hydrate_todos_from_disk(state_dir)

    result = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"must fail"}]'})
        )
    )

    assert result["success"] is False
    assert path.read_bytes() == corrupt
    assert todo_tools._todos_storage == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "result_key"),
    [
        ("mark_todo_done", {"todo_ids": '["existing", "missing"]'}, "marked"),
        ("mark_todo_pending", {"todo_ids": '["existing", "missing"]'}, "marked"),
        ("delete_todo", {"todo_ids": '["existing", "missing"]'}, "deleted"),
    ],
)
async def test_mixed_existing_and_missing_id_batches_are_atomic(
    tmp_path: Path, tool_name: str, arguments: dict[str, str], result_key: str
) -> None:
    state_dir = tmp_path / "state"
    todo_tools.hydrate_todos_from_disk(state_dir)
    created = json.loads(
        await todo_tools.create_todo.on_invoke_tool(
            _context(), json.dumps({"todos": '[{"title":"keep me"}]'})
        )
    )
    todo_id = created["created"][0]["todo_id"]
    existing_arguments = {
        **arguments,
        "todo_ids": json.dumps([todo_id, "missing"]),
    }
    path = state_dir / "todos.json"
    disk_before = path.read_bytes()
    store_before = deepcopy(todo_tools._todos_storage)

    result = json.loads(
        await getattr(todo_tools, tool_name).on_invoke_tool(
            _context(tool_name=tool_name), json.dumps(existing_arguments)
        )
    )

    assert result["success"] is False
    assert result[result_key] == []
    assert todo_tools._todos_storage == store_before
    assert path.read_bytes() == disk_before
