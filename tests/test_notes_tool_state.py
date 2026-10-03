from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

import pytest
from agents.tool_context import ToolContext

from lyrashield.agents import factory
from lyrashield.agents import overrides as deferred_overrides
from lyrashield.tools.notes import tools as notes_tools
from lyrashield_adapter.cli import _register_lyrashield_tool_overrides


def _context(tool_name: str, notes_store: Any | None = None) -> ToolContext[Any]:
    context: dict[str, Any] = {"agent_id": "agent-1"}
    if notes_store is not None:
        context["notes_store"] = notes_store
    return ToolContext(
        context=context,
        tool_name=tool_name,
        tool_call_id="test-call",
        tool_arguments="{}",
    )


@pytest.fixture(autouse=True)
def _isolate_note_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notes_tools, "_notes_path", None)
    monkeypatch.setattr(notes_tools, "_notes_store_available", True)
    notes_tools._notes_storage.clear()


@pytest.fixture
def registered_notes() -> Any:
    saved_overrides = dict(factory._TOOL_OVERRIDES)
    saved_loaders = dict(deferred_overrides._tool_override_loaders)
    deferred_overrides._tool_override_loaders.clear()
    _register_lyrashield_tool_overrides()
    factory.resolve_product_overrides()
    try:
        yield factory._TOOL_OVERRIDES
    finally:
        factory._TOOL_OVERRIDES.clear()
        factory._TOOL_OVERRIDES.update(saved_overrides)
        deferred_overrides._tool_override_loaders.clear()
        deferred_overrides._tool_override_loaders.update(saved_loaders)


@pytest.mark.asyncio
async def test_registered_note_create_keeps_disk_and_memory_unchanged_on_write_failure(
    registered_notes: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "scan-state"
    notes_tools.hydrate_notes_from_disk(state_dir)
    target = state_dir / "notes.json"
    original_replace = Path.replace

    def fail_target_replace(self: Path, destination: Path) -> Path:
        if destination == target:
            raise OSError("injected note write failure")
        return original_replace(self, destination)

    monkeypatch.setattr(Path, "replace", fail_target_replace)
    result = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"),
            json.dumps({"title": "durable", "content": "must not be lost", "tags": ["auth"]}),
        )
    )

    assert result["success"] is False
    assert notes_tools._notes_storage == {}
    assert not target.exists()


@pytest.mark.asyncio
async def test_corrupt_note_hydration_refuses_registered_mutation(
    registered_notes: Any,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "scan-state"
    state_dir.mkdir()
    target = state_dir / "notes.json"
    corrupt = b"{truncated json"
    target.write_bytes(corrupt)
    notes_tools.hydrate_notes_from_disk(state_dir)

    result = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"), json.dumps({"title": "new", "content": "note"})
        )
    )

    assert result["success"] is False
    assert target.read_bytes() == corrupt
    assert notes_tools._notes_storage == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["read", "malformed"])
async def test_failed_note_rehydration_clears_memory_and_preserves_disk(
    registered_notes: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    state_dir = tmp_path / "scan-state"
    notes_tools.hydrate_notes_from_disk(state_dir)
    created = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"),
            json.dumps({"title": "preserve", "content": "recoverable note"}),
        )
    )
    note_id = created["note_id"]
    target = state_dir / "notes.json"
    valid_bytes = target.read_bytes()
    if failure == "read":
        original_read_text = Path.read_text

        def fail_note_read(self: Path, *args: Any, **kwargs: Any) -> str:
            if self == target:
                raise OSError("injected note read failure")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", fail_note_read)
    else:
        target.write_bytes(b"{ malformed notes")
    bytes_before_retry = target.read_bytes()

    notes_tools.hydrate_notes_from_disk(state_dir)
    result = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"), json.dumps({"title": "blocked", "content": "blocked"})
        )
    )

    assert result["success"] is False
    assert notes_tools._notes_storage == {}
    assert target.read_bytes() == bytes_before_retry

    if failure == "read":
        monkeypatch.setattr(Path, "read_text", original_read_text)
    else:
        target.write_bytes(valid_bytes)
    notes_tools.hydrate_notes_from_disk(state_dir)
    assert notes_tools._notes_storage[note_id]["content"] == "recoverable note"


@pytest.mark.asyncio
async def test_registered_note_update_is_atomic_across_all_fields(
    registered_notes: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "scan-state"
    notes_tools.hydrate_notes_from_disk(state_dir)
    created = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"), json.dumps({"title": "original", "content": "body"})
        )
    )
    note_id = created["note_id"]
    target = state_dir / "notes.json"
    original_disk = target.read_bytes()
    original_note = json.loads(original_disk)[note_id]
    original_replace = Path.replace

    def fail_target_replace(self: Path, destination: Path) -> Path:
        if destination == target:
            raise OSError("injected note update failure")
        return original_replace(self, destination)

    monkeypatch.setattr(Path, "replace", fail_target_replace)
    result = json.loads(
        await registered_notes["update_note"].on_invoke_tool(
            _context("update_note"),
            json.dumps(
                {
                    "note_id": note_id,
                    "title": "changed title",
                    "content": "changed body",
                    "tags": ["changed"],
                }
            ),
        )
    )

    assert result["success"] is False
    assert target.read_bytes() == original_disk
    assert notes_tools._notes_storage[note_id] == original_note


@pytest.mark.asyncio
async def test_registered_note_tools_keep_filter_author_update_and_delete_behavior(
    registered_notes: Any,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "scan-state"
    notes_tools.hydrate_notes_from_disk(state_dir)
    created = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"),
            json.dumps(
                {
                    "title": "Authentication review",
                    "content": "Found a session boundary to inspect",
                    "category": "findings",
                    "tags": ["auth", "session"],
                }
            ),
        )
    )
    note_id = created["note_id"]

    listed = json.loads(
        await registered_notes["list_notes"].on_invoke_tool(
            _context("list_notes"),
            json.dumps(
                {
                    "category": "findings",
                    "tags": ["auth"],
                    "search": "SESSION",
                    "include_content": True,
                }
            ),
        )
    )
    assert listed["filtered_count"] == 1
    assert listed["notes"][0]["note_id"] == note_id
    assert listed["notes"][0]["content"] == "Found a session boundary to inspect"
    assert listed["notes"][0]["by_you"] is True

    updated = json.loads(
        await registered_notes["update_note"].on_invoke_tool(
            _context("update_note"),
            json.dumps({"note_id": note_id, "title": "Reviewed", "tags": ["done"]}),
        )
    )
    fetched = json.loads(
        await registered_notes["get_note"].on_invoke_tool(
            _context("get_note"), json.dumps({"note_id": note_id})
        )
    )
    assert updated["success"] is True
    assert fetched["note"]["title"] == "Reviewed"
    assert fetched["note"]["tags"] == ["done"]
    assert json.loads((state_dir / "notes.json").read_text(encoding="utf-8"))[note_id]["title"] == (
        "Reviewed"
    )

    deleted = json.loads(
        await registered_notes["delete_note"].on_invoke_tool(
            _context("delete_note"), json.dumps({"note_id": note_id})
        )
    )
    assert deleted["success"] is True
    assert json.loads((state_dir / "notes.json").read_text(encoding="utf-8")) == {}


@pytest.mark.asyncio
async def test_notes_rehydrate_isolates_fresh_and_resumed_scan_state(
    registered_notes: Any,
    tmp_path: Path,
) -> None:
    first_run = tmp_path / "first-run" / "state"
    fresh_run = tmp_path / "fresh-run" / "state"
    notes_tools.hydrate_notes_from_disk(first_run)
    created = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"),
            json.dumps({"title": "first run note", "content": "persisted for resume"}),
        )
    )
    note_id = created["note_id"]

    notes_tools._notes_storage.clear()
    notes_tools.hydrate_notes_from_disk(first_run)
    assert notes_tools._notes_storage[note_id]["content"] == "persisted for resume"

    notes_tools.hydrate_notes_from_disk(fresh_run)
    assert notes_tools._notes_storage == {}
    notes_tools.hydrate_notes_from_disk(first_run)
    assert notes_tools._notes_storage[note_id]["title"] == "first run note"
    notes_tools.hydrate_notes_from_disk(fresh_run)
    assert notes_tools._notes_storage == {}


@pytest.mark.asyncio
async def test_note_hydration_cannot_rebind_store_during_a_write(
    registered_notes: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "scan-state"
    next_state_dir = tmp_path / "next-scan-state"
    store = notes_tools.hydrate_notes_from_disk(state_dir)
    created = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note", store), json.dumps({"title": "before", "content": "body"})
        )
    )
    note_id = created["note_id"]
    persist_entered = threading.Event()
    allow_persist = threading.Event()
    original_persist = notes_tools._persist_candidate

    def pause_before_persist(
        candidate: dict[str, dict[str, Any]], bound_store: Any | None = None
    ) -> bool:
        persist_entered.set()
        if not allow_persist.wait(timeout=3):
            raise TimeoutError("test did not release the note write")
        return original_persist(candidate, bound_store)

    monkeypatch.setattr(notes_tools, "_persist_candidate", pause_before_persist)
    update_task = asyncio.create_task(
        registered_notes["update_note"].on_invoke_tool(
            _context("update_note", store), json.dumps({"note_id": note_id, "title": "after"})
        )
    )

    try:
        assert await asyncio.to_thread(persist_entered.wait, 2)
        next_store = await asyncio.to_thread(notes_tools.hydrate_notes_from_disk, next_state_dir)
        assert next_store.storage == {}
        allow_persist.set()
        result = json.loads(await update_task)
        assert result["success"] is True
    finally:
        allow_persist.set()
        if not update_task.done():
            await update_task

    persisted = json.loads((state_dir / "notes.json").read_text(encoding="utf-8"))
    assert persisted[note_id]["title"] == "after"
    assert not (next_state_dir / "notes.json").exists()


@pytest.mark.asyncio
async def test_old_note_callback_stays_bound_to_its_scan_after_a_new_scan_starts(
    registered_notes: Any,
    tmp_path: Path,
) -> None:
    first_state = tmp_path / "first" / "state"
    second_state = tmp_path / "second" / "state"
    first_store = notes_tools.hydrate_notes_from_disk(first_state)
    first_context = _context("create_note", first_store)
    created = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            first_context, json.dumps({"title": "first", "content": "first scan"})
        )
    )

    second_store = notes_tools.hydrate_notes_from_disk(second_state)
    second_context = _context("create_note", second_store)
    stale_update = json.loads(
        await registered_notes["update_note"].on_invoke_tool(
            _context("update_note", first_store),
            json.dumps({"note_id": created["note_id"], "content": "updated first scan"}),
        )
    )
    second_create = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            second_context, json.dumps({"title": "second", "content": "second scan"})
        )
    )
    stale_read = json.loads(
        await registered_notes["get_note"].on_invoke_tool(
            _context("get_note", first_store), json.dumps({"note_id": created["note_id"]})
        )
    )
    cross_scan_read = json.loads(
        await registered_notes["get_note"].on_invoke_tool(
            _context("get_note", second_store), json.dumps({"note_id": created["note_id"]})
        )
    )

    assert stale_update["success"] is True
    assert stale_read["success"] is True
    assert stale_read["note"]["content"] == "updated first scan"
    assert cross_scan_read["success"] is False
    assert first_store.storage[created["note_id"]]["content"] == "updated first scan"
    assert second_store.storage == {
        second_create["note_id"]: second_store.storage[second_create["note_id"]]
    }
    assert json.loads((first_state / "notes.json").read_text())[created["note_id"]]["content"] == (
        "updated first scan"
    )
    assert json.loads((second_state / "notes.json").read_text()).keys() == {
        second_create["note_id"]
    }


@pytest.mark.asyncio
async def test_malformed_nested_note_record_fails_closed_without_overwriting(
    registered_notes: Any,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "scan-state"
    state_dir.mkdir()
    target = state_dir / "notes.json"
    corrupt = json.dumps(
        {
            "valid-looking": {
                "title": "saved",
                "content": "saved note",
                "category": "general",
                "tags": ["ok"],
            },
            "malformed": ["not", "a", "note object"],
        }
    ).encode()
    target.write_bytes(corrupt)
    notes_tools.hydrate_notes_from_disk(state_dir)

    result = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"), json.dumps({"title": "new", "content": "must fail"})
        )
    )

    assert result["success"] is False
    assert target.read_bytes() == corrupt
    assert notes_tools._notes_storage == {}


@pytest.mark.asyncio
async def test_unbound_note_store_commits_successful_mutation_to_memory(
    registered_notes: Any,
) -> None:
    result = json.loads(
        await registered_notes["create_note"].on_invoke_tool(
            _context("create_note"), json.dumps({"title": "memory", "content": "in memory"})
        )
    )

    assert result["success"] is True
    assert notes_tools._notes_storage[result["note_id"]]["content"] == "in memory"
