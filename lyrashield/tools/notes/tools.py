# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Per-run notes tools with atomic, failure-safe persistence."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.nullish import clean_optional


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _NotesStoreState:
    storage: dict[str, dict[str, Any]] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    available: bool = True


@dataclass(frozen=True, slots=True)
class NotesStore:
    """Immutable-path note storage bound to one scan runtime context."""

    path: Path
    state: _NotesStoreState = field(default_factory=_NotesStoreState)

    @property
    def storage(self) -> dict[str, dict[str, Any]]:
        return self.state.storage

    @property
    def lock(self) -> Any:
        return self.state.lock

    @property
    def available(self) -> bool:
        return self.state.available


_notes_storage: dict[str, dict[str, Any]] = {}
_VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan", "wiki"]
_notes_lock = threading.RLock()
_notes_stores_by_path: dict[Path, NotesStore] = {}
_notes_stores_lock = threading.RLock()
_DEFAULT_CONTENT_PREVIEW_CHARS = 280
_NOTE_ID_GENERATION_ATTEMPTS = 1024

_notes_path: Path | None = None
_notes_store_available = True


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    """Return the (agent_id, agent_name) of the agent invoking this tool."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None
    return agent_id, agent_name


def hydrate_notes_from_disk(state_dir: Path) -> NotesStore:
    """Hydrate and return the store bound to this scan's immutable state path."""
    path = state_dir / "notes.json"
    with _notes_stores_lock:
        store = _notes_stores_by_path.get(path)
        if store is None:
            store = NotesStore(path=path)
            _notes_stores_by_path[path] = store

    with store.lock:
        store.state.available = False
        store.storage.clear()
        if path.is_symlink():
            _bind_legacy_note_store(store)
            logger.error("notes.json at %s is a symbolic link; refusing note mutations", path)
            return store
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            store.state.available = True
            _bind_legacy_note_store(store)
            return store
        except (OSError, json.JSONDecodeError):
            _bind_legacy_note_store(store)
            logger.exception("notes.json at %s is unreadable; refusing note mutations", path)
            return store
        hydrated = _validated_notes(data)
        if hydrated is None:
            _bind_legacy_note_store(store)
            logger.error("notes.json at %s is not an object; refusing note mutations", path)
            return store
        store.storage.update(hydrated)
        store.state.available = True
        _bind_legacy_note_store(store)
        logger.info("notes hydrated from %s (%d note(s))", path, len(store.storage))
        return store


def _bind_legacy_note_store(store: NotesStore) -> None:
    """Keep the old module-level accessors aligned for non-runtime callers."""
    global _notes_storage, _notes_lock, _notes_path, _notes_store_available  # noqa: PLW0603
    _notes_storage = store.storage
    _notes_lock = store.lock
    _notes_path = store.path
    _notes_store_available = store.available


def get_notes_store(state_dir: Path) -> NotesStore:
    """Return the already-hydrated scan store for binding into tool context."""
    path = state_dir / "notes.json"
    with _notes_stores_lock:
        store = _notes_stores_by_path.get(path)
    if store is None:
        store = hydrate_notes_from_disk(state_dir)
    return store


def _validated_notes(data: Any) -> dict[str, dict[str, Any]] | None:
    if not isinstance(data, dict):
        return None
    hydrated: dict[str, dict[str, Any]] = {}
    for note_id, note in data.items():
        if not isinstance(note_id, str) or not note_id or not isinstance(note, dict):
            return None
        if not isinstance(note.get("title"), str) or not isinstance(note.get("content"), str):
            return None
        category = note.get("category", "general")
        tags = note.get("tags", [])
        if (
            not isinstance(category, str)
            or category not in _VALID_NOTE_CATEGORIES
            or not isinstance(tags, list)
            or not all(isinstance(tag, str) for tag in tags)
        ):
            return None
        for key in ("created_at", "updated_at", "agent_id", "agent_name"):
            if key in note and not isinstance(note[key], str):
                return None
        hydrated[note_id] = note
    return hydrated


def _context_notes_store(ctx: RunContextWrapper) -> NotesStore | None:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    store = context.get("notes_store")
    return store if isinstance(store, NotesStore) else None


def _store_values(
    store: NotesStore | None,
) -> tuple[dict[str, dict[str, Any]], Any, bool]:
    if store is None:
        return _notes_storage, _notes_lock, _notes_store_available
    return store.storage, store.lock, store.available


def _persist_candidate(
    candidate: dict[str, dict[str, Any]], store: NotesStore | None = None
) -> bool:
    """Persist a complete snapshot before publishing it to in-memory readers."""
    path = _notes_path if store is None else store.path
    available = _notes_store_available if store is None else store.available
    storage = _notes_storage if store is None else store.storage
    if not available:
        return False
    if path is None:
        storage.clear()
        storage.update(candidate)
        return True
    if path.is_symlink():
        logger.error("notes.json at %s is a symbolic link; refusing note mutations", path)
        return False

    tmp_path: Path | None = None
    try:
        payload = json.dumps(candidate, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        tmp_path.replace(path)
        tmp_path = None
    except Exception:
        logger.exception("notes persist to %s failed", path)
        return False
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    storage.clear()
    storage.update(candidate)
    return True


def _generate_note_id(storage: dict[str, dict[str, Any]]) -> str | None:
    for _ in range(_NOTE_ID_GENERATION_ATTEMPTS):
        note_id = uuid.uuid4().hex[:6]
        if note_id not in storage:
            return note_id
    return None


def _mark_authorship(
    entry: dict[str, Any], note: dict[str, Any], caller_agent_id: str | None
) -> dict[str, Any]:
    """Attach the note's author and flag whether the caller wrote it."""
    agent_name = note.get("agent_name")
    if agent_name:
        entry["agent_name"] = agent_name
    agent_id = note.get("agent_id")
    if agent_id:
        entry["agent_id"] = agent_id
    if caller_agent_id is not None and agent_id == caller_agent_id:
        entry["by_you"] = True
    return entry


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
    storage: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    category = clean_optional(category)
    search_query = clean_optional(search_query)

    filtered: list[dict[str, Any]] = []
    for note_id, note in (_notes_storage if storage is None else storage).items():
        if category and note.get("category") != category:
            continue
        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue
        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            if not (title_match or content_match):
                continue
        entry = note.copy()
        entry["note_id"] = note_id
        filtered.append(entry)
    filtered.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return filtered


def _to_note_listing_entry(
    note: dict[str, Any],
    *,
    include_content: bool = False,
    caller_agent_id: str | None = None,
) -> dict[str, Any]:
    entry = {
        "note_id": note.get("note_id"),
        "title": note.get("title", ""),
        "category": note.get("category", "general"),
        "tags": note.get("tags", []),
        "created_at": note.get("created_at", ""),
        "updated_at": note.get("updated_at", ""),
    }
    content = str(note.get("content", ""))
    if include_content:
        entry["content"] = content
    elif content:
        if len(content) > _DEFAULT_CONTENT_PREVIEW_CHARS:
            entry["content_preview"] = f"{content[:_DEFAULT_CONTENT_PREVIEW_CHARS].rstrip()}..."
        else:
            entry["content_preview"] = content
    return _mark_authorship(entry, note, caller_agent_id)


def _create_note_impl(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    store: NotesStore | None = None,
) -> dict[str, Any]:
    storage, lock, available = _store_values(store)
    with lock:
        try:
            if not title or not title.strip():
                return {"success": False, "error": "Title cannot be empty", "note_id": None}
            if not content or not content.strip():
                return {"success": False, "error": "Content cannot be empty", "note_id": None}
            if category not in _VALID_NOTE_CATEGORIES:
                return {
                    "success": False,
                    "error": (
                        f"Invalid category. Must be one of: {', '.join(_VALID_NOTE_CATEGORIES)}"
                    ),
                    "note_id": None,
                }
            if not available:
                return {
                    "success": False,
                    "error": "Note changes could not be saved; no changes were applied",
                    "note_id": None,
                }

            candidate = deepcopy(storage)
            note_id = _generate_note_id(candidate)
            if note_id is None:
                return {
                    "success": False,
                    "error": "Failed to generate a unique note ID",
                    "note_id": None,
                }
            timestamp = datetime.now(UTC).isoformat()
            note: dict[str, Any] = {
                "title": title.strip(),
                "content": content.strip(),
                "category": category,
                "tags": list(tags or []),
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            if agent_id:
                note["agent_id"] = agent_id
            if agent_name:
                note["agent_name"] = agent_name
            candidate[note_id] = note
        except (ValueError, TypeError) as exc:
            return {"success": False, "error": f"Failed to create note: {exc}", "note_id": None}

        if not _persist_candidate(candidate, store):
            return {
                "success": False,
                "error": "Note changes could not be saved; no changes were applied",
                "note_id": None,
            }
        return {
            "success": True,
            "note_id": note_id,
            "message": f"Note '{title}' created successfully",
            "total_count": len(storage),
        }


def _list_notes_impl(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
    caller_agent_id: str | None = None,
    store: NotesStore | None = None,
) -> dict[str, Any]:
    storage, lock, _available = _store_values(store)
    with lock:
        try:
            filtered = _filter_notes(
                category=category, tags=tags, search_query=search, storage=storage
            )
            notes = [
                _to_note_listing_entry(
                    note, include_content=include_content, caller_agent_id=caller_agent_id
                )
                for note in filtered
            ]
        except (ValueError, TypeError) as exc:
            return {
                "success": False,
                "error": f"Failed to list notes: {exc}",
                "notes": [],
                "filtered_count": 0,
                "total_count": 0,
            }
        return {
            "success": True,
            "notes": notes,
            "filtered_count": len(notes),
            "total_count": len(storage),
        }


def _get_note_impl(
    note_id: str, caller_agent_id: str | None = None, store: NotesStore | None = None
) -> dict[str, Any]:
    storage, lock, _available = _store_values(store)
    with lock:
        try:
            if not note_id or not note_id.strip():
                return {"success": False, "error": "Note ID cannot be empty", "note": None}
            note = storage.get(note_id)
            if note is None:
                return {
                    "success": False,
                    "error": f"Note with ID '{note_id}' not found",
                    "note": None,
                }
            note_with_id = note.copy()
            note_with_id["note_id"] = note_id
            _mark_authorship(note_with_id, note, caller_agent_id)
        except (ValueError, TypeError) as exc:
            return {"success": False, "error": f"Failed to get note: {exc}", "note": None}
        else:
            return {"success": True, "note": note_with_id}


def _update_note_impl(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
    store: NotesStore | None = None,
) -> dict[str, Any]:
    storage, lock, available = _store_values(store)
    with lock:
        if note_id not in storage:
            return {"success": False, "error": f"Note with ID '{note_id}' not found"}
        if not available:
            return {
                "success": False,
                "error": "Note changes could not be saved; no changes were applied",
            }
        try:
            if title is not None and not title.strip():
                return {"success": False, "error": "Title cannot be empty"}
            if content is not None and not content.strip():
                return {"success": False, "error": "Content cannot be empty"}
            candidate = deepcopy(storage)
            note = candidate[note_id]
            if title is not None:
                note["title"] = title.strip()
            if content is not None:
                note["content"] = content.strip()
            if tags is not None:
                note["tags"] = list(tags)
            note["updated_at"] = datetime.now(UTC).isoformat()
        except (ValueError, TypeError) as exc:
            return {"success": False, "error": f"Failed to update note: {exc}"}

        if not _persist_candidate(candidate, store):
            return {
                "success": False,
                "error": "Note changes could not be saved; no changes were applied",
            }
        return {
            "success": True,
            "note_id": note_id,
            "message": f"Note '{storage[note_id]['title']}' updated successfully",
            "total_count": len(storage),
        }


def _delete_note_impl(note_id: str, store: NotesStore | None = None) -> dict[str, Any]:
    storage, lock, available = _store_values(store)
    with lock:
        note = storage.get(note_id)
        if note is None:
            return {"success": False, "error": f"Note with ID '{note_id}' not found"}
        if not available:
            return {
                "success": False,
                "error": "Note changes could not be saved; no changes were applied",
            }
        candidate = deepcopy(storage)
        note_title = str(candidate[note_id].get("title", ""))
        del candidate[note_id]
        if not _persist_candidate(candidate, store):
            return {
                "success": False,
                "error": "Note changes could not be saved; no changes were applied",
            }
        return {
            "success": True,
            "note_id": note_id,
            "message": f"Note '{note_title}' deleted successfully",
            "total_count": len(storage),
        }


@function_tool(timeout=30)
async def create_note(
    ctx: RunContextWrapper,
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> str:
    """Document an observation, finding, methodology step, or research note.

    Notes are visible to every agent in the same scan and persist in that
    scan's state directory. Each note records its author, so ``list_notes``
    and ``get_note`` show ``agent_name`` and flag your notes with ``by_you``.

    For actionable tasks, use ``todo`` instead. Categories are ``general``,
    ``findings``, ``methodology``, ``questions``, ``plan`` and ``wiki``.

    Args:
        title: Short headline.
        content: Full note body. Markdown is preserved.
        category: One of the supported categories. Defaults to ``general``.
        tags: Optional free-form tags for later filtering.
    """
    agent_id, agent_name = _caller_identity(ctx)
    return json.dumps(
        await asyncio.to_thread(
            _create_note_impl,
            title,
            content,
            category,
            tags,
            agent_id,
            agent_name,
            _context_notes_store(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_notes(
    ctx: RunContextWrapper,
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> str:
    """List notes with optional category, tag or text filters.

    Metadata-first results include a 280-character content preview. Set
    ``include_content=True`` to return full note bodies.

    Args:
        category: Optional category filter.
        tags: Match notes containing any of these tags.
        search: Case-insensitive substring search of title and content.
        include_content: Return the full content instead of a preview.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await asyncio.to_thread(
            _list_notes_impl,
            category=category,
            tags=tags,
            search=search,
            include_content=include_content,
            caller_agent_id=caller_agent_id,
            store=_context_notes_store(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Fetch one note by its six-character ID and return its full content."""
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await asyncio.to_thread(
            _get_note_impl, note_id, caller_agent_id, _context_notes_store(ctx)
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_note(
    ctx: RunContextWrapper,
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Update a note's title, content or tags; content is a full replacement.

    Args:
        note_id: Target note's six-character ID.
        title: New title, or ``None`` to keep the current title.
        content: Replacement content, or ``None`` to keep the current body.
        tags: Replacement tag list, or ``None`` to keep current tags.
    """
    return json.dumps(
        await asyncio.to_thread(
            _update_note_impl,
            note_id=note_id,
            title=title,
            content=content,
            tags=tags,
            store=_context_notes_store(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def delete_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Delete a note by its six-character ID."""
    return json.dumps(
        await asyncio.to_thread(_delete_note_impl, note_id, _context_notes_store(ctx)),
        ensure_ascii=False,
        default=str,
    )
