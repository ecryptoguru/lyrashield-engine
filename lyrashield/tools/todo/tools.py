"""Per-agent todo tools — mirrored to {state_dir}/todos.json."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


VALID_PRIORITIES = ["low", "normal", "high", "critical"]
VALID_STATUSES = ["pending", "in_progress", "done"]

_PRIORITY_RANK = {"critical": 0, "high": 1, "normal": 2, "low": 3}
_STATUS_RANK = {"done": 0, "in_progress": 1, "pending": 2}


def _todo_sort_key(todo: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _STATUS_RANK.get(todo.get("status", "pending"), 99),
        _PRIORITY_RANK.get(todo.get("priority", "normal"), 99),
        todo.get("created_at", ""),
    )


_todos_storage: dict[str, dict[str, dict[str, Any]]] = {}

_todos_path: Path | None = None
_todos_io_lock = threading.RLock()
_todos_store_available = True


def hydrate_todos_from_disk(state_dir: Path) -> None:
    global _todos_path, _todos_store_available  # noqa: PLW0603
    with _todos_io_lock:
        _todos_path = state_dir / "todos.json"
        _todos_storage.clear()
        _todos_store_available = False
        try:
            data = json.loads(_todos_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            _todos_store_available = True
            return
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "todos.json at %s is unreadable; refusing todo mutations",
                _todos_path,
            )
            return
        if not isinstance(data, dict):
            _todos_store_available = False
            logger.error("todos.json at %s is not an object; refusing todo mutations", _todos_path)
            return
        hydrated: dict[str, dict[str, dict[str, Any]]] = {}
        for aid, by_id in data.items():
            if not isinstance(aid, str) or not aid or not isinstance(by_id, dict):
                logger.error(
                    "todos.json at %s has a malformed agent record; refusing mutations",
                    _todos_path,
                )
                return
            cleaned: dict[str, dict[str, Any]] = {}
            for tid, todo in by_id.items():
                if (
                    not isinstance(tid, str)
                    or not tid
                    or not isinstance(todo, dict)
                    or not isinstance(todo.get("title"), str)
                    or not todo["title"].strip()
                ):
                    logger.error(
                        "todos.json at %s has a malformed todo record; refusing mutations",
                        _todos_path,
                    )
                    return
                priority = todo.get("priority", "normal")
                status = todo.get("status", "pending")
                description = todo.get("description")
                if (
                    not isinstance(priority, str)
                    or priority not in VALID_PRIORITIES
                    or not isinstance(status, str)
                    or status not in VALID_STATUSES
                    or (description is not None and not isinstance(description, str))
                ):
                    logger.error(
                        "todos.json at %s has invalid todo fields; refusing mutations",
                        _todos_path,
                    )
                    return
                for field_name in ("created_at", "updated_at"):
                    if field_name in todo and not isinstance(todo[field_name], str):
                        logger.error(
                            "todos.json at %s has malformed timestamps; refusing mutations",
                            _todos_path,
                        )
                        return
                completed_at = todo.get("completed_at")
                if completed_at is not None and not isinstance(completed_at, str):
                    logger.error(
                        "todos.json at %s has malformed completion timestamp; refusing mutations",
                        _todos_path,
                    )
                    return
                cleaned[tid] = todo
            hydrated[aid] = cleaned
        _todos_storage.clear()
        _todos_storage.update(hydrated)
        _todos_store_available = True
        logger.info(
            "todos hydrated from %s (%d agent(s), %d todo(s))",
            _todos_path,
            len(_todos_storage),
            sum(len(todos) for todos in _todos_storage.values()),
        )


def _persist(storage: dict[str, dict[str, dict[str, Any]]] | None = None) -> bool:
    path = _todos_path
    if path is None:
        return True
    if not _todos_store_available:
        return False
    tmp_path: Path | None = None
    try:
        payload = json.dumps(
            storage if storage is not None else _todos_storage, ensure_ascii=False, default=str
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _todos_io_lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp_path = Path(tmp.name)
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        tmp_path.replace(path)
        tmp_path = None
    except Exception:
        logger.exception("todos persist to %s failed", path)
        return False
    else:
        return True
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _persist_candidate(candidate: dict[str, dict[str, dict[str, Any]]]) -> bool:
    """Persist a complete candidate snapshot before exposing it in memory."""
    with _todos_io_lock:
        if not _persist(candidate):
            return False
        _todos_storage.clear()
        _todos_storage.update(candidate)
        return True


def _store_error() -> str:
    return json.dumps(
        {"success": False, "error": "Todo changes could not be saved; no changes were applied"},
        ensure_ascii=False,
        default=str,
    )


def _agent_id_from(ctx: RunContextWrapper) -> str:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return str(inner.get("agent_id") or "default")


def _get_agent_todos(agent_id: str) -> dict[str, dict[str, Any]]:
    return _todos_storage.get(agent_id, {})


def _normalize_priority(priority: str | None, default: str = "normal") -> str:
    candidate = (priority or default or "normal").lower()
    if candidate not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Must be one of: {', '.join(VALID_PRIORITIES)}")
    return candidate


def _sorted_todos(agent_id: str) -> list[dict[str, Any]]:
    todos_list = [
        {**todo, "todo_id": todo_id} for todo_id, todo in _get_agent_todos(agent_id).items()
    ]
    todos_list.sort(key=_todo_sort_key)
    return todos_list


def _normalize_todo_ids(raw_ids: Any) -> list[str]:
    if raw_ids is None:
        return []
    if isinstance(raw_ids, str):
        stripped = raw_ids.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = stripped.split(",") if "," in stripped else [stripped]
        if isinstance(data, list):
            return [str(item).strip() for item in data if str(item).strip()]
        return [str(data).strip()]
    if isinstance(raw_ids, list):
        return [str(item).strip() for item in raw_ids if str(item).strip()]
    return [str(raw_ids).strip()]


def _normalize_bulk_updates(raw_updates: Any) -> list[dict[str, Any]]:
    if raw_updates is None:
        return []
    data: Any = raw_updates
    if isinstance(raw_updates, str):
        stripped = raw_updates.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError("Updates must be valid JSON") from e

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise TypeError("Updates must be a list of update objects")

    normalized: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise TypeError("Each update must be an object with todo_id")
        todo_id = item.get("todo_id") or item.get("id")
        if not todo_id:
            raise ValueError("Each update must include 'todo_id'")
        normalized.append(
            {
                "todo_id": str(todo_id).strip(),
                "title": item.get("title"),
                "description": item.get("description"),
                "priority": item.get("priority"),
                "status": item.get("status"),
            },
        )
    return normalized


def _normalize_bulk_todos(raw_todos: Any) -> list[dict[str, Any]]:
    if raw_todos is None:
        return []
    data: Any = raw_todos
    if isinstance(raw_todos, str):
        stripped = raw_todos.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            entries = [line.strip(" -*\t") for line in stripped.splitlines() if line.strip(" -*\t")]
            return [{"title": entry} for entry in entries]

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise TypeError("Todos must be provided as a list, dict, or JSON string")

    normalized: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, str):
            title = item.strip()
            if title:
                normalized.append({"title": title})
            continue
        if not isinstance(item, dict):
            raise TypeError("Each todo entry must be a string or object with a title")
        title = item.get("title", "")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Each todo entry must include a non-empty 'title'")
        normalized.append(
            {
                "title": title.strip(),
                "description": (item.get("description") or "").strip() or None,
                "priority": item.get("priority"),
            },
        )
    return normalized


def _apply_single_update(  # noqa: PLR0912 - validate before mutating any candidate fields.
    agent_todos: dict[str, dict[str, Any]],
    todo_id: str,
    title: Any = None,
    description: Any = None,
    priority: Any = None,
    status: Any = None,
) -> dict[str, Any] | None:
    if todo_id not in agent_todos:
        return {"todo_id": todo_id, "error": f"Todo with ID '{todo_id}' not found"}
    todo = agent_todos[todo_id]
    if title is not None:
        if not isinstance(title, str):
            return {"todo_id": todo_id, "error": "Title must be a string"}
        if not title.strip():
            return {"todo_id": todo_id, "error": "Title cannot be empty"}
    if description is not None and not isinstance(description, str):
        return {"todo_id": todo_id, "error": "Description must be a string"}

    normalized_priority: str | None = None
    if priority is not None:
        if not isinstance(priority, str):
            return {"todo_id": todo_id, "error": "Priority must be a string"}
        try:
            normalized_priority = _normalize_priority(priority, str(todo.get("priority", "normal")))
        except ValueError as exc:
            return {"todo_id": todo_id, "error": str(exc)}

    normalized_status: str | None = None
    if status is not None:
        if not isinstance(status, str):
            return {"todo_id": todo_id, "error": "Status must be a string"}
        status_candidate = status.lower()
        if status_candidate not in VALID_STATUSES:
            return {
                "todo_id": todo_id,
                "error": f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
            }
        normalized_status = status_candidate

    if title is not None:
        todo["title"] = title.strip()
    if description is not None:
        todo["description"] = description.strip() if description else None
    if normalized_priority is not None:
        todo["priority"] = normalized_priority
    if normalized_status is not None:
        todo["status"] = normalized_status
        todo["completed_at"] = (
            datetime.now(UTC).isoformat() if normalized_status == "done" else None
        )
    todo["updated_at"] = datetime.now(UTC).isoformat()
    return None


@function_tool(timeout=30)
async def create_todo(ctx: RunContextWrapper, todos: str) -> str:
    """Create one or many todos for the current agent.

    Always pass a list, even for a single todo (wrap it in a one-item array).

    Each agent (including subagents) has its **own private todo list** —
    your todos don't leak to other agents and vice versa.

    When to use:

    - Planning multi-step assessments with parallel workstreams.
    - Tracking work you'll come back to later.
    - Breaking down complex scopes (per-endpoint, per-target, per-vuln-class).

    When NOT to use:

    - Simple linear workflows where progress is obvious.
    - Single quick task — just do it.

    Args:
        todos: JSON array of todo objects. For one todo, pass a one-item
            list. Each object's fields:

            - ``title`` (str, **required**): short actionable title,
              e.g. ``"Test /api/admin for IDOR"``.
            - ``description`` (str, optional): extra context or
              acceptance criteria.
            - ``priority`` (str, optional): one of ``"low"`` /
              ``"normal"`` / ``"high"`` / ``"critical"``. Defaults to
              ``"normal"``.

            Example: ``[{"title": "Probe /admin", "priority": "high"},
            {"title": "Check JWT alg=none"}]``.
    """
    agent_id = _agent_id_from(ctx)
    if not _todos_store_available:
        return _store_error()
    try:
        tasks = _normalize_bulk_todos(todos)
        if not tasks:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'todos' list to create"},
                ensure_ascii=False,
                default=str,
            )

        with _todos_io_lock:
            candidate = deepcopy(_todos_storage)
            agent_todos = candidate.setdefault(agent_id, {})
            created: list[dict[str, Any]] = []
            for task in tasks:
                task_priority = _normalize_priority(task.get("priority"))
                todo_id = str(uuid.uuid4())[:6]
                timestamp = datetime.now(UTC).isoformat()
                agent_todos[todo_id] = {
                    "title": task["title"],
                    "description": task.get("description"),
                    "priority": task_priority,
                    "status": "pending",
                    "created_at": timestamp,
                    "updated_at": timestamp,
                    "completed_at": None,
                }
                created.append(
                    {"todo_id": todo_id, "title": task["title"], "priority": task_priority}
                )
            if not _persist_candidate(candidate):
                return _store_error()
    except (ValueError, TypeError) as e:
        return json.dumps(
            {"success": False, "error": f"Failed to create todo: {e}"},
            ensure_ascii=False,
            default=str,
        )

    return json.dumps(
        {
            "success": True,
            "created": created,
            "created_count": len(created),
            "todos": sorted(
                ({**todo, "todo_id": todo_id} for todo_id, todo in agent_todos.items()),
                key=_todo_sort_key,
            ),
            "total_count": len(agent_todos),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_todos(
    ctx: RunContextWrapper,
    status: str | None = None,
    priority: str | None = None,
) -> str:
    """List the current agent's todos, sorted by status then priority.

    Sort order: status (done → in_progress → pending), then priority
    within each status (critical → high → normal → low).

    Args:
        status: Filter — ``"pending"`` / ``"in_progress"`` / ``"done"``.
        priority: Filter — ``"low"`` / ``"normal"`` / ``"high"`` /
            ``"critical"``.
    """
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        status_filter = status.lower() if isinstance(status, str) else None
        priority_filter = priority.lower() if isinstance(priority, str) else None

        todos_list: list[dict[str, Any]] = []
        for todo_id, todo in agent_todos.items():
            if status_filter and todo.get("status") != status_filter:
                continue
            if priority_filter and todo.get("priority") != priority_filter:
                continue
            entry = todo.copy()
            entry["todo_id"] = todo_id
            todos_list.append(entry)

        todos_list.sort(key=_todo_sort_key)

        summary: dict[str, int] = {"pending": 0, "in_progress": 0, "done": 0}
        for todo in todos_list:
            sv = todo.get("status", "pending")
            summary[sv] = summary.get(sv, 0) + 1
    except (ValueError, TypeError) as e:
        return json.dumps(
            {
                "success": False,
                "error": f"Failed to list todos: {e}",
                "todos": [],
                "filtered_count": 0,
                "total_count": 0,
                "summary": {"pending": 0, "in_progress": 0, "done": 0},
            },
            ensure_ascii=False,
            default=str,
        )

    return json.dumps(
        {
            "success": True,
            "todos": todos_list,
            "filtered_count": len(todos_list),
            "total_count": len(agent_todos),
            "summary": summary,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_todo(ctx: RunContextWrapper, updates: str) -> str:
    """Update one or many todos.

    Always pass a list, even for a single update (wrap it in a one-item
    array).

    For toggling status only, prefer the dedicated ``mark_todo_done`` /
    ``mark_todo_pending`` tools — they're simpler and accept the same
    list-of-ids form.

    Args:
        updates: JSON array of update objects. For one update, pass a
            one-item list. Each object's fields:

            - ``todo_id`` (str, **required**): ID returned by
              ``create_todo``.
            - ``title`` (str, optional): new title.
            - ``description`` (str, optional): new description (empty
              string clears it).
            - ``priority`` (str, optional): one of ``"low"`` /
              ``"normal"`` / ``"high"`` / ``"critical"``.
            - ``status`` (str, optional): one of ``"pending"`` /
              ``"in_progress"`` / ``"done"``.

            Omitted fields stay unchanged. Example:
            ``[{"todo_id": "abc", "status": "in_progress",
            "priority": "high"}]``.
    """
    agent_id = _agent_id_from(ctx)
    if not _todos_store_available:
        return _store_error()
    try:
        updates_to_apply = _normalize_bulk_updates(updates)
        if not updates_to_apply:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'updates' list"},
                ensure_ascii=False,
                default=str,
            )

        with _todos_io_lock:
            candidate = deepcopy(_todos_storage)
            agent_todos = candidate.setdefault(agent_id, {})
            updated: list[str] = []
            errors: list[dict[str, Any]] = []
            for upd in updates_to_apply:
                err = _apply_single_update(
                    agent_todos,
                    upd["todo_id"],
                    upd.get("title"),
                    upd.get("description"),
                    upd.get("priority"),
                    upd.get("status"),
                )
                if err:
                    errors.append(err)
                else:
                    updated.append(upd["todo_id"])
            if errors:
                summary = "; ".join(str(item["error"]) for item in errors)
                return json.dumps(
                    {
                        "success": False,
                        "error": summary,
                        "updated": [],
                        "updated_count": 0,
                        "todos": _sorted_todos(agent_id),
                        "total_count": len(_get_agent_todos(agent_id)),
                        "errors": errors,
                    },
                    ensure_ascii=False,
                    default=str,
                )
            if updated and not _persist_candidate(candidate):
                return _store_error()
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "updated": updated,
        "updated_count": len(updated),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)


def _mark(*, agent_id: str, todo_ids: str, new_status: str) -> str:
    if not _todos_store_available:
        return _store_error()
    try:
        ids = _normalize_todo_ids(todo_ids)
        if not ids:
            msg = f"Provide a non-empty 'todo_ids' list to mark as {new_status}"
            return json.dumps({"success": False, "error": msg}, ensure_ascii=False, default=str)

        with _todos_io_lock:
            agent_todos = _get_agent_todos(agent_id)
            unique_ids = list(dict.fromkeys(ids))
            errors = [
                {"todo_id": tid, "error": f"Todo with ID '{tid}' not found"}
                for tid in unique_ids
                if tid not in agent_todos
            ]
            if errors:
                return json.dumps(
                    {
                        "success": False,
                        "marked": [],
                        "marked_count": 0,
                        "new_status": new_status,
                        "todos": _sorted_todos(agent_id),
                        "total_count": len(agent_todos),
                        "errors": errors,
                    },
                    ensure_ascii=False,
                    default=str,
                )
            candidate = deepcopy(_todos_storage)
            candidate_agent_todos = candidate[agent_id]
            timestamp = datetime.now(UTC).isoformat()
            for tid in unique_ids:
                todo = candidate_agent_todos[tid]
                todo["status"] = new_status
                todo["completed_at"] = timestamp if new_status == "done" else None
                todo["updated_at"] = timestamp
            marked = unique_ids
            agent_todos = candidate_agent_todos
            if marked and not _persist_candidate(candidate):
                return _store_error()
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "marked": marked,
        "marked_count": len(marked),
        "new_status": new_status,
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def mark_todo_done(ctx: RunContextWrapper, todo_ids: str) -> str:
    """Mark one or many todos as done.

    Always pass a list, even for a single ID (wrap it in a one-item array).

    Args:
        todo_ids: JSON array of todo IDs to mark done. For one todo,
            pass a one-item list.
    """
    return _mark(agent_id=_agent_id_from(ctx), todo_ids=todo_ids, new_status="done")


@function_tool(timeout=30)
async def mark_todo_pending(ctx: RunContextWrapper, todo_ids: str) -> str:
    """Reset one or many todos to pending (e.g., to retry a failed task).

    Always pass a list, even for a single ID (wrap it in a one-item array).

    Args:
        todo_ids: JSON array of todo IDs to reset to pending. For one
            todo, pass a one-item list.
    """
    return _mark(agent_id=_agent_id_from(ctx), todo_ids=todo_ids, new_status="pending")


@function_tool(timeout=30)
async def delete_todo(ctx: RunContextWrapper, todo_ids: str) -> str:
    """Delete one or many todos. Removes them entirely (no soft-delete).

    Always pass a list, even for a single ID (wrap it in a one-item array).

    Args:
        todo_ids: JSON array of todo IDs to delete. For one todo, pass
            a one-item list.
    """
    agent_id = _agent_id_from(ctx)
    if not _todos_store_available:
        return _store_error()
    try:
        ids = _normalize_todo_ids(todo_ids)
        if not ids:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'todo_ids' list to delete"},
                ensure_ascii=False,
                default=str,
            )

        with _todos_io_lock:
            agent_todos = _get_agent_todos(agent_id)
            unique_ids = list(dict.fromkeys(ids))
            errors = [
                {"todo_id": tid, "error": f"Todo with ID '{tid}' not found"}
                for tid in unique_ids
                if tid not in agent_todos
            ]
            if errors:
                return json.dumps(
                    {
                        "success": False,
                        "deleted": [],
                        "deleted_count": 0,
                        "todos": _sorted_todos(agent_id),
                        "total_count": len(agent_todos),
                        "errors": errors,
                    },
                    ensure_ascii=False,
                    default=str,
                )
            candidate = deepcopy(_todos_storage)
            candidate_agent_todos = candidate[agent_id]
            for tid in unique_ids:
                del candidate_agent_todos[tid]
            deleted = unique_ids
            agent_todos = candidate_agent_todos
            if deleted and not _persist_candidate(candidate):
                return _store_error()
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "deleted": deleted,
        "deleted_count": len(deleted),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)
