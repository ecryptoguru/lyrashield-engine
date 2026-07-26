"""Pure input builders for Strix scan runs."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any, cast

from agents.model_settings import ModelSettings
from openai.types.shared import Reasoning

from strix.config.models import (
    DEFAULT_MODEL_RETRY,
    is_gpt56_model,
    is_known_openai_bare_model,
    model_supports_reasoning,
    request_timeout_extra_args,
)
from strix.core.sessions import scrub_images_from_items


if TYPE_CHECKING:
    from strix.config.settings import ReasoningEffort


DEFAULT_MAX_TURNS = 500
MAX_CHILD_INHERITED_HISTORY_BYTES = 24 * 1024

# Opt-in/opt-out for explicit prompt-cache breakpoints. "auto" (default) enables
# breakpoints for known GPT-5.6 deployments; "1"/"true" forces them on; "0"/"false"
# forces them off. Provider support should be confirmed with a smoke scan.
_PROMPT_CACHE_BREAKPOINT_ENV = "LYRASHIELD_PROMPT_CACHE_BREAKPOINTS"


def _prompt_cache_breakpoints_enabled(model_name: str | None) -> bool:
    """Return whether the model/provider pair should emit explicit cache breakpoints.

    Defaults to the known GPT-5.6 allowlist (OpenAI/Azure AI) and can be overridden
    with ``LYRASHIELD_PROMPT_CACHE_BREAKPOINTS``.
    """
    env = os.environ.get(_PROMPT_CACHE_BREAKPOINT_ENV, "").strip().lower()
    if env in ("1", "true", "yes"):
        return True
    if env in ("0", "false", "no"):
        return False
    return is_gpt56_model(model_name)


def _accepts_required_tool_choice(model_name: str | None) -> bool:
    name = (model_name or "").strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.startswith("openai/") or is_known_openai_bare_model(name)


def _supports_parallel_tool_calls_setting(model_name: str | None) -> bool:
    """Return whether the routed provider accepts ``parallel_tool_calls``.

    The Azure AI GPT-5.6 Chat Completions route rejects the parameter itself,
    including the value ``false``, with HTTP 400. Omitting it keeps the request
    compatible; LyraShield's turn, agent, concurrency, and spend limits remain
    enforced independently of this provider hint.
    """
    name = (model_name or "").strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return not name.startswith("azure_ai/gpt-5.6-")


def _as_str_dict(value: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _as_str_list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[Any] = cast("list[Any]", value)
    return [cast("dict[str, Any]", item) for item in items if isinstance(item, dict)]


def _build_root_task_parts(scan_config: dict[str, Any]) -> tuple[list[str], str]:
    """Return the raw task parts and any user instructions separately."""
    targets = _as_str_list_of_dicts(scan_config.get("targets", []))
    diff_scope = _as_str_dict(scan_config.get("diff_scope"))
    user_instructions = scan_config.get("user_instructions", "") or ""

    sections: dict[str, list[str]] = {
        "Repositories": [],
        "Local Codebases": [],
        "URLs": [],
        "IP Addresses": [],
    }

    for target in targets:
        ttype = str(target.get("type") or "")
        details = _as_str_dict(target.get("details"))
        workspace_subdir_raw = details.get("workspace_subdir")
        workspace_subdir = workspace_subdir_raw if isinstance(workspace_subdir_raw, str) else None
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype == "repository":
            url = str(details.get("target_repo") or "")
            cloned_raw = details.get("cloned_repo_path")
            cloned = cloned_raw if isinstance(cloned_raw, str) else None
            sections["Repositories"].append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = str(details.get("target_path") or "unknown")
            suffix = ", read-only mount" if details.get("mount") else ""
            sections["Local Codebases"].append(f"- {path} (available at: {workspace_path}{suffix})")
        elif ttype == "web_application":
            sections["URLs"].append(f"- {(details.get('target_url') or '')!s}")
        elif ttype == "ip_address":
            sections["IP Addresses"].append(f"- {(details.get('target_ip') or '')!s}")

    parts: list[str] = []
    for label, items in sections.items():
        if items:
            parts.append(f"\n\n{label}:")
            parts.extend(items)

    if diff_scope.get("active"):
        parts.append("\n\nScope Constraints:")
        parts.append(
            "- Pull request diff-scope mode is active. Prioritize changed files "
            "and use other files only for context.",
        )
        for repo_scope in _as_str_list_of_dicts(diff_scope.get("repos")):
            label = str(
                repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
            )
            changed = int(repo_scope.get("analyzable_files_count") or 0)
            deleted = int(repo_scope.get("deleted_files_count") or 0)
            parts.append(f"- {label}: {changed} changed file(s) in primary scope")
            if deleted:
                parts.append(f"- {label}: {deleted} deleted file(s) are context-only")

    return parts, user_instructions


def build_root_task(scan_config: dict[str, Any]) -> str:
    """Return the root task as a single string, used for metadata and tests."""
    parts, user_instructions = _build_root_task_parts(scan_config)
    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"
    return task


def build_root_initial_input(
    scan_config: dict[str, Any],
    model_name: str | None = None,
) -> str | list[dict[str, Any]]:
    """Return the root agent's first user message.

    For models that support explicit prompt-cache breakpoints, split the stable
    target/scope prefix from the variable per-scan instructions and mark the
    boundary. This lets the provider cache the prefix across turns.
    """
    parts, user_instructions = _build_root_task_parts(scan_config)
    stable = " ".join(parts).strip()

    if not _prompt_cache_breakpoints_enabled(model_name) or not user_instructions:
        # No breakpoint needed when there is no variable suffix to separate.
        return build_root_task(scan_config)

    variable = f"Special instructions: {user_instructions}"
    if not stable:
        return build_root_task(scan_config)

    content: list[dict[str, Any]] = [
        {
            "type": "input_text",
            "text": stable,
            "prompt_cache_breakpoint": {"mode": "explicit"},
        },
        {"type": "input_text", "text": variable},
    ]
    return [{"role": "user", "content": content}]


def build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    authorized: list[dict[str, str]] = []
    value_keys = {
        "repository": "target_repo",
        "local_code": "target_path",
        "web_application": "target_url",
        "ip_address": "target_ip",
    }
    for target in _as_str_list_of_dicts(scan_config.get("targets", [])):
        ttype = str(target.get("type") or "unknown")
        details = _as_str_dict(target.get("details"))
        key = value_keys.get(ttype)
        raw_value = details.get(key, "") if key is not None else target.get("original", "")
        value = str(raw_value or "")

        workspace_subdir_raw = details.get("workspace_subdir")
        workspace_subdir = workspace_subdir_raw if isinstance(workspace_subdir_raw, str) else ""
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )

    return {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
    }


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    model_name: str,
    force_required_tool_choice: bool = False,
    request_timeout: float | None = None,
    max_output_tokens: int | None = None,
    prompt_cache_key: str | None = None,
    prompt_cache_breakpoints: bool = False,
) -> ModelSettings:
    extra_args: dict[str, Any] = request_timeout_extra_args(request_timeout) or {}
    if prompt_cache_key:
        extra_args["prompt_cache_key"] = prompt_cache_key
    model_settings = ModelSettings(
        parallel_tool_calls=(False if _supports_parallel_tool_calls_setting(model_name) else None),
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        max_tokens=max_output_tokens,
        extra_args=extra_args or None,
        prompt_cache_options=(
            {"mode": "explicit", "ttl": "30m"} if prompt_cache_breakpoints else None
        ),
    )
    if (
        reasoning_effort is not None
        and reasoning_effort != "none"
        and model_supports_reasoning(model_name)
    ):
        model_settings = model_settings.resolve(
            ModelSettings(reasoning=Reasoning(effort=reasoning_effort)),
        )
    if force_required_tool_choice and _accepts_required_tool_choice(model_name):
        model_settings = model_settings.resolve(ModelSettings(tool_choice="required"))
    return model_settings


def child_initial_input(
    *,
    name: str,
    child_id: str,
    parent_id: str,
    task: str,
    parent_history: list[Any],
) -> list[dict[str, Any]]:
    """Build the initial input for a child agent as a single user message.

    Collapsing the inherited-context block, the identity line, and the task into
    one ``{"role": "user"}`` message keeps providers that require strictly
    alternating roles from rejecting consecutive user messages.
    """
    parts: list[str] = []
    if parent_history:
        rendered = json.dumps(
            scrub_images_from_items(parent_history),
            ensure_ascii=False,
            default=str,
        )
        encoded = rendered.encode("utf-8")
        if len(encoded) > MAX_CHILD_INHERITED_HISTORY_BYTES:
            # ponytail: bounded handoff; large evidence stays in sandbox artifacts.
            rendered = encoded[-MAX_CHILD_INHERITED_HISTORY_BYTES:].decode("utf-8", errors="ignore")
            rendered = (
                "[Earlier parent history omitted; inspect referenced artifacts as needed.]\n"
                + rendered
            )
        parts.append(
            "== Inherited context from parent (background only) ==\n"
            f"{rendered}\n"
            "== End of inherited context ==\n"
            "Use the above as background only; do not continue the "
            "parent's work. Your task follows.",
        )
    parts.append(
        f"You are agent {name} ({child_id}); your parent is {parent_id}. "
        "Maintain your own identity. Call agent_finish when your task "
        "is complete.",
    )
    parts.append(task)
    return [{"role": "user", "content": "\n\n".join(parts)}]
