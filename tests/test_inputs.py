"""Tests for pure input builders in lyrashield.lifecycle.inputs."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import pytest

from lyrashield.lifecycle.inputs import (
    build_root_initial_input,
    build_root_task,
    child_initial_input,
    make_model_settings,
    prompt_cache_options_for_model,
    prompt_cache_routing_enabled,
)
from strix.core.inputs import build_scan_targets


def _child_kwargs(parent_history: list[Any]) -> dict[str, Any]:
    return {
        "name": "scout",
        "child_id": "agent-2",
        "parent_id": "agent-1",
        "task": "Audit the login flow.",
        "parent_history": parent_history,
    }


def test_child_initial_input_single_message_without_history() -> None:
    result = child_initial_input(**_child_kwargs([]))

    assert len(result) == 1
    assert result[0]["role"] == "user"
    content = result[0]["content"]
    assert "agent scout (agent-2)" in content
    assert "Audit the login flow." in content
    assert "Inherited context" not in content


def test_child_initial_input_single_message_with_history() -> None:
    history = [{"role": "assistant", "content": "previous work"}]
    result = child_initial_input(**_child_kwargs(history))

    assert len(result) == 1
    assert result[0]["role"] == "user"
    content = result[0]["content"]
    assert "Inherited context from parent" in content
    assert "previous work" in content
    assert "agent scout (agent-2)" in content
    assert "Audit the login flow." in content


def test_child_initial_input_marks_the_stable_prefix_for_explicit_gpt6_cache(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", "1")

    result = child_initial_input(
        **_child_kwargs([{"role": "assistant", "content": "previous work"}]),
        model_name="azure_ai/gpt-6-luna",
    )

    content = result[0]["content"]
    assert isinstance(content, list)
    assert content[0]["prompt_cache_breakpoint"] == {"mode": "explicit"}
    assert "Inherited context from parent" in content[0]["text"]
    assert "Audit the login flow." in content[1]["text"]


def test_gpt6_routing_only_preserves_implicit_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    monkeypatch.delenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", raising=False)

    assert prompt_cache_routing_enabled("azure/gpt-6-luna") is True
    assert prompt_cache_options_for_model("azure/gpt-6-luna") is None
    assert isinstance(
        build_root_initial_input(
            {"targets": [{"type": "REPOSITORY", "value": "owner/repo"}]},
            "azure/gpt-6-luna",
        ),
        str,
    )


def test_gpt6_routing_only_keeps_child_input_flat(monkeypatch: pytest.MonkeyPatch) -> None:
    # Routing alone must not split the delegate message: content breakpoints
    # belong to the explicit mode only.
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    monkeypatch.delenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", raising=False)

    result = child_initial_input(**_child_kwargs([]), model_name="azure_ai/gpt-6-luna")

    assert isinstance(result[0]["content"], str)


def test_gpt6_routing_and_explicit_are_independent_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", "1")

    assert prompt_cache_routing_enabled("azure_ai/gpt-6-luna") is True
    assert prompt_cache_options_for_model("azure_ai/gpt-6-luna") == {
        "mode": "explicit",
        "ttl": "30m",
    }


@pytest.mark.parametrize("request_phase", ["normal", "resume", "post_compaction"])
def test_gpt6_cache_settings_serialize_at_sdk_boundary(request_phase: str) -> None:
    """Every request phase reuses these SDK settings, not a hand-built payload."""
    settings = make_model_settings(
        None,
        model_name="azure_ai/gpt-6-luna",
        prompt_cache_key=f"lyrashield:v2:coordinator:{request_phase}",
        prompt_cache_options={"mode": "explicit", "ttl": "30m"},
    )

    wire = settings.to_json_dict()

    assert wire["extra_args"] == {"prompt_cache_key": f"lyrashield:v2:coordinator:{request_phase}"}
    assert wire["prompt_cache_options"] == {"mode": "explicit", "ttl": "30m"}


@pytest.mark.parametrize(
    "model_name",
    ["anthropic/claude-sonnet-4-5", "bedrock/anthropic.claude-opus-4-8"],
)
def test_rejected_provider_models_do_not_receive_legacy_cache_injection(
    model_name: str,
) -> None:
    settings = make_model_settings(None, model_name=model_name)
    assert not (settings.extra_args or {}).get("cache_control_injection_points")


@pytest.mark.parametrize(
    "model_name",
    ["openai/gpt-4o", "azure_ai/gpt-5.5-luna", None],
)
def test_unsupported_models_get_no_gpt6_cache_features(
    model_name: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_ROUTING", "1")
    monkeypatch.setenv("LYRASHIELD_PROMPT_CACHE_EXPLICIT", "1")

    assert prompt_cache_routing_enabled(model_name) is False
    assert prompt_cache_options_for_model(model_name) is None


@pytest.mark.parametrize(
    "parent_history",
    [[], [{"role": "assistant", "content": "previous work"}]],
)
def test_child_initial_input_no_consecutive_same_role(parent_history: list[Any]) -> None:
    result = child_initial_input(**_child_kwargs(parent_history))

    roles = [msg["role"] for msg in result]
    assert all(prev != nxt for prev, nxt in pairwise(roles))


@pytest.mark.parametrize("model_name", ["gpt-5", "openai/o3"])
def test_make_model_settings_adds_no_provider_specific_cache_fields(model_name: str) -> None:
    assert make_model_settings(None, model_name=model_name).extra_args is None


def test_max_reasoning_effort_sent_as_raw_body_field() -> None:
    # "max" is absent from the OpenAI SDK's Reasoning enum, so it has to ride
    # along as a raw body field to reach an approved GPT-6 deployment even
    # when LiteLLM's bundled metadata predates that model family.
    settings = make_model_settings("max", model_name="azure_ai/gpt-6-sol", request_timeout=30)
    assert settings.reasoning is None
    assert settings.extra_args == {"timeout": 30}
    assert settings.extra_body == {"reasoning_effort": "max"}


def test_build_root_task_empty_config() -> None:
    assert build_root_task({}) == ""


def test_build_root_task_repository_target() -> None:
    config = {
        "targets": [
            {
                "type": "repository",
                "details": {
                    "target_repo": "https://example.com/repo.git",
                    "cloned_repo_path": "/workspace/repo",
                    "workspace_subdir": "repo",
                },
            },
        ],
    }
    task = build_root_task(config)

    assert "Repositories:" in task
    assert "/workspace/repo" in task
    assert "https://example.com/repo.git" in task


def test_build_root_task_web_application_with_instructions() -> None:
    config = {
        "targets": [
            {"type": "web_application", "details": {"target_url": "https://app.example.com"}},
        ],
        "user_instructions": "Focus on auth.",
    }
    task = build_root_task(config)

    assert "URLs:" in task
    assert "https://app.example.com" in task
    assert "Special instructions: Focus on auth." in task


def test_build_root_task_diff_scope() -> None:
    config = {
        "targets": [],
        "diff_scope": {
            "active": True,
            "repos": [
                {
                    "workspace_subdir": "repo",
                    "analyzable_files_count": 3,
                    "deleted_files_count": 2,
                },
            ],
        },
    }
    task = build_root_task(config)

    assert "Scope Constraints:" in task
    assert "3 changed file(s)" in task
    assert "2 deleted file(s)" in task


@pytest.mark.parametrize("model_name", ["openai/o3", "gpt-4o"])
def test_make_model_settings_forces_required_tool_choice_for_openai_models(
    model_name: str,
) -> None:
    settings = make_model_settings(
        "none",
        model_name=model_name,
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_skips_required_tool_choice_for_non_openai_models() -> None:
    settings = make_model_settings(
        "none",
        model_name="anthropic/claude-3-7-sonnet-latest",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice is None


def test_make_model_settings_forces_required_for_routed_openai_model() -> None:
    settings = make_model_settings(
        None,
        model_name="litellm/openai/gpt-4o",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_forces_required_for_anyllm_routed_openai_model() -> None:
    settings = make_model_settings(
        None,
        model_name="any-llm/openai/gpt-4o",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_sets_request_timeout() -> None:
    settings = make_model_settings(
        "none",
        model_name="gpt-4o",
        request_timeout=300.0,
    )

    assert settings.extra_args is not None
    assert settings.extra_args["timeout"] == 300.0


def test_make_model_settings_omits_timeout_when_unset() -> None:
    settings = make_model_settings("none", model_name="gpt-4o")

    assert settings.extra_args is None


def test_make_model_settings_sets_extra_headers() -> None:
    settings = make_model_settings(
        "none",
        model_name="openai/some-model",
        extra_headers={"X-Feature-Key": "svc", "X-Tenant": "acme"},
    )

    assert settings.extra_headers == {"X-Feature-Key": "svc", "X-Tenant": "acme"}


def test_make_model_settings_omits_extra_headers_when_unset() -> None:
    assert make_model_settings("none", model_name="gpt-4o").extra_headers is None


def test_make_model_settings_extra_headers_survive_reasoning_resolve() -> None:
    settings = make_model_settings(
        "high",
        model_name="openai/o3",
        extra_headers={"X-Feature-Key": "svc"},
    )

    assert settings.extra_headers == {"X-Feature-Key": "svc"}


def test_make_model_settings_timeout_survives_reasoning_resolve() -> None:
    # Reasoning is resolved via ModelSettings.resolve(); the timeout in extra_args
    # must not be dropped when a reasoning override is merged in.
    settings = make_model_settings(
        "high",
        model_name="openai/o3",
        request_timeout=120.0,
    )

    assert settings.extra_args is not None
    assert settings.extra_args["timeout"] == 120.0


def test_scan_targets_prefer_the_workspace_checkout_over_the_remote_url() -> None:
    config = {
        "targets": [
            {
                "type": "repository",
                "details": {
                    "target_repo": "https://github.com/acme/billing",
                    "workspace_subdir": "billing",
                },
            },
            {"type": "web_application", "details": {"target_url": "https://app.example.com"}},
        ]
    }

    assert build_scan_targets(config) == ["/workspace/billing", "https://app.example.com"]


def test_scan_targets_drop_empty_and_duplicate_entries() -> None:
    config = {
        "targets": [
            {"type": "web_application", "details": {"target_url": "https://app.example.com"}},
            {"type": "web_application", "details": {"target_url": "https://app.example.com"}},
            {"type": "ip_address", "details": {}},
        ]
    }

    assert build_scan_targets(config) == ["https://app.example.com"]
