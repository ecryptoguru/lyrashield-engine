from __future__ import annotations

import importlib
import json
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.lifecycle.deadline import RunDeadline
from lyrashield.policy import loader
from lyrashield.policy.loader import apply_config_override
from lyrashield.policy.settings import (
    PRODUCT_BOUNDARY_ENV_VAR,
    is_chatgpt_subscription_allowed,
)
from lyrashield_adapter import cli


if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_product_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent `cli.main()` from leaving product-boundary env vars in the process."""
    monkeypatch.delenv(PRODUCT_BOUNDARY_ENV_VAR, raising=False)
    monkeypatch.delenv("STRIX_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", raising=False)
    monkeypatch.delenv("STRIX_ALLOW_CHATGPT_SUBSCRIPTION", raising=False)
    for name in (
        "STRIX_LLM",
        "STRIX_DELEGATE_LLM",
        "STRIX_DEDUPE_MODEL",
        "LYRASHIELD_LLM",
        "LYRASHIELD_DELEGATE_LLM",
        "LYRASHIELD_DEDUPE_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("product", "upstream"),
    [
        ("LYRASHIELD_LLM", "STRIX_LLM"),
        ("LYRASHIELD_DELEGATE_LLM", "STRIX_DELEGATE_LLM"),
        ("LYRASHIELD_IMAGE", "STRIX_IMAGE"),
        ("LYRASHIELD_RUNTIME_BACKEND", "STRIX_RUNTIME_BACKEND"),
        ("LYRASHIELD_MAX_LOCAL_COPY_MB", "STRIX_MAX_LOCAL_COPY_MB"),
        ("LYRASHIELD_MAX_CONTEXT_IMAGES", "STRIX_MAX_CONTEXT_IMAGES"),
        ("LYRASHIELD_REASONING_EFFORT", "STRIX_REASONING_EFFORT"),
        (
            "LYRASHIELD_DELEGATE_REASONING_EFFORT",
            "STRIX_DELEGATE_REASONING_EFFORT",
        ),
        (
            "LYRASHIELD_FORCE_REQUIRED_TOOL_CHOICE",
            "STRIX_FORCE_REQUIRED_TOOL_CHOICE",
        ),
        ("LYRASHIELD_LLM_TIMEOUT", "LLM_TIMEOUT"),
        ("LYRASHIELD_WEB_SEARCH_ENABLED", "STRIX_WEB_SEARCH_ENABLED"),
        ("LYRASHIELD_WEB_SEARCH_PROVIDER", "STRIX_WEB_SEARCH_PROVIDER"),
        ("LYRASHIELD_WEB_SEARCH_MODE", "STRIX_WEB_SEARCH_MODE"),
        ("LYRASHIELD_WEB_SEARCH_MAX_RESULTS", "STRIX_WEB_SEARCH_MAX_RESULTS"),
        ("LYRASHIELD_WEB_SEARCH_MAX_CHARS_TOTAL", "STRIX_WEB_SEARCH_MAX_CHARS_TOTAL"),
        ("LYRASHIELD_WEB_SEARCH_MAX_CALLS_PER_SCAN", "STRIX_WEB_SEARCH_MAX_CALLS_PER_SCAN"),
        ("LYRASHIELD_WEB_SEARCH_BUDGET_USD", "STRIX_WEB_SEARCH_BUDGET_USD"),
        ("LYRASHIELD_WEB_SEARCH_API_KEY", "PARALLEL_API_KEY"),
    ],
)
def test_prepare_environment_maps_product_variable(product: str, upstream: str) -> None:
    value = (
        "openai/gpt-6-luna" if upstream in {"STRIX_LLM", "STRIX_DELEGATE_LLM"} else "product-value"
    )
    env: MutableMapping[str, str] = {product: value}
    cli.prepare_environment(env)
    assert env[upstream] == value


def test_prepare_environment_keeps_explicit_upstream_value() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "openai/gpt-6-luna",
        "STRIX_LLM": "openai/gpt-6-sol",
    }
    cli.prepare_environment(env)
    assert env["STRIX_LLM"] == "openai/gpt-6-sol"


def test_prepare_environment_forces_telemetry_off() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_TELEMETRY": "1",
        "STRIX_TELEMETRY": "1",
    }
    cli.prepare_environment(env)
    assert env["STRIX_TELEMETRY"] == "0"


def test_main_prints_product_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "get_version", lambda: "1.0.4.post1")
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--version"])
    cli.main()
    assert capsys.readouterr().out == "lyrashield 1.0.4.post1\n"


def test_main_delegates_non_version_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, float | None] = {}

    def fake_upstream_main(*, entry_monotonic: float | None) -> None:
        captured["entry_monotonic"] = entry_monotonic

    # Isolate from the developer's local .env, which may name any deployment.
    monkeypatch.setattr(cli, "load_dotenv", None)
    monkeypatch.setattr(cli, "_run_upstream", fake_upstream_main)
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--non-interactive"])
    cli.main()
    assert isinstance(captured["entry_monotonic"], float)


def test_adapter_deadline_starts_before_setup_and_covers_pull_and_clone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    product_main = importlib.import_module("lyrashield.interface.main")
    run_product_main = product_main.main
    clock = [100.0]
    captured: dict[str, object] = {}

    class StopAfterCloneError(Exception):
        pass

    def advance_setup() -> None:
        clock[0] += 1.5

    def product_entry(*, entry_monotonic: float | None = None) -> None:
        captured["entry_monotonic"] = entry_monotonic
        run_product_main(entry_monotonic=entry_monotonic, monotonic=lambda: clock[0])

    def pull_image(*, deadline: Any) -> None:
        captured["pull_deadline"] = deadline
        clock[0] += 1.0

    def clone_repository(*_args: Any, deadline: Any, **_kwargs: Any) -> str:
        captured["clone_deadline"] = deadline
        captured["clone_remaining"] = deadline.remaining_seconds()
        raise StopAfterCloneError

    args = SimpleNamespace(
        config=None,
        runtime_budget_seconds=10.0,
        non_interactive=True,
        resume=None,
        run_name="adapter-deadline",
        targets_info=[
            {"type": "repository", "details": {"target_repo": "https://example.test/repo.git"}}
        ],
        repository_revision=None,
        diff_head=None,
        diff_base=None,
        repository_branch=None,
    )

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli.multiprocessing, "freeze_support", lambda: None)
    monkeypatch.setattr(cli, "load_dotenv", None)
    monkeypatch.setattr(cli, "prepare_environment", advance_setup)
    monkeypatch.setattr(cli, "_register_lyrashield_skills", advance_setup)
    monkeypatch.setattr(cli, "_register_lyrashield_tool_overrides", advance_setup)
    monkeypatch.setattr(cli, "_register_lyrashield_model_policy", advance_setup)
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--non-interactive"])
    monkeypatch.setattr(product_main, "main", product_entry)
    monkeypatch.setattr(product_main, "configure_dependency_logging", lambda: None)
    monkeypatch.setattr(product_main, "parse_arguments", lambda: args)
    monkeypatch.setattr(product_main, "validate_environment", lambda: None)
    monkeypatch.setattr(product_main, "check_docker_installed", lambda: None)
    monkeypatch.setattr(product_main, "pull_docker_image", pull_image)
    monkeypatch.setattr(product_main, "clone_repository", clone_repository)

    with pytest.raises(StopAfterCloneError):
        cli.main()

    deadline = captured["pull_deadline"]
    assert isinstance(deadline, RunDeadline)
    assert captured["entry_monotonic"] == 100.0
    assert deadline.hard_at == 110.0
    assert deadline.remaining_seconds() == 3.0
    assert captured["clone_deadline"] is deadline
    assert captured["clone_remaining"] == 3.0


def test_prepare_environment_disables_update_check() -> None:
    env: MutableMapping[str, str] = {}
    cli.prepare_environment(env)
    assert env["STRIX_NO_UPDATE_CHECK"] == "1"


@pytest.mark.parametrize("name", ["STRIX_LLM", "STRIX_DELEGATE_LLM", "STRIX_DEDUPE_MODEL"])
def test_prepare_environment_rejects_subscription_models_when_disabled(name: str) -> None:
    env: MutableMapping[str, str] = {
        name: "chatgpt/gpt-6-luna",
        "LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION": "0",
    }
    with pytest.raises(SystemExit, match="ChatGPT subscription"):
        cli.prepare_environment(env)


def test_prepare_environment_rejects_subscription_model_via_product_alias_when_disabled() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "ChatGPT/gpt-6-sol",
        "LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION": "0",
    }
    with pytest.raises(SystemExit, match="ChatGPT subscription"):
        cli.prepare_environment(env)


def test_prepare_environment_accepts_chatgpt_gpt6_when_subscription_enabled() -> None:
    """The subscription route is admitted for the main model when enabled."""
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": "chatgpt/gpt-6-sol"}
    assert cli.prepare_environment(env)["STRIX_LLM"] == "chatgpt/gpt-6-sol"


@pytest.mark.parametrize("model", ["chatgpt/gpt-5.6-luna", "chatgpt/gpt-4o"])
def test_prepare_environment_rejects_non_gpt6_subscription_models(model: str) -> None:
    """Subscription routing does not widen the model family: still GPT-6 only."""
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": model}
    with pytest.raises(SystemExit, match="not an approved GPT-6"):
        cli.prepare_environment(env)


@pytest.mark.parametrize(
    "model",
    [
        "openai/gpt-6-luna",
        "azure/gpt-6-sol",
        "azure_ai/gpt-6-luna",
    ],
)
def test_prepare_environment_accepts_supported_gpt6_providers(model: str) -> None:
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": model}
    assert cli.prepare_environment(env)["STRIX_LLM"] == model


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/gpt-6-luna",
        "bedrock/gpt-6-sol",
        "vertex_ai/gpt-6-luna",
        "novita/gpt-6-luna",
    ],
)
def test_prepare_environment_rejects_unsupported_gpt6_providers(model: str) -> None:
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": model}
    with pytest.raises(SystemExit, match="not an approved GPT-6"):
        cli.prepare_environment(env)


def test_prepare_environment_accepts_api_key_deployments() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "azure/gpt-6-sol",
        "STRIX_DELEGATE_LLM": "azure/gpt-6-luna",
    }
    cli.prepare_environment(env)
    assert env["STRIX_LLM"] == "azure/gpt-6-sol"


def test_cli_update_flag_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    strix_main = importlib.import_module("lyrashield.interface.main")

    monkeypatch.setattr(strix_main.sys, "argv", ["strix", "--update"])
    with pytest.raises(SystemExit) as excinfo:
        strix_main.parse_arguments()
    assert excinfo.value.code == 1


def test_config_file_can_use_subscription_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--config` can name a chatgpt/ model when subscription support is on by default."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("lyrashield.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-6-luna"}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setattr(strix_main.codex, "is_authenticated", lambda: True)
    apply_config_override(config)
    strix_main.validate_environment()


@pytest.mark.parametrize(
    "model",
    [
        "openai/gpt-6-luna",
        "azure/gpt-6-sol",
        "azure_ai/gpt-6-luna",
    ],
)
def test_config_file_can_use_supported_gpt6_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, model: str
) -> None:
    """`--config` can name a GPT-6 model from a supported provider."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("lyrashield.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": model}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    apply_config_override(config)
    strix_main.validate_environment()


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/gpt-6-luna",
        "bedrock/gpt-6-sol",
        "vertex_ai/gpt-6-luna",
        "novita/gpt-6-luna",
    ],
)
def test_config_file_rejects_unsupported_gpt6_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, model: str
) -> None:
    """`--config` rejects a GPT-6 model from an unsupported provider."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("lyrashield.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": model}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    apply_config_override(config)
    with pytest.raises(SystemExit) as excinfo:
        strix_main.validate_environment()
    assert excinfo.value.code == 1


def test_config_file_rejects_subscription_model_when_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--config` is applied after the env gate, so the resolved settings are re-checked."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("lyrashield.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-6-luna"}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setenv("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", "0")
    # Signed in, so upstream's subscription path would happily proceed; only the
    # product-boundary gate should reject this.
    monkeypatch.setattr(strix_main.codex, "is_authenticated", lambda: True)
    apply_config_override(config)
    with pytest.raises(SystemExit) as excinfo:
        strix_main.validate_environment()
    assert excinfo.value.code == 1


def test_config_file_rejects_non_gpt6_subscription_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--config` cannot sneak a non-GPT-6 model through the subscription route."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("lyrashield.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-4o"}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setattr(strix_main.codex, "is_authenticated", lambda: True)
    apply_config_override(config)
    with pytest.raises(SystemExit) as excinfo:
        strix_main.validate_environment()
    assert excinfo.value.code == 1


def test_config_subscription_model_rejected_when_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Subscription-backed models are rejected when explicitly disabled."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("lyrashield.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-6-luna"}}))

    monkeypatch.delenv(PRODUCT_BOUNDARY_ENV_VAR, raising=False)
    monkeypatch.setenv("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", "0")
    monkeypatch.setattr(strix_main.codex, "is_authenticated", lambda: True)
    apply_config_override(config)
    with pytest.raises(SystemExit) as excinfo:
        strix_main.validate_environment()
    assert excinfo.value.code == 1


def test_is_chatgpt_subscription_allowed_defaults_to_true() -> None:
    assert is_chatgpt_subscription_allowed({}) is True


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("lyrashield_allow_chatgpt_subscription", "0"),
        ("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", "false"),
        ("strix_allow_chatgpt_subscription", "no"),
        ("STRIX_ALLOW_CHATGPT_SUBSCRIPTION", "off"),
    ],
)
def test_is_chatgpt_subscription_allowed_is_case_insensitive(key: str, value: str) -> None:
    assert is_chatgpt_subscription_allowed({key: value}) is False
