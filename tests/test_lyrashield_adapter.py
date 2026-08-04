from __future__ import annotations

import importlib
import json
from typing import TYPE_CHECKING

import pytest

from lyrashield_adapter import cli
from strix.config import apply_config_override, loader
from strix.config.settings import (
    PRODUCT_BOUNDARY_ENV_VAR,
    is_chatgpt_subscription_allowed,
)


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
    env: MutableMapping[str, str] = {product: "product-value"}
    cli.prepare_environment(env)
    assert env[upstream] == "product-value"


def test_prepare_environment_keeps_explicit_upstream_value() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "product-model",
        "STRIX_LLM": "operator-model",
    }
    cli.prepare_environment(env)
    assert env["STRIX_LLM"] == "operator-model"


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
    called = False

    def fake_upstream_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(cli, "_run_upstream", fake_upstream_main)
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--non-interactive"])
    cli.main()
    assert called is True


def test_prepare_environment_disables_update_check() -> None:
    env: MutableMapping[str, str] = {}
    cli.prepare_environment(env)
    assert env["STRIX_NO_UPDATE_CHECK"] == "1"


@pytest.mark.parametrize("name", ["STRIX_LLM", "STRIX_DELEGATE_LLM", "STRIX_DEDUPE_MODEL"])
def test_prepare_environment_rejects_subscription_models_when_disabled(name: str) -> None:
    env: MutableMapping[str, str] = {
        name: "chatgpt/gpt-5.6-luna",
        "LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION": "0",
    }
    with pytest.raises(SystemExit, match="ChatGPT subscription"):
        cli.prepare_environment(env)


def test_prepare_environment_rejects_subscription_model_via_product_alias_when_disabled() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "ChatGPT/gpt-5.6-terra",
        "LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION": "0",
    }
    with pytest.raises(SystemExit, match="ChatGPT subscription"):
        cli.prepare_environment(env)


def test_prepare_environment_accepts_chatgpt_by_default() -> None:
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": "chatgpt/gpt-5.6-terra"}
    assert cli.prepare_environment(env)["STRIX_LLM"] == "chatgpt/gpt-5.6-terra"


@pytest.mark.parametrize(
    "model",
    [
        "openai/gpt-5.6-luna",
        "azure/eu/gpt-5.6-terra",
        "azure_ai/gpt-5.6-luna",
        "bedrock_mantle/openai.gpt-5.6-luna",
    ],
)
def test_prepare_environment_accepts_supported_gpt56_providers(model: str) -> None:
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": model}
    assert cli.prepare_environment(env)["STRIX_LLM"] == model


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/gpt-5.6-luna",
        "bedrock/gpt-5.6-terra",
        "vertex_ai/gpt-5.6-luna",
        "novita/gpt-5.6-luna",
    ],
)
def test_prepare_environment_rejects_unsupported_gpt56_providers(model: str) -> None:
    env: MutableMapping[str, str] = {"LYRASHIELD_LLM": model}
    with pytest.raises(SystemExit, match="provider is not currently supported"):
        cli.prepare_environment(env)


def test_prepare_environment_accepts_api_key_deployments() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "azure/gpt-5.6-terra",
        "STRIX_DELEGATE_LLM": "azure/gpt-5.6-luna",
    }
    cli.prepare_environment(env)
    assert env["STRIX_LLM"] == "azure/gpt-5.6-terra"


def test_cli_update_flag_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    strix_main = importlib.import_module("strix.interface.main")

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

    strix_main = importlib.import_module("strix.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-5.6-luna"}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setattr(strix_main.codex, "is_authenticated", lambda: True)
    apply_config_override(config)
    strix_main.validate_environment()


@pytest.mark.parametrize(
    "model",
    [
        "openai/gpt-5.6-luna",
        "azure/eu/gpt-5.6-terra",
        "azure_ai/gpt-5.6-luna",
        "bedrock_mantle/openai.gpt-5.6-luna",
    ],
)
def test_config_file_can_use_supported_gpt56_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, model: str
) -> None:
    """`--config` can name a GPT-5.6 model from a supported provider."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("strix.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": model}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    apply_config_override(config)
    strix_main.validate_environment()


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/gpt-5.6-luna",
        "bedrock/gpt-5.6-terra",
        "vertex_ai/gpt-5.6-luna",
        "novita/gpt-5.6-luna",
    ],
)
def test_config_file_rejects_unsupported_gpt56_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, model: str
) -> None:
    """`--config` rejects a GPT-5.6 model from an unsupported provider."""
    monkeypatch.setattr(loader, "_override", None, raising=False)
    monkeypatch.setattr(loader, "_cached", None, raising=False)

    strix_main = importlib.import_module("strix.interface.main")

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

    strix_main = importlib.import_module("strix.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-5.6-luna"}}))

    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setenv("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", "0")
    # Signed in, so upstream's subscription path would happily proceed; only the
    # product-boundary gate should reject this.
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

    strix_main = importlib.import_module("strix.interface.main")

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_LLM": "chatgpt/gpt-5.6-luna"}}))

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
