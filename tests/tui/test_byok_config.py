# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the LyraShield Local BYOK config module."""

from __future__ import annotations

import pytest

from lyrashield.tui.byok_config import (
    LAUNCH_PROVIDERS,
    PROFILE_FALLBACK,
    PROFILE_LUNA,
    PROFILE_TERRA,
    SCAN_MODES,
    AzureConfig,
    ByokConfig,
    ChatGptConfig,
    ModelProfile,
    Provider,
    apply_env,
    engine_mode_for,
    is_launch_provider,
    load_config,
    provider_label,
    save_config,
    validate_azure_credential,
)


def test_scan_modes_all_available_locally() -> None:
    """All scan depths are available locally — no Cloud-style depth gating."""
    assert set(SCAN_MODES) == {"SAFE", "QUICK", "STANDARD", "DEEP", "CUSTOM"}


def test_launch_providers_exclude_local_self_hosted() -> None:
    """Local/self-hosted is never a launch claim."""
    assert Provider.LOCAL_SELF_HOSTED not in LAUNCH_PROVIDERS
    assert is_launch_provider(Provider.CHATGPT_OAUTH)
    assert is_launch_provider(Provider.AZURE_OPENAI)
    assert not is_launch_provider(Provider.LOCAL_SELF_HOSTED)


def test_local_self_hosted_label_is_experimental() -> None:
    label = provider_label(Provider.LOCAL_SELF_HOSTED)
    assert "experimental" in label.lower() or "coming" in label.lower()


def test_engine_mode_mapping() -> None:
    assert engine_mode_for("SAFE") == "quick"
    assert engine_mode_for("QUICK") == "quick"
    assert engine_mode_for("STANDARD") == "standard"
    assert engine_mode_for("DEEP") == "deep"
    assert engine_mode_for("CUSTOM") == "deep"
    # Unknown mode defaults to deep (fullest), never gated.
    assert engine_mode_for("UNKNOWN") == "deep"


def test_chatgpt_config_to_env() -> None:
    cfg = ChatGptConfig(enabled=True, model="chatgpt/gpt-5.6")
    env = cfg.to_env()
    assert env == {"LYRASHIELD_LLM": "chatgpt/gpt-5.6"}
    assert ChatGptConfig(enabled=False).to_env() == {}


def test_azure_config_to_env() -> None:
    azure = AzureConfig(api_key="k", endpoint="https://x.openai.azure.com", deployment="dep")
    env = azure.to_env()
    assert env["AZURE_OPENAI_API_KEY"] == "k"
    assert env["AZURE_OPENAI_ENDPOINT"] == "https://x.openai.azure.com"
    assert env["LYRASHIELD_LLM"] == "azure/dep"
    assert not AzureConfig().is_complete()
    assert azure.is_complete()


def test_byok_config_is_configured() -> None:
    chatgpt = ByokConfig(provider=Provider.CHATGPT_OAUTH, chatgpt=ChatGptConfig(enabled=True))
    assert chatgpt.is_configured()
    azure = ByokConfig(
        provider=Provider.AZURE_OPENAI,
        azure=AzureConfig(api_key="k", endpoint="https://x.openai.azure.com"),
    )
    assert azure.is_configured()
    assert not ByokConfig(provider=Provider.LOCAL_SELF_HOSTED).is_configured()


def test_apply_env_merges_provider_vars(monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ARG001
    cfg = ByokConfig(provider=Provider.AZURE_OPENAI, azure=AzureConfig(api_key="k", endpoint="e"))
    env = apply_env(cfg, {"EXISTING": "1"})
    assert env["EXISTING"] == "1"
    assert env["AZURE_OPENAI_API_KEY"] == "k"


def test_model_profile_defaults() -> None:
    p = ModelProfile()
    assert p.name == PROFILE_FALLBACK
    assert PROFILE_LUNA != PROFILE_TERRA != PROFILE_FALLBACK


def test_save_load_config_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Config persists; secrets go to keychain (mocked), not the blob."""
    store: dict[str, str] = {}

    def fake_set(service: str, key: str, value: str) -> bool:
        store[f"{service}:{key}"] = value
        return True

    def fake_get(service: str, key: str) -> str | None:
        return store.get(f"{service}:{key}")

    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_set", fake_set)
    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_get", fake_get)

    cfg = ByokConfig(
        provider=Provider.AZURE_OPENAI,
        azure=AzureConfig(
            api_key="secret-key", endpoint="https://x.openai.azure.com", deployment="dep"
        ),
        profiles={"DEEP": ModelProfile(name=PROFILE_LUNA, model="gpt-5.6-luna")},
    )
    save_config(cfg)

    # The Azure key must be in the keychain, not in the config blob.
    assert store["LyraShield-Local:azure-openai-api-key"] == "secret-key"
    blob = store["LyraShield-Local:byok-config-v1"]
    assert "secret-key" not in blob

    loaded = load_config()
    assert loaded.provider == Provider.AZURE_OPENAI
    assert loaded.azure.api_key == "secret-key"
    assert loaded.azure.endpoint == "https://x.openai.azure.com"
    assert loaded.azure.deployment == "dep"
    assert loaded.profiles["DEEP"].name == PROFILE_LUNA


def test_validate_azure_credential_incomplete() -> None:
    assert validate_azure_credential(AzureConfig()) is False
