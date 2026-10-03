# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the LyraShield Local BYOK config module."""

from __future__ import annotations

import json

import pytest

from lyrashield.tui.byok_config import (
    CONFIG_KEY,
    KEYCHAIN_AZURE_KEY,
    LEGACY_CONFIG_KEY,
    LAUNCH_PROVIDERS,
    PROFILE_FALLBACK,
    PROFILE_LUNA,
    PROFILE_SOL,
    SCAN_MODES,
    AzureConfig,
    ByokConfig,
    ByokConfigError,
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
    cfg = ChatGptConfig(enabled=True, model="chatgpt/gpt-6-luna")
    env = cfg.to_env()
    assert env == {"LYRASHIELD_LLM": "chatgpt/gpt-6-luna"}
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
        azure=AzureConfig(api_key="k", endpoint="https://x.openai.azure.com", deployment="dep"),
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
    assert PROFILE_LUNA != PROFILE_SOL != PROFILE_FALLBACK


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
        profiles={"DEEP": ModelProfile(name=PROFILE_LUNA, model="gpt-6-luna")},
    )
    save_config(cfg)

    # The Azure key stays in a versioned keychain item, outside the config blob.
    blob = store[f"LyraShield-Local:{CONFIG_KEY}"]
    assert "secret-key" not in blob
    azure_blob = json.loads(blob)["azure"]
    assert azure_blob["credential_version"] == 2
    assert store[f"LyraShield-Local:{azure_blob['key_id']}"] == "secret-key"

    loaded = load_config()
    assert loaded.provider == Provider.AZURE_OPENAI
    assert loaded.azure.api_key == "secret-key"
    assert loaded.azure.endpoint == "https://x.openai.azure.com"
    assert loaded.azure.deployment == "dep"
    assert loaded.profiles["DEEP"].name == PROFILE_LUNA


def test_save_config_allows_repeated_keyless_chatgpt_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store: dict[str, str] = {}
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_set",
        lambda service, key, value: store.__setitem__(f"{service}:{key}", value) is None,
    )
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_get",
        lambda service, key: store.get(f"{service}:{key}"),
    )
    config = ByokConfig(
        provider=Provider.CHATGPT_OAUTH,
        chatgpt=ChatGptConfig(enabled=True),
    )

    save_config(config)
    save_config(config)

    assert json.loads(store[f"LyraShield-Local:{CONFIG_KEY}"])["provider"] == "chatgpt-oauth"


def test_save_config_rejects_incomplete_azure_credential_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = {
        f"LyraShield-Local:{CONFIG_KEY}": json.dumps(
            {
                "provider": Provider.AZURE_OPENAI.value,
                "azure": {"credential_version": 2},
            }
        )
    }
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_get",
        lambda service, key: store.get(f"{service}:{key}"),
    )
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_set",
        lambda service, key, value: store.__setitem__(f"{service}:{key}", value) is None,
    )

    with pytest.raises(ByokConfigError, match="credential reference is incomplete"):
        save_config(ByokConfig(provider=Provider.AZURE_OPENAI))


def test_failed_config_write_keeps_old_azure_key_bound_to_old_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key_id = f"{KEYCHAIN_AZURE_KEY}-{'a' * 32}"
    old_blob = json.dumps(
        {
            "provider": Provider.AZURE_OPENAI.value,
            "azure": {
                "endpoint": "https://prior.example",
                "deployment": "prior",
                "credential_version": 2,
                "key_id": old_key_id,
            },
        }
    )
    store = {
        f"LyraShield-Local:{CONFIG_KEY}": old_blob,
        f"LyraShield-Local:{old_key_id}": "prior-api-key",
        f"LyraShield-Local:{KEYCHAIN_AZURE_KEY}": "prior-api-key",
    }

    def fake_get(service: str, key: str) -> str | None:
        return store.get(f"{service}:{key}")

    def fake_set(service: str, key: str, value: str) -> bool:
        if key == CONFIG_KEY:
            return False
        store[f"{service}:{key}"] = value
        return True

    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_get", fake_get)
    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_set", fake_set)

    with pytest.raises(RuntimeError, match="BYOK setup could not be saved"):
        save_config(
            ByokConfig(
                provider=Provider.AZURE_OPENAI,
                azure=AzureConfig(
                    api_key="replacement-api-key",
                    endpoint="https://replacement.example",
                    deployment="replacement",
                ),
            )
        )

    assert store[f"LyraShield-Local:{CONFIG_KEY}"] == old_blob
    loaded = load_config()
    assert loaded.azure.endpoint == "https://prior.example"
    assert loaded.azure.api_key == "prior-api-key"
    assert store[f"LyraShield-Local:{old_key_id}"] == "prior-api-key"


def test_missing_versioned_azure_key_does_not_fall_back_to_legacy_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = json.dumps(
        {
            "provider": Provider.AZURE_OPENAI.value,
            "azure": {
                "endpoint": "https://replacement.example",
                "deployment": "replacement",
                "credential_version": 2,
                "key_id": f"{KEYCHAIN_AZURE_KEY}-{'a' * 32}",
            },
        }
    )
    store = {
        f"LyraShield-Local:{CONFIG_KEY}": blob,
        f"LyraShield-Local:{KEYCHAIN_AZURE_KEY}": "prior-endpoint-key",
    }
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_get",
        lambda service, key: store.get(f"{service}:{key}"),
    )

    loaded = load_config()

    assert loaded.azure.endpoint == "https://replacement.example"
    assert loaded.azure.api_key == ""
    assert loaded.is_configured() is False


def test_legacy_azure_key_is_migrated_to_a_versioned_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = {
        f"LyraShield-Local:{LEGACY_CONFIG_KEY}": json.dumps(
            {
                "provider": Provider.AZURE_OPENAI.value,
                "azure": {
                    "endpoint": "https://legacy.example",
                    "deployment": "legacy-deployment",
                },
            }
        ),
        f"LyraShield-Local:{KEYCHAIN_AZURE_KEY}": "legacy-endpoint-key",
    }

    def fake_get(service: str, key: str) -> str | None:
        return store.get(f"{service}:{key}")

    def fake_set(service: str, key: str, value: str) -> bool:
        store[f"{service}:{key}"] = value
        return True

    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_get", fake_get)
    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_set", fake_set)

    save_config(
        ByokConfig(
            provider=Provider.AZURE_OPENAI,
            azure=AzureConfig(endpoint="https://legacy.example", deployment="legacy-deployment"),
        )
    )

    blob = json.loads(store[f"LyraShield-Local:{CONFIG_KEY}"])
    migrated_key_id = blob["azure"]["key_id"]
    assert migrated_key_id != KEYCHAIN_AZURE_KEY
    assert blob["azure"]["credential_version"] == 2
    assert store[f"LyraShield-Local:{migrated_key_id}"] == "legacy-endpoint-key"
    assert load_config().azure.api_key == "legacy-endpoint-key"


def test_changing_azure_endpoint_requires_a_new_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = {}

    def fake_get(service: str, key: str) -> str | None:
        return store.get(f"{service}:{key}")

    def fake_set(service: str, key: str, value: str) -> bool:
        store[f"{service}:{key}"] = value
        return True

    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_get", fake_get)
    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_set", fake_set)
    save_config(
        ByokConfig(
            provider=Provider.AZURE_OPENAI,
            azure=AzureConfig(
                api_key="old-endpoint-key",
                endpoint="https://old.example",
                deployment="production",
            ),
        )
    )
    old_blob = store[f"LyraShield-Local:{CONFIG_KEY}"]
    old_key_id = json.loads(old_blob)["azure"]["key_id"]

    with pytest.raises(
        ByokConfigError, match="Azure endpoint change requires entering the API key"
    ):
        save_config(
            ByokConfig(
                provider=Provider.AZURE_OPENAI,
                azure=AzureConfig(endpoint="https://new.example", deployment="production"),
            )
        )

    assert store[f"LyraShield-Local:{CONFIG_KEY}"] == old_blob
    assert store[f"LyraShield-Local:{old_key_id}"] == "old-endpoint-key"


def test_endpoint_trailing_slash_and_deployment_change_reuse_existing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = {}

    def fake_get(service: str, key: str) -> str | None:
        return store.get(f"{service}:{key}")

    def fake_set(service: str, key: str, value: str) -> bool:
        store[f"{service}:{key}"] = value
        return True

    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_get", fake_get)
    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_set", fake_set)
    save_config(
        ByokConfig(
            provider=Provider.AZURE_OPENAI,
            azure=AzureConfig(
                api_key="saved-key",
                endpoint="https://resource.example",
                deployment="old-deployment",
            ),
        )
    )
    old_blob = json.loads(store[f"LyraShield-Local:{CONFIG_KEY}"])
    old_key_id = old_blob["azure"]["key_id"]

    save_config(
        ByokConfig(
            provider=Provider.AZURE_OPENAI,
            azure=AzureConfig(
                endpoint="https://resource.example/",
                deployment="new-deployment",
            ),
        )
    )

    new_blob = json.loads(store[f"LyraShield-Local:{CONFIG_KEY}"])
    assert new_blob["azure"]["key_id"] == old_key_id
    loaded = load_config()
    assert loaded.azure.deployment == "new-deployment"
    assert loaded.azure.api_key == "saved-key"


@pytest.mark.parametrize("raw", ["[]", "null", '{"profiles": []}'])
def test_malformed_saved_config_has_recovery_error(
    raw: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_get",
        lambda _service, key: raw if key == CONFIG_KEY else None,
    )

    with pytest.raises(ValueError, match="saved BYOK setup is malformed"):
        load_config()


@pytest.mark.parametrize(
    "legacy_model",
    ["chatgpt/gpt-5.6", "chatgpt/gpt-5.6-luna", "chatgpt/gpt-5.6-terra"],
)
def test_load_config_migrates_legacy_chatgpt_model(
    legacy_model: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_blob = json.dumps(
        {
            "provider": Provider.CHATGPT_OAUTH.value,
            "chatgpt": {"enabled": True, "model": legacy_model},
            "azure": {"credential_version": 2},
        }
    )
    monkeypatch.setattr(
        "lyrashield.tui.byok_config.keyring_get",
        lambda _service, key: config_blob if key == CONFIG_KEY else None,
    )

    loaded = load_config()

    assert loaded.chatgpt.model == "chatgpt/gpt-6-luna"
    assert loaded.to_env()["LYRASHIELD_LLM"] == "chatgpt/gpt-6-luna"


def test_save_config_rejects_failed_keychain_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lyrashield.tui.byok_config.keyring_set", lambda *_: False)
    config = ByokConfig(provider=Provider.AZURE_OPENAI, azure=AzureConfig(api_key="synthetic"))
    with pytest.raises(RuntimeError, match="keychain"):
        save_config(config)


def test_validate_azure_credential_incomplete() -> None:
    assert validate_azure_credential(AzureConfig()) is False
