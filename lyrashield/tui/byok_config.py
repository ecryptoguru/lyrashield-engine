# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""BYOK configuration for LyraShield Local.

Friendly setup that maps onto the engine's existing routing. Launch providers:

* **ChatGPT subscription OAuth** — token stored by the engine in an owner-only
  local JSON auth store. Routed through the engine's
  Codex/ChatGPT subscription path (``chatgpt/<model>``).
* **Azure OpenAI** — ``AZURE_OPENAI_API_KEY`` / ``AZURE_OPENAI_ENDPOINT`` /
  ``AZURE_OPENAI_API_VERSION``. The API key is stored in the OS keychain and
  surfaced to the engine via environment variables at scan time.

Local/self-hosted models are hidden from the launch surface and marked
"experimental / coming soon" — they are never a launch claim.

A per-scan-mode model profile (LUNA/SOL/fallback) is persisted locally and
applied when the TUI shells into the engine CLI.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import requests

from lyrashield.tui.results_store import (
    ResultsStoreKeyError,
    keyring_delete,
    keyring_get,
    keyring_set,
)


logger = logging.getLogger(__name__)


# Keychain service names. Never write secrets to plaintext files.
KEYCHAIN_SERVICE = "LyraShield-Local"
KEYCHAIN_CHATGPT_TOKEN = "chatgpt-oauth-token"  # noqa: S105 - keychain item name, not a credential
KEYCHAIN_AZURE_KEY = "azure-openai-api-key"

# Model profile names mirror the engine's LUNA/SOL deployment naming.
PROFILE_LUNA = "luna"
PROFILE_SOL = "sol"
PROFILE_FALLBACK = "fallback"


class Provider(StrEnum):
    """Launch BYOK providers.

    ``LOCAL_SELF_HOSTED`` is kept for forward-compat but is never offered as a
    launch claim — the UI marks it "experimental / coming".
    """

    CHATGPT_OAUTH = "chatgpt-oauth"
    AZURE_OPENAI = "azure-openai"
    LOCAL_SELF_HOSTED = "local-self-hosted"


LAUNCH_PROVIDERS: tuple[Provider, ...] = (Provider.CHATGPT_OAUTH, Provider.AZURE_OPENAI)


@dataclass
class AzureConfig:
    """Azure OpenAI BYOK configuration."""

    api_key: str = ""
    endpoint: str = ""
    api_version: str = "2024-10-21"
    deployment: str = ""

    def is_complete(self) -> bool:
        return bool(self.api_key and self.endpoint and self.deployment)

    def to_env(self) -> dict[str, str]:
        """Return env vars the engine CLI expects for Azure OpenAI."""
        env: dict[str, str] = {
            "AZURE_OPENAI_API_KEY": self.api_key,
            "AZURE_OPENAI_ENDPOINT": self.endpoint,
            "AZURE_OPENAI_API_VERSION": self.api_version,
        }
        if self.deployment:
            # The engine resolves ``STRIX_LLM``/``LYRASHIELD_LLM``; an Azure
            # deployment is expressed as ``azure/<deployment>``.
            env["LYRASHIELD_LLM"] = f"azure/{self.deployment}"
        return env


@dataclass
class ChatGptConfig:
    """ChatGPT subscription OAuth configuration.

    The access token is stored in the engine's owner-only auth store. Its existing
    ``lyrashield auth login chatgpt`` flow performs the OAuth dance; this
    config records that the provider is selected and which model profile to
    route through the subscription.
    """

    enabled: bool = False
    model: str = "chatgpt/gpt-6-luna"

    def to_env(self) -> dict[str, str]:
        if not self.enabled:
            return {}
        return {"LYRASHIELD_LLM": self.model}


@dataclass
class ModelProfile:
    """Per-scan-mode model profile (LUNA/SOL/fallback)."""

    name: str = PROFILE_FALLBACK
    # The engine model string (e.g. ``gpt-6-luna``, ``azure/<dep>``).
    model: str = ""


# All scan modes are available locally — no Cloud-style depth gating.
SCAN_MODES: tuple[str, ...] = ("SAFE", "QUICK", "STANDARD", "DEEP", "CUSTOM")

# Map TUI scan modes to the engine CLI ``--scan-mode`` choices. SAFE and
# CUSTOM are TUI-side framing; the engine CLI accepts quick/standard/deep.
# SAFE maps to quick (lightest), CUSTOM maps to deep ( fullest) — the TUI
# passes the engine mode through ``scan_flow``.
_ENGINE_MODE_MAP: dict[str, str] = {
    "SAFE": "quick",
    "QUICK": "quick",
    "STANDARD": "standard",
    "DEEP": "deep",
    "CUSTOM": "deep",
}


def engine_mode_for(tui_mode: str) -> str:
    """Return the engine CLI ``--scan-mode`` value for a TUI scan mode."""
    return _ENGINE_MODE_MAP.get(tui_mode.upper(), "deep")


@dataclass
class ByokConfig:
    """Full BYOK configuration persisted locally."""

    provider: Provider = Provider.CHATGPT_OAUTH
    chatgpt: ChatGptConfig = field(default_factory=ChatGptConfig)
    azure: AzureConfig = field(default_factory=AzureConfig)
    # Per-scan-mode model profile.
    profiles: dict[str, ModelProfile] = field(default_factory=dict)

    def is_configured(self) -> bool:
        if self.provider == Provider.CHATGPT_OAUTH:
            return self.chatgpt.enabled
        if self.provider == Provider.AZURE_OPENAI:
            return self.azure.is_complete()
        return False

    def to_env(self) -> dict[str, str]:
        """Return env vars to hand to the engine CLI for the active provider."""
        if self.provider == Provider.CHATGPT_OAUTH:
            return self.chatgpt.to_env()
        if self.provider == Provider.AZURE_OPENAI:
            return self.azure.to_env()
        return {}

    def profile_for(self, scan_mode: str) -> ModelProfile:
        return self.profiles.get(scan_mode.upper(), ModelProfile())


# ---------------------------------------------------------------------------
# Persistence (OS keychain for secrets; a small JSON blob for non-secret
# config is stored alongside the results store metadata, never containing
# raw credentials).
# ---------------------------------------------------------------------------

LEGACY_CONFIG_KEY = "byok-config-v1"
CONFIG_KEY = "byok-config-v2"


def azure_endpoints_equivalent(left: str, right: str) -> bool:
    """Compare Azure resource endpoints while ignoring harmless URL spelling."""

    def normalize(endpoint: str) -> tuple[str, ...]:
        value = endpoint.strip()
        if not value:
            return ("",)
        try:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.netloc or not parsed.hostname:
                return (value.rstrip("/"),)
            scheme = parsed.scheme.lower()
            host = parsed.hostname.lower()
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            port = parsed.port
            if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                port = None
            userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
            authority = f"{userinfo}@" if userinfo else ""
            authority += host
            if port is not None:
                authority += f":{port}"
            return (
                scheme,
                authority,
                parsed.path.rstrip("/"),
                parsed.query,
                parsed.fragment,
            )
        except ValueError:
            return (value.rstrip("/"),)

    return normalize(left) == normalize(right)


class ByokConfigError(ValueError):
    """Persisted setup is malformed or cannot be safely updated."""


def _read_previous_azure_binding(
    raw: str | None, *, is_v2: bool, has_replacement_key: bool
) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    try:
        previous_blob, previous_provider = _read_config_blob(raw)
    except (TypeError, ValueError) as exc:
        if has_replacement_key:
            return None, None
        raise ByokConfigError(
            "The saved BYOK setup is malformed. Re-enter the Azure key before saving."
        ) from exc

    previous_azure = previous_blob.get("azure", {})
    previous_endpoint = previous_azure.get("endpoint", "")
    previous_key_id = previous_azure.get("key_id")
    if previous_key_id:
        return previous_key_id, previous_endpoint
    if is_v2 and previous_provider == Provider.AZURE_OPENAI and not has_replacement_key:
        raise ByokConfigError(
            "The saved BYOK credential reference is incomplete. Re-enter the Azure key."
        )
    if not is_v2 and previous_azure.get("credential_version") is None:
        # Migrate only a genuine v1 shared-key binding. V2 state with no
        # reference must never adopt an unrelated legacy key.
        return KEYCHAIN_AZURE_KEY, previous_endpoint
    return None, previous_endpoint


def _stage_azure_credential(
    config: ByokConfig, blob: dict[str, Any], previous_key_id: str | None
) -> tuple[str | None, str]:
    key_to_store = config.azure.api_key
    if key_to_store:
        staged_key_id = f"{KEYCHAIN_AZURE_KEY}-{uuid4().hex}"
        blob["azure"]["key_id"] = staged_key_id
        return staged_key_id, key_to_store
    if previous_key_id == KEYCHAIN_AZURE_KEY:
        key_to_store = keyring_get(KEYCHAIN_SERVICE, KEYCHAIN_AZURE_KEY) or ""
        if key_to_store:
            staged_key_id = f"{KEYCHAIN_AZURE_KEY}-{uuid4().hex}"
            blob["azure"]["key_id"] = staged_key_id
            return staged_key_id, key_to_store
    elif previous_key_id:
        blob["azure"]["key_id"] = previous_key_id
    return None, key_to_store


def _store_staged_azure_key(key_id: str | None, value: str) -> None:
    if not key_id:
        return
    if not keyring_set(KEYCHAIN_SERVICE, key_id, value):
        raise RuntimeError("Azure API key could not be saved to the keychain")
    if keyring_get(KEYCHAIN_SERVICE, key_id) != value:
        keyring_delete(KEYCHAIN_SERVICE, key_id)
        raise RuntimeError("Azure API key could not be verified in the keychain")


def _write_config_blob(serialized: str, staged_key_id: str | None) -> None:
    if keyring_set(KEYCHAIN_SERVICE, CONFIG_KEY, serialized):
        return
    if staged_key_id:
        try:
            if keyring_get(KEYCHAIN_SERVICE, CONFIG_KEY) != serialized:
                keyring_delete(KEYCHAIN_SERVICE, staged_key_id)
        except ResultsStoreKeyError:
            pass  # Keep a possibly published credential if readback is unavailable.
    raise RuntimeError("BYOK setup could not be saved to the keychain")


def save_config(config: ByokConfig) -> None:
    """Persist non-secret BYOK config. Secrets go to the keychain."""
    blob: dict[str, Any] = {
        "provider": config.provider.value,
        "chatgpt": {
            "enabled": config.chatgpt.enabled,
            "model": config.chatgpt.model,
        },
        "azure": {
            "endpoint": config.azure.endpoint,
            "api_version": config.azure.api_version,
            "deployment": config.azure.deployment,
            "credential_version": 2,
        },
        "profiles": {
            mode: {"name": p.name, "model": p.model} for mode, p in config.profiles.items()
        },
    }
    previous_raw = keyring_get(KEYCHAIN_SERVICE, CONFIG_KEY)
    previous_is_v2 = bool(previous_raw)
    if not previous_raw:
        previous_raw = keyring_get(KEYCHAIN_SERVICE, LEGACY_CONFIG_KEY)
    previous_key_id, previous_endpoint = _read_previous_azure_binding(
        previous_raw,
        is_v2=previous_is_v2,
        has_replacement_key=bool(config.azure.api_key),
    )
    if (
        previous_key_id
        and not config.azure.api_key
        and previous_endpoint is not None
        and not azure_endpoints_equivalent(config.azure.endpoint, previous_endpoint)
    ):
        raise ByokConfigError(
            "Azure endpoint change requires entering the API key again; "
            "the existing key remains with the prior endpoint."
        )

    staged_key_id, key_to_store = _stage_azure_credential(config, blob, previous_key_id)
    _store_staged_azure_key(staged_key_id, key_to_store)
    _write_config_blob(_json_dumps(blob), staged_key_id)
    if (
        previous_key_id
        and previous_key_id != KEYCHAIN_AZURE_KEY
        and previous_key_id != blob["azure"].get("key_id")
    ):
        keyring_delete(KEYCHAIN_SERVICE, previous_key_id)


def _read_config_blob(raw: str) -> tuple[dict[str, Any], Provider]:
    blob = _json_loads(raw)
    provider = Provider(blob.get("provider", Provider.CHATGPT_OAUTH.value))
    for section in ("chatgpt", "azure", "profiles"):
        if not isinstance(blob.get(section, {}), dict):
            raise TypeError(f"{section} must be an object")
    chatgpt_blob = blob.get("chatgpt", {})
    if not isinstance(chatgpt_blob.get("enabled", False), bool):
        raise TypeError("enabled must be a boolean")
    if not isinstance(chatgpt_blob.get("model", "chatgpt/gpt-6-luna"), str):
        raise TypeError("model must be text")
    azure_blob = blob.get("azure", {})
    if any(
        not isinstance(value, str)
        for key, value in azure_blob.items()
        if key != "credential_version"
    ):
        raise TypeError("Azure settings must be text")
    credential_version = azure_blob.get("credential_version")
    if credential_version is not None and (
        type(credential_version) is not int or credential_version != 2
    ):
        raise ValueError("Azure credential version is unsupported")
    key_id = azure_blob.get("key_id")
    if key_id is not None and credential_version is None:
        raise ValueError("Azure credential reference is incomplete")
    if key_id is not None and not re.fullmatch(
        re.escape(KEYCHAIN_AZURE_KEY) + r"-[0-9a-f]{32}", key_id
    ):
        raise ValueError("Azure credential reference is invalid")
    for profile in blob.get("profiles", {}).values():
        if not isinstance(profile, dict) or any(
            not isinstance(value, str) for value in profile.values()
        ):
            raise TypeError("model profiles must contain text settings")
    return blob, provider


def load_config() -> ByokConfig:
    """Load persisted BYOK config, pulling secrets back from the keychain."""
    raw = keyring_get(KEYCHAIN_SERVICE, CONFIG_KEY)
    versioned = bool(raw)
    if not raw:
        raw = keyring_get(KEYCHAIN_SERVICE, LEGACY_CONFIG_KEY)
    if not raw:
        return ByokConfig()
    try:
        blob, provider = _read_config_blob(raw)
        azure_blob = blob.get("azure", {})
    except (TypeError, ValueError) as exc:
        raise ByokConfigError(
            "The saved BYOK setup is malformed or unsupported. Re-enter setup; "
            "existing credentials have been preserved."
        ) from exc
    if versioned and azure_blob.get("credential_version") != 2:
        raise ByokConfigError(
            "The saved BYOK setup is malformed or unsupported. Re-enter setup; "
            "existing credentials have been preserved."
        )
    chatgpt_model = blob.get("chatgpt", {}).get("model", "chatgpt/gpt-6-luna")
    if isinstance(chatgpt_model, str):
        normalized_model = chatgpt_model.strip().lower()
        if normalized_model == "chatgpt/gpt-5.6" or normalized_model.startswith("chatgpt/gpt-5.6-"):
            chatgpt_model = "chatgpt/gpt-6-luna"
    chatgpt = ChatGptConfig(
        enabled=bool(blob.get("chatgpt", {}).get("enabled", False)),
        model=chatgpt_model,
    )
    azure = AzureConfig(
        endpoint=azure_blob.get("endpoint", ""),
        api_version=azure_blob.get("api_version", "2024-10-21"),
        deployment=azure_blob.get("deployment", ""),
    )
    key_id = azure_blob.get("key_id")
    if key_id is None and not versioned and azure_blob.get("credential_version") is None:
        key_id = KEYCHAIN_AZURE_KEY
    azure_key = keyring_get(KEYCHAIN_SERVICE, key_id) if key_id else None
    if azure_key:
        azure.api_key = azure_key

    profiles: dict[str, ModelProfile] = {}
    for mode, p in blob.get("profiles", {}).items():
        profiles[mode] = ModelProfile(
            name=p.get("name", PROFILE_FALLBACK), model=p.get("model", "")
        )

    return ByokConfig(provider=provider, chatgpt=chatgpt, azure=azure, profiles=profiles)


# ---------------------------------------------------------------------------
# Credential validation — a tiny test call before offering "connected".
# ChatGPT OAuth validation delegates to the engine's ``auth status``; Azure
# validation issues a minimal models list call.
# ---------------------------------------------------------------------------


def validate_chatgpt_credential() -> bool:
    """Validate the ChatGPT OAuth token by shelling into ``auth status``."""
    executable = shutil.which("lyrashield")
    if executable is None:
        return False

    try:
        result = subprocess.run(  # noqa: S603 - resolved fixed CLI with constant arguments
            [executable, "auth", "status"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def validate_azure_credential(azure: AzureConfig) -> bool:
    """Validate Azure OpenAI credentials with a tiny models/list call."""
    if not azure.is_complete():
        return False
    try:
        url = f"{azure.endpoint.rstrip('/')}/openai/models?api-version={azure.api_version}"
        resp = requests.get(
            url,
            headers={"api-key": azure.api_key},
            timeout=15,
        )
    except requests.RequestException:
        return False
    return resp.status_code == 200


def validate_credential(config: ByokConfig) -> bool:
    """Validate the active provider's credential with a tiny test call."""
    if config.provider == Provider.CHATGPT_OAUTH:
        return validate_chatgpt_credential()
    if config.provider == Provider.AZURE_OPENAI:
        return validate_azure_credential(config.azure)
    return False


def apply_env(config: ByokConfig, env: dict[str, str] | None = None) -> dict[str, str]:
    """BYOK test helper: merge provider vars into a supplied environment."""
    target = env if env is not None else dict(os.environ)
    target.update(config.to_env())
    return target


# ---------------------------------------------------------------------------
# JSON helpers (kept local to avoid importing the whole results store).
# ---------------------------------------------------------------------------


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _json_loads(raw: str) -> dict[str, Any]:
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        msg = "BYOK config blob is not an object"
        raise TypeError(msg)
    return loaded


def provider_label(provider: Provider) -> str:
    """Human-friendly provider label for the TUI."""
    if provider == Provider.CHATGPT_OAUTH:
        return "ChatGPT subscription (OAuth)"
    if provider == Provider.AZURE_OPENAI:
        return "Azure OpenAI"
    return "Local / self-hosted (experimental / coming)"


def is_launch_provider(provider: Provider) -> bool:
    """BYOK test helper: return whether a provider is a launch claim."""
    return provider in LAUNCH_PROVIDERS
