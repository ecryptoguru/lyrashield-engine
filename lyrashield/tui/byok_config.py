# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""BYOK configuration for LyraShield Local.

Friendly setup that maps onto the engine's existing routing. Launch providers:

* **ChatGPT subscription OAuth** — token stored in the OS keychain via the
  ``keyring`` library (never a plaintext file). Routed through the engine's
  Codex/ChatGPT subscription path (``chatgpt/<model>``).
* **Azure OpenAI** — ``AZURE_OPENAI_API_KEY`` / ``AZURE_OPENAI_ENDPOINT`` /
  ``AZURE_OPENAI_API_VERSION``. The API key is stored in the OS keychain and
  surfaced to the engine via environment variables at scan time.

Local/self-hosted models are hidden from the launch surface and marked
"experimental / coming soon" — they are never a launch claim.

A per-scan-mode model profile (LUNA/TERRA/fallback) is persisted locally and
applied when the TUI shells into the engine CLI.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from lyrashield.tui.results_store import keyring_get, keyring_set


if TYPE_CHECKING:
    pass


logger = logging.getLogger(__name__)


# Keychain service names. Never write secrets to plaintext files.
KEYCHAIN_SERVICE = "LyraShield-Local"
KEYCHAIN_CHATGPT_TOKEN = "chatgpt-oauth-token"
KEYCHAIN_AZURE_KEY = "azure-openai-api-key"

# Model profile names mirror the engine's LUNA/TERRA deployment naming.
PROFILE_LUNA = "luna"
PROFILE_TERRA = "terra"
PROFILE_FALLBACK = "fallback"


class Provider(str, Enum):
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
        return bool(self.api_key and self.endpoint)

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

    The access token is stored in the OS keychain. The engine's existing
    ``lyrashield auth login chatgpt`` flow performs the OAuth dance; this
    config records that the provider is selected and which model profile to
    route through the subscription.
    """

    enabled: bool = False
    model: str = "chatgpt/gpt-5.6"

    def to_env(self) -> dict[str, str]:
        if not self.enabled:
            return {}
        return {"LYRASHIELD_LLM": self.model}


@dataclass
class ModelProfile:
    """Per-scan-mode model profile (LUNA/TERRA/fallback)."""

    name: str = PROFILE_FALLBACK
    # The engine model string (e.g. ``gpt-5.6-luna``, ``azure/<dep>``).
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

CONFIG_KEY = "byok-config-v1"


def save_config(config: ByokConfig) -> None:
    """Persist non-secret BYOK config. Secrets go to the keychain."""
    # Store the Azure API key in the keychain, not in the config blob.
    if config.azure.api_key:
        keyring_set(KEYCHAIN_SERVICE, KEYCHAIN_AZURE_KEY, config.azure.api_key)
    # ChatGPT token is managed by the engine's own auth flow; we only record
    # that the provider is enabled.
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
        },
        "profiles": {
            mode: {"name": p.name, "model": p.model} for mode, p in config.profiles.items()
        },
    }
    keyring_set(KEYCHAIN_SERVICE, CONFIG_KEY, _json_dumps(blob))


def load_config() -> ByokConfig:
    """Load persisted BYOK config, pulling secrets back from the keychain."""
    raw = keyring_get(KEYCHAIN_SERVICE, CONFIG_KEY)
    if not raw:
        return ByokConfig()
    try:
        blob = _json_loads(raw)
    except Exception:  # noqa: BLE001
        logger.warning("BYOK config blob unreadable; returning defaults")
        return ByokConfig()

    provider = Provider(blob.get("provider", Provider.CHATGPT_OAUTH.value))
    chatgpt = ChatGptConfig(
        enabled=bool(blob.get("chatgpt", {}).get("enabled", False)),
        model=blob.get("chatgpt", {}).get("model", "chatgpt/gpt-5.6"),
    )
    azure_blob = blob.get("azure", {})
    azure = AzureConfig(
        endpoint=azure_blob.get("endpoint", ""),
        api_version=azure_blob.get("api_version", "2024-10-21"),
        deployment=azure_blob.get("deployment", ""),
    )
    azure_key = keyring_get(KEYCHAIN_SERVICE, KEYCHAIN_AZURE_KEY)
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
    import subprocess  # noqa: PLC0415

    try:
        result = subprocess.run(  # noqa: S603
            ["lyrashield", "auth", "status"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return False
    return result.returncode == 0


def validate_azure_credential(azure: AzureConfig) -> bool:
    """Validate Azure OpenAI credentials with a tiny models/list call."""
    if not azure.is_complete():
        return False
    try:
        import requests  # noqa: PLC0415

        url = f"{azure.endpoint.rstrip('/')}/openai/models?api-version={azure.api_version}"
        resp = requests.get(  # noqa: S113
            url,
            headers={"api-key": azure.api_key},
            timeout=15,
        )
    except Exception:  # noqa: BLE001
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
    """Apply BYOK env vars into ``env`` (defaults to ``os.environ`` copy)."""
    target = env if env is not None else dict(os.environ)
    target.update(config.to_env())
    return target


# ---------------------------------------------------------------------------
# JSON helpers (kept local to avoid importing the whole results store).
# ---------------------------------------------------------------------------


def _json_dumps(obj: Any) -> str:
    import json  # noqa: PLC0415

    return json.dumps(obj, separators=(",", ":"))


def _json_loads(raw: str) -> dict[str, Any]:
    import json  # noqa: PLC0415

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
    if provider == Provider.LOCAL_SELF_HOSTED:
        return "Local / self-hosted (experimental / coming)"
    return provider.value


def is_launch_provider(provider: Provider) -> bool:
    """Return whether a provider is a launch claim."""
    return provider in LAUNCH_PROVIDERS
