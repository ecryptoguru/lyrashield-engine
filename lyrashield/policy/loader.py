# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""LyraShield product settings loader, override switch, and disk persistence."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pydantic import AliasChoices, BaseModel

from lyrashield.policy.settings import LlmSettings, Settings
from strix.config import loader as _strix_loader
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic.fields import FieldInfo


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".strix" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None

# Model, API key, and API base describe one provider connection. When the shell
# changes any of them, the stored values of the others no longer belong together
# and are dropped rather than mixed with the new value.
_LINKED_LLM_FIELDS = ("model", "api_key", "api_base")


def load_settings() -> Settings:
    """Resolve settings from env + JSON file + defaults. Memoized.

    Precedence: env vars win, then the JSON file, then field defaults.
    """
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = _override or _DEFAULT_PATH
        init_kwargs: dict[str, Any] = _read_json_overrides(source_path)
        _cached = Settings(**init_kwargs)
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(v) for v in init_kwargs.values()),
        )
    return _cached


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _override = path
    _cached = None
    logger.info("config override applied: %s", path)


def persist_current() -> None:
    """Merge currently-set env vars into the active config file (0o600).

    Values already in the file survive when their env var is unset, so a
    run that gets its settings from the file does not erase them. An env
    var set to the empty string clears the field from the file. A change to
    any linked LLM connection var drops the whole stored connection first.
    """
    s = load_settings()
    target = _override or _DEFAULT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    env_block = _drop_stale_llm_connection(_read_env_block(target))
    for sub_name in type(s).model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            active = next((alias for alias in aliases if alias in os.environ), None)
            if active is None:
                continue
            for alias in aliases:
                env_block.pop(alias, None)
            if os.environ[active]:
                env_block[active] = os.environ[active]

    with contextlib.suppress(OSError):
        write_secret_text(target, json.dumps({"env": env_block}, indent=2))


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    va = finfo.validation_alias
    if isinstance(va, AliasChoices):
        aliases.extend(c for c in va.choices if isinstance(c, str))
    elif isinstance(va, str):
        aliases.append(va)
    return aliases


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read ``{"env": {...}}`` from ``path`` and remap to nested kwargs.

    Only includes keys whose env var is NOT already set, so env always
    wins over the persisted file.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    data = cast("dict[str, Any]", data)

    env_block_upper = _drop_stale_llm_connection(_read_env_block(path))
    if not env_block_upper:
        return {}
    env_present = {k.upper() for k in os.environ}

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        sub_data: dict[str, Any] = {}
        for fname, finfo in sub_cls.model_fields.items():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            if any(alias in env_present for alias in aliases):
                continue  # env wins under some alias; skip the JSON file for this field
            for alias in aliases:
                if alias in env_block_upper:
                    sub_data[fname] = env_block_upper[alias]
                    break
        if sub_data:
            nested[sub_name] = sub_data
    return nested


def _first_alias_value(aliases: list[str], source: Mapping[str, Any]) -> Any | None:
    return next((source[alias] for alias in aliases if alias in source), None)


def _drop_stale_llm_connection(env_block: dict[str, Any]) -> dict[str, Any]:
    """Remove every linked LLM var from ``env_block`` if the shell changed any of them.

    Unlike upstream, a link group the file never stored cannot go stale: the
    product contract is secrets-in-env + reviewed-config-in-file, so ambient
    ``LLM_API_KEY`` alongside a file-supplied model stays valid.
    """
    linked_aliases = [
        [alias.upper() for alias in _aliases_for(LlmSettings.model_fields[name])]
        for name in _LINKED_LLM_FIELDS
    ]
    changed = any(
        (env_value := _first_alias_value(aliases, os.environ)) is not None
        and (stored := _first_alias_value(aliases, env_block)) is not None
        and env_value != stored
        for aliases in linked_aliases
    )
    if not changed:
        return env_block
    stale = {alias for aliases in linked_aliases for alias in aliases}
    return {k: v for k, v in env_block.items() if k not in stale}


def _read_env_block(path: Path) -> dict[str, Any]:
    """Return the ``env`` block stored in ``path`` with upper-cased keys, or ``{}``."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    env_block = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env_block, dict):
        return {}
    return {str(k).upper(): v for k, v in env_block.items()}


def _register_with_strix() -> None:
    """Register this product loader with the upstream Strix config seam."""
    _strix_loader.register_settings_loader(sys.modules[__name__])


_register_with_strix()
