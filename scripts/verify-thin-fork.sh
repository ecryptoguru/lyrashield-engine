#!/usr/bin/env bash
set -euo pipefail

# --extra viewer: the viewer's PDF export is an optional extra, but the gate must
# still exercise it (those tests skip themselves on a base install, so syncing
# without it would silently stop covering that code).
uv sync --frozen --extra viewer
uv run ruff check .
uv run ruff format --check .
uv run pytest -W error::pydantic.PydanticDeprecatedSince211
uv run mypy --exclude 'strix/interface/tui' strix lyrashield_adapter
uv run bandit -r strix lyrashield_adapter -q
