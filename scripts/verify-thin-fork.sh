#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest -W error::pydantic.PydanticDeprecatedSince211
uv run mypy --exclude 'strix/interface/tui' strix lyrashield_adapter
uv run bandit -r strix lyrashield_adapter -q
