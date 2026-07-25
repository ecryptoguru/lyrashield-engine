#!/usr/bin/env bash
set -euo pipefail

# The PDF tests import pypdf and must run to exercise the viewer code path.
# A bare sync would omit the viewer extra and the gate would pass while that
# code was never exercised.
uv sync --frozen --extra viewer
uv run ruff check .
uv run ruff format --check .
uv run pytest -W error::pydantic.PydanticDeprecatedSince211
uv run mypy --exclude 'strix/interface/tui' strix lyrashield_adapter
uv run bandit -r strix lyrashield_adapter -q
