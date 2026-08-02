#!/usr/bin/env bash
set -euo pipefail

# Verify the controlled-derivative invariants:
# - pinned upstream base exists and is fetchable
# - every strix/** modification since the last upstream import is documented
#   (attribution banner or UPGRADES.md entry)
# - lint, format, tests, types, and security checks pass

BASE_FILE=".lyrashield-upstream-base"

if [[ ! -f "$BASE_FILE" ]]; then
  echo "error: $BASE_FILE not found; pin the upstream base first" >&2
  exit 1
fi

BASE=$(tr -d '[:space:]' < "$BASE_FILE")
if [[ -z "$BASE" ]]; then
  echo "error: $BASE_FILE is empty" >&2
  exit 1
fi

if ! git cat-file -t "$BASE" >/dev/null 2>&1; then
  echo "info: upstream base $BASE not present locally; fetching from upstream remote" >&2
  git fetch --depth=1 upstream "$BASE" || {
    echo "error: could not fetch upstream base $BASE" >&2
    exit 1
  }
fi

# Find the fork commit that imported this upstream base into strix/.
# (The sync commit message mentions the upstream short SHA and touches strix/.)
SYNC_COMMIT=$(git log --all --grep="${BASE:0:7}" --format=%H -- strix/ | tail -1)
if [[ -z "$SYNC_COMMIT" ]]; then
  echo "error: cannot find fork sync commit for upstream base $BASE" >&2
  exit 1
fi

missing=()
for f in $(git diff --name-only "$SYNC_COMMIT..HEAD" -- strix/); do
  has_banner=false
  if head -n 2 "$f" | grep -q "Modifications.*LyraShield"; then
    has_banner=true
  fi
  in_ledger=false
  if grep -q "$f" UPGRADES.md; then
    in_ledger=true
  fi
  if [[ "$has_banner" == false && "$in_ledger" == false ]]; then
    missing+=("$f")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "error: undocumented strix/ modifications (add banner or UPGRADES.md entry):" >&2
  for f in "${missing[@]}"; do
    echo "  $f" >&2
  done
  exit 1
fi

# The PDF tests import pypdf and must run to exercise the viewer code path.
# A bare sync would omit the viewer extra and the gate would pass while that
# code was never exercised.
uv sync --frozen --extra viewer
uv run ruff check .
uv run ruff format --check .
uv run pytest -W error::pydantic.PydanticDeprecatedSince211
uv run mypy strix lyrashield_adapter
uv run bandit -c pyproject.toml -r strix lyrashield_adapter -q
