#!/usr/bin/env bash
set -euo pipefail

# Verify the controlled-derivative invariants:
# - pinned upstream base exists and is fetchable
# - every strix/** modification since the last upstream import is documented
#   (attribution banner or UPGRADES.md entry)
# - footprint budget check: warns (does not fail) if strix/** drift vs the
#   pinned base exceeds the configured thresholds, so accumulated drift stays
#   visible without blocking legitimate work
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

if ! git remote get-url upstream >/dev/null 2>&1; then
  echo "info: adding upstream remote for strix" >&2
  git remote add upstream https://github.com/usestrix/strix.git
fi

if ! git cat-file -t "$BASE" >/dev/null 2>&1; then
  echo "info: upstream base $BASE not present locally; fetching" >&2
  if ! git fetch --depth=1 upstream "$BASE"; then
    echo "info: shallow fetch by SHA failed; fetching upstream/main" >&2
    git fetch upstream main || {
      echo "error: could not fetch upstream base $BASE" >&2
      exit 1
    }
  fi
  if ! git cat-file -t "$BASE" >/dev/null 2>&1; then
    echo "error: upstream base $BASE not found after fetch" >&2
    exit 1
  fi
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

# ---------------------------------------------------------------------------
# Footprint budget: measure strix/** drift vs the pinned upstream base and
# warn (not fail) when the delta exceeds the configured thresholds. This keeps
# accumulated drift visible without blocking legitimate work. The thresholds
# give ~20% headroom over the current state (68 files, +5397, -1297).
# ---------------------------------------------------------------------------
MAX_FILES=80
MAX_INSERTIONS=8000
MAX_DELETIONS=2000

# git diff --shortstat prints a single line like:
#   " 68 files changed, 5397 insertions(+), 1297 deletions(-)"
# (deletions are omitted when zero, so guard each parse).
SHORTSTAT=$(git diff --shortstat "$BASE..HEAD" -- strix/)
FP_FILES=$(echo "$SHORTSTAT" | grep -oE '[0-9]+ file' | grep -oE '[0-9]+' || echo 0)
FP_INSERTIONS=$(echo "$SHORTSTAT" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)
FP_DELETIONS=$(echo "$SHORTSTAT" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo 0)

echo "Footprint: ${FP_FILES} files, +${FP_INSERTIONS}/-${FP_DELETIONS} lines (budget: ${MAX_FILES} files, +${MAX_INSERTIONS}/-${MAX_DELETIONS})"

budget_warned=false
if (( FP_FILES > MAX_FILES )); then
  echo "warning: footprint budget exceeded — ${FP_FILES} files changed (max ${MAX_FILES})" >&2
  budget_warned=true
fi
if (( FP_INSERTIONS > MAX_INSERTIONS )); then
  echo "warning: footprint budget exceeded — ${FP_INSERTIONS} insertions (max ${MAX_INSERTIONS})" >&2
  budget_warned=true
fi
if (( FP_DELETIONS > MAX_DELETIONS )); then
  echo "warning: footprint budget exceeded — ${FP_DELETIONS} deletions (max ${MAX_DELETIONS})" >&2
  budget_warned=true
fi
if [[ "$budget_warned" == true ]]; then
  echo "warning: strix/** drift exceeds the footprint budget; review whether this drift is intentional and document it in UPGRADES.md" >&2
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
