#!/usr/bin/env bash
set -euo pipefail

# Verify the controlled-derivative invariants:
# - pinned upstream base exists and is fetchable
# - every strix/** change vs the pinned upstream base is documented
#   (attribution banner or UPGRADES.md entry)
# - added files in strix/ are forbidden (new files must not be added to
#   upstream tree)
# - deleted files in strix/ are expected when product code moves out of strix/
#   into lyrashield/** or lyrashield_adapter/**
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

has_banner_or_ledger() {
  local f=$1
  if head -n 2 "$f" | grep -qEi "LyraShield.*(modification|seam|controlled)"; then
    return 0
  fi
  if grep -qF "$f" UPGRADES.md; then
    return 0
  fi
  return 1
}

missing=()
added=()
other=()

# Compare strix/** directly against the pinned upstream base.
# Statuses:
#   D = deleted (product file moved out of strix; expected)
#   A = added (forbidden)
#   M = modified (must have banner or UPGRADES.md entry)
#   R/C/T = rename/copy/type change (unexpected; treated as error)
while IFS=$'\t' read -r status path dest; do
  [[ -z "$status" ]] && continue
  case "$status" in
    D)
      echo "info: deleted $path (product file moved out of strix; expected)"
      ;;
    A)
      added+=("$path")
      ;;
    M)
      if ! has_banner_or_ledger "$path"; then
        missing+=("$path")
      fi
      ;;
    R*|C*)
      added+=("$dest (renamed/copied from $path)")
      if ! has_banner_or_ledger "$dest"; then
        missing+=("$dest")
      fi
      ;;
    *)
      other+=("$path (status $status)")
      ;;
  esac
done < <(git diff --name-status "$BASE..HEAD" -- strix/)

if [[ ${#added[@]} -gt 0 ]]; then
  echo "error: new files must not be added to strix/:" >&2
  for f in "${added[@]}"; do
    echo "  $f" >&2
  done
fi

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "error: undocumented strix/ modifications (add banner or UPGRADES.md entry):" >&2
  for f in "${missing[@]}"; do
    echo "  $f" >&2
  done
fi

if [[ ${#other[@]} -gt 0 ]]; then
  echo "error: unexpected strix/ diff status:" >&2
  for f in "${other[@]}"; do
    echo "  $f" >&2
  done
fi

if [[ ${#added[@]} -gt 0 || ${#missing[@]} -gt 0 || ${#other[@]} -gt 0 ]]; then
  exit 1
fi

# ---------------------------------------------------------------------------
# Footprint budget: measure strix/** drift vs the pinned upstream base and
# warn (not fail) when the delta exceeds the configured thresholds. This keeps
# accumulated drift visible without blocking legitimate work.
#
# v1.5.2 reset state: 4 files changed, 76 insertions(+), 720 deletions(-).
# The four generic seams (strix/agents/factory.py, strix/agents/prompt.py,
# strix/config/loader.py, strix/skills/__init__.py) account for the entire
# footprint. Thresholds include a small headroom for reviewed seam work.
# ---------------------------------------------------------------------------
MAX_FILES=6
MAX_INSERTIONS=100
MAX_DELETIONS=900

# git diff --shortstat prints a single line like:
#   " 4 files changed, 76 insertions(+), 720 deletions(-)"
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
