#!/usr/bin/env bash
set -euo pipefail

# Verify the controlled-derivative invariants:
# - pinned upstream base exists and is fetchable
# - the working strix/** tree differs only at the two reviewed generic seams
# - added, deleted, renamed, copied, or otherwise changed upstream files fail
# - the micro-fork footprint is a hard invariant
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

ALLOWED_MODIFIED=(
  "strix/config/loader.py"
  "strix/skills/__init__.py"
)
unexpected=()

# Compare the actual working tree, including staged and unstaged changes.
while IFS=$'\t' read -r status path dest; do
  [[ -z "$status" ]] && continue
  if [[ "$status" != "M" ]] || [[ ! " ${ALLOWED_MODIFIED[*]} " =~ " ${path} " ]]; then
    unexpected+=("$path (status $status${dest:+, destination $dest})")
  fi
done < <(git diff --name-status "$BASE" -- strix/)

if [[ ${#unexpected[@]} -gt 0 ]]; then
  echo "error: strix/** differs outside the reviewed micro-fork allowlist:" >&2
  for f in "${unexpected[@]}"; do
    echo "  $f" >&2
  done
  exit 1
fi

# ---------------------------------------------------------------------------
# Hard footprint invariant for the v1.5.3 micro-fork.
# ---------------------------------------------------------------------------
MAX_FILES=2
MAX_INSERTIONS=30
MAX_DELETIONS=0

# git diff --shortstat prints a single line like:
#   " 4 files changed, 76 insertions(+), 720 deletions(-)"
# (deletions are omitted when zero, so guard each parse).
SHORTSTAT=$(git diff --shortstat "$BASE" -- strix/)
FP_FILES=$(echo "$SHORTSTAT" | grep -oE '[0-9]+ file' | grep -oE '[0-9]+' || echo 0)
FP_INSERTIONS=$(echo "$SHORTSTAT" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)
FP_DELETIONS=$(echo "$SHORTSTAT" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo 0)

echo "Footprint: ${FP_FILES} files, +${FP_INSERTIONS}/-${FP_DELETIONS} lines (maximum: ${MAX_FILES} files, +${MAX_INSERTIONS}/-${MAX_DELETIONS})"

footprint_failed=false
if (( FP_FILES > MAX_FILES )); then
  echo "error: footprint exceeds ${MAX_FILES} changed files" >&2
  footprint_failed=true
fi
if (( FP_INSERTIONS > MAX_INSERTIONS )); then
  echo "error: footprint exceeds ${MAX_INSERTIONS} insertions" >&2
  footprint_failed=true
fi
if (( FP_DELETIONS > MAX_DELETIONS )); then
  echo "error: footprint exceeds ${MAX_DELETIONS} deletions" >&2
  footprint_failed=true
fi
if [[ "$footprint_failed" == true ]]; then
  exit 1
fi

# The PDF tests import pypdf and must run to exercise the viewer code path.
# A bare sync would omit the viewer extra and the gate would pass while that
# code was never exercised.
uv sync --frozen --extra viewer
uv run ruff check .
uv run ruff format --check .
uv run pytest -W error::pydantic.PydanticDeprecatedSince211
uv run mypy strix lyrashield_adapter lyrashield
uv run bandit -c pyproject.toml -r strix lyrashield_adapter lyrashield -q
