#!/usr/bin/env bash
set -euo pipefail

base_file=".lyrashield-upstream-base"
remote="${UPSTREAM_REMOTE:-upstream}"
output_file="${GITHUB_OUTPUT:-/dev/stdout}"

if [[ ! -s "$base_file" ]]; then
  echo "Missing $base_file" >&2
  exit 2
fi
if ! git remote get-url "$remote" >/dev/null 2>&1; then
  echo "Missing Git remote: $remote" >&2
  exit 2
fi

base_sha="$(tr -d '[:space:]' < "$base_file")"
git fetch "$remote" main --tags >&2
upstream_sha="$(git rev-parse "$remote/main")"

if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
  echo "Recorded upstream base does not name a commit: $base_sha" >&2
  exit 2
fi
if ! git merge-base --is-ancestor "$base_sha" "$upstream_sha"; then
  echo "Recorded upstream base $base_sha is not an ancestor of $upstream_sha; manual reconciliation is required" >&2
  exit 20
fi

{
  printf 'base_sha=%s\n' "$base_sha"
  printf 'upstream_sha=%s\n' "$upstream_sha"
  if [[ "$base_sha" == "$upstream_sha" ]]; then
    printf 'needs_sync=false\n'
  else
    printf 'needs_sync=true\n'
  fi
} >> "$output_file"
