#!/usr/bin/env bash
set -euo pipefail

base_file=".lyrashield-upstream-base"
release_file=".lyrashield-upstream-release"
release_tag="${1:-}"
remote="${UPSTREAM_REMOTE:-upstream}"
output_file="${GITHUB_OUTPUT:-/dev/stdout}"
report_dir="${SYNC_REPORT_DIR:-${RUNNER_TEMP:-/tmp}/lyrashield-upstream-sync}"

fail() {
  echo "$1" >&2
  exit "${2:-2}"
}

if [[ ! "$release_tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  fail "Expected a stable release tag matching vMAJOR.MINOR.PATCH: ${release_tag:-<empty>}"
fi
selected_version=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")

[[ -s "$base_file" ]] || fail "Missing $base_file"
[[ -s "$release_file" ]] || fail "Missing $release_file"
git remote get-url "$remote" >/dev/null 2>&1 || fail "Missing Git remote: $remote"

recorded_tag="$(tr -d '[:space:]' < "$release_file")"
if [[ ! "$recorded_tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  fail "Recorded release is not a stable release tag: $recorded_tag"
fi
recorded_version=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")

for index in 0 1 2; do
  if ((10#${selected_version[$index]} < 10#${recorded_version[$index]})); then
    fail "Selected release $release_tag is older than recorded release $recorded_tag"
  fi
  if ((10#${selected_version[$index]} > 10#${recorded_version[$index]})); then
    break
  fi
done

if ! git diff --quiet || ! git diff --cached --quiet; then
  fail "Tracked worktree changes must be committed before syncing an upstream release"
fi

base_sha="$(tr -d '[:space:]' < "$base_file")"
git cat-file -e "${base_sha}^{commit}" 2>/dev/null || fail "Recorded base is not a commit: $base_sha"

mkdir -p "$report_dir"
git fetch --no-tags "$remote" "refs/tags/$release_tag:refs/tags/$release_tag" >&2
release_sha="$(git rev-parse "${release_tag}^{commit}")"

emit_outputs() {
  {
    printf 'needs_sync=%s\n' "$1"
    printf 'base_sha=%s\n' "$base_sha"
    printf 'release_sha=%s\n' "$release_sha"
    printf 'release_tag=%s\n' "$release_tag"
  } >> "$output_file"
}

if [[ "$release_tag" == "$recorded_tag" ]]; then
  emit_outputs false
  echo "LyraShield already includes upstream $release_tag (base $base_sha)" >&2
  exit 0
fi

git diff --binary "$base_sha" "$release_sha" > "$report_dir/upstream.patch"
if ! git apply --3way --index "$report_dir/upstream.patch"; then
  git diff --name-only --diff-filter=U > "$report_dir/conflicts.txt"
  emit_outputs true
  echo "Upstream release $release_tag requires review; conflicts are listed in $report_dir/conflicts.txt" >&2
  exit 20
fi

printf '%s\n' "$release_sha" > "$base_file"
printf '%s\n' "$release_tag" > "$release_file"

python3 - "$release_tag" "$release_sha" <<'PY'
from pathlib import Path
import re
import sys

release_tag, release_sha = sys.argv[1:]
version = release_tag.removeprefix("v")

pyproject = Path("pyproject.toml")
text = pyproject.read_text(encoding="utf-8")
updated, count = re.subn(
    r'(?m)^(version\s*=\s*)"[0-9]+\.[0-9]+\.[0-9]+(?:\.post[0-9]+)?"$',
    rf'\1"{version}.post1"',
    text,
    count=1,
)
if count != 1:
    raise SystemExit("Could not update project.version in pyproject.toml")
pyproject.write_text(updated, encoding="utf-8")

upgrades = Path("UPGRADES.md")
if upgrades.exists():
    text = upgrades.read_text(encoding="utf-8")
    release_section = f"## Current upstream release\n\n`{release_tag}`\n\n"
    if "## Current upstream release" in text:
        text, count = re.subn(
            r"## Current upstream release\n\n`[^`]+`\n\n",
            release_section,
            text,
            count=1,
        )
        if count != 1:
            raise SystemExit("Could not update current upstream release in UPGRADES.md")
    else:
        text = text.replace("## Current upstream base\n", release_section + "## Current upstream base\n", 1)
    text, count = re.subn(
        r"(## Current upstream base\n\n)`[0-9a-f]{40}`",
        rf"\1`{release_sha}`",
        text,
        count=1,
    )
    if count != 1:
        raise SystemExit("Could not update current upstream base in UPGRADES.md")
    upgrades.write_text(text, encoding="utf-8")
PY

git add "$base_file" "$release_file" pyproject.toml UPGRADES.md
emit_outputs true
echo "Applied upstream tree delta $base_sha..$release_sha for $release_tag" >&2
