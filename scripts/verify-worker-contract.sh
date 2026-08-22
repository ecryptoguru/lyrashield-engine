#!/usr/bin/env bash
set -euo pipefail

# Verify the pinned worker contract between this engine revision and the
# LyraShield worker consumer (I17):
# - the checked-out consumer revision must equal the reviewed pin
# - every declared contract test must exist in the checkout
# - the engine CLI must expose the flags the worker invokes
# - the declared contract tests must pass in the consumer checkout

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/.lyrashield-worker-pin"
tests_file="$repo_root/scripts/worker-contract-tests.txt"
app_checkout="${1:-}"

if [[ ! -f "$pin_file" || -z "$(tr -d '[:space:]' < "$pin_file")" ]]; then
  echo "Missing or empty worker-consumer pin: $pin_file" >&2
  exit 2
fi
PINNED_CONSUMER_SHA=$(tr -d '[:space:]' < "$pin_file")

if [[ -z "$app_checkout" || ! -f "$app_checkout/package.json" ]]; then
  echo "Expected a LyraShield app checkout containing package.json: ${app_checkout:-<empty>}" >&2
  exit 2
fi

# Fail before running any tests when the consumer revision is not the pinned
# one. A temporarily unavailable pinned revision is a blocked gate, never a
# reason to test against moving main.
checked_out_sha="$(git -C "$app_checkout" rev-parse HEAD 2>/dev/null || true)"
if [[ "$checked_out_sha" != "$PINNED_CONSUMER_SHA" ]]; then
  echo "Worker-consumer revision mismatch: checked out ${checked_out_sha:-<none>} but pin is $PINNED_CONSUMER_SHA" >&2
  echo "Update .lyrashield-worker-pin only through a reviewed compatibility change." >&2
  exit 2
fi
if [[ -n "$(git -C "$app_checkout" status --porcelain 2>/dev/null || true)" ]]; then
  echo "Worker-consumer checkout has local modifications; contract requires a clean checkout." >&2
  exit 2
fi

contract_tests=()
while IFS= read -r test_path; do
  [[ -z "$test_path" ]] && continue
  contract_tests+=("$test_path")
done < "$tests_file"
if [[ ${#contract_tests[@]} -eq 0 ]]; then
  echo "No contract tests declared in $tests_file" >&2
  exit 2
fi
for test_path in "${contract_tests[@]}"; do
  if [[ ! -f "$app_checkout/$test_path" ]]; then
    echo "Missing worker contract test: $test_path" >&2
    exit 2
  fi
done

if [[ -n "${LYRASHIELD_BIN:-}" ]]; then
  cli=("$LYRASHIELD_BIN")
else
  cli=(uv run lyrashield)
fi

help="$("${cli[@]}" --help)"
required_flags=(
  "--non-interactive"
  "--target"
  "--scan-mode"
  "--instruction"
  "--max-budget-usd"
)
for flag in "${required_flags[@]}"; do
  if ! grep -Fq -- "$flag" <<< "$help"; then
    echo "Missing CLI flag required by the LyraShield worker: $flag" >&2
    exit 1
  fi
done

(
  cd "$app_checkout"
  corepack pnpm install --frozen-lockfile
  DATABASE_URL="postgresql://lyrashield:lyrashield@127.0.0.1:5432/lyrashield?schema=public" \
  BETTER_AUTH_SECRET="dummy-ci-only-secret-not-a-real-credential-32chars" \
  BETTER_AUTH_URL="http://127.0.0.1:3100" \
  NEXT_PUBLIC_APP_URL="http://127.0.0.1:3100" \
  corepack pnpm exec vitest run "${contract_tests[@]}"
)
