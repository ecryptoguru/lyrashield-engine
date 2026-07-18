#!/usr/bin/env bash
set -euo pipefail

app_checkout="${1:-}"
if [[ -z "$app_checkout" || ! -f "$app_checkout/package.json" ]]; then
  echo "Expected a LyraShield app checkout containing package.json: ${app_checkout:-<empty>}" >&2
  exit 2
fi

contract_tests=(
  "apps/worker/src/engine/command-builder.test.ts"
  "apps/worker/src/engine/output-parser.test.ts"
)
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
  corepack enable
  pnpm install --frozen-lockfile
  pnpm exec vitest run "${contract_tests[@]}"
)
