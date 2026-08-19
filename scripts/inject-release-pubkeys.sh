#!/usr/bin/env bash
# Fail-closed injection of public halves for a release build.
# Private keys never enter this repo. Secrets:
#   LYRASHIELD_LICENSE_PUBKEY_HEX  — 64-char hex ed25519 public key
#   LYRASHIELD_UPDATER_PUBKEY      — Tauri updater pubkey (minisign/ed25519)
set -euo pipefail

LICENSE_PUBKEY_HEX="${LYRASHIELD_LICENSE_PUBKEY_HEX:-}"
UPDATER_PUBKEY="${LYRASHIELD_UPDATER_PUBKEY:-}"
ZERO="0000000000000000000000000000000000000000000000000000000000000000"
PLACEHOLDER="LYRASHIELD_UPDATER_ED25519_PUBKEY_PLACEHOLDER"

if [ -z "${LICENSE_PUBKEY_HEX}" ] || [ "${LICENSE_PUBKEY_HEX}" = "${ZERO}" ]; then
  echo "LYRASHIELD_LICENSE_PUBKEY_HEX is missing or still the zero placeholder." >&2
  exit 1
fi
if [ -z "${UPDATER_PUBKEY}" ] || [ "${UPDATER_PUBKEY}" = "${PLACEHOLDER}" ]; then
  echo "LYRASHIELD_UPDATER_PUBKEY is missing or still the placeholder." >&2
  exit 1
fi

echo "LYRASHIELD_LICENSE_PUBKEY_HEX=${LICENSE_PUBKEY_HEX}" >> "${GITHUB_ENV:-/dev/null}"

python3 - <<PY
from pathlib import Path
import os
p = Path("desktop/src-tauri/tauri.conf.json")
text = p.read_text()
old = "LYRASHIELD_UPDATER_ED25519_PUBKEY_PLACEHOLDER"
new = os.environ["LYRASHIELD_UPDATER_PUBKEY"]
if old not in text:
    raise SystemExit("updater pubkey placeholder not found in tauri.conf.json")
p.write_text(text.replace(old, new, 1))
print("injected updater pubkey into tauri.conf.json")
PY
