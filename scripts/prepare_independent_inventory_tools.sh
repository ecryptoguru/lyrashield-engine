#!/usr/bin/env bash
# Ephemeral GitHub-hosted Linux runner only; no deployment credentials.
set -euo pipefail
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]]
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" && ! -L /usr/bin/gh ]]
# Refuse to install through a symlink, non-root owner, or writable ancestor.
for parent in / /usr /usr/local /usr/local/lib; do
  [[ -d "$parent" && ! -L "$parent" && "$(stat -c %u "$parent")" == 0 ]]
  mode=$(stat -c %a "$parent")
  [[ "$mode" =~ ^[0-7]{3,4}$ ]]
  (( (8#$mode & 8#022) == 0 ))
done
[[ ! -e /usr/local/lib/lyrashield-inventory && ! -L /usr/local/lib/lyrashield-inventory ]]
tools_dir=$(mktemp -d "$RUNNER_TEMP/inventory-tools.XXXXXXXX")
trap 'rm -rf "$tools_dir"' EXIT
curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --connect-timeout 20 --max-time 180 --max-filesize 134217728 \
  https://github.com/cli/cli/releases/download/v2.95.0/gh_2.95.0_linux_amd64.tar.gz --output "$tools_dir/gh.tar.gz"
printf '%s  %s\n' 25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c "$tools_dir/gh.tar.gz" | sha256sum --check --status
tar -xzf "$tools_dir/gh.tar.gz" -C "$tools_dir" gh_2.95.0_linux_amd64/bin/gh
gh_binary="$tools_dir/gh_2.95.0_linux_amd64/bin/gh"
printf '%s  %s\n' 62c11fbaa08835168c3d1acf8a645ac6268a13a5682c73581388c9df0c622617 "$gh_binary" | sha256sum --check --status
sudo install -o root -g root -m 0755 "$gh_binary" /usr/bin/gh
printf '%s  %s\n' 62c11fbaa08835168c3d1acf8a645ac6268a13a5682c73581388c9df0c622617 /usr/bin/gh | sha256sum --check --status
curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --connect-timeout 20 --max-time 180 --max-filesize 536870912 \
  https://go.dev/dl/go1.27.3.linux-amd64.tar.gz --output "$tools_dir/go.tar.gz"
printf '%s  %s\n' 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 "$tools_dir/go.tar.gz" | sha256sum --check --status
sudo install -d -o root -g root -m 0755 /usr/local/lib/lyrashield-inventory
sudo tar --no-same-owner -xzf "$tools_dir/go.tar.gz" -C /usr/local/lib/lyrashield-inventory
sudo chmod -R go-w /usr/local/lib/lyrashield-inventory/go
printf '%s  %s\n' 5f5eb6d0b2fb6aa0bb5d5f8c5f1c944e0de955c925f0111af92a9d8f79680b5b /usr/local/lib/lyrashield-inventory/go/bin/go | sha256sum --check --status
python3 - <<'PYTOOL'
from pathlib import Path
from scripts.verify_sandbox_package_inventory import GO_TOOL_SHA256, trusted_tool
trusted_tool(Path("/usr/local/lib/lyrashield-inventory/go/bin/go"), GO_TOOL_SHA256)
PYTOOL
test "$(/usr/local/lib/lyrashield-inventory/go/bin/go version)" = 'go version go1.27.3 linux/amd64'
