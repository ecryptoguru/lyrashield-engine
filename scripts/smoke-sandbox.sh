#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: smoke-sandbox.sh <image> [platform]}
platform=${2:-}
docker_args=(--rm)
if [[ -n "$platform" ]]; then
  docker_args+=(--platform "$platform")
fi

docker run "${docker_args[@]}" "$image" sh -lc '
  test "$(id -u)" != "0" &&
  test "$(pwd)" = "/workspace" &&
  test -f /app/certs/ca.p12 &&
  test ! -S /var/run/docker.sock &&
  test "$VIRTUAL_ENV" = "/app/.venv" &&
  test "$HTTP_PROXY" = "http://127.0.0.1:48080" &&
  ! sudo -n true 2>/dev/null &&
  test ! -w /etc &&
  test ! -w /usr/local/bin &&
  caido-cli --version &&
  command -v nmap >/dev/null &&
  getcap /usr/lib/nmap/nmap | grep -q "cap_net_raw" &&
  nmap --version >/dev/null 2>&1 &&
  nmap -sn 127.0.0.1 >/dev/null &&
  /app/.venv/bin/python -c "import caido_api" &&
  /app/.venv/bin/python /opt/lyrashield/verify_semgrep_pyjwt.py &&
  status="$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:48080/graphql/)" &&
  case "$status" in 200|400) exit 0 ;; *) exit 1 ;; esac
'
