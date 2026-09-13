#!/bin/bash
set -e

# Two-phase startup. The container starts as root so this script can perform
# the required certificate/proxy startup mutations; it then irreversibly
# re-execs itself as the unprivileged `pentester` user (setpriv) and never
# regains privileges — the runtime image ships no sudo grant, so the agent
# cannot become root or modify protected system paths.

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

# Default outbound proxy is the in-container Caido sidecar. When the worker
# configures a scan-scoped target relay, the host bootstraps Caido's upstream
# through the local TLS bridge. Keep shell/browser proxy routing consistent;
# only the bridge's upstream configuration carries the scan grant.
PROXY_URL="${http_proxy:-http://127.0.0.1:${CAIDO_PORT}}"
# Quote shell startup assignments; proxy configuration must remain data.
printf -v PROXY_SHELL_URL '%q' "$PROXY_URL"

if [ "$(id -u)" = "0" ]; then
  # ---------------- privileged phase (root, one-shot) ----------------
  cat > /etc/profile.d/proxy.sh << EOF
export http_proxy=${PROXY_SHELL_URL}
export https_proxy=${PROXY_SHELL_URL}
export HTTP_PROXY=${PROXY_SHELL_URL}
export HTTPS_PROXY=${PROXY_SHELL_URL}
export ALL_PROXY=${PROXY_SHELL_URL}
export NO_PROXY=localhost,127.0.0.1
export AGENT_BROWSER_PROXY=${PROXY_SHELL_URL}
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EOF
  chmod 644 /etc/profile.d/proxy.sh

  cat > /etc/environment << EOF
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
HTTP_PROXY=${PROXY_URL}
HTTPS_PROXY=${PROXY_URL}
ALL_PROXY=${PROXY_URL}
NO_PROXY=localhost,127.0.0.1
AGENT_BROWSER_PROXY=${PROXY_URL}
EOF
  chmod 644 /etc/environment

  cat > /etc/wgetrc << EOF
use_proxy=yes
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
EOF
  chmod 644 /etc/wgetrc

  if [ -f /run/lyrashield-relay/upstream ]; then
    /app/.venv/bin/python /opt/lyrashield/target_relay_proxy.py &
    TARGET_RELAY_PID=$!
    TARGET_RELAY_READY=false
    for i in {1..30}; do
      if ! kill -0 "$TARGET_RELAY_PID" 2>/dev/null; then
        echo "ERROR: target relay inspection bridge failed to start."
        exit 1
      fi
      if (echo > /dev/tcp/127.0.0.1/48081) 2>/dev/null; then
        TARGET_RELAY_READY=true
        break
      fi
      sleep 1
    done
    if [ "$TARGET_RELAY_READY" != true ]; then
      echo "ERROR: target relay inspection bridge did not become ready."
      exit 1
    fi
  fi

  # Irreversible privilege drop; the agent phase re-enters this script below.
  exec setpriv --reuid=pentester --regid=pentester --init-groups \
    /usr/local/bin/docker-entrypoint.sh "$@"
fi

# ---------------- agent phase (pentester, no way back to root) ----------------

export HOME=/home/pentester

if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi

# HTTPS clients keep certificate validation enabled. The local bridge uses the
# already-installed testing CA, and the remote relay validates origin TLS.
# Caido enforces a Host allowlist (DNS-rebinding protection) and rejects requests
# whose Host header is a hostname it doesn't recognize. To reach Caido over a
# hostname (rather than an IP literal), set STRIX_CAIDO_ALLOWED_DOMAINS to a
# comma-separated list of hostnames to allow. Unset by default.
# See https://docs.caido.io/app/guides/domain_allowlist
CAIDO_UI_DOMAIN_ARGS=()
if [ -n "${STRIX_CAIDO_ALLOWED_DOMAINS:-}" ]; then
  IFS=',' read -ra _caido_domains <<< "${STRIX_CAIDO_ALLOWED_DOMAINS}"
  for _d in "${_caido_domains[@]}"; do
    [ -n "$_d" ] && CAIDO_UI_DOMAIN_ARGS+=(--ui-domain "$_d")
  done
fi

caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          "${CAIDO_UI_DOMAIN_ARGS[@]}" \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!
echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"

echo "Waiting for Caido API to be ready..."
CAIDO_READY=false
for i in {1..30}; do
  if ! kill -0 $CAIDO_PID 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API (iteration $i)."
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  if curl -s -o /dev/null -w "%{http_code}" http://localhost:${CAIDO_PORT}/graphql/ | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi
  sleep 1
done

if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status: $(kill -0 $CAIDO_PID 2>&1 && echo 'running' || echo 'dead')"
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

sleep 2

echo "Caido is up — host bootstraps the guest token + project via the Python SDK."

# Use POSIX `.` (not the bashism `source`) so these lines are safe when the rc
# files are read by a POSIX shell (e.g. `sh -lc`), which otherwise fails with
# "source: not found". `.` is understood by bash, zsh, and dash alike.
echo ". /etc/profile.d/proxy.sh" >> ~/.bashrc
echo ". /etc/profile.d/proxy.sh" >> ~/.zshrc

. /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
mkdir -p /home/pentester/.pki/nssdb
NSSDB="sql:/home/pentester/.pki/nssdb"
if [ ! -f /home/pentester/.pki/nssdb/cert9.db ]; then
    certutil -N -d "$NSSDB" --empty-password
fi
if ! certutil -L -d "$NSSDB" | grep -q "Testing Root CA"; then
    certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d "$NSSDB"
fi
echo "✅ CA added to browser trust store"

mkdir -p /workspace/.agent-browser-screenshots

echo "✅ Container ready"

cd /workspace
exec "$@"
