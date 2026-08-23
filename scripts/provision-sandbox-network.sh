#!/usr/bin/env bash
set -euo pipefail

# Provision the deny-by-default Docker sandbox network required by
# STRIX_DOCKER_SANDBOX_NETWORK. The network is created with --internal so that
# the default policy is to block all outbound egress; product/worker deployments
# must still explicitly set the environment variable before invoking lyrashield.

NETWORK_NAME="${STRIX_DOCKER_SANDBOX_NETWORK:-lyrashield-sandbox}"

if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  echo "Sandbox network already exists: $NETWORK_NAME"
  exit 0
fi

echo "Creating deny-by-default sandbox network: $NETWORK_NAME"
docker network create --internal "$NETWORK_NAME"
echo "OK. Export STRIX_DOCKER_SANDBOX_NETWORK=$NETWORK_NAME before scanning."
