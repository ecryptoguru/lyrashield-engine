#!/usr/bin/env bash
set -euo pipefail

# Provision the deny-by-default Docker sandbox network required by
# STRIX_DOCKER_SANDBOX_NETWORK. The network is created with --internal so that
# the default policy is to block all outbound egress; product/worker deployments
# must still explicitly set the environment variable before invoking lyrashield.

NETWORK_NAME="${STRIX_DOCKER_SANDBOX_NETWORK:-lyrashield-sandbox}"

if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  echo "Sandbox network already exists: $NETWORK_NAME"
else
  echo "Creating deny-by-default sandbox network: $NETWORK_NAME"
  docker network create --driver bridge --internal \
    --opt com.docker.network.bridge.enable_icc=false "$NETWORK_NAME"
fi

# Validate pre-existing networks too. An internal network blocks outbound
# egress but may still allow sandbox containers to reach each other.
state="$(docker network inspect --format '{{.Driver}} {{.Internal}} {{index .Options "com.docker.network.bridge.enable_icc"}}' "$NETWORK_NAME")"
if [[ "$state" != "bridge true false" ]]; then
  echo "Sandbox network must be an internal bridge with inter-container communication disabled: $NETWORK_NAME ($state)" >&2
  echo "Drain workers and remove/recreate the old network with scripts/provision-sandbox-network.sh." >&2
  exit 1
fi
echo "OK. Export STRIX_DOCKER_SANDBOX_NETWORK=$NETWORK_NAME before scanning."
