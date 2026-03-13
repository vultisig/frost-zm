#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export SESSION_ID="fromt-keygen-$(date +%s)"
export OPERATION=keygen

echo "=== FROMT Keygen ==="
echo "Session: $SESSION_ID"
echo "Running 2-of-3 DKG..."
echo ""

docker compose --env-file ../../.env up --build --abort-on-container-exit
