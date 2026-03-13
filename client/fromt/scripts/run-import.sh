#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export SESSION_ID="fromt-import-$(date +%s)"
export OPERATION=key_import

echo "=== FROMT Key Import ==="
echo "Session: $SESSION_ID"
echo "Importing mnemonic into 2-of-3 threshold shares..."
echo ""

docker compose --env-file ../../.env up --build --abort-on-container-exit
