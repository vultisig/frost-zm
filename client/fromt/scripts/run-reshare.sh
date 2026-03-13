#!/bin/bash
set -e

SESSION_ID="${SESSION_ID:-fromt-reshare-$(date +%s)}"
OPERATION=reshare

echo "=== FROMT Reshare ==="
echo "Session: $SESSION_ID"

export SESSION_ID OPERATION

docker compose up --build --abort-on-container-exit
