#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export SESSION_ID="fromt-spend-$(date +%s)"
export OPERATION=spend
export KEYGEN_SESSION_ID="${KEYGEN_SESSION_ID:?Set KEYGEN_SESSION_ID to the session used for key import}"
export SIGNERS="${SIGNERS:-party-1,party-2}"
export DAEMON_URL="${DAEMON_URL:-http://xmr-node.cakewallet.com:18081}"
export RECIPIENT="${RECIPIENT:?Set RECIPIENT to the destination Monero address}"
export AMOUNT="${AMOUNT:?Set AMOUNT in piconero (1 XMR = 1000000000000)}"
export BIRTHDAY="${BIRTHDAY:-0}"

echo "=== FROMT Spend ==="
echo "Session:    $SESSION_ID"
echo "Keygen:     $KEYGEN_SESSION_ID"
echo "Signers:    $SIGNERS"
echo "Daemon:     $DAEMON_URL"
echo "Recipient:  $RECIPIENT"
echo "Amount:     $AMOUNT piconero"
echo "Birthday:   $BIRTHDAY"
echo ""

docker compose --env-file ../../.env up --build -d redis relay party-1 party-2
echo "Containers started, following coordinator logs..."
echo ""

docker compose --env-file ../../.env logs -f party-1 party-2 &
LOGS_PID=$!

docker wait fromt-party-1-1 2>/dev/null || true

kill $LOGS_PID 2>/dev/null || true

EXIT_CODE=$(docker inspect fromt-party-1-1 --format='{{.State.ExitCode}}' 2>/dev/null || echo "1")
echo ""
echo "Coordinator exited with code $EXIT_CODE"

docker compose --env-file ../../.env down
exit "$EXIT_CODE"
