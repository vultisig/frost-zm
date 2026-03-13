#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export KEYGEN_SESSION_ID="${KEYGEN_SESSION_ID:?Set KEYGEN_SESSION_ID to the session used for keygen}"
export SESSION_ID="fromt-sign-$(date +%s)"
export OPERATION=sign
export SIGN_MESSAGE="${SIGN_MESSAGE:-fromt monero test message}"
export SIGNERS="${SIGNERS:-party-1,party-2}"

echo "=== FROMT Sign ==="
echo "Keygen session: $KEYGEN_SESSION_ID"
echo "Sign session:   $SESSION_ID"
echo "Signers: $SIGNERS"
echo "Message: $SIGN_MESSAGE"
echo ""

IFS=',' read -ra SIGNER_ARRAY <<< "$SIGNERS"
SERVICES="redis relay ${SIGNER_ARRAY[*]}"
echo "Starting services: $SERVICES"
echo ""

docker compose --env-file ../../.env up --build --abort-on-container-exit $SERVICES
