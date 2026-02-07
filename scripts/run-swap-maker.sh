#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

. scripts/_env.sh

# Dev-oriented swap maker/service peer.
# - joins the public OTC channel (RFQ/quotes)
# - requires invites for swap:* channels (confidential private negotiations)
#
# Notes:
# - Welcome enforcement is disabled here to keep OTC join friction low. For stricter authenticity,
#   remove `--sidechannel-welcome-required 0` and distribute owner+welcome for the OTC channel.
#
# Usage:
#   scripts/run-swap-maker.sh [storeName] [scBridgePort] [otcChannel]

STORE_NAME="${1:-swap-maker}"
SC_PORT="${2:-49222}"
OTC_CHANNEL="${3:-0000intercomswapbtcusdt}"

SIDECHANNEL_POW="${SIDECHANNEL_POW:-1}"
SIDECHANNEL_POW_DIFFICULTY="${SIDECHANNEL_POW_DIFFICULTY:-12}"

TOKEN_DIR="onchain/sc-bridge"
TOKEN_FILE="${TOKEN_DIR}/${STORE_NAME}.token"
mkdir -p "$TOKEN_DIR"
if [[ ! -f "$TOKEN_FILE" ]]; then
  token="$(
    openssl rand -hex 32 2>/dev/null || \
    node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  )"
  printf '%s\n' "$token" >"$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE" 2>/dev/null || true
fi
SC_TOKEN="$(tr -d '\r\n' <"$TOKEN_FILE")"

exec pear run . \
  --peer-store-name "$STORE_NAME" \
  --msb 0 \
  --price-oracle 1 \
  --sc-bridge 1 \
  --sc-bridge-token "$SC_TOKEN" \
  --sc-bridge-port "$SC_PORT" \
  --sidechannels "$OTC_CHANNEL" \
  --sidechannel-pow "$SIDECHANNEL_POW" \
  --sidechannel-pow-difficulty "$SIDECHANNEL_POW_DIFFICULTY" \
  --sidechannel-welcome-required 0 \
  --sidechannel-invite-required 1 \
  --sidechannel-invite-prefixes "swap:"
