#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./setup_oauth_crons.sh [WORKSPACE_PATH]

WORKSPACE="${1:-$(pwd)}"
OPS_SCRIPTS="$WORKSPACE/ops/scripts"

TICK_NAME="OAuth Pool Router Tick (5m live)"
SYNC_NAME="OAuth Lease Sync (5m live)"

echo "[cron] adding: $TICK_NAME"
openclaw cron add \
  --agent main \
  --name "$TICK_NAME" \
  --every 5m \
  --session isolated \
  --wake now \
  --model nano \
  --timeout-seconds 300 \
  --no-deliver \
  --message "Run OAuth pool monitor tick.\n\n1) Execute: python3 $OPS_SCRIPTS/oauth_pool_router.py tick\n2) If command exits 0 and JSON ok=true, reply exactly NO_REPLY.\n3) If command fails OR JSON ok=false, return max 4 bullets: error summary + immediate recovery command." \
  --json

echo "[cron] adding: $SYNC_NAME"
openclaw cron add \
  --agent main \
  --name "$SYNC_NAME" \
  --every 5m \
  --session isolated \
  --wake now \
  --model nano \
  --timeout-seconds 120 \
  --no-deliver \
  --message "Run OAuth lease lifecycle sync.\n\n1) Execute: python3 $OPS_SCRIPTS/oauth_lease_sync.py\n2) If command exits 0 and JSON ok=true, reply exactly NO_REPLY.\n3) If command fails OR JSON ok=false, return max 4 bullets with first failing lane/state/cmd." \
  --json

echo "✅ OAuth crons configured. If you rerun this script, remove old jobs first to avoid duplicates."
