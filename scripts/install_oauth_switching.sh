#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./install_oauth_switching.sh [WORKSPACE_PATH]
# Default WORKSPACE_PATH: current directory

WORKSPACE="${1:-$(pwd)}"
KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPS_DIR="$WORKSPACE/ops"
SCRIPTS_DIR="$OPS_DIR/scripts"
STATE_DIR="$OPS_DIR/state"

mkdir -p "$SCRIPTS_DIR" "$STATE_DIR"

cp "$KIT_DIR/scripts/oauth_pool_router.py" "$SCRIPTS_DIR/"
cp "$KIT_DIR/scripts/oauth_command_router.py" "$SCRIPTS_DIR/"
cp "$KIT_DIR/scripts/oauth_lease_sync.py" "$SCRIPTS_DIR/"
cp "$KIT_DIR/scripts/oauth_profile_capture.py" "$SCRIPTS_DIR/"
cp "$KIT_DIR/scripts/onboard_oauth_account.py" "$SCRIPTS_DIR/"
cp "$KIT_DIR/scripts/oauth_telegram_reauth.py" "$SCRIPTS_DIR/"
cp "$KIT_DIR/scripts/oauth_telegram_bridge.py" "$SCRIPTS_DIR/"
chmod +x "$SCRIPTS_DIR"/*.py

if [[ ! -f "$STATE_DIR/oauth-pool-config.json" ]]; then
  cp "$KIT_DIR/templates/oauth-pool-config.template.json" "$STATE_DIR/oauth-pool-config.json"
  echo "[install] created $STATE_DIR/oauth-pool-config.json"
else
  echo "[install] kept existing $STATE_DIR/oauth-pool-config.json"
fi

if [[ ! -f "$STATE_DIR/oauth-lease-project-map.json" ]]; then
  cp "$KIT_DIR/templates/oauth-lease-project-map.template.json" "$STATE_DIR/oauth-lease-project-map.json"
  echo "[install] created $STATE_DIR/oauth-lease-project-map.json"
fi

python3 -m py_compile "$SCRIPTS_DIR/oauth_pool_router.py" "$SCRIPTS_DIR/oauth_command_router.py" "$SCRIPTS_DIR/oauth_lease_sync.py" "$SCRIPTS_DIR/oauth_profile_capture.py" "$SCRIPTS_DIR/onboard_oauth_account.py" "$SCRIPTS_DIR/oauth_telegram_reauth.py" "$SCRIPTS_DIR/oauth_telegram_bridge.py"

echo
echo "✅ Codex OAuth routing kit installed into: $WORKSPACE"
echo "Next steps:"
echo "1) Edit: $STATE_DIR/oauth-pool-config.json"
echo "   - set alerts.telegram/discord targets"
echo "   - set managedAgents for your setup"
echo "2) Replace placeholder targets like REPLACE_TELEGRAM_CHAT_ID if you plan to use Telegram onboarding/reauth"
echo "3) Add accounts using oauth_profile_capture.py or the onboarding flow (see USER-MANUAL.md)"
echo "4) Set up crons via: $KIT_DIR/scripts/setup_oauth_crons.sh \"$WORKSPACE\""
