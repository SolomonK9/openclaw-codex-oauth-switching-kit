#!/usr/bin/env bash
set -euo pipefail

# Install direct systemd user timers for the OpenClaw Codex OAuth routing kit.
# This replaces high-frequency OpenClaw cron wrappers with low-overhead script execution.
#
# Usage:
#   ./scripts/setup_oauth_timers.sh [WORKSPACE_PATH]
#   ./scripts/setup_oauth_timers.sh --uninstall [WORKSPACE_PATH]

MODE="install"
if [[ "${1:-}" == "--uninstall" ]]; then
  MODE="uninstall"
  shift
fi

WORKSPACE="${1:-$(pwd)}"
OPS_SCRIPTS="$WORKSPACE/ops/scripts"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

TICK_SERVICE="openclaw-oauth-pool-router-tick.service"
TICK_TIMER="openclaw-oauth-pool-router-tick.timer"
SYNC_SERVICE="openclaw-oauth-lease-sync.service"
SYNC_TIMER="openclaw-oauth-lease-sync.timer"

require_systemd_user() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "❌ systemctl not found. Use scripts/setup_oauth_crons.sh as fallback."
    exit 2
  fi
  if ! systemctl --user show-environment >/dev/null 2>&1; then
    echo "❌ systemd user manager is not available in this shell."
    echo "Fallback: ./scripts/setup_oauth_crons.sh '$WORKSPACE'"
    exit 2
  fi
}

uninstall_units() {
  require_systemd_user
  systemctl --user disable --now "$TICK_TIMER" "$SYNC_TIMER" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_USER_DIR/$TICK_SERVICE" "$SYSTEMD_USER_DIR/$TICK_TIMER" "$SYSTEMD_USER_DIR/$SYNC_SERVICE" "$SYSTEMD_USER_DIR/$SYNC_TIMER"
  systemctl --user daemon-reload
  echo "✅ OAuth router user timers removed."
}

install_units() {
  require_systemd_user
  if [[ ! -f "$OPS_SCRIPTS/oauth_pool_router.py" ]]; then
    echo "❌ Missing $OPS_SCRIPTS/oauth_pool_router.py. Run install_oauth_switching.sh first."
    exit 2
  fi
  mkdir -p "$SYSTEMD_USER_DIR"

  cat > "$SYSTEMD_USER_DIR/$TICK_SERVICE" <<UNIT
[Unit]
Description=OpenClaw OAuth pool router tick
After=default.target

[Service]
Type=oneshot
WorkingDirectory=$WORKSPACE
ExecStart=$PYTHON_BIN $OPS_SCRIPTS/oauth_pool_router.py tick
Nice=5
UNIT

  cat > "$SYSTEMD_USER_DIR/$TICK_TIMER" <<UNIT
[Unit]
Description=Run OpenClaw OAuth pool router tick every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true
Unit=$TICK_SERVICE

[Install]
WantedBy=timers.target
UNIT

  cat > "$SYSTEMD_USER_DIR/$SYNC_SERVICE" <<UNIT
[Unit]
Description=OpenClaw OAuth lease sync
After=default.target

[Service]
Type=oneshot
WorkingDirectory=$WORKSPACE
ExecStart=$PYTHON_BIN $OPS_SCRIPTS/oauth_lease_sync.py
Nice=5
UNIT

  cat > "$SYSTEMD_USER_DIR/$SYNC_TIMER" <<UNIT
[Unit]
Description=Run OpenClaw OAuth lease sync every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true
Unit=$SYNC_SERVICE

[Install]
WantedBy=timers.target
UNIT

  systemctl --user daemon-reload
  systemctl --user enable --now "$TICK_TIMER" "$SYNC_TIMER"
  echo "✅ OAuth router direct user timers installed."
  systemctl --user list-timers 'openclaw-oauth-*' --no-pager || true
}

if [[ "$MODE" == "uninstall" ]]; then
  uninstall_units
else
  install_units
fi
