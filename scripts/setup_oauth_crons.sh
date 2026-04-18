#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./setup_oauth_crons.sh [WORKSPACE_PATH]

WORKSPACE="${1:-$(pwd)}"
OPS_SCRIPTS="$WORKSPACE/ops/scripts"
OPENCLAW_BIN="${OPENCLAW_BIN:-$(command -v openclaw || true)}"
if [[ -z "$OPENCLAW_BIN" && -x "$HOME/.npm-global/bin/openclaw" ]]; then
  OPENCLAW_BIN="$HOME/.npm-global/bin/openclaw"
fi
if [[ -z "$OPENCLAW_BIN" ]]; then
  echo "[cron] error: openclaw executable not found" >&2
  exit 127
fi
export OPENCLAW_BIN

TICK_NAME="OAuth Pool Router Tick (5m live)"
SYNC_NAME="OAuth Lease Sync (5m live)"

cron_job_count() {
  local target_name="$1"
  python3 - "$target_name" <<'PYCOUNT'
import json
import os
import subprocess
import sys
name = sys.argv[1]
proc = subprocess.run([os.environ['OPENCLAW_BIN'], 'cron', 'list', '--json'], text=True, capture_output=True)
if proc.returncode != 0:
    sys.stderr.write(proc.stderr)
    raise SystemExit(proc.returncode)
obj = json.loads(proc.stdout)
jobs = obj.get('jobs', obj if isinstance(obj, list) else [])
count = sum(1 for job in jobs if isinstance(job, dict) and job.get('name') == name)
print(count)
PYCOUNT
}

maybe_add_job() {
  local name="$1"
  shift
  local count
  count="$(cron_job_count "$name")"
  if [[ "$count" == "0" ]]; then
    echo "[cron] adding: $name"
    "$OPENCLAW_BIN" cron add "$@" --json
    return 0
  fi
  if [[ "$count" == "1" ]]; then
    echo "[cron] kept existing: $name"
    return 0
  fi
  echo "[cron] warning: found $count existing jobs named '$name'; skipping add to avoid more duplicates." >&2
  return 0
}

maybe_add_job "$TICK_NAME"   --agent main   --name "$TICK_NAME"   --every 5m   --session isolated   --wake now   --model nano   --timeout-seconds 300   --no-deliver   --message "Run OAuth pool monitor tick.

1) Execute: python3 $OPS_SCRIPTS/oauth_pool_router.py tick
2) If command exits 0 and JSON ok=true, reply exactly NO_REPLY.
3) If command fails OR JSON ok=false, return max 4 bullets: error summary + immediate recovery command."

maybe_add_job "$SYNC_NAME"   --agent main   --name "$SYNC_NAME"   --every 5m   --session isolated   --wake now   --model nano   --timeout-seconds 120   --no-deliver   --message "Run OAuth lease lifecycle sync.

1) Execute: python3 $OPS_SCRIPTS/oauth_lease_sync.py
2) If command exits 0 and JSON ok=true, reply exactly NO_REPLY.
3) If command fails OR JSON ok=false, return max 4 bullets with first failing lane/state/cmd."

echo "✅ OAuth crons checked. Existing matching jobs were kept; missing ones were added."
