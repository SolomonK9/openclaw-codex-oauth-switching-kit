#!/usr/bin/env bash
set -euo pipefail

KIT_PATH="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

echo "[verify] scanning bundle: $KIT_PATH"

if find "$KIT_PATH" \( -path "$KIT_PATH/.git" -o -path "$KIT_PATH/.git/*" \) -prune -o -type f \( -name "auth-profiles.json" -o -name ".env" -o -name "oauth-pool-state.json" -o -name "*.pyc" -o -name "*.tar.gz" -o -name "*.lock" \) -print | grep -q .; then
  echo "❌ Forbidden file detected."
  find "$KIT_PATH" \( -path "$KIT_PATH/.git" -o -path "$KIT_PATH/.git/*" \) -prune -o -type f \( -name "auth-profiles.json" -o -name ".env" -o -name "oauth-pool-state.json" -o -name "*.pyc" -o -name "*.tar.gz" -o -name "*.lock" \) -print
  exit 2
fi

if find "$KIT_PATH" \( -path "$KIT_PATH/.git" -o -path "$KIT_PATH/.git/*" \) -prune -o \( -type d -name "__pycache__" -o -type d -name "backups" -o -type d -name "snapshots" -o -type f -name ".tmp*" \) -print | grep -q .; then
  echo "❌ Bundle contains temp/cache/backup artifacts."
  find "$KIT_PATH" \( -path "$KIT_PATH/.git" -o -path "$KIT_PATH/.git/*" \) -prune -o \( -type d -name "__pycache__" -o -type d -name "backups" -o -type d -name "snapshots" -o -type f -name ".tmp*" \) -print
  exit 2
fi

# Generic heuristics only — do not hardcode one operator's private identifiers here.
PATTERN="(/home/[^/[:space:]]+)|(channel:[0-9]{8,})|(chat_id[\"'=:[:space:]]*[0-9]{8,})|([0-9]{9,})|(user-[A-Za-z0-9]{8,})"
if grep -RInE --exclude-dir=.git --exclude verify_safe_bundle.sh --exclude '*.template.json' "$PATTERN" "$KIT_PATH" >/dev/null 2>&1; then
  echo "❌ Found likely environment-specific identifier/path in bundle."
  grep -RInE --exclude-dir=.git --exclude verify_safe_bundle.sh --exclude '*.template.json' "$PATTERN" "$KIT_PATH"
  exit 2
fi

echo "✅ Safe bundle check passed."
