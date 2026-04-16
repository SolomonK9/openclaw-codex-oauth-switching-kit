#!/usr/bin/env bash
set -euo pipefail
KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$KIT_DIR/scripts/oauth_routing_cli.py" install --workspace "${1:-$PWD}"
