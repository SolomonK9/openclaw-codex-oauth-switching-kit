# Public Notes — OpenClaw Codex OAuth Routing Kit

## What this package is
A technical OpenClaw routing layer for **OpenAI Codex OAuth** account pools.

It is designed for operators who:
- hit Codex account limits
- want to add more accounts instead of juggling them by hand
- need better continuity across multi-agent workflows
- want API-style operational freedom without moving to API-key infrastructure too early

## What this package is not
- Not one-click magic
- Not the full private operator-control stack
- Not every watchdog or hardening layer used in the source deployment
- Not a promise of unlimited Codex capacity

## Included
- core Codex OAuth routing engine and operator command layer
- profile capture
- lease sync
- onboarding plus Telegram reauth / bridge helpers
- lightweight install script
- core cron setup

## Not included in v1
- exec stuck watchdog
- operator anti-stall audit/dispatch
- native surface-specific ingress glue (`oauth_native_command.py`)

## User responsibility
Before use, replace placeholders and review:
- managed agent IDs
- alert targets
- Telegram target placeholders if using Telegram lifecycle flows
- lease/project mappings if using lane lifecycle integration

## Publishing / forking hygiene
Before publishing, forking, or repackaging:
- do not include live auth stores
- do not include live state, backups, or lock files
- do not include real operator IDs, chat IDs, or local machine paths
- run `./scripts/verify_safe_bundle.sh`
