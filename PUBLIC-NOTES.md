# Public Notes — OAuth Switching Kit

## What this package is
A technical OpenClaw switching kit for shared multi-account OAuth routing, lease pinning, session rebinding, and basic OAuth lifecycle operations.

## What it is not
- Not a one-click magical installer
- Not Solomon's full internal operator-control stack
- Not every watchdog/hardening layer used in the private deployment

## Included
- core switching router + command layer
- profile capture
- lease sync
- onboarding + Telegram reauth/bridge helpers
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
