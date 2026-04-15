# OAuth Switching Kit

Portable OpenClaw kit for multi-account OAuth routing with lease pinning, health-aware failover, background maintenance, and session rebinding.

## What it ships
- `scripts/oauth_pool_router.py` — live router synced from the working controller
- `scripts/oauth_command_router.py` — `/oauth ...` bridge
- `scripts/oauth_profile_capture.py` — capture current OAuth login into a named reusable profile
- `scripts/oauth_lease_sync.py` — lane lifecycle → lease sync (disable if you do not use lane lifecycle files)
- `scripts/onboard_oauth_account.py` — add or re-auth an OAuth account into the pool
- `scripts/oauth_telegram_reauth.py` — Telegram-driven reauth runner for OAuth lifecycle support
- `scripts/oauth_telegram_bridge.py` — message handoff bridge used by Telegram reauth/onboarding flow
- `scripts/install_oauth_switching.sh` — install into a workspace
- `scripts/setup_oauth_crons.sh` — add background cron jobs
- `scripts/verify_safe_bundle.sh` — verify the kit contains no obvious local secrets/artifacts
- `templates/*.json` — starter config + lane/project mapping templates
- `USER-MANUAL.md` — operator guide
- `SHARING-CHECKLIST.md` — pre-share checklist

## Fast install
```bash
cd ~/oauth-switching-kit
./scripts/install_oauth_switching.sh ~/.openclaw/workspace
```

Then:
```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_profile_capture.py --profile-id codex-oauth-<label> --name <Label>
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py sync-profiles
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py tick
```

## Background automation
```bash
./scripts/setup_oauth_crons.sh ~/.openclaw/workspace
```

This installs the **core** background jobs only. Optional hardening jobs (verifier / safety sentinel / capacity watch) should be added separately once the core system is working in your environment.

## Key operator behavior
- **Lease pinning:** active work keeps the same profile mid-task
- **Health-aware routing:** router reorders accounts based on availability/health
- **Session rebinding:** automatic maintenance updates recent session auth overrides so stale auto-bound sessions follow the current top profile without touching explicit user overrides
- **OAuth lifecycle support:** onboarding and Telegram reauth are included as part of the switching lifecycle surface
- **Safe sharing:** no live auth store, state, backups, or machine-specific IDs should ship in the bundle

## Before sharing
```bash
./scripts/verify_safe_bundle.sh
```

If that passes, archive only the kit folder:
```bash
tar -czf oauth-switching-kit-v1.tar.gz oauth-switching-kit
```

Read `USER-MANUAL.md` for full setup and operator commands.
