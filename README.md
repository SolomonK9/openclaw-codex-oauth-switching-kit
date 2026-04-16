# OpenClaw Codex OAuth Routing Kit

**Smart Codex OAuth routing for OpenClaw**.

This system is built for a simple reality: **Codex account limits are not enough for serious usage**.

Instead of manually juggling accounts or getting pushed into API-key cost and infrastructure just to keep work moving, you can add more Codex-authenticated accounts and let the system automatically route work to the best available account at the moment.

That means:
- less manual switching
- better workflow continuity
- smarter account utilization
- and a much cleaner path to high-throughput OpenClaw usage without API-key architecture

If you are running multiple agents, hitting account ceilings, or trying to stretch authenticated capacity further without turning your stack into an API-billing machine, this is the control layer for that.

## What it ships
- `scripts/oauth_pool_router.py` — routing engine for account scoring, lease pinning, health-aware selection, and session rebinding
- `scripts/oauth_command_router.py` — operator command entry point for `/oauth ...` workflows
- `scripts/oauth_profile_capture.py` — capture the current Codex OAuth login into a reusable named profile
- `scripts/oauth_lease_sync.py` — keep lane/project lease state aligned with the routing layer
- `scripts/onboard_oauth_account.py` — guided account add / reauth helper for bringing accounts into the pool
- `scripts/oauth_telegram_reauth.py` — Telegram-driven reauth helper for OAuth lifecycle support
- `scripts/oauth_telegram_bridge.py` — Telegram message bridge used by the onboarding / reauth flow
- `scripts/install_oauth_switching.sh` — install the routing kit into an OpenClaw workspace
- `scripts/setup_oauth_crons.sh` — install the core background automation jobs
- `scripts/verify_safe_bundle.sh` — verify the bundle does not contain obvious secrets or local artifacts
- `templates/*.json` — starter templates for pool config and lease/project mapping
- `USER-MANUAL.md` — setup and operator guide
- `PUBLIC-NOTES.md` — public scope, boundaries, and sharing notes

## Fast install
```bash
cd ~/openclaw-oauth-switching-kit
./oauth-routing install --workspace ~/.openclaw/workspace
./oauth-routing init --workspace ~/.openclaw/workspace
```

Then:
```bash
~/.openclaw/workspace/ops/bin/oauth-routing add-account --workspace ~/.openclaw/workspace --name <Label>
~/.openclaw/workspace/ops/bin/oauth-routing status --workspace ~/.openclaw/workspace --json
```

## Background automation
```bash
~/.openclaw/workspace/ops/bin/oauth-routing enable --workspace ~/.openclaw/workspace
```

This installs the **core** background jobs only. The enable path is confirmation-gated and duplicate-safe for the default core job names: existing matching jobs are kept, missing ones are added. Optional hardening jobs should be added separately once the routing layer is working cleanly in your environment.

## Why this exists
Once usage gets serious, a single Codex-authenticated account stops being enough. The real problem is not just limits — it is the operational mess around them:
- which account still has headroom?
- which sessions are pinned to an older account?
- how do multiple agents share capacity without stepping on each other?
- how do you reauth or onboard accounts without hand-editing everything?

This kit is the control layer that fixes that mess.

## Key behavior
- **Automatic routing:** work is routed to the best available account instead of being rotated manually
- **Lease pinning:** active work stays on the same account mid-task
- **Health-aware selection:** account ordering reacts to availability, verification, and capacity signals
- **Session rebinding:** recent auto-bound sessions follow the current best account without overriding explicit user choices
- **OAuth lifecycle support:** onboarding and Telegram reauth are included as part of the account lifecycle surface
- **Shareable bundle:** the public package is designed to ship without live auth stores or machine-specific state

## Before publishing or forking
```bash
./scripts/verify_safe_bundle.sh
```

## Scope note
This is a **technical OpenClaw kit**, not one-click magic. It is meant for operators who are comfortable editing config/templates, replacing placeholders, and running install/verify commands.

Read `USER-MANUAL.md` for full setup and the new `oauth-routing` command flow.
