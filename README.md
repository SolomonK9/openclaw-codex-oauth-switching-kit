# OpenClaw Codex OAuth Switching Kit

**Automatic OpenAI Codex OAuth account switching for OpenClaw** — built for operators hitting usage limits, juggling multiple authenticated accounts, and trying to keep multi-agent workflows alive **without rebuilding everything around API keys**.

If your current workflow involves:
- hitting Codex/ChatGPT limits
- manually rotating accounts to keep work moving
- losing context when sessions drift across account changes
- running multiple agents against too little authenticated capacity

this kit is the operational layer that fixes that mess.

## What it ships
- `scripts/oauth_pool_router.py` — shared Codex OAuth pool router with health-aware selection, lease pinning, retry/quarantine logic, and session rebinding
- `scripts/oauth_command_router.py` — `/oauth ...` operator command surface
- `scripts/oauth_profile_capture.py` — capture the current Codex OAuth login into a reusable named profile
- `scripts/oauth_lease_sync.py` — lane lifecycle → lease sync bridge (disable if you do not use lane lifecycle files)
- `scripts/onboard_oauth_account.py` — add or re-auth a Codex OAuth account into the pool
- `scripts/oauth_telegram_reauth.py` — Telegram-driven reauth runner for Codex OAuth lifecycle support
- `scripts/oauth_telegram_bridge.py` — message handoff bridge used by Telegram reauth/onboarding flow
- `scripts/install_oauth_switching.sh` — install into a workspace
- `scripts/setup_oauth_crons.sh` — add core background cron jobs
- `scripts/verify_safe_bundle.sh` — verify the kit contains no obvious local secrets/artifacts
- `templates/*.json` — starter config + lane/project mapping templates
- `USER-MANUAL.md` — operator guide
- `PUBLIC-NOTES.md` — public scope notes

## Fast install
```bash
cd ~/openclaw-oauth-switching-kit
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

This installs the **core** background jobs only. Optional hardening jobs (verifier / safety sentinel / capacity watch) should be added separately once the core system is working cleanly in your environment.

## Why this exists
If you are running Codex-authenticated workflows, the usual pain is not just "limits" — it is the operational mess around them:
- which account still has headroom?
- which sessions are still pinned to an older account?
- how do multiple agents share a pool without stepping on each other?
- how do you reauth/onboard accounts without hand-editing everything?

This kit is the answer to that operational layer.

## Key operator behavior
- **Automatic account switching:** choose from a shared Codex OAuth pool instead of manually rotating accounts
- **Lease pinning:** active work stays on the same account mid-task
- **Health-aware routing:** the router reorders accounts based on availability, verification, and capacity signals
- **Session rebinding:** recent auto-bound sessions follow the current best account without overriding explicit user choices
- **OAuth lifecycle support:** onboarding and Telegram reauth are included as part of the switching lifecycle surface
- **No private auth/state in the repo:** the package is designed to be shareable without shipping live auth stores or state files

## Before publishing or forking
```bash
./scripts/verify_safe_bundle.sh
```

## Scope note
This is a **technical OpenClaw kit**, not a magical one-click installer. It is meant for users who are comfortable editing config/templates, replacing placeholders, and running install/verify commands.

Read `USER-MANUAL.md` for full setup and operator commands.
