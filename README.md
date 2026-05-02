# OpenClaw Codex OAuth Switching Kit

Technical OpenClaw kit for **automatic OpenAI Codex OAuth account switching**.

This package is built for operators who hit **Codex/ChatGPT usage limits**, juggle multiple authenticated accounts, and want automatic routing across a shared account pool **without rebuilding everything around API keys**.

It addresses pain points like:
- manually switching between Codex-authenticated accounts when limits hit
- losing time and context during account rotation
- running multiple agents against a limited pool of OAuth-authenticated accounts
- keeping sessions aligned when the best account changes underneath the system
- avoiding API-key-only redesigns when you want to operate on top of existing Codex OAuth accounts

## What it ships
- `scripts/oauth_pool_router.py` — shared Codex OAuth pool router with health-aware selection, lease pinning, retry/quarantine logic, and session rebinding
- `scripts/oauth_command_router.py` — `/oauth ...` operator command surface
- `scripts/oauth_profile_capture.py` — capture the current Codex OAuth login into a reusable named profile
- `scripts/oauth_lease_sync.py` — lane lifecycle → lease sync bridge (disable if you do not use lane lifecycle files)
- `scripts/onboard_oauth_account.py` — add or re-auth a Codex OAuth account into the pool
- `scripts/oauth_telegram_reauth.py` — Telegram-driven reauth runner for Codex OAuth lifecycle support
- `scripts/oauth_telegram_bridge.py` — message handoff bridge used by Telegram reauth/onboarding flow
- `scripts/install_oauth_switching.sh` — install into a workspace
- `scripts/setup_oauth_timers.sh` — install direct systemd user timers for low-overhead background execution
- `scripts/setup_oauth_crons.sh` — legacy OpenClaw cron fallback when systemd user timers are unavailable
- `CLAW-INSTALL-PROMPT.md` — copy/paste handoff prompt for another OpenClaw agent to install the kit safely
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
Preferred path: direct systemd user timers. They run the router scripts directly, avoid high-frequency LLM/cron wakeups, and reduce token/session churn.

```bash
./scripts/setup_oauth_timers.sh ~/.openclaw/workspace
```

Fallback only when systemd user timers are unavailable: run `./scripts/setup_oauth_crons.sh ~/.openclaw/workspace`. Do not install both timer and cron automation.

This installs the **core** background automation only. Optional hardening jobs (verifier / safety sentinel / capacity watch) should be added separately once the core system is working cleanly in your environment.

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
- **Health-aware routing:** the router reorders accounts based on availability, verification, capacity signals, live 429/throttle cooldowns, recent timeouts, and active leases
- **Session rebinding:** recent auto-bound sessions follow the current best account without overriding explicit user choices
- **OAuth lifecycle support:** onboarding and Telegram reauth are included as part of the switching lifecycle surface
- **No private auth/state in the repo:** the package is designed to be shareable without shipping live auth stores or state files

## Give this to another OpenClaw agent
Open `CLAW-INSTALL-PROMPT.md` and paste it into the target OpenClaw. It tells the agent how to clone, verify, install, configure, and validate the kit without leaking private auth/session state.

## Before publishing or forking
```bash
./scripts/verify_safe_bundle.sh
```

## Scope note
This is a **technical OpenClaw kit**, not a magical one-click installer. It is meant for users who are comfortable editing config/templates, replacing placeholders, and running install/verify commands.

Read `USER-MANUAL.md` for full setup and operator commands.
