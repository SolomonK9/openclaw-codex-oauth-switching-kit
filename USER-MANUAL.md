# OAuth Switching Kit — User Manual

This kit gives OpenClaw a reusable multi-account OAuth pool with:
- lease pinning (no mid-task profile switching)
- health/usage-aware routing
- manual override + auto mode
- background tick / lease sync automation
- **session rebinding** so recent sessions stop drifting behind the live top profile

## 1) Install

```bash
cd ~/oauth-switching-kit
./scripts/install_oauth_switching.sh ~/.openclaw/workspace
```

This copies the scripts into `~/.openclaw/workspace/ops/scripts` and creates starter config under `~/.openclaw/workspace/ops/state`.

## 2) Configure

Edit:
- `~/.openclaw/workspace/ops/state/oauth-pool-config.json`

Minimum edits:
- `managedAgents` → your real agent IDs
- `accounts` → your captured profile IDs / names
- `alerts.telegram.target` and/or `alerts.discord.target` if you want critical alerts
- replace placeholder values like `REPLACE_TELEGRAM_CHAT_ID` in any lifecycle script/config you plan to use

Notes:
- `sessionRebind.enabled=true` keeps recent auto-bound sessions aligned with the current winning profile
- `sessionRebind.respectUserOverride=true` preserves deliberate user-set overrides
- `sessionRebind.lookbackMinutes` bounds how far back maintenance will touch sessions

## 3) Capture OAuth accounts

For each account:

```bash
openclaw models auth login --provider openai-codex
python3 ~/.openclaw/workspace/ops/scripts/oauth_profile_capture.py --profile-id codex-oauth-<label> --name <Label>
```

Then sync and run one maintenance pass:

```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py sync-profiles
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py tick
```

## 4) Enable background automation

```bash
cd ~/oauth-switching-kit
./scripts/setup_oauth_crons.sh ~/.openclaw/workspace
```

Default jobs:
- OAuth Pool Router Tick
- OAuth Lease Sync

Optional hardening jobs are intentionally not auto-installed in v1. Add them only after the core system is working cleanly in your environment.


## 4b) OAuth lifecycle support

This kit includes onboarding + Telegram reauth helpers:
- `onboard_oauth_account.py`
- `oauth_telegram_reauth.py`
- `oauth_telegram_bridge.py`

These are useful if you want guided account add/reauth flows over Telegram.
If you do **not** use Telegram for this workflow, the switching core still works without using these helpers.

Before using them, replace placeholder targets such as:
- `REPLACE_TELEGRAM_CHAT_ID`

in the installed script copies under:
- `~/.openclaw/workspace/ops/scripts/`

## 5) Operator commands

Terminal bridge examples:

```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth status"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth list"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth probe"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth use <label>"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth auto"
```

What they do:
- `/oauth status` — router state + ordering + account health
- `/oauth list` — known accounts
- `/oauth probe` — per-profile usage refresh
- `/oauth use <label>` — force a specific profile to the top
- `/oauth auto` — clear manual override and return to automatic routing

## 6) Session rebinding behavior

During `tick` / `watchdog`, the router can update recent session auth overrides when:
- the session matches the managed provider
- the override source is automatic (not explicit user choice)
- the session is inside the configured rebinding lookback window

This closes the stale-session failure mode where auth order changed correctly but a previously auto-bound session kept using an older profile.

## 7) Verification

Recommended pass after install or changes:

```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py status --json
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py probe --json
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py tick
```

Expected outcome:
- accounts visible
- no obvious missing-profile or cooldown drift
- `tick` exits successfully

## 8) Safe sharing rules

Never share:
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- any live `oauth-pool-state.json`
- `.env` or gateway tokens
- machine-specific alert targets you do not intend to disclose

Before sharing the kit:

```bash
./scripts/verify_safe_bundle.sh
```

## 9) Archive

```bash
cd ~/.openclaw/workspace/ops
tar -czf oauth-switching-kit-v1.tar.gz oauth-switching-kit
```
