# OpenClaw Codex OAuth Routing Kit — User Manual

This kit gives OpenClaw a reusable multi-account Codex OAuth routing layer with:
- lease pinning (no mid-task account switching)
- health and usage-aware routing
- manual override plus automatic mode
- background tick / lease sync automation
- session rebinding so recent sessions stop drifting behind the live top account

## 1) Install

```bash
cd ~/openclaw-oauth-switching-kit
./oauth-routing install --workspace ~/.openclaw/workspace
```

This stages the scripts into `~/.openclaw/workspace/ops/scripts`, installs a runnable shim at `~/.openclaw/workspace/ops/bin/oauth-routing`, and creates starter state safely without overwriting existing config files.

## 2) Init

```bash
./oauth-routing init --workspace ~/.openclaw/workspace
```

This generates a standard starter config, sets `managedAgents`, `usageProbe.agentId`, and `sessionRebind.agents` to a safe default (`main` unless you pass repeated `--managed-agent` flags), then validates the config immediately through `oauth_pool_router.py status --json`.

## 3) Configure

Review:
- `~/.openclaw/workspace/ops/state/oauth-pool-config.json`

Typical follow-up edits:
- `managedAgents` → change only if you run more than the default `main` agent
- `alerts.telegram.target` and/or `alerts.discord.target` if you want critical alerts
- replace placeholder values like `REPLACE_TELEGRAM_CHAT_ID` in any lifecycle script/config you plan to use

Notes:
- `sessionRebind.enabled=true` keeps recent auto-bound sessions aligned with the current winning account
- `sessionRebind.respectUserOverride=true` preserves deliberate user-set overrides
- `sessionRebind.lookbackMinutes` bounds how far back maintenance will touch sessions

## 4) Capture Codex OAuth accounts

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

## 5) Enable background automation

```bash
~/.openclaw/workspace/ops/bin/oauth-routing enable --workspace ~/.openclaw/workspace
```

Default jobs:
- OAuth Pool Router Tick
- OAuth Lease Sync

Behavior:
- the command still asks for confirmation before changing scheduler state
- reruns are duplicate-safe for these core job names: existing matching jobs are kept, missing ones are added
- if duplicate jobs already exist from an earlier broken pass, the command warns and skips adding more

Optional hardening jobs are intentionally not auto-installed in v1. Add them only after the core routing layer is working cleanly in your environment.

## 5b) Account lifecycle support

This kit includes onboarding and Telegram reauth helpers:
- `onboard_oauth_account.py`
- `oauth_telegram_reauth.py`
- `oauth_telegram_bridge.py`

These are useful if you want guided account add / reauth flows over Telegram.
If you do **not** use Telegram for this workflow, the routing core still works without these helpers.

Before using them, replace placeholder targets such as:
- `REPLACE_TELEGRAM_CHAT_ID`

in the installed script copies under:
- `~/.openclaw/workspace/ops/scripts/`

## 6) Operator commands

Public wrapper examples:

```bash
~/.openclaw/workspace/ops/bin/oauth-routing status --workspace ~/.openclaw/workspace --json
~/.openclaw/workspace/ops/bin/oauth-routing doctor --workspace ~/.openclaw/workspace
~/.openclaw/workspace/ops/bin/oauth-routing add-account --workspace ~/.openclaw/workspace --name <Label>
```

Advanced/manual bridge examples:

```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth status"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth list"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth probe"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth use <label>"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth auto"
```

What they do:
- `/oauth status` — routing state, ordering, and account health
- `/oauth list` — known accounts
- `/oauth probe` — per-profile usage refresh
- `/oauth use <label>` — force a specific account to the top
- `/oauth auto` — clear manual override and return to automatic routing

## 7) Session rebinding behavior

During `tick` / `watchdog`, the router can update recent session auth overrides when:
- the session matches the managed provider
- the override source is automatic (not an explicit user choice)
- the session is inside the configured rebinding lookback window

This closes the stale-session failure mode where auth order changed correctly but a previously auto-bound session kept using an older account.

## 8) Verification

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

## 9) Safe sharing rules

Never share:
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- any live `oauth-pool-state.json`
- `.env` or gateway tokens
- machine-specific alert targets you do not intend to disclose

Before sharing the kit:

```bash
./scripts/verify_safe_bundle.sh
```

## 10) Archive

```bash
cd ~/.openclaw/workspace/ops
tar -czf oauth-switching-kit-v1.tar.gz oauth-switching-kit
```
