# OpenClaw Codex OAuth Routing Kit — User Manual

This manual describes the **public productized slice** of the OAuth routing system.

It is meant to be the operator guide for the public repo, not a dump of any private live deployment.

The package gives OpenClaw a reusable multi-account Codex OAuth routing layer with:
- lease pinning (no mid-task account switching)
- health- and usage-aware ordering
- manual override plus automatic mode
- background maintenance jobs
- session rebinding support
- account onboarding / reauth helpers
- native `/oauth` plugin packaging
- a guided `setup` entrypoint

---

## 1) Primary path: `setup`

```bash
cd ~/openclaw-oauth-switching-kit
./oauth-routing setup --workspace ~/.openclaw/workspace
```

This is now the main public installation path.

### What setup does
`setup` orchestrates:
1. prerequisite checks
2. workspace staging
3. starter config generation
4. Telegram / Discord ID collection
5. router config updates
6. native plugin staging
7. supported OpenClaw plugin install/enable attempts
8. scheduler enablement (interactive default = yes)
9. validation through router status + doctor
10. final next-step output

### Interactive defaults
- channels: `both`
- managed agent: `main`
- native plugin enablement: **yes**
- scheduler enablement: **yes**

### Non-interactive / automation usage

```bash
./oauth-routing setup \
  --workspace ~/.openclaw/workspace \
  --managed-agent main \
  --channel both \
  --telegram-sender-id <telegram-user-id> \
  --telegram-chat-id <telegram-chat-id> \
  --discord-channel-id <discord-channel-id> \
  --enable-plugin \
  --enable-scheduler \
  --yes
```

### JSON summary mode
For automation / agent usage:

```bash
./oauth-routing setup ... --json
```

That returns a machine-readable summary of the setup result.

### Optional profile-scoped OpenClaw operations
If you want plugin/config operations against a specific OpenClaw profile:

```bash
./oauth-routing setup --workspace ~/.openclaw/workspace --openclaw-profile myprofile ...
```

---

## 1b) Quick operator flow

If you just want the shortest honest operator path:

1. run setup
2. add your first real account
3. run status
4. run a maintenance tick

```bash
./oauth-routing setup --workspace ~/.openclaw/workspace
~/.openclaw/workspace/ops/bin/oauth-routing add-account --workspace ~/.openclaw/workspace --name <Label>
~/.openclaw/workspace/ops/bin/oauth-routing status --workspace ~/.openclaw/workspace --json
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py tick
```

That is the shortest path from fresh install to a structurally working routing kit.

---

## 2) What `setup` writes and stages

### Router-side workspace files
`setup` writes/updates:
- `~/.openclaw/workspace/ops/state/oauth-pool-config.json`
- `~/.openclaw/workspace/ops/state/oauth-lease-project-map.json`
- `~/.openclaw/workspace/ops/bin/oauth-routing`
- `~/.openclaw/workspace/ops/scripts/*`

### Native plugin staging path
It stages:
- `~/.openclaw/workspace/plugins/oauth-native-command/*`

### Where operator/channel values are persisted
`setup` persists Telegram / Discord operator values in **two places**:
1. router config (`oauth-pool-config.json`)
2. OpenClaw plugin config for the native `/oauth` plugin

This is intentional. The router and native plugin both need aligned inputs.

---

## 3) Starter config behavior

The public setup/init flow now writes a **valid starter config**.

### Why this matters
An invalid starter config can trigger router validation rollback behavior, which makes setup appear successful while the config silently falls back to an older or default-safe state.

The public CLI now seeds a valid starter account when the template does not contain one.

### Important truth
That valid starter account is a **structural bootstrap account**, not proof that real additional accounts already exist.

You still need to onboard/capture real accounts after setup.

---

## 4) Native plugin behavior

### What the native plugin is for
The bundled plugin gives you:
- native `/oauth` handling without needing the LLM to interpret every command
- Telegram inline buttons
- refresh metadata
- a router-backed operator surface

### Supported OpenClaw path used by setup
Setup attempts the real OpenClaw plugin path:
- `openclaw plugins install <workspace/plugins/oauth-native-command>`
- `openclaw config set plugins.allow ...`
- `openclaw config set plugins.entries.oauth-native-command.config...`
- `openclaw plugins enable oauth-native-command`

### Plugin config fields
Setup configures:
- `workspacePath`
- `telegramSenderIds`
- `telegramChatIds`
- `discordChannelIds`

### Why `workspacePath` exists
The plugin may be installed into OpenClaw’s extension area, not run directly from the workspace tree.

`workspacePath` ensures the installed plugin still resolves the correct:
- router script
- router config
- router state files

### Honest fallback behavior
If the supported plugin install/enable path cannot be proven in the target environment, setup reports the plugin as:
- **staged-only**

It does **not** claim native `/oauth` is live unless that path is actually proven.

### Telegram slash command visibility
The bundled plugin is expected to register `/oauth` as a native command surface.

If the plugin is enabled but Telegram still does not show `/oauth` in the slash-command picker:
- restart the OpenClaw gateway so the updated plugin is reloaded
- reopen the Telegram chat and type `/` again

If `/oauth` still does not appear after that, treat native Telegram command registration as **not yet proven** in that environment and do not market it as working.

---

## 5) Manual commands still exist

If you want the older staged flow or need to debug a specific step manually:

### Install only
```bash
./oauth-routing install --workspace ~/.openclaw/workspace
```

### Init only
```bash
./oauth-routing init --workspace ~/.openclaw/workspace --managed-agent main
```

### Enable scheduler only
```bash
~/.openclaw/workspace/ops/bin/oauth-routing enable --workspace ~/.openclaw/workspace
```

---

## 6) Capture Codex OAuth accounts

For each real account you want to add:

```bash
openclaw models auth login --provider openai-codex
python3 ~/.openclaw/workspace/ops/scripts/oauth_profile_capture.py --profile-id codex-oauth-<label> --name <Label>
```

Then sync and run one maintenance pass:

```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py sync-profiles
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py tick
```

---

## 7) Account lifecycle support

This package includes:
- `onboard_oauth_account.py`
- `oauth_telegram_reauth.py`
- `oauth_telegram_bridge.py`

These exist to support:
- guided add-account flows
- guided reauth flows
- Telegram-driven lifecycle operations

If you do **not** use Telegram for those lifecycle flows, the routing core still works without them.

---

## 8) Native plugin package contents

After install/setup, the workspace contains:
- `plugins/oauth-native-command/index.js`
- `plugins/oauth-native-command/openclaw.plugin.json`
- `plugins/oauth-native-command/package.json`

Configured plugin schema:

```json
{
  "workspacePath": "~/.openclaw/workspace",
  "telegramSenderIds": ["<telegram-user-id>"],
  "telegramChatIds": ["<telegram-chat-id>"],
  "discordChannelIds": ["<discord-channel-id>"]
}
```

---

## 9) Operator commands

### Public wrapper examples

```bash
~/.openclaw/workspace/ops/bin/oauth-routing status --workspace ~/.openclaw/workspace --json
~/.openclaw/workspace/ops/bin/oauth-routing doctor --workspace ~/.openclaw/workspace
~/.openclaw/workspace/ops/bin/oauth-routing add-account --workspace ~/.openclaw/workspace --name <Label>
```

### Manual bridge examples

```bash
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth status"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth list"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth probe"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth use <label>"
python3 ~/.openclaw/workspace/ops/scripts/oauth_command_router.py "/oauth auto"
```

### What those commands are for
- `/oauth status` — current routing state, ordering, and health signals
- `/oauth list` — known accounts
- `/oauth probe` — refresh profile usage/health telemetry
- `/oauth use <label>` — force an account to the top manually
- `/oauth auto` — return to automatic routing mode

---

## 10) Session rebinding behavior

If you want specific control surfaces treated as privileged rebinding targets, set:
- `sessionRebind.privilegedSessionKeys`

in:
- `~/.openclaw/workspace/ops/state/oauth-pool-config.json`

During `tick` / `watchdog`, the router can update recent session auth overrides when:
- the session matches the managed provider
- the override source is automatic rather than a deliberate user override
- the session is within the configured rebinding lookback window

This is meant to reduce stale auto-bound sessions without clobbering explicit user intent.

---

## 11) Background automation

The scheduler path is available directly:

```bash
~/.openclaw/workspace/ops/bin/oauth-routing enable --workspace ~/.openclaw/workspace
```

### Intended behavior
- install the core routing jobs
- remain duplicate-safe for the default core job names
- avoid multiplying duplicate cron entries on reruns

### Important limit
This public package can install and validate its **core** background automation path.
That is **not** the same as proving every private live control-plane job in some separate deployment is healthy.

---

## 12) Verification

Recommended pass after setup or meaningful changes:

```bash
~/.openclaw/workspace/ops/bin/oauth-routing doctor --workspace ~/.openclaw/workspace
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py status --json
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py probe --json
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py tick
```

Expected outcome:
- doctor reports the staged kit correctly
- router status JSON works
- accounts become visible after capture
- `tick` exits successfully

If the native plugin was enabled successfully, you should also be able to use the native `/oauth` command surface through OpenClaw.

---

## 12b) What “up and running” means

For this package, “up and running” honestly means:
- routing kit staged into the workspace
- starter config written successfully
- scheduler path enabled successfully
- native plugin staged and, when proven, enabled
- router status JSON works
- doctor passes

It does **not** mean:
- all real accounts are already onboarded
- every private control-plane job in some other deployment is healthy
- every environment is frictionless

---

## 13) Platform truth

Current support posture for this public slice:
- **Linux:** primary supported/proven path
- **macOS:** intended in the same flow, but not yet fully proven in this public release work
- **Windows:** not supported in this slice

Do not market Windows support.
Do not oversell macOS proof if you have not actually exercised it.

---

## 14) What this package is and is not

### It is
- a guided setup-first OAuth routing kit for OpenClaw
- a public/shareable product slice
- a materially better operator experience than manual install/init stitching

### It is not
- universal zero-thought one-click magic
- proven on every OpenClaw environment
- proof that a separate private live control plane is healthy

A Linux OpenClaw user in a reasonably normal environment should have a much better install experience with this package than before.

That does **not** mean every environment will be frictionless.

---

## 15) Safe sharing rules

Never share:
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- any live `oauth-pool-state.json`
- `.env` or gateway tokens
- machine-specific alert targets you do not intend to disclose
- private deployment backups or operational state snapshots

Before sharing the kit:

```bash
./scripts/verify_safe_bundle.sh
```
