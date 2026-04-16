# OpenClaw Codex OAuth Routing Kit

**Multi-account Codex OAuth routing for OpenClaw, with a guided setup path and native `/oauth` operator surface.**

This package exists for one practical reason:

**a single Codex-authenticated account is often not enough for sustained OpenClaw usage.**

Once usage becomes serious, the real problem is not just account ceilings. The real problem is the operational mess around them:
- which account still has usable headroom?
- which session is still pinned to an older account?
- how do multiple agents avoid stepping on each other?
- how do you reauth and onboard accounts without hand-editing half the system?
- how do you expose a clean operator control surface without wiring a custom stack around it?

This kit is the control layer for that.

It gives you:
- account scoring and ordering
- lease pinning so active work stays on one account mid-task
- health- and usage-aware routing
- manual override plus automatic routing mode
- background maintenance jobs
- session rebinding support
- account onboarding / reauth helpers
- a native `/oauth` plugin package for OpenClaw
- a **guided `setup` flow** instead of pure manual assembly

---

## What this package ships

### Core router / control scripts
- `scripts/oauth_pool_router.py`
  - main routing engine
  - tracks pool state
  - scores accounts
  - runs health/capacity logic
  - drives automatic account selection
  - handles session rebinding logic
- `scripts/oauth_command_router.py`
  - operator command bridge for `/oauth ...`
  - can return machine-readable JSON for plugin/operator surfaces
- `scripts/oauth_lease_sync.py`
  - keeps lease state aligned with the routing layer
- `scripts/oauth_profile_capture.py`
  - captures the current Codex OAuth login into a reusable named profile

### Account lifecycle helpers
- `scripts/onboard_oauth_account.py`
  - guided add/reauth helper
- `scripts/oauth_telegram_reauth.py`
  - Telegram-driven reauth helper
- `scripts/oauth_telegram_bridge.py`
  - Telegram bridge used by lifecycle helper flows

### Setup / packaging / ops helpers
- `scripts/oauth_routing_cli.py`
  - public CLI wrapper
  - now includes the new guided `setup` flow
- `scripts/setup_oauth_crons.sh`
  - installs the core background automation jobs
- `scripts/verify_safe_bundle.sh`
  - verifies that the public bundle is clean enough to share
- `oauth-routing`
  - top-level wrapper entrypoint

### Templates / public docs
- `templates/oauth-pool-config.template.json`
- `templates/oauth-lease-project-map.template.json`
- `USER-MANUAL.md`
- `PUBLIC-NOTES.md`

### Native OpenClaw plugin package
- `plugins/oauth-native-command/index.js`
- `plugins/oauth-native-command/openclaw.plugin.json`
- `plugins/oauth-native-command/package.json`

That plugin package is not decorative. It is part of the real public product slice.

---

## What changed in this version

This public slice is no longer just:
- `install`
- `init`
- and then a bunch of manual stitching

It now includes:
- a **guided `setup` flow**
- bundled native `/oauth` plugin packaging
- supported OpenClaw plugin install/enable attempts
- plugin config wiring through OpenClaw config
- valid starter router config generation
- scheduler setup in the same flow
- verification output at the end of setup

That means the package is now much closer to a **guided setup-first product** instead of a raw operator toolkit.

---

## Fast start

```bash
cd ~/openclaw-oauth-switching-kit
./oauth-routing setup --workspace ~/.openclaw/workspace
```

That flow now attempts to do the following in one pass:
1. verify basic prerequisites (`python3`, `openclaw`, supported OS)
2. stage the routing kit into the target workspace
3. write starter state/config files
4. collect Telegram / Discord operator IDs
5. write those values into router config
6. stage the native plugin into the workspace
7. attempt supported plugin install/enable through OpenClaw itself
8. enable the core scheduler jobs (interactive default = yes)
9. validate the resulting setup with `doctor` + router status checks
10. print the exact next step for account onboarding

After setup:

```bash
~/.openclaw/workspace/ops/bin/oauth-routing add-account --workspace ~/.openclaw/workspace --name <Label>
~/.openclaw/workspace/ops/bin/oauth-routing status --workspace ~/.openclaw/workspace --json
```

---

## The new `setup` flow

### What it is
`oauth-routing setup` is now the main public entrypoint.

### What it is trying to solve
Before `setup`, users had to think about:
- staging scripts
- writing config
- wiring managed agents
- wiring Telegram / Discord IDs
- staging the native plugin
- figuring out whether plugin enablement was even real
- enabling scheduler jobs separately

Now the package owns that flow.

### Interactive defaults
In interactive mode, setup defaults to:
- channels: `both`
- managed agent: `main`
- plugin enablement: **yes**
- scheduler enablement: **yes**

### Agent / automation usage
Setup is still flaggable for automation:

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

Optional profile-scoped plugin/config operations:

```bash
./oauth-routing setup \
  --workspace ~/.openclaw/workspace \
  --openclaw-profile myprofile \
  ...
```

### JSON mode
The public CLI also supports a machine-readable setup summary:

```bash
./oauth-routing setup ... --json
```

That mode is intended for agents and automation, not just human operators.

---

## What `setup` writes or stages

### Router-side workspace files
`setup` writes/updates:
- `~/.openclaw/workspace/ops/state/oauth-pool-config.json`
- `~/.openclaw/workspace/ops/state/oauth-lease-project-map.json`
- `~/.openclaw/workspace/ops/bin/oauth-routing`
- `~/.openclaw/workspace/ops/scripts/*`

### Native plugin staging path
It stages:
- `~/.openclaw/workspace/plugins/oauth-native-command/*`

### Important detail
The setup flow persists operator/channel inputs in **two places**:
1. router config (`oauth-pool-config.json`)
2. OpenClaw plugin config for the native `/oauth` plugin

That dual write is intentional.

---

## Native `/oauth` plugin

### What it does
The bundled native plugin provides:
- native `/oauth` handling inside OpenClaw
- Telegram inline button support
- refresh metadata support
- the same router-backed status surface used by the cleaned operator flow

### Supported OpenClaw path
Setup tries the supported OpenClaw plugin path:
- `openclaw plugins install <workspace/plugins/oauth-native-command>`
- `openclaw config set plugins.allow ...`
- `openclaw config set plugins.entries.oauth-native-command.config...`
- `openclaw plugins enable oauth-native-command`

### Plugin config values
The plugin is configured through OpenClaw config with:
- `workspacePath`
- `telegramSenderIds`
- `telegramChatIds`
- `discordChannelIds`

### Why `workspacePath` exists
This matters because the plugin may be installed by OpenClaw into its extension area rather than running directly from the workspace tree.

Without `workspacePath`, the plugin can resolve the wrong router/config/state files.

With `workspacePath`, the installed extension can still target the intended workspace.

### Honest fallback behavior
If plugin install/enable cannot be proven cleanly in the target environment, setup reports the plugin as:
- **staged-only**

It does **not** falsely claim native `/oauth` is live.

The scripted `/oauth ...` bridge still remains available in that case.

---

## Router config behavior

The public setup flow now writes a **valid starter config** instead of an empty/invalid pool configuration.

That matters because an invalid starter config can trigger router validation rollback behavior and make setup look successful while the actual written config falls back to an older safe/default state.

The public setup flow now seeds a valid starter account so router validation succeeds structurally.

That does **not** mean the user magically has multiple real accounts already onboarded.
It means the initial config is structurally valid and the system can proceed cleanly to the onboarding step.

---

## Background automation

The core scheduler flow is still available directly:

```bash
~/.openclaw/workspace/ops/bin/oauth-routing enable --workspace ~/.openclaw/workspace
```

But `setup` now includes scheduler enablement in the guided path.

### What the scheduler enable path is meant to do
- install the core routing jobs
- keep the default core jobs duplicate-safe
- avoid blindly spamming duplicate cron entries

### What it is not doing
- it is not a guarantee that every possible live ops/control-plane job in your private environment is healthy
- it is not the same thing as proving a full private production control plane is recovered

That distinction matters.

---

## Operator surfaces

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

---

## What this package is good for

This public slice is a good fit if you want:
- multi-account Codex OAuth routing
- a cleaner way to share capacity across agents
- lease pinning
- health-aware routing
- operator control through `/oauth`
- onboarding / reauth helpers
- a public bundle that does **not** ship live auth stores or private runtime state

---

## What this package is **not** claiming

It is **not** claiming:
- zero-thought magic for every OpenClaw environment
- proven Windows support
- proven macOS runtime behavior in this release
- recovery of every private live control-plane issue you may have in a separate environment

That last point is important:
**the public package can be correct while a private live routing/control-plane deployment is still degraded.**

---

## Platform truth

Current support posture for this public slice:
- **Linux:** primary supported/proven path
- **macOS:** intended in the same flow, but not fully proven in this public release work
- **Windows:** not supported in this slice

Do not market Windows support.
Do not oversell macOS proof unless you have actually exercised it.

---

## Shareability / safety

Before sharing or publishing:

```bash
./scripts/verify_safe_bundle.sh
```

The public release boundary is designed to exclude:
- live auth stores
- private environment state
- machine-specific operator residue
- local proof artifacts
- secrets/tokens

But you should still verify the bundle before every share/publish step.

---

## Reality check before sharing with a friend

A Linux OpenClaw user with a reasonably normal environment should be able to use the guided setup flow with far less manual work than before.

That is true.

What is **not** honest to claim yet is:
- “works seamlessly for everyone”
- “one-click magic”
- “proven on any OpenClaw machine”

The right framing is:

**guided setup-first OAuth routing kit for OpenClaw**

not

**universal zero-friction install for every environment**

---

## Full operator guide

Read `USER-MANUAL.md` for:
- the exact setup flow
- lifecycle helpers
- plugin packaging details
- operator commands
- verification steps
- safe sharing rules
