# Public Notes — OpenClaw Codex OAuth Routing Kit

These notes define the **public release boundary** of this repository.

They exist to answer three questions clearly:
1. **what this package is**
2. **what this package is not**
3. **what must never be shipped with it**

---

## What this package is

This is a **public, shareable OpenClaw package** for multi-account **Codex OAuth routing**.

It is designed for operators who:
- hit Codex account ceilings
- want to add more authenticated accounts instead of juggling them manually
- need better continuity across multi-agent or multi-session workflows
- want higher authenticated throughput without prematurely moving to API-key architecture

It now ships as a **guided setup-first package**, not just a loose collection of scripts.

The public slice includes:
- routing core
- operator command layer
- lifecycle helpers
- scheduler setup
- native `/oauth` plugin packaging
- guided `setup` flow
- public docs/templates

---

## What this package is not

This package is **not**:
- universal zero-friction magic for every OpenClaw environment
- proof that every private live control-plane deployment is healthy
- a dump of private operational state
- a promise of unlimited Codex capacity
- a promise of proven Windows support
- a promise of fully proven macOS support in this release

It should be described honestly as:

**a guided setup-first OAuth routing kit for OpenClaw**

not:

**magic plug-and-play for every environment**

---

## Included in the public package

### Core routing layer
- account scoring and ordering
- lease pinning
- health-/usage-aware routing
- manual override + automatic mode
- session rebinding support

### Lifecycle / operator surface
- profile capture
- account onboarding helpers
- Telegram reauth / bridge helpers
- `/oauth` command bridge
- bundled native `/oauth` plugin package

### Setup / packaging
- `oauth-routing setup`
- scheduler installation helper
- starter templates
- bundle verification script
- public docs

---

## Important product reality in v2

This release is materially different from the earlier public slice.

It now includes:
- guided `setup`
- bundled native plugin package
- supported OpenClaw plugin install/config/enable flow
- valid starter config generation
- scheduler wiring in the setup flow
- machine-readable setup summary output

That means the public package is now closer to a **real productized kit** rather than a manual operator bundle.

---

## Platform truth

Current support posture for the public slice:
- **Linux:** primary supported/proven path
- **macOS:** intended in the same flow, but not fully proven in this public release cycle
- **Windows:** not supported in this slice

Do not market Windows support.
Do not overclaim macOS proof.

---

## What a new user should reasonably expect

A Linux OpenClaw user with a reasonably normal environment should be able to:
- clone the repo
- run `./oauth-routing setup --workspace ~/.openclaw/workspace`
- get the routing kit staged
- get router config written
- get scheduler jobs installed
- get the native plugin staged and, when the environment supports it cleanly, enabled
- move on to real account onboarding

That is the honest expectation.

What should **not** be promised yet:
- perfectly seamless install for every user and every environment
- proven macOS parity
- automatic real-account onboarding without user action

---

## Public bundle hygiene rules

Before publishing, forking, tagging, or sharing, the repo must **not** include:
- live auth stores
- live state dumps
- backups / lock files / local proof artifacts
- real operator IDs or chat/channel IDs
- machine-specific local paths or runtime residue
- tokens, secrets, or private keys

Always run:

```bash
./scripts/verify_safe_bundle.sh
```

before sharing or release tagging.

---

## Safe sharing rules

Never share:
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- any live `oauth-pool-state.json`
- `.env` files or gateway tokens
- private deployment backups
- private runtime transcripts / state snapshots
- local machine-specific alert targets unless you explicitly intend to disclose them

---

## Scope boundary vs private live systems

A private live routing/control-plane deployment may still have:
- additional watchdogs
- local hardening layers
- private automation jobs
- private operational state
- temporary degradation or failure modes

That does **not** mean the public package is invalid.

The public package should be judged by its **own release boundary**, not by every private deployment detail it was derived from.

---

## Recommended framing when sharing

Use language like:

> OpenClaw Codex OAuth Routing Kit v2 is a guided setup-first package for multi-account Codex OAuth routing, with bundled native `/oauth` plugin support and Linux-proven setup flow.

Avoid language like:

> works seamlessly for everyone on any OpenClaw machine

---

## Release boundary summary

**Safe public boundary:**
- code
- docs
- templates
- packaged plugin
- setup helpers

**Unsafe private boundary:**
- auth stores
- live state
- private backups
- machine-specific ops residue
- secrets/tokens

Keep those boundaries hard.
