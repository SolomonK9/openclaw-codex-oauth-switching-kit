# Public Notes — OpenClaw Codex OAuth Switching Kit

## What this package is
A technical OpenClaw kit for **OpenAI Codex OAuth** account pooling and automatic switching.

It is designed for operators who:
- hit Codex/ChatGPT limits
- juggle multiple Codex-authenticated accounts
- want automatic switching and session stability
- want multi-account routing without moving to an API-key-only architecture

## What this package is not
- Not a one-click magical installer
- Not Solomon's full internal operator-control stack
- Not every watchdog/hardening layer used in the private deployment
- Not a promise of perfect or unlimited Codex capacity

## Included
- core Codex OAuth switching router + command layer
- profile capture
- lease sync
- onboarding + Telegram reauth/bridge helpers
- lightweight install script
- direct systemd user timer setup for the core router scripts
- legacy OpenClaw cron fallback setup

## Not included in v1
- private exec stuck watchdog implementation
- private operator anti-stall audit/dispatch
- native surface-specific ingress glue (`oauth_native_command.py`)

## User responsibility
Before use, replace placeholders and review:
- managed agent IDs
- alert targets
- Telegram target placeholders if using Telegram lifecycle flows
- lease/project mappings if using lane lifecycle integration

## Publishing / forking hygiene
Before publishing, forking, or repackaging:
- do not include live auth stores
- do not include live state, backups, or lock files
- do not include real operator IDs / chat IDs / home paths
- run `./scripts/verify_safe_bundle.sh`

## v2.2 public packaging focus
- Adds live 429/rate-limit aware routing: temporary throttles cool down without poisoning 5h/week capacity telemetry.
- Preserves longer existing cooldowns when duplicate/noisy throttle signals arrive.
- Broadens rate-limit detection for common provider strings such as 429, too many requests, overloaded, quota exceeded, and usage limit.
- Prefers direct systemd user timers over high-frequency OpenClaw cron wrappers.
- Adds a copy/paste `CLAW-INSTALL-PROMPT.md` so another OpenClaw agent can install and verify the kit safely.
