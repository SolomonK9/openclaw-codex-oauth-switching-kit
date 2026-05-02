# Release Notes — v2.2.0

## Headline

Public packaging update for the OpenClaw Codex OAuth Routing Kit focused on live 429/rate-limit resilience and low-overhead background execution.

## Added

- Live rate-limit/throttle state in `oauth_pool_router.py`:
  - temporary `liveFailover` cooldown state per profile
  - `throttleHealth` summary per profile
  - route demotion for recently hot/throttled profiles
  - duplicate noisy events cannot shorten a longer existing cooldown
- Broader provider error normalization:
  - `429`
  - `rate_limit` / `ratelimit`
  - `too many requests` / `TooManyRequests`
  - `overloaded`
  - `quota exceeded`
  - `usage limit`
- Direct systemd user timer installer:
  - `scripts/setup_oauth_timers.sh`
  - preferred over high-frequency OpenClaw cron wrappers
  - keeps `scripts/setup_oauth_crons.sh` as fallback
- Copy/paste install handoff for another OpenClaw agent:
  - `CLAW-INSTALL-PROMPT.md`
- Focused public tests:
  - `tests/test_rate_limit_routing.py`

## Changed

- Installer now recommends direct timers first and cron fallback second.
- README/User Manual now explain timer-first automation and rate-limit behavior.
- Safe-bundle verification now ignores `.git/` internals so checks work inside a cloned repo.
- Public defaults in helper scripts use generic `project-a/project-b/project-c` instead of private project labels.

## Safety model

This release still does **not** include live auth stores, live state, tokens, gateway config, session stores, or private operator watchdogs.

## Verification run

Validated locally with:

```bash
bash -n scripts/install_oauth_switching.sh scripts/setup_oauth_timers.sh scripts/setup_oauth_crons.sh scripts/verify_safe_bundle.sh
python3 -m py_compile scripts/*.py tests/test_rate_limit_routing.py
python3 -m unittest tests.test_rate_limit_routing -v
./scripts/install_oauth_switching.sh <temp-workspace>
python3 <temp-workspace>/ops/scripts/oauth_pool_router.py status --json
python3 <temp-workspace>/ops/scripts/oauth_pool_router.py health-check --json
./scripts/verify_safe_bundle.sh .
git diff --check
```
