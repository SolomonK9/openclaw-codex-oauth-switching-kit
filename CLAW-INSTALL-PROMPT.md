# Copy/paste prompt for an OpenClaw agent

Use this prompt when you want another OpenClaw instance to install the kit for its operator.

```text
Install the OpenClaw Codex OAuth Routing Kit safely.

Repo: https://github.com/SolomonK9/OpenClaw-Codex-OAuth-Routing-Kit

Goals:
1. Clone or update the repo.
2. Run the safe bundle verification script before installing.
3. Install the kit into my OpenClaw workspace.
4. Create/keep the OAuth pool config template, but do not overwrite existing config/state.
5. Help me add OAuth profiles using the included profile capture/onboarding scripts.
6. Prefer direct systemd user timers via scripts/setup_oauth_timers.sh. If systemd user timers are unavailable, fall back to scripts/setup_oauth_crons.sh.
7. Run a router health check and one tick after configuration.
8. Report exact files changed, commands run, verification output, and anything still needing my approval.

Safety rules:
- Do not read, print, commit, upload, or share auth tokens, session stores, .env files, or live state files.
- Do not overwrite existing ops/state/oauth-pool-config.json or ops/state/oauth-pool-state.json without asking.
- Do not expose my gateway publicly.
- Ask before enabling Telegram/Discord lifecycle alerts or sending messages.
- If a command requires credentials or OAuth login, pause and guide me through the browser/terminal step.
```

Minimal command path for the agent:

```bash
git clone https://github.com/SolomonK9/OpenClaw-Codex-OAuth-Routing-Kit.git
cd OpenClaw-Codex-OAuth-Routing-Kit
./scripts/verify_safe_bundle.sh
./scripts/install_oauth_switching.sh ~/.openclaw/workspace
./scripts/setup_oauth_timers.sh ~/.openclaw/workspace
python3 ~/.openclaw/workspace/ops/scripts/oauth_pool_router.py health-check --json
```
