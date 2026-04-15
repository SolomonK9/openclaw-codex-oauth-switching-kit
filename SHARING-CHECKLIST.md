# Sharing Checklist (No Secrets)

Before sending this kit to another person:

- [ ] Confirm the archive contains only `oauth-switching-kit/` files
- [ ] Confirm there is **no** `auth-profiles.json` in the bundle
- [ ] Confirm there is **no** `.env` in the bundle
- [ ] Confirm there is **no** live `oauth-pool-state.json` / backups / lock files / snapshots in the bundle
- [ ] Confirm template alert targets are placeholders
- [ ] Confirm lifecycle helper scripts still use placeholders like `REPLACE_TELEGRAM_CHAT_ID` rather than real operator targets
- [ ] Confirm no private chat IDs, channel IDs, usernames, or local home paths remain
- [ ] Run `./scripts/verify_safe_bundle.sh` and keep the passing output

Safe export command:

```bash
cd ~/.openclaw/workspace/ops
tar -czf oauth-switching-kit-v1.tar.gz oauth-switching-kit
```
