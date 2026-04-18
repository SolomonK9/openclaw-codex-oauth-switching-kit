#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_openclaw_bin() -> str:
    candidates = [
        os.environ.get("OPENCLAW_BIN"),
        shutil.which("openclaw"),
        str(Path.home() / ".npm-global/bin/openclaw"),
        "/usr/local/bin/openclaw",
        "/usr/bin/openclaw",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists() and os.access(path, os.X_OK):
            return str(path)
    return "openclaw"


OPENCLAW_BIN = resolve_openclaw_bin()



def resolve_workspace(anchor: str | Path | None = None) -> Path:
    env_workspace = os.environ.get("OPENCLAW_WORKSPACE")
    if env_workspace:
        return Path(env_workspace).expanduser().resolve()
    here = Path(anchor or __file__).resolve()
    for candidate in [here.parent, *here.parents]:
        ops_dir = candidate / "ops"
        if (ops_dir / "scripts" / "oauth_pool_router.py").exists() and (ops_dir / "state").exists():
            return candidate
    return here.parent



def resolve_telegram_target(workspace: str | Path | None = None, fallback: str = "REPLACE_TELEGRAM_CHAT_ID") -> str:
    env_target = str(os.environ.get("OPENCLAW_TELEGRAM_TARGET") or "").strip()
    if env_target:
        return env_target
    base = Path(workspace).expanduser().resolve() if workspace else resolve_workspace(__file__)
    config_path = base / "ops" / "state" / "oauth-pool-config.json"
    try:
        if config_path.exists():
            import json
            obj = json.loads(config_path.read_text())
            alerts = obj.get("alerts") if isinstance(obj, dict) else {}
            telegram = alerts.get("telegram") if isinstance(alerts, dict) else {}
            target = str(telegram.get("target") or "").strip() if isinstance(telegram, dict) else ""
            if target and target != fallback:
                return target
            meta = obj.get("meta") if isinstance(obj, dict) else {}
            setup = meta.get("setup") if isinstance(meta, dict) else {}
            chat_ids = setup.get("telegramChatIds") if isinstance(setup, dict) else []
            if isinstance(chat_ids, list):
                for item in chat_ids:
                    raw = str(item or "").strip()
                    if raw:
                        return raw
    except Exception:
        pass
    return fallback
