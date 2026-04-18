#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path

from openclaw_resolver import OPENCLAW_BIN
from typing import Dict, Any, List

SCRIPT_DIR = Path(__file__).resolve().parent
OPS_DIR = SCRIPT_DIR.parent
STATE_DIR = OPS_DIR / 'state'
LANE_MAP = STATE_DIR / 'lane-map.json'
LIFECYCLE = STATE_DIR / 'lane-lifecycle.json'
ROUTER = SCRIPT_DIR / 'oauth_pool_router.py'
PROJECT_MAP_PATH = STATE_DIR / 'oauth-lease-project-map.json'
CONFIG_PATH = STATE_DIR / 'oauth-pool-config.json'

DEFAULT_PROJECT_MAP = {
    'lane-a': 'project-a',
    'lane-b': 'project-a',
    'lane-c': 'project-b',
    'lane-d': 'project-b',
    'lane-e': 'project-c',
}

TELEGRAM_TARGET = ''
DISCORD_TARGET = ''


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def load_project_map() -> Dict[str, str]:
    if PROJECT_MAP_PATH.exists():
        try:
            obj = json.loads(PROJECT_MAP_PATH.read_text())
            if isinstance(obj, dict):
                return {str(k): str(v) for k, v in obj.items()}
        except Exception:
            pass
    return dict(DEFAULT_PROJECT_MAP)


def load_alert_targets() -> Dict[str, str]:
    telegram = TELEGRAM_TARGET or ''
    discord = DISCORD_TARGET or ''
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
            alerts = cfg.get('alerts', {}) if isinstance(cfg, dict) else {}
            tg = alerts.get('telegram', {}) if isinstance(alerts, dict) else {}
            dc = alerts.get('discord', {}) if isinstance(alerts, dict) else {}
            if not telegram and tg.get('enabled') and tg.get('target'):
                telegram = str(tg.get('target'))
            if not discord and dc.get('enabled') and dc.get('target'):
                discord = str(dc.get('target'))
        except Exception:
            pass
    return {'telegram': telegram, 'discord': discord}


def run(cmd: List[str]) -> Dict[str, Any]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return {
        'ok': p.returncode == 0,
        'code': p.returncode,
        'cmd': ' '.join(cmd),
        'stdout': (p.stdout or '').strip(),
        'stderr': (p.stderr or '').strip(),
    }


def alert_critical(message: str) -> Dict[str, Any]:
    targets = load_alert_targets()
    out: Dict[str, Any] = {}
    tg_target = targets.get('telegram')
    dc_target = targets.get('discord')
    if tg_target:
        out['telegram'] = run([OPENCLAW_BIN, 'message', 'send', '--channel', 'telegram', '--target', tg_target, '--message', f'[OAUTH-POOL][CRITICAL] {message}'])
    else:
        out['telegram'] = {'ok': False, 'skipped': True, 'reason': 'telegram target not configured'}
    if dc_target:
        out['discord'] = run([OPENCLAW_BIN, 'message', 'send', '--channel', 'discord', '--target', dc_target, '--message', f'[OAUTH-POOL][CRITICAL] {message}'])
    else:
        out['discord'] = {'ok': False, 'skipped': True, 'reason': 'discord target not configured'}
    return out


def sync(dry_run: bool = False) -> Dict[str, Any]:
    if not ROUTER.exists():
        return {'ok': False, 'error': f'router missing: {ROUTER}'}

    lane_map = load_json(LANE_MAP, {})
    lifecycle = load_json(LIFECYCLE, {'defaultState': 'standby', 'lanes': {}})
    lanes_state = lifecycle.get('lanes', {}) if isinstance(lifecycle, dict) else {}
    default_state = lifecycle.get('defaultState', 'standby') if isinstance(lifecycle, dict) else 'standby'

    results = []
    failures = []
    project_map = load_project_map()

    for alias, session_key in sorted(lane_map.items()):
        project = project_map.get(alias)
        if not project:
            continue

        state = (lanes_state.get(session_key) or {}).get('state', default_state)
        if state == 'active':
            cmd = ['python3', str(ROUTER), 'lease-acquire', '--lane', alias, '--task-id', 'lane-session', '--project', project]
        else:
            cmd = ['python3', str(ROUTER), 'lease-release', '--lane', alias, '--task-id', 'lane-session', '--result', 'success']

        if dry_run:
            res = {'ok': True, 'dryRun': True, 'cmd': ' '.join(cmd), 'lane': alias, 'state': state}
        else:
            res = run(cmd)
            res.update({'lane': alias, 'state': state})
            if state != 'active' and (not res['ok']):
                msg = (res.get('stderr') or res.get('stdout') or '')
                if ('No active lease found' in msg) or ('No active lease for' in msg):
                    res['ok'] = True
                    res['ignored'] = 'no_active_lease'

        results.append(res)
        if not res.get('ok'):
            failures.append(res)

    out = {'ok': len(failures) == 0, 'total': len(results), 'failed': len(failures), 'results': results}
    if failures and not dry_run:
        summary = '; '.join([f"{f['lane']}->{f['state']} code={f.get('code')}" for f in failures[:4]])
        out['alerts'] = alert_critical(f'OAuth lease sync failures: {summary}')
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description='Sync lane lifecycle states to OAuth pool leases')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    out = sync(dry_run=args.dry_run)
    print(json.dumps(out, indent=2))
    return 0 if out.get('ok') else 2


if __name__ == '__main__':
    raise SystemExit(main())
