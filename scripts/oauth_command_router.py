#!/usr/bin/env python3
"""
Simple command bridge for manual OAuth switching.

Examples:
  python3 ops/scripts/oauth_command_router.py "/oauth list"
  python3 ops/scripts/oauth_command_router.py "/oauth use Demo"
  python3 ops/scripts/oauth_command_router.py "/oauth use codex-oauth-demo"
  python3 ops/scripts/oauth_command_router.py "/oauth auto"
  python3 ops/scripts/oauth_command_router.py "/oauth status"
  python3 ops/scripts/oauth_command_router.py "/oauth probe"
"""

from __future__ import annotations
import os
import json
import shlex
import subprocess
import sys
import argparse
from pathlib import Path

from openclaw_resolver import OPENCLAW_BIN

SCRIPT_DIR = Path(__file__).resolve().parent
OPS_DIR = SCRIPT_DIR.parent
ROUTER = SCRIPT_DIR / 'oauth_pool_router.py'
DEFAULT_WORKSPACE = Path(os.environ.get('OPENCLAW_WORKSPACE', str(Path.home() / '.openclaw/workspace'))).expanduser().resolve()


def workspace_dir() -> Path:
    if OPS_DIR.name == 'ops' and (OPS_DIR / 'state').exists():
        return OPS_DIR.parent
    return DEFAULT_WORKSPACE


def config_path() -> Path:
    direct = OPS_DIR / 'state' / 'oauth-pool-config.json'
    if direct.exists() and OPS_DIR.name == 'ops':
        return direct
    candidate = workspace_dir() / 'ops' / 'state' / 'oauth-pool-config.json'
    if candidate.exists():
        return candidate
    return direct


def run(cmd, timeout: int = 60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or '').strip(), (p.stderr or '').strip()
    except subprocess.TimeoutExpired as e:
        so = (e.stdout or '').strip() if isinstance(e.stdout, str) else ''
        se = (e.stderr or '').strip() if isinstance(e.stderr, str) else ''
        return 124, so, (se or f'timeout after {timeout}s')


def load_accounts():
    obj = json.loads(config_path().read_text())
    return obj.get('accounts', [])


def resolve_profile(token: str):
    token_l = token.strip().lower()
    for a in load_accounts():
        pid = str(a.get('profileId', ''))
        name = str(a.get('name', ''))
        if token_l in (pid.lower(), name.lower()):
            return pid
    return None


def set_order(target_pid: str):
    accounts = [a for a in load_accounts() if a.get('enabled', True)]
    ordered = [target_pid] + [a['profileId'] for a in accounts if a.get('profileId') != target_pid]
    return run([OPENCLAW_BIN, 'models', 'auth', 'order', 'set', '--provider', 'openai-codex', '--agent', 'main', *ordered])


def cmd_list():
    rows = []
    for a in load_accounts():
        rows.append({
            'name': a.get('name') or a.get('profileId'),
            'profileId': a.get('profileId'),
            'enabled': bool(a.get('enabled', True)),
            'priority': a.get('priority', 1),
        })
    print(json.dumps({'ok': True, 'accounts': rows}, indent=2))


def cmd_use(token: str, force: bool = False):
    pid = resolve_profile(token)
    if not pid:
        print(json.dumps({'ok': False, 'error': f'unknown account: {token}'}, indent=2))
        return 1

    rc_s, so_s, _ = run(['python3', str(ROUTER), 'status', '--json'])
    if rc_s == 0 and so_s:
        try:
            st = json.loads(so_s)
            acc = (st.get('accounts') or {}).get(pid, {})
            u = acc.get('usage', {})
            week = u.get('weekRemaining')
            five = u.get('fiveHourRemaining')
            exhausted = (isinstance(week, (int, float)) and float(week) <= 0.0) or (isinstance(five, (int, float)) and float(five) <= 0.0)
            if exhausted and not force:
                print(json.dumps({
                    'ok': False,
                    'error': 'target account exhausted (weekly or 5h). pass --force to override anyway',
                    'profileId': pid,
                    'weekRemaining': week,
                    'fiveHourRemaining': five,
                }, indent=2))
                return 2
        except Exception:
            pass

    rc1, so1, se1 = run(['python3', str(ROUTER), 'override', 'set', '--profile', pid])
    rc2, so2, se2 = set_order(pid)

    out = {'ok': rc1 == 0 and rc2 == 0, 'profileId': pid, 'override': {'code': rc1, 'stdout': so1, 'stderr': se1}, 'authOrder': {'code': rc2, 'stdout': so2, 'stderr': se2}}
    print(json.dumps(out, indent=2))
    return 0 if out['ok'] else 2


def cmd_auto():
    rc1, so1, se1 = run(['python3', str(ROUTER), 'override', 'clear'])
    rc2, so2, se2 = run(['python3', str(ROUTER), 'tick'], timeout=240)
    out = {'ok': rc1 == 0 and rc2 == 0, 'overrideClear': {'code': rc1, 'stdout': so1, 'stderr': se1}, 'tick': {'code': rc2, 'stdout': so2, 'stderr': se2}}
    print(json.dumps(out, indent=2))
    return 0 if out['ok'] else 2




def shell_workspace() -> str:
    return str(workspace_dir())


def routing_shim() -> str:
    return str(workspace_dir() / 'ops' / 'bin' / 'oauth-routing')


def cmd_reauth(token: str):
    pid = resolve_profile(token)
    if not pid:
        print(json.dumps({'ok': False, 'error': f'unknown account: {token}'}, indent=2))
        return 1
    accounts = {str(a.get('profileId')): a for a in load_accounts()}
    acc = accounts.get(pid, {})
    name = str(acc.get('name') or pid)
    cmd = f"{routing_shim()} add-account --workspace {shell_workspace()} --name {json.dumps(name)} --reauth"
    msg = (
        '🔐 REAUTH VIA TERMINAL\n'
        f'Account: {name}\n'
        f'Profile: {pid}\n\n'
        'Start was selected from Telegram. Finish it in terminal with:\n'
        f'{cmd}\n\n'
        'This flow is terminal-only. Do not send callback URLs here.'
    )
    print(json.dumps({'ok': True, 'command': 'reauth', 'profileId': pid, 'name': name, 'terminalCommand': cmd, 'message': msg}, indent=2))
    return 0


def cmd_add():
    cmd = f"{routing_shim()} add-account --workspace {shell_workspace()} --name <Label>"
    msg = (
        '➕ ADD ACCOUNT VIA TERMINAL\n\n'
        'Start from Telegram, complete in terminal with:\n'
        f'{cmd}\n\n'
        'Pick a real label and finish the OAuth login in that terminal session.'
    )
    print(json.dumps({'ok': True, 'command': 'add', 'terminalCommand': cmd, 'message': msg}, indent=2))
    return 0

def cmd_probe():
    rc, so, se = run(['python3', str(ROUTER), 'probe'], timeout=240)
    if so:
        print(so)
    if se:
        print(se, file=sys.stderr)
    return rc


def cmd_status():
    rc, so, se = run(['python3', str(ROUTER), 'status'])
    if so:
        print(so)
    if se:
        print(se, file=sys.stderr)
    return rc


def parse_args():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--json', action='store_true', dest='json_mode')
    ap.add_argument('--session-key')
    ap.add_argument('command', nargs=argparse.REMAINDER)
    return ap.parse_args()


def main():
    args = parse_args()
    raw = ' '.join(args.command).strip()
    if not raw:
        print('Usage: oauth_command_router.py "/oauth <list|use NAME|auto|status|probe>"')
        return 1

    parts = shlex.split(raw)
    if not parts:
        return 1
    if parts[0] != '/oauth':
        print(json.dumps({'ok': False, 'error': 'command must start with /oauth'}, indent=2))
        return 1

    if len(parts) == 1 or parts[1] == 'status':
        if args.json_mode:
            rc, so, se = run(['python3', str(ROUTER), 'status', '--json'])
            if so:
                print(so)
            elif se:
                print(json.dumps({'ok': False, 'error': se}, indent=2))
            return rc
        return cmd_status()
    if parts[1] == 'list':
        cmd_list()
        return 0
    if parts[1] == 'auto':
        return cmd_auto()
    if parts[1] == 'probe':
        return cmd_probe()
    if parts[1] == 'add':
        return cmd_add()
    if parts[1] == 'reauth' and len(parts) >= 3:
        return cmd_reauth(' '.join(parts[2:]))
    if parts[1] == 'use' and len(parts) >= 3:
        force = '--force' in parts[2:]
        tokens = [x for x in parts[2:] if x != '--force']
        return cmd_use(' '.join(tokens), force=force)

    print(json.dumps({'ok': False, 'error': 'unknown oauth command'}, indent=2))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
