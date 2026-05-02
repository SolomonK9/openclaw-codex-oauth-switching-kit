#!/usr/bin/env python3
"""
Capture current openai-codex OAuth token from `openai-codex:default` into a named profile
across all agent auth stores, then register/update that profile in oauth-pool config.

Usage:
  python3 ops/scripts/oauth_profile_capture.py --profile-id codex-oauth-demo --name Demo
  python3 ops/scripts/oauth_profile_capture.py --profile-id codex-oauth-demo --name Demo --dry-run
"""

from __future__ import annotations

import argparse
import copy
import glob
import json
import os
from pathlib import Path
from typing import Any, Dict, List

WORKSPACE = Path(__file__).resolve().parents[2]
OPENCLAW_HOME = Path(os.environ.get('OPENCLAW_HOME', str(Path.home() / '.openclaw'))).expanduser()
AGENTS_ROOT = OPENCLAW_HOME / 'agents'
POOL_CONFIG = WORKSPACE / 'ops/state/oauth-pool-config.json'
DEFAULT_PROJECTS = ['project-a', 'project-b', 'project-c']


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def auth_profile_paths() -> List[Path]:
    paths = [Path(p) for p in glob.glob(str(AGENTS_ROOT / '*/agent/auth-profiles.json'))]
    return sorted(paths)


def capture_profile(profile_id: str, name: str, dry_run: bool) -> Dict[str, Any]:
    changed_files: List[str] = []
    skipped_files: List[str] = []

    paths = auth_profile_paths()
    if not paths:
        raise RuntimeError('No auth-profiles.json files found under OPENCLAW_HOME/agents/*/agent')

    main_path = AGENTS_ROOT / 'main/agent/auth-profiles.json'
    main_obj = load_json(main_path)
    profiles = main_obj.get('profiles', {})
    if 'openai-codex:default' not in profiles:
        raise RuntimeError('main auth-profiles missing openai-codex:default')

    source = copy.deepcopy(profiles['openai-codex:default'])
    source['provider'] = 'openai-codex'

    for path in paths:
        obj = load_json(path)
        profs = obj.setdefault('profiles', {})
        before = json.dumps(profs.get(profile_id), sort_keys=True)
        profs[profile_id] = copy.deepcopy(source)
        after = json.dumps(profs.get(profile_id), sort_keys=True)
        if before != after:
            changed_files.append(str(path))
            if not dry_run:
                save_json(path, obj)
        else:
            skipped_files.append(str(path))

    pool_changed = False
    pool_path_exists = POOL_CONFIG.exists()
    if pool_path_exists:
        pool_obj: Dict[str, Any] = load_json(POOL_CONFIG)
        accounts = pool_obj.setdefault('accounts', [])
        found = None
        for a in accounts:
            if a.get('profileId') == profile_id:
                found = a
                break
        if found is None:
            accounts.append({
                'profileId': profile_id,
                'name': name,
                'enabled': True,
                'priority': 1,
                'projects': list(DEFAULT_PROJECTS),
            })
            pool_changed = True
        else:
            if found.get('name') != name:
                found['name'] = name
                pool_changed = True
            if found.get('enabled') is not True:
                found['enabled'] = True
                pool_changed = True
        if pool_changed and not dry_run:
            save_json(POOL_CONFIG, pool_obj)

    return {
        'ok': True,
        'profileId': profile_id,
        'name': name,
        'changedFiles': changed_files,
        'unchangedFiles': skipped_files,
        'poolConfigExists': pool_path_exists,
        'poolConfigChanged': pool_changed,
        'dryRun': dry_run,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile-id', required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    out = capture_profile(args.profile_id.strip(), args.name.strip(), args.dry_run)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
