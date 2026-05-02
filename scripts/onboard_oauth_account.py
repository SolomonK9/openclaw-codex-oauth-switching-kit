#!/usr/bin/env python3
from __future__ import annotations
import argparse, atexit, copy, json, os, re, signal, subprocess, time
from urllib import error as urllib_error, request as urllib_request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE = Path(__file__).resolve().parents[3]
OPENCLAW_HOME = Path.home() / '.openclaw'
AUTH_PROFILES = OPENCLAW_HOME / 'agents' / 'main' / 'agent' / 'auth-profiles.json'
POOL_CONFIG = WORKSPACE / 'ops/state/oauth-pool-config.json'
POOL_STATE = WORKSPACE / 'ops/state/oauth-pool-state.json'
ROUTER = WORKSPACE / 'ops/scripts/oauth_pool_router.py'
ONBOARDING_LOCK = WORKSPACE / 'ops/state/onboarding-lock.json'
DEFAULT_TELEGRAM_TARGET = 'REPLACE_TELEGRAM_CHAT_ID'
CALLBACK_PORT = 1455

_LOCK_HELD = False
_JSON_MODE = False


def ts() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def progress(msg: str) -> None:
    stream = __import__('sys').stderr if _JSON_MODE else __import__('sys').stdout
    print(msg, file=stream, flush=True)


def run(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=str(WORKSPACE), capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or '').strip(), (p.stderr or '').strip()


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + '\n')


def slugify(name: str) -> str:
    s = re.sub(r'[^a-z0-9]+', '-', name.strip().lower())
    return re.sub(r'-+', '-', s).strip('-')


def normalize_profile_id(name: str) -> str:
    slug = slugify(name)
    if not slug:
        raise RuntimeError('Account name normalizes to empty slug')
    return f'codex-oauth-{slug}'


def profile_fingerprint(profile: Dict[str, Any]) -> str:
    return json.dumps(profile, sort_keys=True)


def load_auth_store() -> Dict[str, Any]:
    return load_json(AUTH_PROFILES)


def save_auth_store(store: Dict[str, Any]) -> None:
    save_json(AUTH_PROFILES, store)


def auth_profiles(store: Dict[str, Any]) -> Dict[str, Any]:
    return store.setdefault('profiles', {})


def auth_usage(store: Dict[str, Any]) -> Dict[str, Any]:
    return store.setdefault('usageStats', {})


def pool_config() -> Dict[str, Any]:
    return load_json(POOL_CONFIG)


def save_pool_config(cfg: Dict[str, Any]) -> None:
    save_json(POOL_CONFIG, cfg)


def existing_account(profile_id: str) -> Optional[Dict[str, Any]]:
    for a in pool_config().get('accounts', []):
        if a.get('profileId') == profile_id:
            return a
    return None


def pool_state() -> Dict[str, Any]:
    return load_json(POOL_STATE)


def is_pid_alive(pid: Optional[int]) -> bool:
    try:
        return bool(pid) and pid > 0 and Path(f'/proc/{pid}').exists()
    except Exception:
        return False


def process_cmdline(pid: int) -> str:
    try:
        data = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\x00', b' ').decode(errors='ignore').strip()
        return data
    except Exception:
        return ''


def is_stale_process(pid: int) -> bool:
    if not is_pid_alive(pid):
        return True
    cmd = process_cmdline(pid)
    return not any(x in cmd for x in ('onboard_oauth_account.py', 'openclaw-models', 'openclaw models auth login'))


def process_ancestors(pid: int) -> set[int]:
    seen: set[int] = set()
    cur = int(pid or 0)
    while cur > 1 and cur not in seen:
        seen.add(cur)
        try:
            stat = Path(f'/proc/{cur}/stat').read_text()
            parts = stat.split()
            cur = int(parts[3]) if len(parts) > 3 else 0
        except Exception:
            break
    return seen


def cleanup_stale_lock() -> Optional[Dict[str, Any]]:
    if not ONBOARDING_LOCK.exists():
        return None
    lock = load_json(ONBOARDING_LOCK)
    pid = int(lock.get('pid') or 0)
    if is_pid_alive(pid):
        return None
    stale = {'removed': True, 'reason': 'stale_lock_pid_dead', 'lock': lock}
    ONBOARDING_LOCK.unlink(missing_ok=True)
    return stale


def acquire_lock(mode: str, display_name: str, profile_id: str) -> Dict[str, Any]:
    global _LOCK_HELD
    stale = cleanup_stale_lock()
    if ONBOARDING_LOCK.exists():
        lock = load_json(ONBOARDING_LOCK)
        pid = int(lock.get('pid') or 0)
        if is_pid_alive(pid):
            return {'ok': False, 'code': 'OAUTH_SINGLE_FLIGHT_ACTIVE', 'lock': lock, 'staleCleanup': stale}
        ONBOARDING_LOCK.unlink(missing_ok=True)
    lock = {
        'pid': os.getpid(),
        'startedAt': ts(),
        'mode': mode,
        'displayName': display_name,
        'profileId': profile_id,
        'command': ' '.join(os.environ.get('OPENCLAW_ONBOARD_CMD', '').split()) or ' '.join(['python3', str(Path(__file__))]),
        'phase': 'starting',
    }
    save_json(ONBOARDING_LOCK, lock)
    _LOCK_HELD = True
    return {'ok': True, 'lock': lock, 'staleCleanup': stale}


def update_lock_phase(phase: str) -> None:
    if not _LOCK_HELD or not ONBOARDING_LOCK.exists():
        return
    lock = load_json(ONBOARDING_LOCK)
    lock['phase'] = phase
    lock['updatedAt'] = ts()
    save_json(ONBOARDING_LOCK, lock)


def release_lock() -> None:
    global _LOCK_HELD
    if _LOCK_HELD and ONBOARDING_LOCK.exists():
        try:
            lock = load_json(ONBOARDING_LOCK)
            if int(lock.get('pid') or 0) == os.getpid():
                ONBOARDING_LOCK.unlink(missing_ok=True)
        except Exception:
            pass
    _LOCK_HELD = False
_JSON_MODE = False


def _handle_exit(*_args: Any) -> None:
    release_lock()


atexit.register(release_lock)
signal.signal(signal.SIGTERM, _handle_exit)
signal.signal(signal.SIGINT, _handle_exit)


def list_matching_processes() -> List[Dict[str, Any]]:
    rc, out, _ = run(['ps', '-eo', 'pid=,ppid=,comm=,args='])
    rows: List[Dict[str, Any]] = []
    if rc != 0:
        return rows
    ignored = process_ancestors(os.getpid())
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^(\d+)\s+(\d+)\s+(\S+)\s+(.*)$', line)
        if not m:
            continue
        pid, ppid, comm, args = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
        if pid in ignored:
            continue
        is_onboard_python = comm.startswith('python') and 'onboard_oauth_account.py' in args
        is_openclaw_models = comm == 'openclaw-model' or comm == 'openclaw-models' or 'openclaw-models' in args
        is_openclaw_login = comm == 'openclaw' and 'models auth login' in args
        if is_onboard_python or is_openclaw_models or is_openclaw_login:
            rows.append({'pid': pid, 'ppid': ppid, 'comm': comm, 'args': args})
    return rows


def classify_preflight_processes() -> Dict[str, Any]:
    rows = list_matching_processes()
    stale: List[Dict[str, Any]] = []
    active: List[Dict[str, Any]] = []
    for row in rows:
        if 'onboard_oauth_account.py' in row['args'] or 'openclaw-models' in row['args']:
            active.append(row)
    return {'all': rows, 'activeOnboardingProcesses': active, 'staleCandidates': stale}


def port_holder(port: int) -> Optional[Dict[str, Any]]:
    rc, out, _ = run(['lsof', '-nP', f'-iTCP:{port}', '-sTCP:LISTEN'])
    if rc != 0 or not out:
        return None
    lines = out.splitlines()
    if len(lines) < 2:
        return None
    parts = re.split(r'\s+', lines[1].strip())
    if len(parts) < 2:
        return {'raw': lines[1]}
    pid = int(parts[1]) if parts[1].isdigit() else None
    return {'command': parts[0], 'pid': pid, 'raw': lines[1], 'cmdline': process_cmdline(pid) if pid else ''}


def kill_process_tree(pid: int) -> Dict[str, Any]:
    killed: List[int] = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
            killed.append(pid)
        except Exception:
            pass
        time.sleep(1)
        if not is_pid_alive(pid):
            break
    return {'pid': pid, 'killed': not is_pid_alive(pid), 'signalsTried': ['TERM', 'KILL'], 'killedPids': killed}


def preflight_hygiene() -> Dict[str, Any]:
    info = {'staleCleaned': [], 'blocked': None, 'port': None, 'processes': classify_preflight_processes()}
    live_others = [r for r in info['processes']['activeOnboardingProcesses'] if r.get('pid') != os.getpid()]
    if live_others:
        info['blocked'] = {'code': 'OAUTH_SINGLE_FLIGHT_ACTIVE', 'processes': live_others}
        return info
    holder = port_holder(CALLBACK_PORT)
    info['port'] = holder or {'free': True}
    if holder and holder.get('pid'):
        cmdline = holder.get('cmdline') or ''
        if 'openclaw-models' in cmdline or holder.get('command') == 'openclaw-models':
            cleanup = kill_process_tree(int(holder['pid']))
            cleanup['reason'] = 'stale_port_holder'
            info['staleCleaned'].append(cleanup)
            time.sleep(1)
            holder_after = port_holder(CALLBACK_PORT)
            info['port'] = {'free': True} if not holder_after else holder_after
            if holder_after:
                info['blocked'] = {'code': 'OAUTH_PORT_IN_USE_UNKNOWN', 'holder': holder_after}
        else:
            info['blocked'] = {'code': 'OAUTH_PORT_IN_USE_UNKNOWN', 'holder': holder}
    return info


def verification_status(profile_id: str) -> Optional[str]:
    row = ((pool_state().get('accounts') or {}).get(profile_id) or {})
    if not isinstance(row, dict):
        return None
    verification = row.get('verification') or {}
    if not isinstance(verification, dict):
        return None
    status = str(verification.get('status') or '').strip().upper()
    return status or None


def auth_profile_identity(profile_id: str) -> Optional[str]:
    row = auth_profiles(load_auth_store()).get(profile_id) or {}
    if not isinstance(row, dict):
        return None
    ident = str(row.get('accountId') or row.get('providerAccountId') or '').strip()
    return ident or None


def should_resume_add(profile_id: str, auth_exists: bool, pool_exists: bool) -> bool:
    if not (auth_exists or pool_exists):
        return False
    return verification_status(profile_id) != 'VERIFIED' or not auth_profile_identity(profile_id)


def is_router_lock_error(message: str) -> bool:
    msg = str(message or '').lower()
    return 'router lock busy' in msg or 'lock_busy' in msg


def router_json(args: List[str], *, timeout: int, ok_codes: Tuple[int, ...] = (0,), attempts: int = 10) -> Dict[str, Any]:
    last_rc = 1
    last_msg = 'router command failed'
    last_stdout = ''
    for idx in range(attempts):
        rc, out, err = run(['python3', str(ROUTER), *args], timeout=timeout)
        msg = err or out or 'router command failed'
        if rc in ok_codes:
            try:
                return {'ok': True, 'code': rc, 'payload': json.loads(out) if out else {}, 'stderr': err, 'attemptsUsed': idx + 1}
            except Exception:
                return {'ok': False, 'code': rc, 'error': f'invalid router json: {out[:400]}', 'stdout': out[:400], 'attemptsUsed': idx + 1}
        last_rc = rc
        last_msg = msg
        last_stdout = out
        if not is_router_lock_error(msg) or idx == attempts - 1:
            break
        time.sleep(0.75 + (idx * 1.25))
    return {'ok': False, 'code': last_rc, 'error': last_msg, 'stdout': last_stdout[:400], 'attemptsUsed': attempts}


def run_router_step(step_name: str, args: List[str], *, timeout: int, ok_codes: Tuple[int, ...] = (0,)) -> Dict[str, Any]:
    result = router_json(args, timeout=timeout, ok_codes=ok_codes)
    result['step'] = step_name
    return result


def compare_profiles(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, List[str]]:
    out = {'added': [], 'changed': [], 'removed': []}
    bp, ap = auth_profiles(before), auth_profiles(after)
    before_keys, after_keys = set(bp.keys()), set(ap.keys())
    out['added'] = sorted(list(after_keys - before_keys))
    out['removed'] = sorted(list(before_keys - after_keys))
    for pid in sorted(before_keys & after_keys):
        if profile_fingerprint(bp.get(pid) or {}) != profile_fingerprint(ap.get(pid) or {}):
            out['changed'].append(pid)
    return out


def provider_profile_sort_key(store: Dict[str, Any], pid: str) -> Tuple[int, str]:
    prof = (auth_profiles(store).get(pid) or {}) if isinstance(store, dict) else {}
    provider = str(prof.get('provider') or '')
    ptype = str(prof.get('type') or '')
    oauthish = 0 if (provider == 'openai-codex' or ptype == 'oauth' or pid.startswith('openai-codex:')) else 1
    return (oauthish, pid)


def detect_capture_source(before: Dict[str, Any], after: Dict[str, Any], target_profile_id: str) -> Tuple[Optional[str], Dict[str, Any]]:
    diff = compare_profiles(before, after)
    candidates: List[str] = []
    candidate_details: List[Dict[str, Any]] = []
    rejected: List[Dict[str, str]] = []
    default_changed = 'openai-codex:default' in diff['changed']

    def priority_for(pid: str) -> int:
        if pid == 'openai-codex:default':
            return 40
        if pid.startswith('openai-codex:'):
            return 10
        if pid.startswith('codex-oauth-'):
            return 20
        return 30

    def consider(pid: str, reason: str) -> None:
        if pid == target_profile_id:
            rejected.append({'profileId': pid, 'reason': 'target_profile_id'})
            return
        prof = auth_profiles(after).get(pid) or {}
        provider = str(prof.get('provider') or '')
        ptype = str(prof.get('type') or '')
        if pid.startswith('codex-oauth-') or pid.startswith('openai-codex:') or provider == 'openai-codex' or ptype == 'oauth':
            if pid not in candidates:
                candidates.append(pid)
                has_identity = bool(str(prof.get('accountId') or prof.get('providerAccountId') or '').strip())
                candidate_details.append({
                    'profileId': pid,
                    'priority': priority_for(pid),
                    'identityPriority': 0 if has_identity else 1,
                    'hasIdentity': has_identity,
                    'reason': reason,
                })
            return
        rejected.append({'profileId': pid, 'reason': reason})

    for pid in sorted(diff['added'], key=lambda x: provider_profile_sort_key(after, x)):
        consider(pid, 'added_not_oauthish')
    for pid in sorted(diff['changed'], key=lambda x: provider_profile_sort_key(after, x)):
        consider(pid, 'changed_not_oauthish')
    if default_changed and 'openai-codex:default' not in candidates:
        candidates.append('openai-codex:default')
        prof = auth_profiles(after).get('openai-codex:default') or {}
        has_identity = bool(str(prof.get('accountId') or prof.get('providerAccountId') or '').strip())
        candidate_details.append({
            'profileId': 'openai-codex:default',
            'priority': priority_for('openai-codex:default'),
            'identityPriority': 0 if has_identity else 1,
            'hasIdentity': has_identity,
            'reason': 'default_changed_fallback',
        })
    candidate_details.sort(key=lambda x: (int(x.get('identityPriority', 1)), int(x.get('priority', 99)), str(x.get('profileId') or '')))
    candidates = [str(x.get('profileId')) for x in candidate_details]
    best_priority = candidate_details[0]['priority'] if candidate_details else None
    best_identity_priority = candidate_details[0]['identityPriority'] if candidate_details else None
    ambiguous = best_priority is not None and best_identity_priority is not None and sum(1 for x in candidate_details if x.get('priority') == best_priority and x.get('identityPriority') == best_identity_priority) > 1
    chosen = None if ambiguous else (candidates[0] if candidates else None)
    return chosen, {'diff': diff, 'defaultChanged': default_changed, 'candidates': candidates, 'candidateDetails': candidate_details, 'ambiguous': ambiguous, 'chosen': chosen, 'rejected': rejected}


def discover_profile_identity(store: Dict[str, Any], profile_id: str, timeout: int = 30) -> Dict[str, Any]:
    row = auth_profiles(store).get(profile_id) or {}
    if not isinstance(row, dict):
        return {'ok': False, 'reason': 'profile_not_found'}
    existing = str(row.get('accountId') or row.get('providerAccountId') or '').strip()
    if existing:
        return {'ok': True, 'updated': False, 'accountId': existing, 'email': row.get('email')}
    token = str(row.get('access') or row.get('token') or '').strip()
    if not token:
        return {'ok': False, 'reason': 'missing_access_token'}
    req = urllib_request.Request('https://chatgpt.com/backend-api/wham/usage', headers={'Authorization': f'Bearer {token}', 'User-Agent': 'CodexBar', 'Accept': 'application/json'}, method='GET')
    try:
        with urllib_request.urlopen(req, timeout=timeout) as res:
            data = json.loads(res.read().decode())
    except urllib_error.HTTPError as exc:
        body = exc.read().decode(errors='ignore')[:300]
        return {'ok': False, 'reason': f'http_{exc.code}', 'error': body}
    except Exception as exc:
        return {'ok': False, 'reason': f'fetch_failed:{exc}'}
    account_id = str(data.get('account_id') or data.get('user_id') or '').strip()
    email = str(data.get('email') or row.get('email') or '').strip() or None
    if not account_id:
        return {'ok': False, 'reason': 'missing_account_id_in_usage', 'email': email}
    row['accountId'] = account_id
    if email and not str(row.get('email') or '').strip():
        row['email'] = email
    auth_profiles(store)[profile_id] = row
    return {'ok': True, 'updated': True, 'accountId': account_id, 'email': email, 'source': 'wham_usage'}


def clone_profile_to_target(store: Dict[str, Any], source_profile_id: str, target_profile_id: str) -> Dict[str, Any]:
    profiles, usage = auth_profiles(store), auth_usage(store)
    if source_profile_id not in profiles:
        raise RuntimeError(f'source profile missing in auth store: {source_profile_id}')
    source_row = copy.deepcopy(profiles[source_profile_id])
    target_row = profiles.get(target_profile_id) if isinstance(profiles.get(target_profile_id), dict) else {}
    carried_forward: List[str] = []
    for field in ('accountId', 'providerAccountId', 'email', 'displayName'):
        if isinstance(target_row, dict) and target_row.get(field) not in (None, '') and source_row.get(field) in (None, ''):
            source_row[field] = copy.deepcopy(target_row[field])
            carried_forward.append(field)
    profiles[target_profile_id] = source_row
    if isinstance(usage.get(source_profile_id), dict):
        usage[target_profile_id] = copy.deepcopy(usage[source_profile_id])
    elif target_profile_id not in usage:
        usage[target_profile_id] = {'errorCount': 0, 'lastUsed': 0}
    return {'sourceProfileId': source_profile_id, 'targetProfileId': target_profile_id, 'carriedForwardFields': carried_forward}


def register_pool_account(profile_id: str, display_name: str) -> Dict[str, Any]:
    cfg = pool_config()
    changed = False
    accounts = cfg.setdefault('accounts', [])
    target = None
    for a in accounts:
        if a.get('profileId') == profile_id:
            target = a
            break
    if target is None:
        target = {'profileId': profile_id, 'name': display_name, 'enabled': True, 'priority': 1, 'projects': ['project-a', 'project-b', 'project-c'], 'verificationRequired': True}
        accounts.append(target)
        changed = True
    else:
        if target.get('name') != display_name:
            target['name'] = display_name; changed = True
        if target.get('enabled') is not True:
            target['enabled'] = True; changed = True
        if target.get('verificationRequired') is not True:
            target['verificationRequired'] = True; changed = True
    aps = cfg.setdefault('autoProfileSync', {})
    removed = aps.get('removedProfileIds', [])
    if isinstance(removed, list) and profile_id in removed:
        aps['removedProfileIds'] = [x for x in removed if x != profile_id]
        changed = True
    if changed:
        save_pool_config(cfg)
    return {'changed': changed, 'account': target}


def run_hygiene() -> Dict[str, Any]:
    return run_router_step('hygieneInitial', ['hygiene', '--json'], timeout=300)


def run_tick() -> Dict[str, Any]:
    return run_router_step('tick', ['tick'], timeout=300)


def run_verify(profile_id: str) -> Dict[str, Any]:
    return run_router_step('verification', ['verify', '--profile', profile_id, '--json'], timeout=300, ok_codes=(0, 2))


def run_probe() -> Dict[str, Any]:
    return run_router_step('probe', ['probe', '--json'], timeout=300)


def run_status() -> Dict[str, Any]:
    return run_router_step('status', ['status', '--json'], timeout=180)


def run_onboarding_tail(profile_id: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    update_lock_phase('hygieneInitial')
    hygiene1 = run_hygiene()
    results['hygieneInitial'] = hygiene1
    if not hygiene1.get('ok'):
        return {'ok': False, 'failedStage': 'hygieneInitial', 'results': results, 'transient': is_router_lock_error(hygiene1.get('error', ''))}

    update_lock_phase('tick')
    tick = run_tick()
    results['tick'] = tick
    if not tick.get('ok'):
        return {'ok': False, 'failedStage': 'tick', 'results': results, 'transient': is_router_lock_error(tick.get('error', ''))}

    update_lock_phase('verification')
    verification = run_verify(profile_id)
    results['verification'] = verification
    if not verification.get('ok'):
        return {'ok': False, 'failedStage': 'verification', 'results': results, 'transient': is_router_lock_error(verification.get('error', ''))}

    update_lock_phase('hygieneFinal')
    hygiene2 = run_router_step('hygieneFinal', ['hygiene', '--json'], timeout=300)
    results['hygieneFinal'] = hygiene2
    if not hygiene2.get('ok'):
        return {'ok': False, 'failedStage': 'hygieneFinal', 'results': results, 'transient': is_router_lock_error(hygiene2.get('error', ''))}

    update_lock_phase('status')
    status = run_status()
    results['status'] = status
    if not status.get('ok'):
        return {'ok': False, 'failedStage': 'status', 'results': results, 'transient': is_router_lock_error(status.get('error', ''))}

    status_payload = status.get('payload') or {}
    target_row = next((r for r in status_payload.get('accountInventory', []) if r.get('profileId') == profile_id), None)
    routing_state = str((target_row or {}).get('routingState') or '').strip().upper() if isinstance(target_row, dict) else ''
    if routing_state != 'READY':
        update_lock_phase('probe')
        probe = run_probe()
        results['probe'] = probe
        if not probe.get('ok'):
            return {'ok': False, 'failedStage': 'probe', 'results': results, 'transient': is_router_lock_error(probe.get('error', ''))}
        update_lock_phase('status')
        status = run_status()
        results['status'] = status
        if not status.get('ok'):
            return {'ok': False, 'failedStage': 'status', 'results': results, 'transient': is_router_lock_error(status.get('error', ''))}

    return {'ok': True, 'results': results, 'failedStage': None, 'transient': False}


def run_auth_add() -> Dict[str, Any]:
    print('Step 1/5: complete the OpenAI Codex OAuth flow in this terminal.')
    print('Finish the provider OAuth/device login for openai-codex, then return here.')
    p = subprocess.run(['openclaw', 'models', 'auth', 'login', '--provider', 'openai-codex'], cwd=str(WORKSPACE))
    return {'returncode': p.returncode, 'provider': 'openai-codex', 'command': ['openclaw', 'models', 'auth', 'login', '--provider', 'openai-codex']}


def render_final(payload: Dict[str, Any], json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(payload, indent=2))
        return
    code = payload.get('code') or payload.get('finalState') or 'UNKNOWN'
    msg = payload.get('message') or code
    print(f'{code} | {msg}')
    next_step = payload.get('nextStep')
    if next_step:
        print(f'Next: {next_step}')


def send_success_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    profile_id = str(payload.get('profileId') or '')
    display_name = str(payload.get('displayName') or profile_id)
    mode = str(payload.get('mode') or 'add')
    routing_state = str(((payload.get('targetAccount') or {}).get('routingState') or 'UNKNOWN'))
    verification = (((payload.get('verification') or {}).get('status')) if isinstance(payload.get('verification'), dict) else None) or (((payload.get('verification') or {}).get('raw') or {}).get('status') if isinstance((payload.get('verification') or {}).get('raw'), dict) else None)
    msg = (
        '✅ OAuth onboarding succeeded\n'
        f'Account: {display_name}\n'
        f'Profile: {profile_id}\n'
        f'Mode: {mode}\n'
        f'Final: {payload.get("finalState")}\n'
        f'Routing: {routing_state}\n'
        f'Verification: {verification or "VERIFIED"}'
    )
    rc, out, err = run(['openclaw', 'message', 'send', '--channel', 'telegram', '--target', DEFAULT_TELEGRAM_TARGET, '--message', msg, '--json'], timeout=60)
    try:
        parsed = json.loads(out) if out else {}
    except Exception:
        parsed = {'raw': out}
    return {'ok': rc == 0, 'code': rc, 'stdout': parsed, 'stderr': err}


def failure_payload(code: str, stage: str, display_name: str, profile_id: str, message: str, *, mode: str, exit_code: int, **extra: Any) -> Tuple[Dict[str, Any], int]:
    payload: Dict[str, Any] = {
        'ok': False,
        'finalState': stage,
        'code': code,
        'stage': stage,
        'profileId': profile_id,
        'displayName': display_name,
        'mode': mode,
        'message': message,
    }
    payload.update(extra)
    return payload, exit_code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--name', required=True)
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--no-login', action='store_true')
    ap.add_argument('--reauth', action='store_true')
    ap.add_argument('--source-profile', default=None)
    args = ap.parse_args()
    global _JSON_MODE
    _JSON_MODE = bool(args.json)

    display_name = args.name.strip()
    profile_id = normalize_profile_id(display_name)
    mode = 'reauth' if args.reauth else 'add'

    lock_result = acquire_lock(mode, display_name, profile_id)
    if not lock_result.get('ok'):
        payload, code = failure_payload(
            'OAUTH_SINGLE_FLIGHT_ACTIVE', 'FAILED_LOCK_ACTIVE', display_name, profile_id,
            'Another onboarding/reauth run is already active. Refusing to start a concurrent run.',
            mode=mode, exit_code=6, lock=lock_result.get('lock'), staleCleanup=lock_result.get('staleCleanup'), nextStep='Wait for the active run to finish or clean it up explicitly if it is stuck.'
        )
        render_final(payload, args.json)
        return code

    try:
        update_lock_phase('preflight_hygiene')
        preflight = preflight_hygiene()
        preflight['staleLockCleanup'] = lock_result.get('staleCleanup')
        if preflight.get('blocked'):
            blocked = preflight['blocked']
            code_id = str(blocked.get('code') or 'OAUTH_PRECHECK_BLOCKED')
            message = 'Onboarding preflight detected a blocking active run.' if code_id == 'OAUTH_SINGLE_FLIGHT_ACTIVE' else 'Onboarding preflight detected a port conflict or unknown login residue.'
            payload, code = failure_payload(code_id, 'FAILED_PREFLIGHT', display_name, profile_id, message, mode=mode, exit_code=7, preflight=preflight, nextStep='Resolve the reported active run/port conflict, then rerun the same command.')
            render_final(payload, args.json)
            return code

        before_store = load_auth_store()
        target_exists_in_auth = profile_id in auth_profiles(before_store)
        target_exists_in_pool = existing_account(profile_id) is not None
        resume_add = False
        if args.reauth:
            if args.no_login and not args.source_profile:
                payload, code = failure_payload('OAUTH_PRECHECK_REAUTH_NEEDS_LOGIN', 'FAILED_PRECHECK', display_name, profile_id, 'Reauth must run login and capture in the same command. Use --reauth without --no-login, or provide --source-profile explicitly.', mode=mode, exit_code=2, preflight=preflight)
                render_final(payload, args.json)
                return code
            if not target_exists_in_auth:
                payload, code = failure_payload('OAUTH_PRECHECK_TARGET_MISSING_AUTH', 'FAILED_PRECHECK', display_name, profile_id, f'Reauth target missing in auth store: {profile_id}', mode=mode, exit_code=2, preflight=preflight)
                render_final(payload, args.json)
                return code
            if not target_exists_in_pool:
                payload, code = failure_payload('OAUTH_PRECHECK_TARGET_MISSING_POOL', 'FAILED_PRECHECK', display_name, profile_id, f'Reauth target missing in pool config: {profile_id}', mode=mode, exit_code=2, preflight=preflight)
                render_final(payload, args.json)
                return code
        else:
            resume_add = should_resume_add(profile_id, target_exists_in_auth, target_exists_in_pool)
            if not resume_add and target_exists_in_auth:
                payload, code = failure_payload('OAUTH_PRECHECK_TARGET_EXISTS_AUTH', 'FAILED_PRECHECK', display_name, profile_id, f'Target profile already exists in auth store: {profile_id}', mode=mode, exit_code=2, preflight=preflight)
                render_final(payload, args.json)
                return code
            if not resume_add and target_exists_in_pool:
                payload, code = failure_payload('OAUTH_PRECHECK_TARGET_EXISTS_POOL', 'FAILED_PRECHECK', display_name, profile_id, f'Target profile already exists in pool config: {profile_id}', mode=mode, exit_code=2, preflight=preflight)
                render_final(payload, args.json)
                return code

        login = {'returncode': 0, 'skipped': True, 'reason': 'no_login' if args.no_login else ('resume_existing_target' if resume_add else 'not_required')}
        if not args.no_login and not resume_add:
            update_lock_phase('provider_login')
            login = run_auth_add()
            if login['returncode'] != 0:
                payload, code = failure_payload('OAUTH_PROVIDER_LOGIN_FAILED', 'FAILED_PROVIDER_LOGIN', display_name, profile_id, 'Provider login/auth flow did not complete successfully.', mode=mode, exit_code=login['returncode'], login=login, preflight=preflight, nextStep='Retry the same command from a clean single terminal session.')
                render_final(payload, args.json)
                return code

        progress('Step 2/5: capturing auth-store mutation...')
        update_lock_phase('capture_auth_change')
        after_store = load_auth_store()
        source_profile_id = args.source_profile
        detection = {'mode': 'explicit_source', 'chosen': source_profile_id, 'candidates': [source_profile_id] if source_profile_id else [], 'diff': compare_profiles(before_store, after_store)} if source_profile_id else None
        if source_profile_id and source_profile_id not in auth_profiles(after_store):
            payload, code = failure_payload('OAUTH_CAPTURE_EXPLICIT_SOURCE_MISSING', 'FAILED_CAPTURE', display_name, profile_id, f'Explicit source profile missing after login: {source_profile_id}', mode=mode, exit_code=3, login=login, detection=detection, preflight=preflight)
            render_final(payload, args.json)
            return code
        if resume_add and not source_profile_id:
            if profile_id in auth_profiles(after_store):
                source_profile_id = profile_id
                detection = {'mode': 'resume_existing_target', 'chosen': source_profile_id, 'candidates': [source_profile_id], 'diff': compare_profiles(before_store, after_store)}
            else:
                payload, code = failure_payload('OAUTH_CAPTURE_RESUME_TARGET_MISSING', 'FAILED_CAPTURE', display_name, profile_id, 'Add target is partially registered but missing from auth store. Provide --source-profile to resume cleanly.', mode=mode, exit_code=3, login=login, detection={'mode': 'resume_existing_target', 'chosen': None, 'candidates': [], 'diff': compare_profiles(before_store, after_store)}, preflight=preflight)
                render_final(payload, args.json)
                return code
        if not source_profile_id:
            source_profile_id, detection = detect_capture_source(before_store, after_store, profile_id)
        if not source_profile_id:
            ambiguous = bool((detection or {}).get('ambiguous'))
            payload, code = failure_payload('OAUTH_CAPTURE_AMBIGUOUS' if ambiguous else 'OAUTH_CAPTURE_SOURCE_NOT_FOUND', 'FAILED_CAPTURE', display_name, profile_id, 'Multiple possible OAuth source profiles detected after login.' if ambiguous else 'No new/changed OAuth profile detected after login.', mode=mode, exit_code=3, login=login, detection=detection, preflight=preflight, nextStep='Run a single clean login attempt and avoid overlapping onboarding sessions.')
            render_final(payload, args.json)
            return code

        identityRepair = discover_profile_identity(after_store, source_profile_id)
        if identityRepair.get('updated'):
            save_auth_store(after_store)

        progress('Step 3/5: cloning/normalizing profile into named slot...')
        update_lock_phase('clone_to_target')
        target_row_before_clone = copy.deepcopy(auth_profiles(after_store).get(profile_id) or {})
        source_row_before_clone = copy.deepcopy(auth_profiles(after_store).get(source_profile_id) or {})
        source_same_as_target = source_profile_id == profile_id and profile_id in auth_profiles(after_store)
        materially_fresher_source = False
        if source_same_as_target:
            src_exp = source_row_before_clone.get('expires')
            tgt_exp = target_row_before_clone.get('expires')
            if src_exp and tgt_exp:
                materially_fresher_source = int(src_exp) > int(tgt_exp)
            elif source_row_before_clone.get('access') and target_row_before_clone.get('access'):
                materially_fresher_source = str(source_row_before_clone.get('access')) != str(target_row_before_clone.get('access'))
        if source_same_as_target and not materially_fresher_source:
            clone_result = {'sourceProfileId': source_profile_id, 'targetProfileId': profile_id, 'carriedForwardFields': [], 'skipped': True, 'reason': 'existing_target_profile_without_fresher_delta'}
        else:
            clone_result = clone_profile_to_target(after_store, source_profile_id, profile_id)
            save_auth_store(after_store)

        progress('Step 4/5: registering pool account + hygiene/tick...')
        update_lock_phase('register_pool_account')
        pool_result = register_pool_account(profile_id, display_name)

        progress('Step 5/5: running targeted verification...')
        update_lock_phase('tail_proof')
        tail = run_onboarding_tail(profile_id)
        if not tail.get('ok'):
            failed_stage = str(tail.get('failedStage') or 'unknown')
            failed_result = (tail.get('results') or {}).get(failed_stage) or {}
            transient = bool(tail.get('transient'))
            payload, code = failure_payload('OAUTH_ROUTER_LOCK_BUSY' if transient else f'OAUTH_{failed_stage.upper()}_FAILED', 'PENDING_RETRY' if transient else 'FAILED_TAIL', display_name, profile_id, f'Onboarding tail failed at {failed_stage}: {failed_result.get("error") or "unknown"}', mode=mode, exit_code=(4 if transient else 1), login=login, sourceProfileId=source_profile_id, clone=clone_result, poolRegistration=pool_result, tail=tail, preflight=preflight, detection=detection, nextStep='Rerun the same command; wrapper will resume without repeating provider login.' if transient else 'Investigate router failure before retrying this command.')
            render_final(payload, args.json)
            return code

        hygiene1 = ((tail.get('results') or {}).get('hygieneInitial') or {}).get('payload') or {}
        tick = ((tail.get('results') or {}).get('tick') or {}).get('payload') or {}
        verification = ((tail.get('results') or {}).get('verification') or {}).get('payload') or {}
        hygiene2 = ((tail.get('results') or {}).get('hygieneFinal') or {}).get('payload') or {}
        status = ((tail.get('results') or {}).get('status') or {}).get('payload') or {}
        target_row = next((r for r in status.get('accountInventory', []) if r.get('profileId') == profile_id), None)
        verify_ok = bool(verification.get('success'))
        routing_state = str((target_row or {}).get('routingState') or '').strip().upper() if isinstance(target_row, dict) else ''
        target_account_id = str((target_row or {}).get('accountId') or (target_row or {}).get('providerAccountId') or auth_profile_identity(profile_id) or '').strip()
        ready_ok = bool(target_row) and routing_state == 'READY' and bool(target_account_id)
        final_ok = verify_ok and ready_ok

        if final_ok:
            final_state = 'REAUTH_SUCCESS' if args.reauth else 'ONBOARDED_SUCCESS'
            code_id = 'OAUTH_SUCCESS_REAUTH_READY' if args.reauth else 'OAUTH_SUCCESS_ONBOARD_READY'
            message = ('Reauthentication completed successfully.' if args.reauth else 'Onboarding completed successfully.') + f' target={profile_id}'
            next_step = None
        elif verify_ok:
            blockers = []
            if routing_state and routing_state != 'READY':
                blockers.append(f'routingState={routing_state}')
            if not target_account_id:
                blockers.append('missingAccountId')
            blocker_text = '; '.join(blockers) if blockers else 'notReady'
            final_state = 'REAUTH_PARTIAL' if args.reauth else 'ONBOARD_PARTIAL'
            code_id = 'OAUTH_VERIFY_OK_NOT_READY'
            message = f'Account auth works but is not fully routable yet ({blocker_text}).'
            next_step = 'Keep non-routable and repair metadata/capture before treating it as usable.'
        else:
            final_state = 'REAUTH_UNVERIFIED' if args.reauth else 'ONBOARD_UNVERIFIED'
            code_id = 'OAUTH_VERIFY_FAILED'
            message = 'Account was captured but verification did not prove it usable.'
            next_step = 'Keep non-routable and inspect verification/auth truth before retrying.'

        result: Dict[str, Any] = {
            'ok': final_ok,
            'finalState': final_state,
            'code': code_id,
            'profileId': profile_id,
            'displayName': display_name,
            'normalizedName': profile_id,
            'mode': 'reauth' if args.reauth else ('add-resume' if resume_add else 'add'),
            'sourceProfileId': source_profile_id,
            'defaultOverwriteTrapHandled': source_profile_id == 'openai-codex:default',
            'preflight': preflight,
            'login': login,
            'identityRepair': identityRepair,
            'clone': clone_result,
            'poolRegistration': pool_result,
            'hygieneInitial': hygiene1,
            'tick': tick,
            'verification': verification,
            'hygieneFinal': hygiene2,
            'status': {
                'mode': status.get('mode'),
                'statusLabel': status.get('statusLabel'),
                'runtimeHead': status.get('runtimeHead'),
                'policyHead': status.get('policyHead'),
                'rawRuntimeAuthOrder': status.get('rawRuntimeAuthOrder'),
                'sanitizedRuntimeAuthOrder': status.get('sanitizedRuntimeAuthOrder'),
                'effectiveAuthOrder': status.get('effectiveAuthOrder'),
                'contradictions': status.get('contradictions')},
            'targetAccount': target_row,
            'routingReady': ready_ok,
            'targetAccountId': target_account_id or None,
            'message': message,
            'nextStep': next_step,
            'detection': detection,
        }
        if final_ok:
            result['successAlert'] = send_success_alert(result)
        progress('Onboarding tail complete.')
        render_final(result, args.json)
        return 0 if final_ok else 5
    finally:
        release_lock()


if __name__ == '__main__':
    raise SystemExit(main())
