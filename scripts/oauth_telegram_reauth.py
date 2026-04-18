#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pty
import re
import select
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from openclaw_resolver import OPENCLAW_BIN, resolve_telegram_target, resolve_workspace

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE = resolve_workspace(__file__)
BRIDGE = SCRIPT_DIR / 'oauth_telegram_bridge.py'
ONBOARD = SCRIPT_DIR / 'onboard_oauth_account.py'
DEFAULT_TELEGRAM_TARGET = resolve_telegram_target(WORKSPACE)
OAUTH_URL_RE = re.compile(r'https://auth\.openai\.com/oauth/authorize\?[^\s]+')
PROMPT_RE = re.compile(r'Paste the authorization code \(or full redirect URL\):')


def callback_variants(callback: str) -> list[str]:
    raw = str(callback or '').strip()
    if not raw:
        return []
    variants: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        v = str(value or '').strip()
        if v and v not in seen:
            seen.add(v)
            variants.append(v)

    add(raw)
    m = re.search(r'(?:^|[?&])code=([^&]+)', raw)
    if m:
        add(m.group(1))
    if raw.startswith('localhost:'):
        add('http://' + raw)
    elif raw.startswith('http://localhost:') or raw.startswith('https://localhost:'):
        add(re.sub(r'^https?://', '', raw))
    ordered: list[str] = []
    code = m.group(1) if m else None
    if code:
        ordered.append(code)
    ordered.extend([v for v in variants if v not in ordered])
    return ordered


def try_callback_inputs(master_fd: int, pid: int, callback: str) -> tuple[str, str]:
    attempts = callback_variants(callback)
    transcript = ''
    enter = bytes([13])
    for value in attempts:
        try:
            os.write(master_fd, value.encode())
            os.write(master_fd, enter)
            time.sleep(0.35)
            done_pid, _ = os.waitpid(pid, os.WNOHANG)
            if done_pid != pid:
                os.write(master_fd, enter)
        except OSError:
            transcript += '\n[bridge] failed to write callback variant'
            break
        tail = read_until_exit(master_fd, pid, timeout_sec=45)
        transcript += f'\n--- attempt: {value[:160]} ---\n' + tail
        if '[bridge] child still running after timeout' not in tail:
            return value, transcript
    return '', transcript

def run(cmd: list[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(WORKSPACE), capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout or '', proc.stderr or ''


def send_telegram(message: str) -> Dict[str, Any]:
    rc, out, err = run([
        OPENCLAW_BIN, 'message', 'send', '--channel', 'telegram', '--target', DEFAULT_TELEGRAM_TARGET,
        '--message', message, '--json'
    ], timeout=60)
    try:
        payload = json.loads(out) if out.strip() else {}
    except Exception:
        payload = {'raw': out[:400]}
    return {'ok': rc == 0, 'code': rc, 'stdout': payload, 'stderr': err[:400]}


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


onboard = load_module(ONBOARD, 'onboard_oauth_account')


def bridge_json(args: list[str]) -> Dict[str, Any]:
    rc, out, err = run(['python3', str(BRIDGE), *args], timeout=60)
    if rc != 0 and not out.strip():
        return {'ok': False, 'code': 'BRIDGE_EXEC_FAIL', 'message': err[:400], 'exitCode': rc}
    try:
        payload = json.loads(out)
    except Exception:
        return {'ok': False, 'code': 'BRIDGE_JSON_INVALID', 'message': out[:400] or err[:400], 'exitCode': rc}
    return payload


def normalize(name: str) -> str:
    return onboard.normalize_profile_id(name)


def precheck_reauth(profile_id: str) -> Optional[Dict[str, Any]]:
    before_store = onboard.load_auth_store()
    if profile_id not in onboard.auth_profiles(before_store):
        return {'ok': False, 'code': 'OAUTH_PRECHECK_TARGET_MISSING_AUTH', 'message': f'Reauth target missing in auth store: {profile_id}'}
    if onboard.existing_account(profile_id) is None:
        return {'ok': False, 'code': 'OAUTH_PRECHECK_TARGET_MISSING_POOL', 'message': f'Reauth target missing in pool config: {profile_id}'}
    return None


def auth_store_summary(store: Dict[str, Any], profile_ids: list[str]) -> Dict[str, Any]:
    profiles = onboard.auth_profiles(store)
    out: Dict[str, Any] = {}
    for pid in profile_ids:
        row = profiles.get(pid) or {}
        out[pid] = {
            'exists': bool(row),
            'expires': row.get('expires'),
            'accountId': row.get('accountId') or row.get('providerAccountId'),
            'email': row.get('email'),
            'hasAccess': bool(row.get('access')),
            'hasRefresh': bool(row.get('refresh')),
        }
    return out


def auth_delta(before_store: Dict[str, Any], after_store: Dict[str, Any], profile_ids: list[str]) -> Dict[str, Any]:
    before_profiles = onboard.auth_profiles(before_store)
    after_profiles = onboard.auth_profiles(after_store)
    rows = []
    meaningful = False
    for pid in profile_ids:
        before = before_profiles.get(pid) or {}
        after = after_profiles.get(pid) or {}
        before_exp = before.get('expires')
        after_exp = after.get('expires')
        access_changed = bool(before.get('access')) != bool(after.get('access')) or str(before.get('access') or '') != str(after.get('access') or '')
        refresh_changed = bool(before.get('refresh')) != bool(after.get('refresh')) or str(before.get('refresh') or '') != str(after.get('refresh') or '')
        expires_advanced = bool(before_exp and after_exp and int(after_exp) > int(before_exp))
        exists_changed = bool(before) != bool(after)
        row = {
            'profileId': pid,
            'existsChanged': exists_changed,
            'accessChanged': access_changed,
            'refreshChanged': refresh_changed,
            'beforeExpires': before_exp,
            'afterExpires': after_exp,
            'expiresAdvanced': expires_advanced,
        }
        meaningful = meaningful or exists_changed or access_changed or refresh_changed or expires_advanced
        rows.append(row)
    return {'meaningful': meaningful, 'profiles': rows}


def choose_reauth_source(profile_id: str, detected_source: Optional[str], delta: Dict[str, Any]) -> Tuple[Optional[str], str]:
    rows = {str(r.get('profileId')): r for r in (delta.get('profiles') or [])}
    target = rows.get(profile_id) or {}
    default = rows.get('openai-codex:default') or {}
    if detected_source and detected_source != profile_id:
        return detected_source, 'detected_source_non_target'
    target_changed = bool(target.get('existsChanged') or target.get('accessChanged') or target.get('refreshChanged') or target.get('expiresAdvanced'))
    default_changed = bool(default.get('existsChanged') or default.get('accessChanged') or default.get('refreshChanged') or default.get('expiresAdvanced'))
    if target_changed:
        return profile_id, 'target_delta'
    if default_changed:
        return 'openai-codex:default', 'default_delta'
    return detected_source, 'no_meaningful_source'


def safe_finish_bridge(success: bool, code: str, message: str) -> Dict[str, Any]:
    try:
        return finish_bridge(success, code, message)
    except Exception as exc:
        return {'ok': False, 'code': 'BRIDGE_FINISH_FAIL', 'message': str(exc)}


def wait_for_url_and_prompt(master_fd: int, timeout_sec: int = 60) -> Tuple[Optional[str], str]:
    deadline = time.time() + timeout_sec
    buf = ''
    found_url: Optional[str] = None
    while time.time() < deadline:
        r, _, _ = select.select([master_fd], [], [], 1.0)
        if not r:
            continue
        try:
            data = os.read(master_fd, 4096).decode(errors='ignore')
        except OSError:
            break
        buf += data
        try:
            (WORKSPACE / 'ops/state/oauth-telegram-last-capture.log').write_text(buf[-12000:])
        except Exception:
            pass
        if not found_url:
            m = OAUTH_URL_RE.search(buf)
            if m:
                found_url = m.group(0)
        if found_url and PROMPT_RE.search(buf):
            return found_url, buf
    return found_url, buf


def wait_for_callback(handoff_timeout_sec: int) -> Dict[str, Any]:
    deadline = time.time() + handoff_timeout_sec
    while time.time() < deadline:
        status = bridge_json(['status'])
        handoff = status.get('handoff') or {}
        if handoff and handoff.get('status') == 'callback_received':
            return {'ok': True, 'status': status}
        if handoff and handoff.get('status') in {'failed', 'completed'}:
            return {'ok': False, 'code': 'OAUTH_HANDOFF_TERMINATED', 'status': status}
        time.sleep(2)
    return {'ok': False, 'code': 'OAUTH_CALLBACK_TIMEOUT'}


def wait_for_exit_or_auth_delta(master_fd: int, pid: int, before_store: Dict[str, Any], profile_id: str, timeout_sec: int = 120) -> Dict[str, Any]:
    deadline = time.time() + timeout_sec
    buf = ''
    last_delta = {'meaningful': False, 'profiles': []}
    after_store = before_store
    while time.time() < deadline:
        r, _, _ = select.select([master_fd], [], [], 1.0)
        if r:
            try:
                chunk = os.read(master_fd, 4096).decode(errors='ignore')
                if chunk:
                    buf += chunk
            except OSError:
                break
        after_store = onboard.load_auth_store()
        last_delta = auth_delta(before_store, after_store, ['openai-codex:default', profile_id])
        if last_delta.get('meaningful'):
            done_pid, _ = os.waitpid(pid, os.WNOHANG)
            return {
                'tail': buf,
                'exited': done_pid == pid,
                'deltaObserved': True,
                'afterStore': after_store,
                'delta': last_delta,
            }
        done_pid, _ = os.waitpid(pid, os.WNOHANG)
        if done_pid == pid:
            return {
                'tail': buf,
                'exited': True,
                'deltaObserved': False,
                'afterStore': after_store,
                'delta': last_delta,
            }
    return {
        'tail': buf + '\n[bridge] child still running after timeout',
        'exited': False,
        'deltaObserved': bool(last_delta.get('meaningful')),
        'afterStore': after_store,
        'delta': last_delta,
    }


def read_until_exit(master_fd: int, pid: int, timeout_sec: int = 120) -> str:
    deadline = time.time() + timeout_sec
    buf = ''
    exited = False
    while time.time() < deadline:
        r, _, _ = select.select([master_fd], [], [], 1.0)
        if r:
            try:
                chunk = os.read(master_fd, 4096).decode(errors='ignore')
                if chunk:
                    buf += chunk
            except OSError:
                break
        done_pid, _ = os.waitpid(pid, os.WNOHANG)
        if done_pid == pid:
            exited = True
            break
    return buf + ('' if exited else '\n[bridge] child still running after timeout')


def start_login_session() -> Tuple[int, int]:
    pid, master_fd = pty.fork()
    if pid == 0:
        os.chdir(str(WORKSPACE))
        cmd = [OPENCLAW_BIN, 'models', 'auth', 'login', '--provider', 'openai-codex']
        if '/' in OPENCLAW_BIN:
            os.execv(OPENCLAW_BIN, cmd)
        os.execvp(OPENCLAW_BIN, cmd)
    return pid, master_fd


def terminate_login_session(pid: int, master_fd: Optional[int] = None) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    time.sleep(1)
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass
    if master_fd is not None:
        try:
            os.close(master_fd)
        except Exception:
            pass


def complete_reauth(display_name: str, source_profile_id: str) -> Dict[str, Any]:
    rc, out, err = run([
        'python3', str(ONBOARD), '--name', display_name, '--reauth', '--no-login', '--source-profile', source_profile_id, '--json'
    ], timeout=600)
    if not out.strip():
        return {'ok': False, 'code': 'OAUTH_REAUTH_WRAPPER_FAIL', 'message': err[:400], 'exitCode': rc}
    try:
        payload = json.loads(out)
    except Exception:
        return {'ok': False, 'code': 'OAUTH_REAUTH_WRAPPER_JSON_INVALID', 'message': out[:400], 'exitCode': rc}
    return payload


def finish_bridge(success: bool, code: str, message: str) -> Dict[str, Any]:
    args = ['finish', '--result-code', code, '--result-message', message]
    if success:
        args.insert(1, '--success')
    return bridge_json(args)


def run_reauth(display_name: str) -> Dict[str, Any]:
    profile_id = normalize(display_name)
    pre = precheck_reauth(profile_id)
    if pre:
        return {'ok': False, 'phase': 'precheck', 'profileId': profile_id, 'displayName': display_name, **pre}

    before_store = onboard.load_auth_store()
    pid, master_fd = start_login_session()
    session_id = f'pid-{pid}'
    handoff_started = False
    try:
        oauth_url, initial_output = wait_for_url_and_prompt(master_fd, timeout_sec=90)
    except Exception:
        oauth_url, initial_output = None, ''
    if not oauth_url:
        terminate_login_session(pid, master_fd)
        return {
            'ok': False,
            'phase': 'provider_login',
            'code': 'OAUTH_URL_NOT_CAPTURED',
            'message': 'Failed to capture OAuth URL from login session.',
            'profileId': profile_id,
            'displayName': display_name,
            'initialOutputTail': initial_output[-1200:],
        }

    started = bridge_json([
        'start', '--profile-id', profile_id, '--display-name', display_name, '--mode', 'reauth',
        '--oauth-url', oauth_url, '--process-session-id', session_id, '--process-pid', str(pid)
    ])
    handoff_started = bool(started.get('ok'))
    if not started.get('ok'):
        terminate_login_session(pid, master_fd)
        bridge_json(['clear'])
        return {'ok': False, 'phase': 'bridge_start', 'profileId': profile_id, 'displayName': display_name, 'bridge': started}

    telegram = send_telegram(
        '🔐 OAuth reauth started\n'
        f'Account: {display_name}\n'
        f'Profile: {profile_id}\n\n'
        'Open this URL in your browser and finish the login:\n'
        f'{oauth_url}\n\n'
        'Then send me the returned callback in this exact format:\n'
        'AUTH_CALLBACK <full_redirect_url>'
    )

    callback_wait = wait_for_callback(handoff_timeout_sec=15 * 60)
    if not callback_wait.get('ok'):
        finish_bridge(False, callback_wait.get('code', 'OAUTH_CALLBACK_TIMEOUT'), 'OAuth callback was not received in time.')
        terminate_login_session(pid, master_fd)
        send_telegram(
            '❌ OAuth reauth failed\n'
            f'Account: {display_name}\n'
            f'Profile: {profile_id}\n'
            f'Reason: {callback_wait.get("code", "timeout")}'
        )
        return {
            'ok': False,
            'phase': 'await_callback',
            'profileId': profile_id,
            'displayName': display_name,
            'oauthUrl': oauth_url,
            'telegramDispatch': telegram,
            'callbackWait': callback_wait,
        }

    consumed = bridge_json(['consume'])
    if not consumed.get('ok'):
        terminate_login_session(pid, master_fd)
        safe_finish_bridge(False, 'OAUTH_CALLBACK_CONSUME_FAILED', 'Callback could not be consumed by the bridge.')
        return {
            'ok': False,
            'phase': 'consume_callback',
            'profileId': profile_id,
            'displayName': display_name,
            'oauthUrl': oauth_url,
            'telegramDispatch': telegram,
            'callbackWait': callback_wait,
            'consume': consumed,
        }

    callback = str(consumed.get('callback') or '')
    accepted_input, initial_tail = try_callback_inputs(master_fd, pid, callback)
    settle = wait_for_exit_or_auth_delta(master_fd, pid, before_store, profile_id, timeout_sec=90)
    tail = (initial_tail or '') + (settle.get('tail') or '')
    try:
        (WORKSPACE / 'ops/state/oauth-telegram-last-post-callback.log').write_text(tail[-20000:])
    except Exception:
        pass

    after_store = settle.get('afterStore') or onboard.load_auth_store()
    store_diff = onboard.compare_profiles(before_store, after_store)
    store_summary = auth_store_summary(after_store, ['openai-codex:default', profile_id])
    delta = settle.get('delta') or auth_delta(before_store, after_store, ['openai-codex:default', profile_id])
    source_profile_id, detection = onboard.detect_capture_source(before_store, after_store, profile_id)
    if not delta.get('meaningful'):
        send_telegram(
            '❌ OAuth reauth failed after callback\n'
            f'Account: {display_name}\n'
            f'Profile: {profile_id}\n'
            'Reason: callback accepted but no fresh auth delta was persisted.'
        )
        return {
            'ok': False,
            'phase': 'post_callback_delta',
            'profileId': profile_id,
            'displayName': display_name,
            'oauthUrl': oauth_url,
            'telegramDispatch': telegram,
            'consume': consumed,
            'providerTail': tail[-2000:],
            'acceptedCallbackInput': accepted_input,
            'childExited': settle.get('exited'),
            'deltaObserved': settle.get('deltaObserved'),
            'detection': detection,
            'storeDiff': store_diff,
            'storeSummary': store_summary,
            'delta': delta,
        }
    if not source_profile_id:
        finish_bridge(False, 'OAUTH_CAPTURE_SOURCE_NOT_FOUND', 'Could not identify the captured OAuth source profile after callback.')
        send_telegram(
            '❌ OAuth reauth failed after callback\n'
            f'Account: {display_name}\n'
            f'Profile: {profile_id}\n'
            'Reason: could not identify captured OAuth source profile.'
        )
        return {
            'ok': False,
            'phase': 'detect_capture',
            'profileId': profile_id,
            'displayName': display_name,
            'oauthUrl': oauth_url,
            'telegramDispatch': telegram,
            'consume': consumed,
            'providerTail': tail[-2000:],
            'acceptedCallbackInput': accepted_input,
            'childExited': settle.get('exited'),
            'deltaObserved': settle.get('deltaObserved'),
            'detection': detection,
            'storeDiff': store_diff,
            'storeSummary': store_summary,
        }

    chosen_source, source_reason = choose_reauth_source(profile_id, source_profile_id, delta)
    if not chosen_source:
        safe_finish_bridge(False, 'OAUTH_SOURCE_SELECTION_FAILED', 'Could not determine a trustworthy source profile after callback.')
        return {
            'ok': False,
            'phase': 'source_selection',
            'profileId': profile_id,
            'displayName': display_name,
            'oauthUrl': oauth_url,
            'telegramDispatch': telegram,
            'consume': consumed,
            'providerTail': tail[-2000:],
            'acceptedCallbackInput': accepted_input,
            'childExited': settle.get('exited'),
            'deltaObserved': settle.get('deltaObserved'),
            'detection': detection,
            'storeDiff': store_diff,
            'storeSummary': store_summary,
            'delta': delta,
            'sourceReason': source_reason,
        }
    final = complete_reauth(display_name, chosen_source)
    finish_bridge(bool(final.get('ok')), str(final.get('code') or ('OAUTH_SUCCESS_REAUTH_READY' if final.get('ok') else 'OAUTH_REAUTH_FAILED')), str(final.get('message') or ('Reauth completed successfully.' if final.get('ok') else 'Reauth failed.')))

    if not final.get('ok'):
        summary = (
            '❌ OAuth reauth failed\n'
            f'Account: {display_name}\n'
            f'Profile: {profile_id}\n'
            f'Final: {final.get("finalState") or final.get("code") or "UNKNOWN"}'
        )
        send_telegram(summary)
    result = {
        'ok': bool(final.get('ok')),
        'phase': 'complete',
        'profileId': profile_id,
        'displayName': display_name,
        'oauthUrl': oauth_url,
        'telegramDispatch': telegram,
        'consume': consumed,
        'providerTail': tail[-2000:],
        'detection': detection,
        'storeDiff': store_diff,
        'storeSummary': store_summary,
        'delta': delta,
        'chosenSourceProfileId': chosen_source,
        'sourceReason': source_reason,
        'final': final,
    }
    if handoff_started:
        bridge_json(['clear'])
    try:
        os.close(master_fd)
    except Exception:
        pass
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    start = sub.add_parser('start')
    start.add_argument('--name', required=True)
    args = ap.parse_args()
    out = run_reauth(args.name) if args.cmd == 'start' else {'ok': False, 'code': 'UNKNOWN_CMD'}
    print(json.dumps(out, indent=2))
    return 0 if out.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
