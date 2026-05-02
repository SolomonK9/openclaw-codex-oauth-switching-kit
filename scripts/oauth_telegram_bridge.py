#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

WORKSPACE = Path(__file__).resolve().parents[3]
STATE_PATH = WORKSPACE / 'ops/state/oauth-telegram-handoff.json'
DEFAULT_TIMEOUT_SECONDS = 15 * 60
DEFAULT_TARGET = 'REPLACE_TELEGRAM_CHAT_ID'
DELIVERY_STATE_PATH = WORKSPACE / 'ops/state/gateway-delivery-state.json'


def ts() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def now_epoch() -> int:
    return int(time.time())


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    return json.loads(STATE_PATH.read_text())


def save_state(data: Dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(data, indent=2) + '\n')


def persist_delivery_state(update: Dict[str, Any]) -> None:
    base = {
        'version': 1,
        'updatedAt': None,
        'plane': 'delivery_gateway',
        'gateway': {
            'bridgeLastSeenAt': None,
            'handoffStatus': None,
            'lastHandoffUpdateAt': None,
            'lastFinishAt': None,
            'lastFinishCode': None,
            'lastClearAt': None,
        },
        'delivery': {
            'lastInboundAt': None,
            'lastInboundKind': None,
            'lastInboundMeta': None,
            'lastOutboundAt': None,
            'lastOutboundKind': None,
            'lastOutboundMeta': None,
            'lastAlertOutboundAt': None,
            'lastAlertMessage': None,
            'lastFailedOutboundAt': None,
            'lastFailedOutboundKind': None,
            'lastFailedOutboundError': None,
            'lastFailedOutboundMeta': None,
        },
    }
    current = base
    if DELIVERY_STATE_PATH.exists():
        try:
            loaded = json.loads(DELIVERY_STATE_PATH.read_text())
            if isinstance(loaded, dict):
                current.update({k: v for k, v in loaded.items() if k not in {'gateway', 'delivery'}})
                if isinstance(loaded.get('gateway'), dict):
                    current['gateway'].update(loaded['gateway'])
                if isinstance(loaded.get('delivery'), dict):
                    current['delivery'].update(loaded['delivery'])
        except Exception:
            pass
    for key in ('gateway', 'delivery'):
        if isinstance(update.get(key), dict):
            current[key].update(update[key])
    current['updatedAt'] = ts()
    DELIVERY_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DELIVERY_STATE_PATH.write_text(json.dumps(current, indent=2) + '\n')


def clear_state() -> None:
    if STATE_PATH.exists():
        STATE_PATH.unlink()


def parse_callback(value: str) -> Dict[str, Any]:
    raw = str(value or '').strip()
    parsed = urlparse(raw)
    q = parse_qs(parsed.query)
    return {
        'raw': raw,
        'scheme': parsed.scheme,
        'netloc': parsed.netloc,
        'path': parsed.path,
        'code': (q.get('code') or [None])[0],
        'state': (q.get('state') or [None])[0],
        'error': (q.get('error') or [None])[0],
    }


def callback_digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def parse_oauth_url(url: str) -> Dict[str, Any]:
    raw = str(url or '').strip()
    parsed = urlparse(raw)
    q = parse_qs(parsed.query)
    redirect_uri = (q.get('redirect_uri') or [None])[0]
    state = (q.get('state') or [None])[0]
    return {
        'raw': raw,
        'state': state,
        'redirectUri': redirect_uri,
        'host': parsed.netloc,
        'path': parsed.path,
    }


def state_expired(row: Dict[str, Any]) -> bool:
    expires = int(row.get('expiresAtEpoch') or 0)
    return bool(expires and now_epoch() > expires)


def active_handoff(row: Dict[str, Any]) -> bool:
    if not row:
        return False
    status = str(row.get('status') or '')
    return status in {'awaiting_callback', 'callback_received', 'callback_consumed'} and not state_expired(row)


def cleanup_if_expired(row: Dict[str, Any]) -> Dict[str, Any]:
    if not row:
        return row
    if state_expired(row) and str(row.get('status') or '') in {'awaiting_callback', 'callback_received', 'callback_consumed'}:
        row['status'] = 'expired'
        row['updatedAt'] = ts()
        row['expiredAt'] = ts()
        save_state(row)
    return row


def redact_callback(raw: str) -> Dict[str, Any]:
    info = parse_callback(raw)
    code = info.get('code') or ''
    return {
        'scheme': info.get('scheme'),
        'netloc': info.get('netloc'),
        'path': info.get('path'),
        'code': (code[:6] + '…') if code else None,
        'state': info.get('state'),
        'error': info.get('error'),
    }


def cmd_start(args: argparse.Namespace) -> Dict[str, Any]:
    current = load_state()
    if active_handoff(current):
        return {
            'ok': False,
            'code': 'OAUTH_HANDOFF_ACTIVE',
            'message': 'Another Telegram OAuth handoff is already active.',
            'active': current,
            'exitCode': 1,
        }
    oauth = parse_oauth_url(args.oauth_url)
    if not oauth.get('state'):
        return {
            'ok': False,
            'code': 'OAUTH_HANDOFF_URL_INVALID',
            'message': 'OAuth URL is missing state.',
            'exitCode': 1,
        }
    row = {
        'version': 1,
        'status': 'awaiting_callback',
        'createdAt': ts(),
        'updatedAt': ts(),
        'expiresAtEpoch': now_epoch() + int(args.timeout_seconds),
        'target': args.target or DEFAULT_TARGET,
        'profileId': args.profile_id,
        'displayName': args.display_name,
        'mode': args.mode,
        'provider': 'openai-codex',
        'processSessionId': args.process_session_id,
        'processPid': args.process_pid,
        'oauthState': oauth.get('state'),
        'oauthUrl': args.oauth_url,
        'redirectUri': oauth.get('redirectUri'),
        'callback': None,
        'callbackDigest': None,
        'consumedAt': None,
    }
    save_state(row)
    persist_delivery_state({'gateway': {'bridgeLastSeenAt': row['updatedAt'], 'handoffStatus': row['status'], 'lastHandoffUpdateAt': row['updatedAt']}, 'delivery': {'lastOutboundAt': row['updatedAt'], 'lastOutboundKind': 'oauth_handoff_start', 'lastOutboundMeta': {'profileId': row.get('profileId'), 'target': row.get('target')}}})
    return {
        'ok': True,
        'code': 'OAUTH_HANDOFF_STARTED',
        'message': 'Telegram OAuth handoff started.',
        'handoff': row,
        'exitCode': 0,
    }


def cmd_status(_: argparse.Namespace) -> Dict[str, Any]:
    row = cleanup_if_expired(load_state())
    if not row:
        return {'ok': True, 'code': 'OAUTH_HANDOFF_EMPTY', 'message': 'No active OAuth Telegram handoff.', 'handoff': None, 'exitCode': 0}
    return {
        'ok': True,
        'code': 'OAUTH_HANDOFF_STATUS',
        'message': 'OAuth Telegram handoff status.',
        'handoff': row,
        'expired': state_expired(row),
        'active': active_handoff(row),
        'exitCode': 0,
    }


def cmd_submit(args: argparse.Namespace) -> Dict[str, Any]:
    row = cleanup_if_expired(load_state())
    if not active_handoff(row):
        return {'ok': False, 'code': 'OAUTH_HANDOFF_NONE', 'message': 'No active pending OAuth handoff to receive a callback.', 'handoff': row or None, 'exitCode': 1}
    text = str(args.callback or '').strip()
    if text.startswith('AUTH_CALLBACK '):
        text = text[len('AUTH_CALLBACK '):].strip()
    cb = parse_callback(text)
    if not cb.get('raw'):
        return {'ok': False, 'code': 'OAUTH_CALLBACK_EMPTY', 'message': 'Callback payload is empty.', 'exitCode': 1}
    if not cb.get('state'):
        return {'ok': False, 'code': 'OAUTH_CALLBACK_STATE_MISSING', 'message': 'Callback URL is missing state.', 'callbackPreview': redact_callback(text), 'exitCode': 1}
    if cb.get('state') != row.get('oauthState'):
        return {'ok': False, 'code': 'OAUTH_CALLBACK_STATE_MISMATCH', 'message': 'Callback state does not match the active OAuth handoff.', 'expectedState': row.get('oauthState'), 'receivedState': cb.get('state'), 'callbackPreview': redact_callback(text), 'exitCode': 1}
    row['status'] = 'callback_received'
    row['updatedAt'] = ts()
    row['callback'] = text
    row['callbackDigest'] = callback_digest(text)
    save_state(row)
    persist_delivery_state({'gateway': {'bridgeLastSeenAt': row['updatedAt'], 'handoffStatus': row['status'], 'lastHandoffUpdateAt': row['updatedAt']}, 'delivery': {'lastInboundAt': row['updatedAt'], 'lastInboundKind': 'oauth_callback', 'lastInboundMeta': {'target': row.get('target'), 'profileId': row.get('profileId'), 'callbackDigest': row.get('callbackDigest')}}})
    return {
        'ok': True,
        'code': 'OAUTH_CALLBACK_ACCEPTED',
        'message': 'Callback accepted for active OAuth handoff.',
        'handoff': row,
        'callbackPreview': redact_callback(text),
        'exitCode': 0,
    }


def cmd_consume(_: argparse.Namespace) -> Dict[str, Any]:
    row = cleanup_if_expired(load_state())
    if not row:
        return {'ok': False, 'code': 'OAUTH_HANDOFF_NONE', 'message': 'No OAuth handoff exists.', 'exitCode': 1}
    if str(row.get('status') or '') != 'callback_received':
        return {'ok': False, 'code': 'OAUTH_CALLBACK_NOT_READY', 'message': 'OAuth callback has not been received yet.', 'handoff': row, 'exitCode': 1}
    callback = str(row.get('callback') or '')
    row['status'] = 'callback_consumed'
    row['consumedAt'] = ts()
    row['updatedAt'] = ts()
    save_state(row)
    persist_delivery_state({'gateway': {'bridgeLastSeenAt': row['updatedAt'], 'handoffStatus': row['status'], 'lastHandoffUpdateAt': row['updatedAt']}})
    return {
        'ok': True,
        'code': 'OAUTH_CALLBACK_CONSUMED',
        'message': 'OAuth callback marked consumed.',
        'callback': callback,
        'callbackPreview': redact_callback(callback),
        'handoff': row,
        'exitCode': 0,
    }


def cmd_finish(args: argparse.Namespace) -> Dict[str, Any]:
    row = load_state()
    if not row:
        return {'ok': False, 'code': 'OAUTH_HANDOFF_NONE', 'message': 'No OAuth handoff exists to finish.', 'exitCode': 1}
    row['status'] = 'completed' if args.success else 'failed'
    row['updatedAt'] = ts()
    row['resultCode'] = args.result_code
    row['resultMessage'] = args.result_message
    save_state(row)
    persist_delivery_state({'gateway': {'bridgeLastSeenAt': row['updatedAt'], 'handoffStatus': row['status'], 'lastHandoffUpdateAt': row['updatedAt'], 'lastFinishAt': row['updatedAt'], 'lastFinishCode': row.get('resultCode')}, 'delivery': {'lastOutboundAt': row['updatedAt'], 'lastOutboundKind': 'oauth_handoff_finish', 'lastOutboundMeta': {'success': bool(args.success), 'resultCode': row.get('resultCode'), 'profileId': row.get('profileId')}}})
    return {'ok': True, 'code': 'OAUTH_HANDOFF_FINISHED', 'message': 'OAuth handoff finalized.', 'handoff': row, 'exitCode': 0}


def cmd_clear(_: argparse.Namespace) -> Dict[str, Any]:
    prior = load_state()
    clear_state()
    persist_delivery_state({'gateway': {'bridgeLastSeenAt': ts(), 'handoffStatus': 'cleared', 'lastClearAt': ts()}})
    return {'ok': True, 'code': 'OAUTH_HANDOFF_CLEARED', 'message': 'OAuth handoff state cleared.', 'prior': prior or None, 'exitCode': 0}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('start')
    s.add_argument('--profile-id', required=True)
    s.add_argument('--display-name', required=True)
    s.add_argument('--mode', required=True, choices=['reauth'])
    s.add_argument('--oauth-url', required=True)
    s.add_argument('--process-session-id', required=True)
    s.add_argument('--process-pid', type=int, default=None)
    s.add_argument('--target', default=DEFAULT_TARGET)
    s.add_argument('--timeout-seconds', type=int, default=DEFAULT_TIMEOUT_SECONDS)

    sub.add_parser('status')

    submit = sub.add_parser('submit')
    submit.add_argument('--callback', required=True)

    sub.add_parser('consume')

    fin = sub.add_parser('finish')
    fin.add_argument('--success', action='store_true')
    fin.add_argument('--result-code', required=True)
    fin.add_argument('--result-message', required=True)

    sub.add_parser('clear')
    return ap


def main() -> int:
    args = build_parser().parse_args()
    handlers = {
        'start': cmd_start,
        'status': cmd_status,
        'submit': cmd_submit,
        'consume': cmd_consume,
        'finish': cmd_finish,
        'clear': cmd_clear,
    }
    out = handlers[args.cmd](args)
    print(json.dumps(out, indent=2))
    return int(out.get('exitCode') or 0)


if __name__ == '__main__':
    raise SystemExit(main())
