#!/usr/bin/env python3
"""
OAuth Pool Router for OpenAI Codex profiles.
Stdlib-only controller managing shared account pool with lease pinning,
retry/quarantine policy, and alerting.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from urllib import error as urllib_error, request as urllib_request
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Tuple

BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-config.json"
STATE_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-state.json"
LOCK_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-router.lock"
HEALTH_LOCK_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-health.lock"
CONTROL_LOOP_PROGRESS_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-control-loop.json"
BACKUP_DIR = BASE_DIR / "ops" / "state" / "backups"
LOG_DIR = BASE_DIR / "ops" / "state" / "logs"
EVENTS_LOG_PATH = LOG_DIR / "oauth-events.jsonl"
ROUTING_LOG_PATH = LOG_DIR / "oauth-routing.jsonl"
SWITCH_LOG_PATH = LOG_DIR / "oauth-switches.jsonl"
USAGE_LOG_PATH = LOG_DIR / "oauth-usage.jsonl"
ERROR_LOG_PATH = LOG_DIR / "oauth-errors.jsonl"
LEASE_LOG_PATH = LOG_DIR / "oauth-leases.jsonl"
BYPASS_LOG_PATH = LOG_DIR / "oauth-bypass.jsonl"
DELIVERY_STATE_PATH = BASE_DIR / "ops" / "state" / "gateway-delivery-state.json"
CONFIG_LKG_PATH = BACKUP_DIR / "oauth-pool-config.last-known-good.json"
STATE_LKG_PATH = BACKUP_DIR / "oauth-pool-state.last-known-good.json"

SCHEMA_VERSION = 2


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ts() -> str:
    return now_utc().isoformat()


def parse_iso(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return dt.datetime.fromisoformat(s)
    except Exception:
        return None

def infer_reset_windows_from_usage_log(profile_id: str, usage: Optional[Dict[str, Any]] = None, max_windows: int = 3) -> Dict[str, Any]:
    usage = usage if isinstance(usage, dict) else {}
    out = {
        "fiveHourResetWindows": [],
        "weekResetWindows": [],
    }
    if not profile_id or not USAGE_LOG_PATH.exists():
        return out
    rows = []
    try:
        for line in USAGE_LOG_PATH.read_text().splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("profileId") != profile_id:
                continue
            at = parse_iso(obj.get("at"))
            if at is None:
                continue
            obj["_dt"] = at
            rows.append(obj)
    except Exception:
        return out
    rows.sort(key=lambda r: r.get("_dt"))

    def _scan(field: str) -> List[Dict[str, Any]]:
        found = []
        prev = None
        for row in rows:
            cur = row.get(field)
            if prev is not None:
                prv = prev.get(field)
                if isinstance(prv, (int, float)) and isinstance(cur, (int, float)) and prv <= 0 and cur > 0:
                    found.append({
                        "notBefore": prev.get("at"),
                        "notAfter": row.get("at"),
                        "windowMinutes": round((row["_dt"] - prev["_dt"]).total_seconds() / 60.0, 1),
                        "source": "derived-transition-window",
                    })
            prev = row
        return found[-max_windows:]

    out["fiveHourResetWindows"] = _scan("fiveHourRemaining")
    out["weekResetWindows"] = _scan("weekRemaining")
    return out


def _stabilize_usage_reset_anchors(prev_usage: Optional[Dict[str, Any]], usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    prev_usage = prev_usage if isinstance(prev_usage, dict) else {}
    usage = dict(usage) if isinstance(usage, dict) else {}
    observed_at = usage.get("observedAt") or usage.get("sampledAt") or prev_usage.get("observedAt") or prev_usage.get("sampledAt")

    def _source_rank(source: Optional[str]) -> int:
        source = str(source or "")
        if source.startswith("provider"):
            return 3
        if source.startswith("manual-operator"):
            return 2
        if source.startswith("derived"):
            return 1
        return 0

    def _pick_reset(anchor_key: str, source_key: str, observed_key: str, remaining_key: str, hours: int) -> tuple[Optional[str], Optional[str], Optional[str]]:
        remaining = usage.get(remaining_key)
        current = usage.get(anchor_key)
        previous = prev_usage.get(anchor_key)
        current_source = usage.get(source_key)
        previous_source = prev_usage.get(source_key)
        current_observed = usage.get(observed_key)
        previous_observed = prev_usage.get(observed_key)
        if isinstance(remaining, (int, float)) and remaining <= 0:
            if current and _source_rank(current_source) >= _source_rank(previous_source):
                return current, current_source, current_observed or observed_at
            if previous:
                return previous, previous_source, previous_observed or prev_usage.get("observedAt")
            base = parse_iso(observed_at) if observed_at else None
            if base is not None:
                return (base + dt.timedelta(hours=hours)).isoformat(), f"derived-{remaining_key}", observed_at
        return None, None, None

    week_remaining = usage.get("weekRemaining")
    five_remaining = usage.get("fiveHourRemaining")
    if str(usage.get("weekResetSource") or prev_usage.get("weekResetSource") or "").startswith(("provider", "manual-operator")):
        week_at = usage.get("weekResetAt") or prev_usage.get("weekResetAt")
        week_source = usage.get("weekResetSource") or prev_usage.get("weekResetSource")
        week_observed = usage.get("weekResetObservedAt") or prev_usage.get("weekResetObservedAt") or observed_at
    else:
        week_at, week_source, week_observed = _pick_reset("weekResetAt", "weekResetSource", "weekResetObservedAt", "weekRemaining", 24 * 7)
    if str(usage.get("fiveHourResetSource") or prev_usage.get("fiveHourResetSource") or "").startswith(("provider", "manual-operator")):
        five_at = usage.get("fiveHourResetAt") or prev_usage.get("fiveHourResetAt")
        five_source = usage.get("fiveHourResetSource") or prev_usage.get("fiveHourResetSource")
        five_observed = usage.get("fiveHourResetObservedAt") or prev_usage.get("fiveHourResetObservedAt") or observed_at
    else:
        five_at, five_source, five_observed = _pick_reset("fiveHourResetAt", "fiveHourResetSource", "fiveHourResetObservedAt", "fiveHourRemaining", 5)
    usage["weekResetAt"] = week_at
    usage["weekResetSource"] = week_source
    usage["weekResetObservedAt"] = week_observed
    if str(usage.get("weekResetSource") or "").startswith("derived"):
        usage["weekResetAt"] = None
        usage["weekResetSource"] = "unknown-unproven"
        usage["weekResetObservedAt"] = None
    usage["fiveHourResetAt"] = five_at
    usage["fiveHourResetSource"] = five_source
    usage["fiveHourResetObservedAt"] = five_observed
    if not (isinstance(week_remaining, (int, float)) and week_remaining <= 0):
        usage["weekResetAt"] = None
        usage["weekResetSource"] = None
        usage["weekResetObservedAt"] = None
    if not (isinstance(five_remaining, (int, float)) and five_remaining <= 0):
        usage["fiveHourResetAt"] = None
        usage["fiveHourResetSource"] = None
        usage["fiveHourResetObservedAt"] = None
    return usage



def _update_week_exhaustion_state(prev_usage: Optional[Dict[str, Any]], usage: Optional[Dict[str, Any]], sample_time: Optional[str]) -> Dict[str, Any]:
    prev_usage = prev_usage if isinstance(prev_usage, dict) else {}
    usage = dict(usage) if isinstance(usage, dict) else {}
    week = usage.get("weekRemaining")
    sticky_source = str(usage.get("weekResetSource") or prev_usage.get("weekResetSource") or "")
    prev_state = prev_usage.get('weekExhaustionState')
    prev_conf = prev_usage.get('weekExhaustedConfirmedAt')
    prev_derived = prev_usage.get('weekResetAtDerived') or prev_usage.get('weekResetAt')
    if str(sticky_source).startswith(("provider", "manual-operator")):
        chosen_reset = usage.get('weekResetAt') or prev_usage.get('weekResetAt')
        chosen_source = usage.get('weekResetSource') or prev_usage.get('weekResetSource')
        chosen_observed = usage.get('weekResetObservedAt') or prev_usage.get('weekResetObservedAt') or sample_time
        chosen_confirmed = usage.get('weekExhaustedConfirmedAt') or prev_conf or chosen_observed
        chosen_candidate = usage.get('weekExhaustedCandidateAt') or prev_usage.get('weekExhaustedCandidateAt') or chosen_confirmed
        usage['weekResetAt'] = chosen_reset
        usage['weekResetSource'] = chosen_source
        usage['weekResetObservedAt'] = chosen_observed
        usage['weekExhaustionState'] = 'confirmed_exhausted'
        usage['weekExhaustedCandidateAt'] = chosen_candidate
        usage['weekExhaustedConfirmedAt'] = chosen_confirmed
        usage['weekRecoveredCandidateAt'] = None
        usage['weekResetAtDerived'] = chosen_reset
        usage['weekExhaustionEvidenceCount'] = max(int(usage.get('weekExhaustionEvidenceCount') or 0), int(prev_usage.get('weekExhaustionEvidenceCount') or 0), 2)
        usage['weekRecoveryEvidenceCount'] = 0
        return usage
    if isinstance(week, (int, float)) and week <= 0 and prev_state == 'confirmed_exhausted' and prev_conf and prev_derived:
        usage['weekExhaustionState'] = 'confirmed_exhausted'
        usage['weekExhaustedCandidateAt'] = prev_usage.get('weekExhaustedCandidateAt') or prev_conf
        usage['weekExhaustedConfirmedAt'] = prev_conf
        usage['weekRecoveredCandidateAt'] = None
        usage['weekResetAtDerived'] = prev_derived
        if str(prev_usage.get('weekResetSource') or '').startswith(('provider', 'manual-operator')):
            usage['weekResetAt'] = prev_usage.get('weekResetAt') or prev_derived
            usage['weekResetSource'] = prev_usage.get('weekResetSource')
            usage['weekResetObservedAt'] = prev_usage.get('weekResetObservedAt') or prev_conf
        else:
            usage['weekResetAt'] = None
            usage['weekResetSource'] = 'unknown-unproven'
            usage['weekResetObservedAt'] = None
        usage['weekExhaustionEvidenceCount'] = max(int(prev_usage.get('weekExhaustionEvidenceCount') or 0), 2)
        usage['weekRecoveryEvidenceCount'] = 0
        return usage
    state = usage.get("weekExhaustionState") or prev_state or "clear"
    cand_at = usage.get("weekExhaustedCandidateAt") or prev_usage.get("weekExhaustedCandidateAt")
    conf_at = usage.get("weekExhaustedConfirmedAt") or prev_usage.get("weekExhaustedConfirmedAt")
    rec_at = usage.get("weekRecoveredCandidateAt") or prev_usage.get("weekRecoveredCandidateAt")
    ev_count = int(usage.get("weekExhaustionEvidenceCount") or prev_usage.get("weekExhaustionEvidenceCount") or 0)
    rec_count = int(usage.get("weekRecoveryEvidenceCount") or prev_usage.get("weekRecoveryEvidenceCount") or 0)
    derived = usage.get("weekResetAtDerived") or prev_usage.get("weekResetAtDerived")
    sample_dt = parse_iso(sample_time) if sample_time else None

    def age_hours(ts_val: Optional[str]) -> float:
        base = parse_iso(ts_val) if ts_val else None
        if base is None or sample_dt is None:
            return 0.0
        return max(0.0, (sample_dt - base).total_seconds() / 3600.0)

    weekly_zero = isinstance(week, (int, float)) and week <= 0
    weekly_pos = isinstance(week, (int, float)) and week > 0

    if weekly_zero:
        if state == 'clear':
            state = 'candidate_exhausted'
            cand_at = sample_time
            ev_count = 1
            rec_at = None
            rec_count = 0
        elif state == 'candidate_exhausted':
            ev_count += 1
            if ev_count >= 2 or age_hours(cand_at) >= 6.0:
                state = 'confirmed_exhausted'
                conf_at = cand_at or sample_time
                base = parse_iso(conf_at) if conf_at else None
                derived = (base + dt.timedelta(days=7)).isoformat() if base else derived
                rec_at = None
                rec_count = 0
        elif state == 'confirmed_exhausted':
            if not conf_at:
                conf_at = cand_at or sample_time
            base = parse_iso(conf_at) if conf_at else None
            derived = (base + dt.timedelta(days=7)).isoformat() if base else derived
            rec_at = None
            rec_count = 0
        elif state == 'candidate_recovered':
            state = 'confirmed_exhausted'
            if not conf_at:
                conf_at = cand_at or sample_time
            base = parse_iso(conf_at) if conf_at else None
            derived = (base + dt.timedelta(days=7)).isoformat() if base else derived
            rec_at = None
            rec_count = 0
    elif weekly_pos:
        if state == 'candidate_exhausted':
            state = 'clear'
            cand_at = None
            conf_at = None
            derived = None
            ev_count = 0
            rec_at = None
            rec_count = 0
        elif state == 'confirmed_exhausted':
            state = 'candidate_recovered'
            rec_at = sample_time
            rec_count = 1
        elif state == 'candidate_recovered':
            rec_count += 1
            if rec_count >= 2 or age_hours(rec_at) >= 6.0:
                state = 'clear'
                cand_at = None
                conf_at = None
                derived = None
                ev_count = 0
                rec_at = None
                rec_count = 0
        else:
            state = 'clear'
            cand_at = None
            conf_at = None
            derived = None
            ev_count = 0
            rec_at = None
            rec_count = 0

    usage['weekExhaustionState'] = state
    usage['weekExhaustedCandidateAt'] = cand_at
    usage['weekExhaustedConfirmedAt'] = conf_at
    usage['weekRecoveredCandidateAt'] = rec_at
    usage['weekResetAtDerived'] = derived
    usage['weekExhaustionEvidenceCount'] = ev_count
    usage['weekRecoveryEvidenceCount'] = rec_count
    if state == 'confirmed_exhausted' and derived and not str(usage.get('weekResetSource') or '').startswith(('provider', 'manual-operator')):
        usage['weekResetAt'] = None
        usage['weekResetSource'] = 'unknown-unproven'
        usage['weekResetObservedAt'] = None
    return usage

def parse_any_datetime(value: Any) -> Optional[dt.datetime]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            raw = float(value)
            if raw > 1_000_000_000_000:
                raw /= 1000.0
            return dt.datetime.fromtimestamp(raw, tz=dt.timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        return parse_iso(value)
    return None


def timeout_tier(config: Dict[str, Any], tier: str = "standard") -> int:
    defaults = {"health": 3, "quick": 180, "standard": 600, "long": 1800}
    key_map = {"health": "healthSec", "quick": "quickSec", "standard": "standardSec", "long": "longSec"}
    tier = tier if tier in defaults else "standard"

    timeouts = config.get("timeouts", {}) if isinstance(config.get("timeouts"), dict) else {}
    raw = timeouts.get(key_map[tier])
    if isinstance(raw, (int, float)) and float(raw) > 0:
        return int(raw)

    # Backward compatibility for older configs.
    legacy = config.get("commandTimeoutSec")
    if isinstance(legacy, (int, float)) and float(legacy) > 0:
        return int(legacy)

    return defaults[tier]


def watchdog_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    wd = config.get("watchdog", {}) if isinstance(config.get("watchdog"), dict) else {}
    return {
        "enabled": bool(wd.get("enabled", True)),
        "maxTickSeconds": int(wd.get("maxTickSeconds", 420)),
        "termGraceSeconds": int(wd.get("termGraceSeconds", 8)),
        "alertCooldownMinutes": int(wd.get("alertCooldownMinutes", 30)),
        "autoNotify": bool(wd.get("autoNotify", True)),
    }



def is_read_only(config: Dict[str, Any], *, respect_main_lock: bool = True) -> bool:
    """Return True if mutation is disallowed for the target agent."""
    # Emergency lock overrides everything
    if config.get("emergencyLock", {}).get("enabled", False):
        return True
    return False

def _dedupe_agents(values: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in values:
        val = str(raw or "").strip()
        if not val or val in seen:
            continue
        seen.add(val)
        out.append(val)
    return out


def discover_codex_agents() -> List[str]:
    cfg_path = openclaw_home() / "openclaw.json"
    try:
        root = json.loads(cfg_path.read_text())
    except Exception:
        return []
    agents = ((root.get("agents") or {}).get("list") or []) if isinstance(root, dict) else []
    out: List[str] = []
    for row in agents:
        if not isinstance(row, dict):
            continue
        agent_id = str(row.get("id") or "").strip()
        model = str(row.get("model") or "").strip().lower()
        if not agent_id:
            continue
        if model.startswith("openai-codex/") or model.startswith("gpt-"):
            out.append(agent_id)
    return _dedupe_agents(out)


def auth_order_agents(config: Dict[str, Any]) -> List[str]:
    raw = config.get("authOrderAgents")
    configured: List[str] = []
    if isinstance(raw, list):
        configured = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str) and raw.strip():
        configured = [raw.strip()]
    managed = [str(x).strip() for x in config.get("managedAgents", []) if str(x).strip()]
    discovered = discover_codex_agents()
    agents = _dedupe_agents(configured + managed + discovered)
    return agents

def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError as e:
        exe = cmd[0] if cmd else "<empty-cmd>"
        return 127, "", f"missing executable: {exe} ({e})"
    except subprocess.TimeoutExpired as e:
        so = (e.stdout or '').strip() if isinstance(e.stdout, str) else ''
        se = (e.stderr or '').strip() if isinstance(e.stderr, str) else ''
        return 124, so, (se or f"timeout after {timeout}s")


def load_json(path: Path, default_obj: Dict[str, Any]) -> Dict[str, Any]:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(default_obj, indent=2) + "\n", encoding="utf-8")
        return json.loads(json.dumps(default_obj))
    return json.loads(path.read_text(encoding="utf-8"))


def json_clone(obj: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(obj))


def safe_reason(exc: Exception) -> str:
    return str(exc)[:300]


def snapshot_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    save_json(path, obj)


def validate_config(config: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(config, dict):
        return ["config must be a JSON object"]
    if not isinstance(config.get("provider"), str) or not str(config.get("provider")).strip():
        errors.append("provider must be a non-empty string")
    accounts = config.get("accounts")
    if not isinstance(accounts, list) or not accounts:
        errors.append("accounts must be a non-empty list")
        return errors
    seen = set()
    for idx, acct in enumerate(accounts):
        if not isinstance(acct, dict):
            errors.append(f"accounts[{idx}] must be an object")
            continue
        pid = acct.get("profileId")
        if not isinstance(pid, str) or not pid.strip():
            errors.append(f"accounts[{idx}].profileId must be a non-empty string")
            continue
        if pid in seen:
            errors.append(f"duplicate profileId: {pid}")
        seen.add(pid)
    return errors


def sanitize_state_runtime_artifacts(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    tombstones = set(tombstoned_profile_ids(config))
    changed = {"authOrderTrace": False, "liveCanary": False}

    trace = state.get("authOrderTrace")
    if isinstance(trace, dict):
        for key in ["desiredOrder", "effectiveOrder", "observedOrder"]:
            raw = trace.get(key)
            if isinstance(raw, list):
                cleaned = [p for p in raw if p not in tombstones]
                if cleaned != raw:
                    trace[key] = cleaned
                    changed["authOrderTrace"] = True
        drift = trace.get("drift")
        if isinstance(drift, dict):
            for key in ["activeHead", "policyHead"]:
                if drift.get(key) in tombstones:
                    drift[key] = None
                    changed["authOrderTrace"] = True
            raw_tail = drift.get("tailNoise")
            if isinstance(raw_tail, list):
                cleaned = [p for p in raw_tail if p not in tombstones]
                if cleaned != raw_tail:
                    drift["tailNoise"] = cleaned
                    changed["authOrderTrace"] = True
            raw_removed = drift.get("removedIneligible")
            if isinstance(raw_removed, list):
                cleaned = [p for p in raw_removed if p not in tombstones]
                if cleaned != raw_removed:
                    drift["removedIneligible"] = cleaned
                    changed["authOrderTrace"] = True

    lc = state.get("liveCanary")
    if isinstance(lc, dict):
        if lc.get("lastProfileId") in tombstones:
            lc["lastProfileId"] = None
            changed["liveCanary"] = True
        lo = lc.get("lastOutcome")
        if isinstance(lo, dict) and lo.get("profileId") in tombstones:
            lc["lastOutcome"] = None
            changed["liveCanary"] = True
        runs = lc.get("runs")
        if isinstance(runs, list):
            cleaned_runs = [r for r in runs if not (isinstance(r, dict) and r.get("profileId") in tombstones)]
            if cleaned_runs != runs:
                lc["runs"] = cleaned_runs[-100:]
                changed["liveCanary"] = True
        cursor = lc.get("cursor")
        profiles = [a.get("profileId") for a in config.get("accounts", []) if a.get("profileId") and a.get("enabled", True)]
        if isinstance(cursor, int) and profiles:
            lc["cursor"] = cursor % len(profiles)

    return changed


def validate_state(state: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(state, dict):
        return ["state must be a JSON object"]
    for key in ["accounts", "leases", "tasks"]:
        if key in state and not isinstance(state.get(key), dict):
            errors.append(f"{key} must be an object")
    if "history" in state and not isinstance(state.get("history"), list):
        errors.append("history must be a list")
    return errors


def load_validated_json(path: Path, default_obj: Dict[str, Any], *, validator, snapshot_path: Path, kind: str, config_for_sanitize: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    created = False
    raw_reason = None
    if not path.exists():
        obj = json_clone(default_obj)
        created = True
    else:
        try:
            obj = load_json(path, default_obj)
        except Exception as exc:
            obj = None
            raw_reason = f"read_error:{safe_reason(exc)}"
    errors = validator(obj) if isinstance(obj, dict) else [f"{kind} must be a JSON object"]
    if (not raw_reason) and errors:
        raw_reason = "; ".join(errors[:6])
    recovered_from = None
    if raw_reason:
        try:
            candidate = load_json(snapshot_path, default_obj)
            if not validator(candidate):
                obj = candidate
                recovered_from = str(snapshot_path)
            else:
                obj = json_clone(default_obj)
        except Exception:
            obj = json_clone(default_obj)
    if created or raw_reason:
        save_json(path, obj)
    snapshot_json(snapshot_path, obj)
    if kind == "state" and isinstance(obj, dict) and isinstance(config_for_sanitize, dict):
        sanitize_state_runtime_artifacts(config_for_sanitize, obj)
    if isinstance(obj, dict):
        meta = obj.setdefault("recovery", {})
        meta[f"last{kind.title()}LoadAt"] = ts()
        if raw_reason:
            meta[f"last{kind.title()}RecoveryAt"] = ts()
            meta[f"last{kind.title()}RecoveryReason"] = raw_reason
            meta[f"last{kind.title()}RecoveredFrom"] = recovered_from or "default"
    return obj


def save_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2, sort_keys=False) + "\n"
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    if not tmp.exists():
        tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)



def default_delivery_state() -> Dict[str, Any]:
    return {
        "version": 1,
        "updatedAt": None,
        "plane": "delivery_gateway",
        "gateway": {
            "bridgeLastSeenAt": None,
            "handoffStatus": None,
            "lastHandoffUpdateAt": None,
            "lastFinishAt": None,
            "lastFinishCode": None,
            "lastClearAt": None,
        },
        "delivery": {
            "lastInboundAt": None,
            "lastInboundKind": None,
            "lastInboundMeta": None,
            "lastOutboundAt": None,
            "lastOutboundKind": None,
            "lastOutboundMeta": None,
            "lastAlertOutboundAt": None,
            "lastAlertMessage": None,
            "lastFailedOutboundAt": None,
            "lastFailedOutboundKind": None,
            "lastFailedOutboundError": None,
            "lastFailedOutboundMeta": None,
        },
    }



def load_delivery_state() -> Dict[str, Any]:
    return load_json(DELIVERY_STATE_PATH, default_delivery_state())



def persist_delivery_state(update: Dict[str, Any]) -> Dict[str, Any]:
    state = load_delivery_state()
    gateway = state.setdefault("gateway", {})
    delivery = state.setdefault("delivery", {})
    for section_name, target in (("gateway", gateway), ("delivery", delivery)):
        incoming = update.get(section_name)
        if isinstance(incoming, dict):
            target.update(incoming)
    state["updatedAt"] = ts()
    save_json(DELIVERY_STATE_PATH, state)
    return state



def append_session_rebind_decision(
    state: Dict[str, Any],
    *,
    reason: str,
    target: Optional[str],
    action: str,
    agent_id: Optional[str] = None,
    session_key: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    event = {
        "at": ts(),
        "type": "session_rebind_decision",
        "decision": reason,
        "action": action,
        "targetProfileId": target,
    }
    if agent_id is not None:
        event["agentId"] = str(agent_id)
    if session_key is not None:
        event["sessionKey"] = str(session_key)
    if isinstance(details, dict) and details:
        event["details"] = details
    append_history(state, event)



def default_control_loop_progress() -> Dict[str, Any]:
    return {
        "version": 1,
        "updatedAt": None,
        "commands": {},
    }



def load_control_loop_progress() -> Dict[str, Any]:
    raw = load_json(CONTROL_LOOP_PROGRESS_PATH, default_control_loop_progress())
    if not isinstance(raw, dict):
        return default_control_loop_progress()
    raw.setdefault("version", 1)
    raw.setdefault("updatedAt", None)
    raw.setdefault("commands", {})
    if not isinstance(raw.get("commands"), dict):
        raw["commands"] = {}
    return raw



def update_control_loop_progress(command: str, status: str, **fields: Any) -> Dict[str, Any]:
    progress = load_control_loop_progress()
    now = ts()
    commands = progress.setdefault("commands", {})
    entry = commands.setdefault(str(command), {})
    entry["command"] = str(command)
    entry["status"] = str(status)
    entry["updatedAt"] = now
    if status == "start":
        entry["lastAttemptAt"] = now
    elif status == "success":
        entry["lastSuccessAt"] = now
        entry["lastErrorAt"] = None
        entry["lastError"] = None
        entry["consecutiveFailures"] = 0
        entry["consecutiveLockBusy"] = 0
    elif status in {"lock_busy", "error"}:
        entry["lastErrorAt"] = now
        entry["lastError"] = str(fields.get("error") or status)
        if status == "error":
            entry["consecutiveFailures"] = int(entry.get("consecutiveFailures") or 0) + 1
    if status == "lock_busy":
        entry["lastLockBusyAt"] = now
        entry["consecutiveLockBusy"] = int(entry.get("consecutiveLockBusy") or 0) + 1
    for key, value in fields.items():
        entry[key] = value
    progress["updatedAt"] = now
    commands[str(command)] = entry
    save_json(CONTROL_LOOP_PROGRESS_PATH, progress)
    return entry


def acquire_file_lock(path: Path, wait_seconds: float = 0.0, poll_seconds: float = 0.1) -> Optional[TextIO]:
    """Acquire an exclusive process lock for a specific file path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+", encoding="utf-8")
    deadline = time.monotonic() + max(0.0, wait_seconds)

    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except BlockingIOError:
            if time.monotonic() >= deadline:
                fh.close()
                return None
            time.sleep(max(0.01, poll_seconds))


def acquire_router_lock(wait_seconds: float = 0.0, poll_seconds: float = 0.1) -> Optional[TextIO]:
    """Acquire an exclusive process lock for router state mutations.

    Returns an open file handle when lock is acquired; caller must close it.
    Returns None when lock cannot be acquired within wait_seconds.
    """
    return acquire_file_lock(LOCK_PATH, wait_seconds=wait_seconds, poll_seconds=poll_seconds)


def release_router_lock(fh: Optional[TextIO]) -> None:
    if not fh:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def mirror_history_event(event: Dict[str, Any]) -> None:
    record = dict(event) if isinstance(event, dict) else {"event": event}
    record.setdefault("loggedAt", ts())
    append_jsonl(EVENTS_LOG_PATH, record)
    append_jsonl(ROUTING_LOG_PATH, record)
    etype = str(record.get("type") or "")
    if etype in {"auth_order_applied", "session_rebind", "runtime_failover_quarantine", "auto_evict_unusable_head"}:
        append_jsonl(SWITCH_LOG_PATH, record)
    if "lease" in etype:
        append_jsonl(LEASE_LOG_PATH, record)
    if etype in {"runtime_failover_quarantine"} or record.get("error") or record.get("raw"):
        append_jsonl(ERROR_LOG_PATH, record)


def append_history(state: Dict[str, Any], event: Dict[str, Any], cap: int = 500) -> None:
    h = state.setdefault("history", [])
    h.append(event)
    if len(h) > cap:
        del h[: len(h) - cap]
    try:
        mirror_history_event(event)
    except Exception:
        pass


def default_config() -> Dict[str, Any]:
    return {
        "provider": "openai-codex",
        "accounts": [
            {"profileId": "openai-codex:default", "name": "OAuth-Primary", "enabled": True, "priority": 1, "projects": ["mb", "autopit4", "temp"]},
        ],
        "managedAgents": [
            "main"
        ],
        "authOrderAgents": [
            "main"
        ],
        "concurrencyCapPerAccount": 3,
        "retryPolicy": {
            "maxRetriesPerTask": 2,
            "rollingWindowMinutes": 15,
            "quarantineOnFailures": 2,
            "quarantineMinutes": 30,
        },
        "override": {"enabled": False, "profileId": None},
        "focus": {"enabled": False, "project": None},
        "autoProfileSync": {
            "enabled": True,
            "autoEnableNewProfiles": True,
            "defaultPriority": 1,
            "defaultProjects": ["mb", "autopit4", "temp"],
            "alertOnNewProfile": True,
            "ignoreProfileIds": ["openai-codex:default"],
        },
        "safeSwitch": {
            "allowGlobalReorderWithoutLease": False
        },
        "routing": {
            "hysteresisMinScoreDelta": 25.0,
            "hysteresisMinHoldMinutes": 10
        },
        "routingGuards": {
            "minWeekRemaining": 5.0,
            "minFiveHourRemaining": 5.0,
            "requireKnownUsage": True
        },
        "authOrderPolicy": {
            "excludeIneligible": True,
            "failOpenOnNoEligible": False,
            "verifyAfterApply": True,
            "verifyRetries": 1,
            "verifyAgents": ["main"],
            "driftAlertThreshold": 4,
            "driftAlertWindowMinutes": 60,
            "driftAlertCooldownMinutes": 180,
            "failoverSafeDepth": 3
        },
        "usageProbe": {
            "perProfileWhenIdle": False,
            "agentId": "main",
            "retainProbeMinutes": 180,
            "capacityHeadroomTopN": 2
        },
        "liveCanary": {
            "enabled": True,
            "intervalMinutes": 30,
            "timeoutTier": "quick",
            "maxRuntimeSeconds": 180,
            "onlyWhenIdle": True
        },
        "poolUsagePolicy": {
            "headroomWeekWeight": 0.7,
            "headroomFiveHourWeight": 0.3,
            "compositeHeadroomWeight": 0.5,
            "compositeCoverageWeight": 0.25,
            "compositeHealthWeight": 0.25,
            "topFraction": 0.3,
            "minTopN": 3,
            "warnBelow": 65.0,
            "criticalBelow": 40.0
        },
        "healthChecks": {
            "missingProfileConsecutiveThreshold": 2,
            "suspectThreshold": 1,
            "confirmThreshold": 2,
            "healthLockWaitSeconds": 0.0
        },
        "lifecycleAdvisor": {
            "lowValueDays": 14,
            "reviewIssueWindowDays": 7,
            "reviewIssueThreshold": 3,
            "alertCooldownMinutes": 180
        },
        "timeouts": {
            "healthSec": 5,
            "truthSec": 15,
            "quickSec": 180,
            "standardSec": 600,
            "longSec": 1800
        },
        "watchdog": {
            "enabled": True,
            "maxTickSeconds": 420,
            "termGraceSeconds": 8,
            "alertCooldownMinutes": 30,
            "autoNotify": True
        },
        "sessionRebind": {
            "enabled": True,
            "lookbackMinutes": 1440,
            "respectUserOverride": True,
            "disableInAuto": True,
            "agents": ["main"],
            "minTargetDwellSeconds": 900,
            "contradictionHoldSeconds": 600,
            "controlSurfacePrimary": True,
            "controlSurfaceLeaseSec": 900,
            "controlSurfaceStableTargetSeconds": 30,
            "privilegedSessionKeys": ["agent:main:telegram:direct:1828174896"]
        },
        "runtimeFailover": {
            "enabled": True,
            "scanLookbackMinutes": 90,
            "keepSeen": 500,
            "timeoutQuarantineMinutes": 5
        },
        "commandTimeoutSec": 600,
        "alerts": {
            "telegram": {"enabled": False, "channel": "telegram", "target": "REPLACE_TELEGRAM_CHAT_ID"},
            "discord": {"enabled": False, "channel": "discord", "target": "channel:REPLACE_DISCORD_CHANNEL_ID"},
        },
        "weights": {"focusAffinity": 40, "remainingCapacity": 30, "lowLeases": 20, "priority": 10},
    }


def default_state() -> Dict[str, Any]:
    return {
        "version": SCHEMA_VERSION,
        "lastTickAt": None,
        "override": {"enabled": False, "profileId": None, "setAt": None},
        "focus": {"enabled": False, "project": None, "setAt": None},
        "accounts": {},
        "leases": {},
        "tasks": {},
        "history": [],
        "alerts": {"lastCriticalAt": None, "count": 0, "families": {}},
        "liveCanary": {"cursor": 0, "lastRunAt": None, "lastProfileId": None, "lastOutcome": None, "runs": []},
        "authOrderTrace": {"desiredOrder": [], "effectiveOrder": [], "observedOrder": [], "lastAppliedAt": None, "lastVerifiedAt": None, "lastWriter": None, "lastSource": None, "lastReason": None, "drift": None},
        "recovery": {},
    }


def ensure_account_state(config: Dict[str, Any], state: Dict[str, Any]) -> None:
    ast = state.setdefault("accounts", {})
    configured = set()

    for a in config.get("accounts", []):
        pid = a["profileId"]
        configured.add(pid)
        if pid not in ast:
            ast[pid] = {
                "profileId": pid,
                "enabled": bool(a.get("enabled", True)),
                "health": {
                    "healthy": True,
                    "expired": False,
                    "observedAt": None,
                    "expiresAt": None,
                    "reason": None,
                    "missingConsecutive": 0,
                    "missingSince": None,
                    "stage": "healthy",
                    "suspectAt": None,
                    "confirmedMissingAt": None,
                },
                "usage": {"available": False, "fiveHourRemaining": None, "weekRemaining": None, "observedAt": None},
                "quarantine": {"active": False, "until": None, "reason": None},
                "failureEvents": [],
                "successEvents": [],
                "activeLeaseCount": 0,
                "lastAssignedAt": None,
                "canary": {"lastRunAt": None, "lastSuccessAt": None, "success": None, "latencyMs": None, "reason": None, "observedOrder": None},
            }
        else:
            ast[pid]["enabled"] = bool(a.get("enabled", True))
        vr = verification_record(state, pid)
        canary = ast[pid].get("canary", {}) if isinstance(ast[pid].get("canary"), dict) else {}
        if vr.get("status") == "UNVERIFIED" and canary.get("success") and canary.get("lastSuccessAt"):
            vr.update({"status": "VERIFIED", "verifiedAt": vr.get("verifiedAt") or canary.get("lastSuccessAt"), "lastAttemptAt": vr.get("lastAttemptAt") or canary.get("lastRunAt") or canary.get("lastSuccessAt"), "lastSuccessAt": vr.get("lastSuccessAt") or canary.get("lastSuccessAt"), "lastValidAuthAt": vr.get("lastValidAuthAt") or canary.get("lastSuccessAt"), "reason": "legacy_canary_backfill", "source": "canary_backfill"})
    clear_stale_runtime_quarantines(state)

    # Remove stale profiles not in active router config.
    for pid in list(ast.keys()):
        if pid not in configured:
            ast.pop(pid, None)

def active_leases_for_profile(state: Dict[str, Any], pid: str) -> int:
    return sum(1 for l in state.get("leases", {}).values() if l.get("active") and l.get("profileId") == pid)


def account_projects(config: Dict[str, Any], pid: str) -> List[str]:
    for a in config.get("accounts", []):
        if a.get("profileId") == pid:
            return list(a.get("projects", []))
    return []


def account_priority(config: Dict[str, Any], pid: str) -> int:
    for a in config.get("accounts", []):
        if a.get("profileId") == pid:
            return int(a.get("priority", 1))
    return 1


def account_name(config: Dict[str, Any], pid: str) -> str:
    for a in config.get("accounts", []):
        if a.get("profileId") == pid:
            name = a.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
            return pid
    return pid


def preferred_healthy_order(config: Dict[str, Any], state: Dict[str, Any], current_order_hint: Optional[List[str]] = None) -> Dict[str, Any]:
    healthy = healthy_profiles(config, state)
    cap = int(config.get("concurrencyCapPerAccount", 3))
    routing_cfg = config.get("routing", {}) if isinstance(config.get("routing"), dict) else {}
    low_five_tail = float(routing_cfg.get("lowFiveHourTailThresholdPct", 10.0))
    current_order = list(current_order_hint or [])
    current_pos = {p: i for i, p in enumerate(current_order)}

    ranking = []
    details: List[Dict[str, Any]] = []
    for pid in healthy:
        active = active_leases_for_profile(state, pid)
        u = ((state.get("accounts", {}).get(pid, {}) or {}).get("usage", {}) or {})
        src = u.get("source")
        wk = u.get("weekRemaining")
        fh = u.get("fiveHourRemaining")
        week = float(wk) if isinstance(wk, (int, float)) else 50.0
        five = float(fh) if isinstance(fh, (int, float)) else 50.0

        unknown_usage = (src == "unknown")
        if unknown_usage:
            week = 0.0
            five = 0.0

        low_five_tail_flag = (not unknown_usage) and isinstance(fh, (int, float)) and float(fh) < low_five_tail
        cap_sig = (week * 4.0) + min(five, 50.0)
        prio = account_priority(config, pid)
        order_hint = (100.0 - float(current_pos[pid])) if pid in current_pos else 0.0
        known_bias = 1 if not unknown_usage else 0
        non_tail_bias = 0 if low_five_tail_flag else 1

        ranking.append((known_bias, non_tail_bias, cap_sig, order_hint, cap - active, prio, pid))
        details.append({
            "profileId": pid,
            "knownBias": known_bias,
            "nonTailBias": non_tail_bias,
            "rawScore": cap_sig,
            "orderHint": order_hint,
            "activeLeaseCount": active,
            "priority": prio,
            "fiveHourRemaining": fh,
            "weekRemaining": wk,
            "tailDemoted": bool(low_five_tail_flag),
        })

    ranking.sort(reverse=True)
    ordered = [x[6] for x in ranking]
    return {
        "ordered": ordered,
        "details": details,
        "lowFiveHourTailThresholdPct": low_five_tail,
    }


def actionable_failover_unsafe_profiles(config: Dict[str, Any], state: Dict[str, Any], profiles: List[str]) -> List[str]:
    """Filter unsafe tail profiles down to entries that are actually actionable.

    Disabled profiles or currently quarantined profiles are treated as non-actionable
    noise for operator alerts/risk flags.
    """
    enabled_map = {a.get("profileId"): bool(a.get("enabled", True)) for a in config.get("accounts", [])}
    out: List[str] = []
    for pid in profiles:
        if not enabled_map.get(pid, False):
            continue
        acc = (state.get("accounts", {}) or {}).get(pid, {})
        if isinstance(acc, dict) and is_quarantined(acc):
            continue
        out.append(pid)
    return out


def account_snapshot(config: Dict[str, Any], state: Dict[str, Any]) -> str:
    rows = []
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        st = (state.get("accounts") or {}).get(pid, {})
        h = st.get("health", {})
        q = st.get("quarantine", {})
        wk = u.get("weekRemaining")
        fh = u.get("fiveHourRemaining")
        wk_s = f"{wk}%" if isinstance(wk, (int, float)) else "n/a"
        fh_s = f"{fh}%" if isinstance(fh, (int, float)) else "n/a"
        health_s = "ok" if h.get("healthy") and not h.get("expired") else "issue"
        q_s = "on" if q.get("active") else "off"
        rows.append(
            f"- {account_name(config, pid)} ({pid}): week={wk_s} · 5h={fh_s} · health={health_s} · quarantine={q_s} · leases={active_leases_for_profile(state, pid)}"
        )
    return "\n".join(rows)


def is_quarantined(acc: Dict[str, Any]) -> bool:
    q = acc.get("quarantine", {})
    if not q.get("active"):
        return False
    until = parse_iso(q.get("until"))
    if until and now_utc() >= until:
        q.update({"active": False, "until": None, "reason": None})
        return False
    return bool(q.get("active"))


def verification_record(state: Dict[str, Any], pid: str) -> Dict[str, Any]:
    acc = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    vr = acc.setdefault("verification", {"status": "UNVERIFIED", "verifiedAt": None, "lastAttemptAt": None, "lastSuccessAt": None, "lastFailureAt": None, "lastValidAuthAt": None, "lastInvalidatedAt": None, "reason": "never_verified", "source": None})
    return vr


def account_is_verified(state: Dict[str, Any], pid: str) -> bool:
    return (verification_record(state, pid).get("status") == "VERIFIED")


def set_verification_status(state: Dict[str, Any], pid: str, status: str, reason: str, source: str) -> Dict[str, Any]:
    vr = verification_record(state, pid)
    now = ts()
    effective_status = status
    vr["lastAttemptAt"] = now
    vr["status"] = effective_status
    vr["reason"] = reason
    vr["source"] = source
    if effective_status == "VERIFIED":
        vr["verifiedAt"] = vr.get("verifiedAt") or now
        vr["lastSuccessAt"] = now
        vr["lastValidAuthAt"] = now
    elif effective_status in {"UNVERIFIED", "FAILED"}:
        vr["lastFailureAt"] = now
    acc = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    auth = acc.get("auth") if isinstance(acc.get("auth"), dict) else {}
    if status == "VERIFIED":
        auth.update({"status": "ALIVE", "reason": reason or "verified", "source": source, "at": now, "raw": None})
        acc["auth"] = auth
        reconcile_account_truth_on_fresh_success({}, state, pid, source=source, reason=reason or "verified")
    elif effective_status in {"UNVERIFIED", "FAILED"} and auth.get("status") != "DEAD":
        auth.update({"status": "UNKNOWN", "reason": reason or "unverified", "source": source, "at": now, "raw": None})
        acc["auth"] = auth
    return vr


def auth_status_record(acc: Dict[str, Any]) -> Dict[str, Any]:
    auth = acc.get("auth") if isinstance(acc.get("auth"), dict) else {}
    if not auth:
        auth = {"status": "UNKNOWN", "reason": None, "source": None, "at": None, "raw": None}
        acc["auth"] = auth
    return auth


def mark_auth_dead(state: Dict[str, Any], pid: str, reason: str, source: str, raw: Optional[str] = None) -> Dict[str, Any]:
    acc = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    auth = auth_status_record(acc)
    now = ts()
    auth.update({"status": "DEAD", "reason": reason, "source": source, "at": now, "raw": raw})
    acc["auth"] = auth
    vr = verification_record(state, pid)
    vr["lastInvalidatedAt"] = now
    vr["lastValidAuthAt"] = None
    return auth


def apply_terminal_dead_state(config: Dict[str, Any], state: Dict[str, Any], pid: str, reason: str, source: str, raw: Optional[str] = None) -> Dict[str, Any]:
    # Guardrail: terminal dead-state normalization must remain idempotent.
    # Repeated semantic dead transitions should short-circuit without new history or alert churn.
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    auth = acct.get("auth", {}) if isinstance(acct.get("auth"), dict) else {}
    verification = acct.get("verification", {}) if isinstance(acct.get("verification"), dict) else {}
    usage = acct.get("usage", {}) if isinstance(acct.get("usage"), dict) else {}
    quarantine = acct.get("quarantine", {}) if isinstance(acct.get("quarantine"), dict) else {}
    live_failover = acct.get("liveFailover", {}) if isinstance(acct.get("liveFailover"), dict) else {}
    structured_success_at = latest_structured_success_at(acct)
    if structured_success_at is not None and not has_current_strong_dead_truth(acct, structured_success_at):
        reconciliation = reconcile_account_truth_on_fresh_success(config, state, pid, source=source, reason=f"fresh_success_outweighs_dead:{reason}")
        return {
            "auth": acct.get("auth", auth),
            "normalization": reconciliation,
            "skipped": True,
            "reason": "fresh_structured_success_precedence",
            "emitted": False,
        }
    already_normalized = (
        str(auth.get("status") or "").upper() == "DEAD"
        and str(auth.get("reason") or "") == str(reason or "")
        and str(verification.get("status") or "").upper() != "VERIFIED"
        and usage.get("available") is False
        and str(usage.get("source") or "") == "normalized-dead-auth"
        and str(usage.get("trust") or "") == "untrusted"
        and not bool(quarantine.get("active"))
        and not bool(live_failover.get("active"))
    )
    semantic_terminal = has_semantic_terminal_dead_state(config, state, pid, reason)
    if already_normalized or semantic_terminal:
        return {
            "auth": auth,
            "normalization": {"profileId": pid, "changed": [], "remainingFlags": []},
            "skipped": True,
            "reason": "already_normalized" if already_normalized else "semantic_terminal_dead",
            "emitted": False,
        }
    auth = mark_auth_dead(state, pid, reason, source, raw)
    normalization = normalize_terminal_account_state(config, state, pid, source=source)
    append_history(state, {
        "at": ts(),
        "type": "terminal_dead_state",
        "profileId": pid,
        "reason": reason,
        "source": source,
        "normalization": normalization,
    })
    return {"auth": auth, "normalization": normalization, "skipped": False, "emitted": True}


def canonical_dead_reason(reason: Optional[str]) -> Optional[str]:
    r = str(reason or "").strip().lower()
    if not r:
        return None
    if r in {"expired", "oauth_expired"}:
        return "expired"
    if r in {"account_deactivated", "account disabled", "deactivated"}:
        return "account_deactivated"
    if r in {"401", "http_401", "unauthorized", "unauthenticated", "auth failed", "authentication failed"}:
        return "http_401"
    if r in {"invalid token", "token invalid", "invalidated", "revoked"}:
        return "invalid_token"
    return r


def dead_alert_cooldown_minutes(dead_reason: Optional[str]) -> int:
    return 24 * 60 if canonical_dead_reason(dead_reason) == "account_deactivated" else 30


def dead_alert_spec(dead_reason: Optional[str]) -> Dict[str, str]:
    canonical = canonical_dead_reason(dead_reason) or str(dead_reason or 'dead')
    if canonical == 'account_deactivated':
        return {
            'code': 'PROFILE_DEACTIVATED',
            'impact': 'This account is deactivated and cannot be used for routing or telemetry.',
            'auto_action': 'Router excludes this profile from routing and telemetry expectations.',
            'your_action': 'Investigate account recovery or replace the account immediately.',
            'label': 'DEACTIVATED',
        }
    return {
        'code': 'PROFILE_DEAD',
        'impact': 'Token unauthorized/invalid; profile is immediately removed from routing.',
        'auto_action': 'Router excludes this profile until re-authenticated.',
        'your_action': 'Re-auth the account or remove it from the pool.',
        'label': 'DEAD',
    }


def dead_reason_from_text(reason: Optional[str], raw: Optional[str]) -> Optional[str]:
    text = " ".join([str(reason or ""), str(raw or "")]).strip().lower()
    if not text:
        return None
    semantic_patterns = [
        (r"\bhttp_401\b", "http_401"),
        (r"\boauth_expired\b", "oauth_expired"),
        (r"\bunauthorized\b", "unauthorized"),
        (r"\bunauthenticated\b", "unauthenticated"),
        (r"\binvalid token\b", "invalid token"),
        (r"\btoken invalid\b", "token invalid"),
        (r"\binvalidated\b", "invalidated"),
        (r"\bdeactivated\b", "deactivated"),
        (r"\brevoked\b", "revoked"),
        (r"\baccount disabled\b", "account disabled"),
        (r"\bauthentication failed\b", "authentication failed"),
        (r"\bauth failed\b", "auth failed"),
    ]
    for pattern, canonical in semantic_patterns:
        if re.search(pattern, text):
            return canonical_dead_reason(canonical)
    if re.search(r"\bexpired\b", text) and ("oauth" in text or "auth" in text or "token" in text):
        return canonical_dead_reason("oauth_expired")
    return None


def dead_reason_from_verifier_probe(probe: Dict[str, Any]) -> Optional[str]:
    status = str(probe.get("status") or "").strip().upper()
    evidence = str(probe.get("evidence") or "")
    if status == VERIFIER_STATUS_AUTH_OK:
        return None
    if status == VERIFIER_STATUS_DEAD:
        return dead_reason_from_text(evidence, None) or "http_401"
    return None


def recent_success_at(acc: Dict[str, Any]) -> Optional[str]:
    canary = acc.get("canary", {}) if isinstance(acc.get("canary"), dict) else {}
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    return canary.get("lastSuccessAt") or verification.get("lastSuccessAt")


def healthy_profiles(config: Dict[str, Any], state: Dict[str, Any]) -> List[str]:
    out = []
    for a in config.get("accounts", []):
        pid = a["profileId"]
        st = state["accounts"].get(pid, {})
        if not a.get("enabled", True):
            continue
        gate = routing_gate_summary(config, st)
        if gate.get("eligible"):
            out.append(pid)
    return out


def discover_provider_profile_ids(config: Dict[str, Any]) -> List[str]:
    provider = config.get("provider", "openai-codex")
    rc, out, _ = run_models_status_json(config, "health")
    if rc != 0 or not out:
        return []
    try:
        payload = json.loads(out)
    except Exception:
        return []

    found = set()

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            pid = obj.get("profileId") or obj.get("profile") or obj.get("id")
            prov = obj.get("provider") or obj.get("vendor")
            if pid and prov == provider:
                found.add(pid)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)

    walk(payload)
    return sorted(found)


def run_models_status_json(config: Dict[str, Any], timeout_tier_name: str = "health") -> Tuple[int, str, str]:
    timeout_sec = timeout_tier(config, timeout_tier_name)
    # Use a direct bounded subprocess call here. Nested shell+python timeout wrappers
    # introduced jitter and made the health path less predictable under live load.
    return run_cmd(["openclaw", "models", "status", "--json"], timeout=timeout_sec)


def parse_models_status_payload(config: Dict[str, Any], payload: Any) -> Dict[str, Dict[str, Any]]:
    provider = config.get("provider", "openai-codex")
    observed: Dict[str, Dict[str, Any]] = {}

    auth = payload.get("auth") if isinstance(payload, dict) else {}
    oauth = auth.get("oauth") if isinstance(auth, dict) else {}
    profiles = oauth.get("profiles") if isinstance(oauth, dict) else []
    if isinstance(profiles, list):
        for n in profiles:
            if not isinstance(n, dict):
                continue
            if (n.get("provider") or n.get("vendor")) != provider:
                continue
            pid = n.get("profileId") or n.get("profile") or n.get("id")
            if not pid:
                continue
            status = str(n.get("status") or "").lower()
            healthy = status in {"ok", "healthy", "active", "ready", "static"}
            expires_at = n.get("expiresAt") or n.get("expiry") or n.get("expires")
            expired = bool(n.get("expired", False))
            if isinstance(expires_at, (int, float)):
                try:
                    expired = expired or int(expires_at) <= int(now_utc().timestamp() * 1000)
                except Exception:
                    pass
            observed[str(pid)] = {
                "healthy": bool(healthy),
                "expired": bool(expired),
                "expiresAt": expires_at,
                "observedAt": ts(),
                "raw": n,
            }

    if observed:
        return observed

    all_nodes: List[Dict[str, Any]] = []
    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            all_nodes.append(obj)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)
    walk(payload)
    for n in all_nodes:
        pid = n.get("profileId") or n.get("profile") or n.get("id")
        if not pid:
            continue
        prov = n.get("provider") or n.get("vendor")
        if prov != provider:
            continue
        healthy = n.get("healthy")
        if healthy is None:
            healthy = str(n.get("status", "")).lower() in {"ok", "healthy", "active", "ready"}
        observed[pid] = {
            "healthy": bool(healthy),
            "expired": bool(n.get("expired", False)),
            "expiresAt": n.get("expiresAt") or n.get("expiry") or n.get("expires"),
            "observedAt": ts(),
            "raw": n,
        }
    return observed


def observe_models_status(config: Dict[str, Any], timeout_tier_name: str = "truth") -> Dict[str, Dict[str, Any]]:
    rc, out, _ = run_models_status_json(config, timeout_tier_name)
    if rc != 0 or not out:
        return {}
    try:
        payload = json.loads(out)
    except Exception:
        return {}
    return parse_models_status_payload(config, payload)


def health_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    hc = config.get("healthChecks", {}) if isinstance(config.get("healthChecks"), dict) else {}
    suspect = max(1, int(hc.get("suspectThreshold", 1)))
    confirm = max(suspect + 1, int(hc.get("confirmThreshold", hc.get("missingProfileConsecutiveThreshold", 2))))
    return {
        "suspectThreshold": suspect,
        "confirmThreshold": confirm,
        "healthLockWaitSeconds": max(0.0, float(hc.get("healthLockWaitSeconds", 0.0))),
        "truthFreshSeconds": max(60, int(hc.get("truthFreshSeconds", 900))),
        "truthStaleSeconds": max(120, int(hc.get("truthStaleSeconds", 1800))),
    }


def evaluate_profile_health(config: Dict[str, Any], prev_h: Dict[str, Any], observed_entry: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    settings = health_settings(config)
    if observed_entry is not None:
        expired = bool(observed_entry.get("expired", False))
        healthy = bool(observed_entry.get("healthy", True)) and not expired
        return {
            "healthy": healthy,
            "expired": expired,
            "expiresAt": observed_entry.get("expiresAt"),
            "observedAt": observed_entry.get("observedAt", ts()),
            "reason": "expired" if expired else None,
            "missingConsecutive": 0,
            "missingSince": None,
            "stage": "expired" if expired else "healthy",
            "suspectAt": None,
            "confirmedMissingAt": None,
        }

    missing = int(prev_h.get("missingConsecutive", 0)) + 1
    suspect_at = prev_h.get("suspectAt")
    confirmed_missing_at = prev_h.get("confirmedMissingAt")
    missing_since = prev_h.get("missingSince") or ts()
    healthy_flag = bool(prev_h.get("healthy", True))
    reason = prev_h.get("reason")

    if missing >= settings["confirmThreshold"]:
        stage = "missing"
        healthy_flag = False
        reason = "not_reported_by_models_status"
        suspect_at = suspect_at or missing_since
        confirmed_missing_at = confirmed_missing_at or ts()
    elif missing >= settings["suspectThreshold"]:
        stage = "suspect" if missing == settings["suspectThreshold"] else "confirm"
        healthy_flag = True
        reason = "missing_probe_pending"
        suspect_at = suspect_at or ts()
        if stage != "confirm":
            confirmed_missing_at = None
    else:
        stage = "healthy"

    return {
        "healthy": healthy_flag,
        "expired": bool(prev_h.get("expired", False)),
        "expiresAt": prev_h.get("expiresAt"),
        "observedAt": ts(),
        "reason": reason,
        "missingConsecutive": missing,
        "missingSince": missing_since,
        "stage": stage,
        "suspectAt": suspect_at,
        "confirmedMissingAt": confirmed_missing_at,
    }


def stale_runtime_quarantine(acc: Dict[str, Any]) -> bool:
    q = acc.get("quarantine", {}) if isinstance(acc.get("quarantine"), dict) else {}
    if not q.get("active"):
        return False
    reason = str(q.get("reason") or "")
    if not reason.startswith("runtime_rate_limit:"):
        return False
    health = acc.get("health", {}) if isinstance(acc.get("health"), dict) else {}
    usage = acc.get("usage", {}) if isinstance(acc.get("usage"), dict) else {}
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    if not health.get("healthy", False):
        return False
    if verification.get("status") != "VERIFIED":
        return False
    fh = usage.get("fiveHourRemaining")
    wk = usage.get("weekRemaining")
    if not isinstance(fh, (int, float)) or float(fh) <= 0.0:
        return False
    if isinstance(wk, (int, float)) and float(wk) <= 0.0 and not suspicious_weekly_zero(usage):
        return False
    return True


def clear_stale_runtime_quarantines(state: Dict[str, Any]) -> Dict[str, Any]:
    cleared = []
    for pid, acc in (state.get("accounts") or {}).items():
        if not isinstance(acc, dict):
            continue
        if stale_runtime_quarantine(acc):
            acc["quarantine"] = {"active": False, "until": None, "reason": None}
            cleared.append(pid)
    if cleared:
        append_history(state, {"at": ts(), "type": "stale_runtime_quarantine_cleared", "profiles": cleared})
    return {"cleared": cleared}


def suspicious_weekly_zero(usage: Dict[str, Any]) -> bool:
    wk = usage.get("weekRemaining")
    fh = usage.get("fiveHourRemaining")
    source = str(usage.get("source") or "unknown")
    if not isinstance(wk, (int, float)):
        return False
    if float(wk) > 0.0:
        return False
    if not isinstance(fh, (int, float)):
        return False
    if float(fh) < 50.0:
        return False
    # Treat high 5h + zero week as suspicious only when telemetry is weak/unknown.
    # Per-profile or active-profile snapshots can legitimately show this when weekly
    # quota is exhausted but 5h resets are still high.
    if source in {"unknown", "stale-probe"}:
        return True
    return False


def telemetry_trust_state(usage: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(usage, dict) or not usage:
        return {"state": "unknown", "reason": "no_usage_snapshot"}
    source = str(usage.get("source") or "unknown")
    if source in PROVIDER_SHARED_USAGE_SOURCES:
        return {"state": "provider_shared", "reason": "provider_wide_usage_not_per_profile"}
    if source in AUTH_ONLY_USAGE_SOURCES:
        return {"state": "auth_only", "reason": "auth_smoke_only"}
    if source not in TRUSTED_NUMERIC_USAGE_SOURCES:
        return {"state": "unknown", "reason": "unrecognized_usage_source"}
    if not usage.get("available", False):
        return {"state": "untrusted", "reason": "usage_unavailable"}
    if suspicious_weekly_zero(usage):
        return {"state": "suspicious", "reason": "weekly_zero_conflicts_with_high_5h"}
    wk = usage.get("weekRemaining")
    fh = usage.get("fiveHourRemaining")
    if isinstance(wk, (int, float)) or isinstance(fh, (int, float)):
        return {"state": "trusted", "reason": "numeric_usage_snapshot"}
    return {"state": "unknown", "reason": "missing_numeric_usage"}


def telemetry_recent_limit_seconds(config: Dict[str, Any]) -> int:
    policy = config.get("telemetryPolicy", {}) if isinstance(config.get("telemetryPolicy"), dict) else {}
    hours = float(policy.get("staleAfterHours", 4.0))
    return max(60, int(hours * 3600))


def usage_exhausted(usage: Dict[str, Any]) -> bool:
    source = str(usage.get("source") or "unknown") if isinstance(usage, dict) else "unknown"
    if source not in TRUSTED_NUMERIC_USAGE_SOURCES:
        return False
    wk = usage.get("weekRemaining")
    fh = usage.get("fiveHourRemaining")
    exhausted_week = isinstance(wk, (int, float)) and float(wk) <= 0.0 and not suspicious_weekly_zero(usage)
    exhausted_five = isinstance(fh, (int, float)) and float(fh) <= 0.0
    return exhausted_week or exhausted_five


def has_recent_success(acc: Dict[str, Any], max_age_sec: int) -> bool:
    last = recent_success_at(acc)
    last_dt = parse_iso(last) if last else None
    return bool(last_dt and (now_utc() - last_dt).total_seconds() <= max_age_sec)


def token_dead_reason(acc: Dict[str, Any]) -> Optional[str]:
    auth = acc.get("auth", {}) if isinstance(acc.get("auth"), dict) else {}
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    if auth.get("status") == "DEAD":
        return str(auth.get("reason") or "dead")
    health = acc.get("health", {}) if isinstance(acc.get("health"), dict) else {}
    if health.get("expired"):
        return "expired"
    # A successful recent verifier/auth-smoke result outranks stale models-status absence.
    if verification.get("status") == "VERIFIED":
        return None
    if (not health.get("healthy", True)) and str(health.get("reason") or "") == "not_reported_by_models_status":
        return "missing_or_unauthorized"
    return None


def contradiction_flags(config: Dict[str, Any], acc: Dict[str, Any]) -> List[str]:
    flags: List[str] = []
    auth = acc.get("auth", {}) if isinstance(acc.get("auth"), dict) else {}
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    usage = acc.get("usage", {}) if isinstance(acc.get("usage"), dict) else {}
    health = acc.get("health", {}) if isinstance(acc.get("health"), dict) else {}
    quarantine = acc.get("quarantine", {}) if isinstance(acc.get("quarantine"), dict) else {}
    live_failover = acc.get("liveFailover", {}) if isinstance(acc.get("liveFailover"), dict) else {}
    if str(auth.get("status") or "").upper() == "DEAD" and str(verification.get("status") or "").upper() == "VERIFIED":
        flags.append("verified_vs_dead_auth")
    if str(auth.get("status") or "").upper() == "DEAD" and usage.get("available") is True and usage.get("source") in TRUSTED_NUMERIC_USAGE_SOURCES:
        flags.append("trusted_usage_vs_dead_auth")
    if health.get("expired") is False and str(auth.get("status") or "").upper() == "DEAD" and str(auth.get("reason") or "").lower() in {"expired", "oauth_expired"}:
        flags.append("healthy_expiry_vs_dead_expired_auth")
    if usage.get("available") is True and usage.get("source") in TRUSTED_NUMERIC_USAGE_SOURCES and quarantine.get("active"):
        flags.append("trusted_usage_vs_quarantine")
    if usage.get("available") is True and usage.get("source") in TRUSTED_NUMERIC_USAGE_SOURCES and live_failover.get("active"):
        flags.append("trusted_usage_vs_live_failover")
    return flags


def latest_structured_success_at(acc: Dict[str, Any]) -> Optional[dt.datetime]:
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    if str(verification.get("status") or "").upper() != "VERIFIED":
        return None
    candidates = [
        parse_iso(verification.get("lastSuccessAt")),
        parse_iso(verification.get("verifiedAt")),
        parse_iso(verification.get("lastValidAuthAt")),
        parse_iso(recent_success_at(acc)),
    ]
    return max((x for x in candidates if x is not None), default=None)


def trusted_positive_usage_truth(acc: Dict[str, Any]) -> bool:
    usage = acc.get("usage", {}) if isinstance(acc.get("usage"), dict) else {}
    telemetry = telemetry_trust_state(usage)
    if telemetry.get("state") != "trusted":
        return False
    if usage.get("available") is not True:
        return False
    five = usage.get("fiveHourRemaining")
    week = usage.get("weekRemaining")
    if isinstance(five, (int, float)) and float(five) <= 0.0:
        return False
    if isinstance(week, (int, float)) and float(week) <= 0.0 and not suspicious_weekly_zero(usage):
        return False
    return isinstance(five, (int, float)) or isinstance(week, (int, float))


def has_current_strong_dead_truth(acc: Dict[str, Any], success_at: Optional[dt.datetime]) -> bool:
    auth = acc.get("auth", {}) if isinstance(acc.get("auth"), dict) else {}
    health = acc.get("health", {}) if isinstance(acc.get("health"), dict) else {}
    auth_at = parse_iso(auth.get("at")) if isinstance(auth.get("at"), str) else None
    auth_dead = str(auth.get("status") or "").upper() == "DEAD"
    if health.get("expired"):
        return True
    if auth_dead and success_at is None:
        return True
    return bool(auth_dead and auth_at and success_at and auth_at >= success_at and str(auth.get("source") or "") in {"manual_verify", "live_canary", "models_status"})


def reconcile_account_truth_on_fresh_success(config: Dict[str, Any], state: Dict[str, Any], pid: str, *, source: str, reason: Optional[str] = None) -> Dict[str, Any]:
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    success_at = latest_structured_success_at(acct)
    if success_at is None:
        return {"profileId": pid, "changed": [], "preserved": []}

    auth = acct.get("auth", {}) if isinstance(acct.get("auth"), dict) else {}
    quarantine = acct.get("quarantine", {}) if isinstance(acct.get("quarantine"), dict) else {}
    live_failover = acct.get("liveFailover", {}) if isinstance(acct.get("liveFailover"), dict) else {}
    usage = acct.get("usage", {}) if isinstance(acct.get("usage"), dict) else {}

    changed: List[str] = []
    preserved: List[str] = []
    trusted_positive = trusted_positive_usage_truth(acct)
    quarantine_reason = str(quarantine.get("reason") or "")
    live_kind = str(live_failover.get("kind") or "")

    if str(auth.get("status") or "").upper() == "DEAD":
        if has_current_strong_dead_truth(acct, success_at):
            preserved.append("dead_auth_preserved")
        else:
            auth.update({
                "status": "ALIVE",
                "reason": reason or f"fresh_success_reconciled:{source}",
                "source": f"{source}_reconciled",
                "at": ts(),
                "raw": None,
            })
            acct["auth"] = auth
            changed.append("dead_auth_reconciled_to_alive")

    if quarantine.get("active"):
        clear_quarantine = False
        if quarantine_reason.startswith("runtime_timeout"):
            clear_quarantine = True
        elif quarantine_reason.startswith("runtime_rate_limit"):
            clear_quarantine = trusted_positive
        elif trusted_positive:
            clear_quarantine = True
        if clear_quarantine:
            acct["quarantine"] = {"active": False, "until": None, "reason": None}
            changed.append("stale_quarantine_cleared_on_fresh_success")
        else:
            preserved.append("quarantine_preserved")

    if live_failover.get("active"):
        clear_live_failover = False
        if live_kind == "timeout":
            clear_live_failover = True
        elif live_kind == "rate_limit":
            clear_live_failover = trusted_positive
        elif trusted_positive:
            clear_live_failover = True
        if clear_live_failover:
            acct["liveFailover"] = {
                "active": False,
                "kind": live_failover.get("kind"),
                "minutes": live_failover.get("minutes"),
                "until": live_failover.get("until"),
                "raw": live_failover.get("raw"),
                "source": f"{source}_reconciled",
                "at": ts(),
            }
            changed.append("stale_live_failover_cleared_on_fresh_success")
        else:
            preserved.append("live_failover_preserved")

    if str(usage.get("source") or "") == "normalized-dead-auth" and str(auth.get("status") or "").upper() == "ALIVE":
        preserved.append("normalized_dead_usage_replaced_by_fresh_success_writer")

    if changed:
        append_history(state, {
            "at": ts(),
            "type": "fresh_success_reconcile",
            "profileId": pid,
            "changed": changed,
            "preserved": preserved,
            "source": source,
            "reason": reason,
        })
    return {"profileId": pid, "changed": changed, "preserved": preserved}


def normalize_terminal_account_state(config: Dict[str, Any], state: Dict[str, Any], pid: str, *, source: str = "normalizer") -> Dict[str, Any]:
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    auth = acct.get("auth", {}) if isinstance(acct.get("auth"), dict) else {}
    usage = acct.get("usage", {}) if isinstance(acct.get("usage"), dict) else {}
    verification = acct.get("verification", {}) if isinstance(acct.get("verification"), dict) else {}
    dead = str(auth.get("status") or "").upper() == "DEAD"
    dead_reason = str(auth.get("reason") or "")
    structured_success_at = latest_structured_success_at(acct)
    if dead and structured_success_at is not None and not has_current_strong_dead_truth(acct, structured_success_at):
        return reconcile_account_truth_on_fresh_success(config, state, pid, source=source, reason=f"terminal_normalize_blocked:{dead_reason or 'dead'}")
    changed = []
    if dead:
        if str(verification.get("status") or "").upper() == "VERIFIED":
            set_verification_status(state, pid, "FAILED", f"normalized_from_dead_auth:{dead_reason or 'dead'}", source)
            changed.append("verification_failed_from_dead_auth")
        should_normalize_usage = (
            str(usage.get("source") or "") != "normalized-dead-auth"
            and (
                usage.get("available") is True
                or str(usage.get("source") or "") in TRUSTED_NUMERIC_USAGE_SOURCES
                or str(usage.get("reason") or "").lower().startswith("http_")
                or str(usage.get("trust") or "").lower() == "untrusted"
            )
        )
        if should_normalize_usage:
            prev_source = str(usage.get("source") or "") or None
            prev_reason = str(usage.get("reason") or "") or None
            acct["usage"] = {
                "available": False,
                "fiveHourRemaining": None,
                "weekRemaining": None,
                "observedAt": ts(),
                "source": "normalized-dead-auth",
                "trust": "untrusted",
                "reason": f"dead_auth:{dead_reason or 'dead'}",
                "previousSource": prev_source,
                "previousReason": prev_reason,
            }
            changed.append("usage_downgraded_from_dead_auth")
        quarantine = acct.get("quarantine") if isinstance(acct.get("quarantine"), dict) else {}
        if quarantine.get("active"):
            acct["quarantine"] = {"active": False, "until": None, "reason": None}
            changed.append("quarantine_cleared_from_dead_auth")
        live_failover = acct.get("liveFailover") if isinstance(acct.get("liveFailover"), dict) else {}
        if live_failover.get("active"):
            acct["liveFailover"] = {
                "active": False,
                "kind": live_failover.get("kind"),
                "minutes": live_failover.get("minutes"),
                "until": live_failover.get("until"),
                "raw": live_failover.get("raw"),
                "source": "normalized_dead_auth",
                "at": ts(),
            }
            changed.append("live_failover_cleared_from_dead_auth")
    flags = contradiction_flags(config, acct)
    if changed or flags:
        append_history(state, {"at": ts(), "type": "terminal_state_normalize", "profileId": pid, "changed": changed, "remainingFlags": flags, "source": source})
    return {"profileId": pid, "changed": changed, "remainingFlags": flags}


def fresh_recovery_truth(config: Dict[str, Any], acc: Dict[str, Any]) -> Dict[str, Any]:
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    usage = acc.get("usage", {}) if isinstance(acc.get("usage"), dict) else {}
    auth = acc.get("auth", {}) if isinstance(acc.get("auth"), dict) else {}
    expiry = _expiry_truth_for_account(acc)
    telemetry = telemetry_trust_state(usage)
    telemetry_f = telemetry_freshness(config, usage if isinstance(usage, dict) else {})
    verified = str(verification.get("status") or "").upper() == "VERIFIED"
    auth_alive = str(auth.get("status") or "").upper() == "ALIVE"
    expiry_healthy = not bool(expiry.get("reauthNeeded")) and not bool(expiry.get("expired"))
    usage_trusted = telemetry.get("state") == "trusted"
    recent = bool(telemetry_f.get("recent"))
    capacity_positive = (
        isinstance(usage.get("fiveHourRemaining"), (int, float)) and float(usage.get("fiveHourRemaining")) > 0
        and isinstance(usage.get("weekRemaining"), (int, float)) and float(usage.get("weekRemaining")) > 0
    )
    active = bool(verified and auth_alive and expiry_healthy and usage_trusted and recent and capacity_positive)
    return {
        "active": active,
        "verified": verified,
        "authAlive": auth_alive,
        "expiryHealthy": expiry_healthy,
        "usageTrusted": usage_trusted,
        "recent": recent,
        "capacityPositive": capacity_positive,
    }


def should_suppress_stale_account_alert(config: Dict[str, Any], acc: Dict[str, Any], code: str) -> bool:
    if code not in {"PROFILE_DEAD", "PROFILE_DEACTIVATED", "PROFILE_EXPIRED", "PROFILE_EXPIRY_1D", "PROFILE_EXPIRY_2D", "PROFILE_UNHEALTHY", "PROFILE_MISSING_OR_UNUSABLE", "PROFILE_QUARANTINED"}:
        return False
    return bool(fresh_recovery_truth(config, acc).get("active"))


def classify_account_effective_state(config: Dict[str, Any], acc: Dict[str, Any]) -> Dict[str, Any]:
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    quarantine = acc.get("quarantine", {}) if isinstance(acc.get("quarantine"), dict) else {}
    health = acc.get("health", {}) if isinstance(acc.get("health"), dict) else {}
    usage = acc.get("usage", {}) if isinstance(acc.get("usage"), dict) else {}
    auth = acc.get("auth", {}) if isinstance(acc.get("auth"), dict) else {}
    live_failover = acc.get("liveFailover", {}) if isinstance(acc.get("liveFailover"), dict) else {}
    telemetry = telemetry_trust_state(usage)
    telemetry_f = telemetry_freshness(config, usage if isinstance(usage, dict) else {})
    max_age = telemetry_recent_limit_seconds(config)
    trusted_capacity = telemetry.get("state") == "trusted"
    auth_status = str(auth.get("status") or "UNKNOWN").upper()
    auth_reason = str(auth.get("reason") or "").strip().lower()
    verification_status = str(verification.get("status") or "UNVERIFIED").upper()
    verification_reason = str(verification.get("reason") or "").strip().lower()
    usage_reason = str(usage.get("reason") or "").strip().lower()
    health_reason = str(health.get("reason") or "").strip().lower()

    contradiction_reasons: List[str] = []
    auth_alive = auth_status == "ALIVE"
    fresh_dead = auth_status == "DEAD" or health.get("expired") or usage_reason == "http_401"
    expired_signal = any("expired" in text for text in [auth_reason, verification_reason, usage_reason, health_reason] if text)
    verified_recent = verification_status == "VERIFIED"
    health_missing_only = (not health.get("healthy", True)) and health_reason == "not_reported_by_models_status"

    if auth_alive and expired_signal:
        contradiction_reasons.append("auth_alive_but_expired_signal")
    if auth_alive and usage_reason == "http_401":
        contradiction_reasons.append("auth_alive_but_usage_401")

    if contradiction_reasons:
        return {
            "effectiveState": "CONTRADICTORY_HOLD",
            "effectiveReason": contradiction_reasons[0],
            "routableNow": False,
            "eligible": False,
            "healthLabel": "contradiction",
            "stateLabel": "HOLD",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": True, "reason": contradiction_reasons[0], "signals": contradiction_reasons},
        }

    if auth_status == "DEAD" or health.get("expired") or usage_reason == "http_401":
        dead_reason = usage_reason if usage_reason == "http_401" else (token_dead_reason(acc) or auth_reason or health_reason or "dead")
        canonical_reason = canonical_dead_reason(dead_reason)
        if canonical_reason == "account_deactivated":
            return {
                "effectiveState": "DEACTIVATED",
                "effectiveReason": dead_reason,
                "routableNow": False,
                "eligible": False,
                "healthLabel": "deactivated",
                "stateLabel": "DEACTIVATED",
                "telemetry": telemetry,
                "telemetryFreshness": telemetry_f,
                "contradiction": {"active": False, "reason": None, "signals": []},
            }
        return {
            "effectiveState": "REAUTH_REQUIRED",
            "effectiveReason": dead_reason,
            "routableNow": False,
            "eligible": False,
            "healthLabel": "reauth_required",
            "stateLabel": "REAUTH_REQUIRED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if verification_status != "VERIFIED":
        return {
            "effectiveState": "DEACTIVATED",
            "effectiveReason": "unverified",
            "routableNow": False,
            "eligible": False,
            "healthLabel": "unverified",
            "stateLabel": "DEACTIVATED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if quarantine.get("active"):
        return {
            "effectiveState": "AUTH_VALID_BUT_EXHAUSTED",
            "effectiveReason": str(quarantine.get("reason") or "quarantined"),
            "routableNow": False,
            "eligible": False,
            "healthLabel": "quarantined",
            "stateLabel": "AUTH_VALID_BUT_EXHAUSTED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if live_fail_penalty_active(acc):
        return {
            "effectiveState": "AUTH_VALID_BUT_EXHAUSTED",
            "effectiveReason": f"live_failover:{live_failover.get('kind') or 'active'}",
            "routableNow": False,
            "eligible": False,
            "healthLabel": "live_failover",
            "stateLabel": "AUTH_VALID_BUT_EXHAUSTED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if not health.get("healthy", True) and not health_missing_only:
        return {
            "effectiveState": "DEACTIVATED",
            "effectiveReason": str(health.get("reason") or "unhealthy"),
            "routableNow": False,
            "eligible": False,
            "healthLabel": "unhealthy",
            "stateLabel": "DEACTIVATED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if telemetry.get("state") in {"suspicious", "untrusted"}:
        suspicious = telemetry.get("state") == "suspicious"
        return {
            "effectiveState": "CONTRADICTORY_HOLD" if suspicious else "DEACTIVATED",
            "effectiveReason": f"telemetry:{telemetry.get('reason')}",
            "routableNow": False,
            "eligible": False,
            "healthLabel": "telemetry_untrusted",
            "stateLabel": "HOLD" if suspicious else "DEACTIVATED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": suspicious, "reason": telemetry.get("reason") if suspicious else None, "signals": [telemetry.get("reason")] if suspicious else []},
        }

    if usage_exhausted(usage):
        return {
            "effectiveState": "AUTH_VALID_BUT_EXHAUSTED",
            "effectiveReason": "capacity_exhausted",
            "routableNow": False,
            "eligible": False,
            "healthLabel": "capacity",
            "stateLabel": "AUTH_VALID_BUT_EXHAUSTED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if trusted_capacity and (telemetry_f.get("ageSeconds") is None or (telemetry_f.get("ageSeconds") or 0) > max_age) and not has_recent_success(acc, max_age):
        return {
            "effectiveState": "DEACTIVATED",
            "effectiveReason": "telemetry_stale",
            "routableNow": False,
            "eligible": False,
            "healthLabel": "telemetry_stale",
            "stateLabel": "DEACTIVATED",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    if trusted_capacity:
        return {
            "effectiveState": "ROUTABLE",
            "effectiveReason": "ready",
            "routableNow": True,
            "eligible": True,
            "healthLabel": "ready",
            "stateLabel": "ROUTABLE",
            "telemetry": telemetry,
            "telemetryFreshness": telemetry_f,
            "contradiction": {"active": False, "reason": None, "signals": []},
        }

    return {
        "effectiveState": "AUTH_VALID_BUT_EXHAUSTED",
        "effectiveReason": "auth_valid_but_capacity_unknown",
        "routableNow": False,
        "eligible": False,
        "healthLabel": "ready_auth_only",
        "stateLabel": "AUTH_VALID_BUT_EXHAUSTED",
        "telemetry": telemetry,
        "telemetryFreshness": telemetry_f,
        "contradiction": {"active": False, "reason": None, "signals": []},
    }


def routing_gate_summary(config: Dict[str, Any], acc: Dict[str, Any]) -> Dict[str, Any]:
    classification = classify_account_effective_state(config, acc)
    return {
        "eligible": bool(classification.get("eligible")),
        "reason": classification.get("effectiveReason"),
        "healthLabel": classification.get("healthLabel"),
        "telemetry": classification.get("telemetry"),
        "stateLabel": classification.get("stateLabel"),
        "telemetryFreshness": classification.get("telemetryFreshness"),
        "effectiveState": classification.get("effectiveState"),
        "effectiveReason": classification.get("effectiveReason"),
        "routableNow": bool(classification.get("routableNow")),
        "contradiction": classification.get("contradiction") or {"active": False, "reason": None, "signals": []},
    }


def telemetry_freshness(config: Dict[str, Any], usage: Dict[str, Any]) -> Dict[str, Any]:
    observed_at = parse_iso(usage.get("observedAt")) if isinstance(usage, dict) else None
    age_seconds = None
    if observed_at is not None:
        age_seconds = max(0, int((now_utc() - observed_at).total_seconds()))

    source = str(usage.get("source") or "unknown")
    trust = str(usage.get("trust") or "").strip().lower() if isinstance(usage, dict) else ""
    if source in {"per-profile", "provider-api-per-profile", "audited-double-pass-main-probe"}:
        confidence = "high"
        factor = 1.0
    elif source in {"active-profile", "probe", "status-main-probe", "manual-status-main-probe"}:
        confidence = "medium"
        factor = 0.8
    elif source == "stale-probe":
        confidence = "low"
        factor = 0.55
    else:
        confidence = "none"
        factor = 0.25

    if trust == "conditional":
        if confidence == "high":
            confidence = "medium"
        factor *= 0.75
    elif trust == "rejected":
        confidence = "none"
        factor = min(factor, 0.25)

    recent_limit = telemetry_recent_limit_seconds(config)

    if age_seconds is None:
        freshness = "unknown"
        factor *= 0.35
    elif age_seconds <= 600:
        freshness = "fresh"
    elif age_seconds <= 1800:
        freshness = "aging"
        factor *= 0.85
    elif age_seconds <= recent_limit:
        freshness = "stale"
        factor *= 0.65
    else:
        freshness = "very_stale"
        factor *= 0.4

    recent = age_seconds is not None and age_seconds <= recent_limit

    return {
        "observedAt": usage.get("observedAt"),
        "ageSeconds": age_seconds,
        "freshness": freshness,
        "confidence": confidence,
        "scoreFactor": round(max(0.0, min(1.0, factor)), 3),
        "source": source,
        "recent": recent,
    }


def merge_health_update(config: Dict[str, Any], target_state: Dict[str, Any], observed: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    # Guardrail: missing health observation is not proof of terminal auth failure.
    # Provider visibility gaps may justify suspect/unknown handling, but not DEAD without explicit auth evidence.
    ensure_account_state(config, target_state)
    target_state.setdefault("monitor", {})["knownProfiles"] = sorted(list(observed.keys()))
    missing_profiles: List[str] = []
    unhealthy_profiles: List[str] = []

    for a in config.get("accounts", []):
        pid = a["profileId"]
        st = target_state["accounts"][pid]
        prev_h = st.get("health", {}) if isinstance(st.get("health"), dict) else {}
        st["health"] = evaluate_profile_health(config, prev_h, observed.get(pid))
        h = st.get("health", {}) if isinstance(st.get("health"), dict) else {}
        if h.get("expired"):
            auth = auth_status_record(st)
            verification = st.get("verification", {}) if isinstance(st.get("verification"), dict) else {}
            gate_pre = routing_gate_summary(config, st)
            if not (
                str(auth.get("status") or "").upper() == "DEAD"
                and canonical_dead_reason(auth.get("reason")) == canonical_dead_reason("expired")
                and str(verification.get("status") or "").upper() != "VERIFIED"
                and gate_pre.get("effectiveState") == "REAUTH_REQUIRED"
                and not contradiction_flags(config, st)
            ):
                apply_terminal_dead_state(config, target_state, pid, "expired", "models_status", h.get("reason"))
        elif h.get("healthy") is False and str(h.get("reason") or "") == "not_reported_by_models_status":
            auth = auth_status_record(st)
            if str(auth.get("status") or "").upper() != "DEAD":
                auth.update({"status": "UNKNOWN", "reason": "models_status_missing", "source": "models_status", "at": ts(), "raw": h.get("reason")})
                st["auth"] = auth
                append_history(target_state, {"at": ts(), "type": "health_missing_suspect", "profileId": pid, "reason": h.get("reason")})
        if pid not in observed:
            missing_profiles.append(pid)
        if st.get("health", {}).get("healthy") is False:
            unhealthy_profiles.append(pid)
        _ = is_quarantined(st)

    return {
        "missingProfiles": missing_profiles,
        "unhealthyProfiles": unhealthy_profiles,
        "contradictionSummary": audit_contradictions(config, target_state),
    }


def parse_usage_output(out: str) -> Dict[str, Any]:
    five_h, week = None, None

    m5p = re.search(r"(?i)\b5h\s*:\s*(\d+(?:\.\d+)?)\s*%\s*left", out)
    if m5p:
        five_h = float(m5p.group(1))
    mwp = re.search(r"(?i)\bweek\s*:\s*(\d+(?:\.\d+)?)\s*%\s*left", out)
    if mwp:
        week = float(mwp.group(1))

    if five_h is None:
        m5 = re.search(r"(?i)(\d+(?:\.\d+)?)\s*h\s*(?:remaining|left)?\s*(?:in|for)?\s*5h", out)
        if m5:
            five_h = float(m5.group(1))
    if week is None:
        mw = re.search(r"(?i)(\d+(?:\.\d+)?)\s*h\s*(?:remaining|left)?\s*(?:in|for)?\s*week", out)
        if mw:
            week = float(mw.group(1))

    return {
        "available": True,
        "fiveHourRemaining": five_h,
        "weekRemaining": week,
        "raw": out,
        "observedAt": ts(),
    }


def observe_usage_snapshot(config: Dict[str, Any]) -> Dict[str, Any]:
    rc, out, err = run_cmd(["openclaw", "status", "--usage"], timeout=timeout_tier(config, "quick"))
    if rc != 0:
        return {"available": False, "error": err or out, "observedAt": ts()}
    return parse_usage_output(out)


def auth_store_path(agent_id: str) -> Path:
    return Path(f"/home/jarvis/.openclaw/agents/{agent_id}/agent/auth-profiles.json")


def load_auth_store(agent_id: str = "main") -> Dict[str, Any]:
    path = auth_store_path(agent_id)
    if not path.exists() and agent_id != "main":
        path = auth_store_path("main")
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_auth_store(agent_id: str, store: Dict[str, Any]) -> None:
    save_json(auth_store_path(agent_id), store if isinstance(store, dict) else {})


def sync_auth_profile_from_main(profile_id: str, target_agents: Optional[List[str]] = None) -> Dict[str, Any]:
    targets = list(target_agents or ["track-t-qa", "main"])
    source_store = load_auth_store("main")
    source_profiles = source_store.get("profiles", {}) if isinstance(source_store, dict) else {}
    source_row = source_profiles.get(profile_id) if isinstance(source_profiles, dict) else None
    if not isinstance(source_row, dict):
        return {"ok": False, "reason": "profile_missing_in_main", "profileId": profile_id, "targets": targets, "changed": []}
    changed: List[str] = []
    for agent_id in targets:
        if agent_id == "main":
            target_path = Path("/home/jarvis/.openclaw/agents/main/auth-profiles.json")
            if target_path.exists():
                try:
                    target_store = json.loads(target_path.read_text())
                except Exception:
                    target_store = {}
                profiles = target_store.setdefault("profiles", {})
                if profiles.get(profile_id) != source_row:
                    profiles[profile_id] = copy.deepcopy(source_row)
                    target_path.write_text(json.dumps(target_store, indent=2) + "\n")
                    changed.append("main-legacy")
        target_store = load_auth_store(agent_id)
        profiles = target_store.setdefault("profiles", {})
        if profiles.get(profile_id) != source_row:
            profiles[profile_id] = copy.deepcopy(source_row)
            save_auth_store(agent_id, target_store)
            changed.append(agent_id)
    return {"ok": True, "profileId": profile_id, "targets": targets, "changed": changed}


def persist_auth_profile_identity(agent_id: str, store: Dict[str, Any], profile_id: str, *, account_id: Optional[str] = None, email: Optional[str] = None) -> bool:
    profiles = store.get("profiles", {}) if isinstance(store, dict) else {}
    row = profiles.get(profile_id) if isinstance(profiles, dict) else None
    if not isinstance(row, dict):
        return False
    changed = False
    norm_account = str(account_id or "").strip() or None
    norm_email = str(email or "").strip() or None
    if norm_account and str(row.get("accountId") or "").strip() != norm_account:
        row["accountId"] = norm_account
        changed = True
    if norm_email and not str(row.get("email") or "").strip():
        row["email"] = norm_email
        changed = True
    if changed:
        profiles[profile_id] = row
        store["profiles"] = profiles
        save_auth_store(agent_id, store)
    return changed


def clamp_pct(value: Any) -> Optional[float]:
    if not isinstance(value, (int, float)):
        return None
    try:
        return max(0.0, min(100.0, float(value)))
    except Exception:
        return None


def remaining_from_used(value: Any) -> Optional[float]:
    pct = clamp_pct(value)
    if pct is None:
        return None
    return round(max(0.0, min(100.0, 100.0 - pct)), 1)


def fetch_openai_codex_usage_for_profile(profile_id: str, *, timeout_sec: int = 30, agent_id: str = "main") -> Dict[str, Any]:
    store = load_auth_store(agent_id)
    profiles = store.get("profiles", {}) if isinstance(store, dict) else {}
    row = profiles.get(profile_id) if isinstance(profiles, dict) else None
    observed_at = ts()
    if not isinstance(row, dict):
        return {"available": False, "observedAt": observed_at, "source": "provider-api-per-profile", "trust": "untrusted", "reason": "profile_not_found"}
    token = str(row.get("access") or row.get("token") or "").strip()
    account_id = str(row.get("accountId") or row.get("providerAccountId") or "").strip()
    if not token:
        return {"available": False, "observedAt": observed_at, "source": "provider-api-per-profile", "trust": "untrusted", "reason": "missing_access_token"}
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "CodexBar",
        "Accept": "application/json",
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    req = urllib_request.Request(
        "https://chatgpt.com/backend-api/wham/usage",
        headers=headers,
        method="GET",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout_sec) as res:
            data = json.loads(res.read().decode())
    except urllib_error.HTTPError as exc:
        body = exc.read().decode(errors="ignore")[:400]
        return {"available": False, "observedAt": observed_at, "source": "provider-api-per-profile", "trust": "untrusted", "reason": f"http_{exc.code}", "error": body}
    except Exception as exc:
        return {"available": False, "observedAt": observed_at, "source": "provider-api-per-profile", "trust": "untrusted", "reason": f"fetch_failed:{exc}"}

    primary = ((data.get("rate_limit") or {}).get("primary_window") or {})
    secondary = ((data.get("rate_limit") or {}).get("secondary_window") or {})
    returned_account = str(data.get("account_id") or data.get("user_id") or "").strip()
    returned_email = str(data.get("email") or "").strip().lower()
    expected_email = str(row.get("email") or "").strip().lower()
    if expected_email and returned_email and expected_email != returned_email:
        return {
            "available": False,
            "observedAt": observed_at,
            "source": "provider-api-per-profile",
            "trust": "rejected",
            "reason": "email_mismatch",
            "expectedEmail": expected_email,
            "returnedEmail": returned_email,
            "expectedAccountId": account_id or None,
            "returnedAccountId": returned_account or None,
        }
    if returned_account and ((not account_id) or account_id != returned_account):
        persist_auth_profile_identity(agent_id, store, profile_id, account_id=returned_account, email=(returned_email or expected_email or None))
        account_id = returned_account
    elif returned_email and not expected_email:
        persist_auth_profile_identity(agent_id, store, profile_id, email=returned_email)
    result = {
        "available": True,
        "fiveHourRemaining": remaining_from_used(primary.get("used_percent")),
        "weekRemaining": remaining_from_used(secondary.get("used_percent")),
        "observedAt": observed_at,
        "source": "provider-api-per-profile",
        "trust": "verified",
        "accountId": account_id or returned_account or None,
        "providerReturnedAccountId": returned_account or None,
        "email": data.get("email") or row.get("email"),
        "rawUsedPrimaryPct": clamp_pct(primary.get("used_percent")),
        "rawUsedSecondaryPct": clamp_pct(secondary.get("used_percent")),
        "primaryWindowSeconds": primary.get("limit_window_seconds"),
        "secondaryWindowSeconds": secondary.get("limit_window_seconds"),
        "limitReached": bool((data.get("rate_limit") or {}).get("limit_reached", False)),
    }
    try:
        append_jsonl(USAGE_LOG_PATH, {
            "at": observed_at,
            "profileId": profile_id,
            "accountId": result.get("accountId"),
            "email": result.get("email"),
            "fiveHourRemaining": result.get("fiveHourRemaining"),
            "weekRemaining": result.get("weekRemaining"),
            "source": result.get("source"),
            "trust": result.get("trust"),
            "agentId": agent_id,
        })
    except Exception:
        pass
    return result


def get_auth_order(provider: str, agent_id: str, timeout_sec: int = 30) -> Optional[List[str]]:
    rc, out, _ = run_cmd([
        "openclaw", "models", "auth", "order", "get",
        "--provider", provider,
        "--agent", agent_id,
        "--json",
    ], timeout=timeout_sec)
    if rc != 0 or not out:
        return None
    try:
        payload = json.loads(out)
    except Exception:
        return None
    order = payload.get("order")
    return list(order) if isinstance(order, list) else None


def set_auth_order(provider: str, agent_id: str, order: List[str], timeout_sec: int = 30) -> bool:
    if not order:
        return False
    rc, _, _ = run_cmd([
        "openclaw", "models", "auth", "order", "set",
        "--provider", provider,
        "--agent", agent_id,
        *order,
    ], timeout=timeout_sec)
    return rc == 0


def clear_auth_order(provider: str, agent_id: str, timeout_sec: int = 30) -> bool:
    rc, _, _ = run_cmd([
        "openclaw", "models", "auth", "order", "clear",
        "--provider", provider,
        "--agent", agent_id,
    ], timeout=timeout_sec)
    return rc == 0


PROVIDER_SHARED_USAGE_SOURCES = {
    "per-profile",
    "active-profile",
    "probe",
    "stale-probe",
    "manual_verify",
    "live_canary",
    "probe-readonly",
    "provider-global",
    "provider-global-unmapped",
    "status-main-probe",
    "manual-status-main-probe",
    "audited-double-pass-main-probe",
}
AUTH_ONLY_USAGE_SOURCES = {
    "auth-smoke",
    "verifier-smoke",
}
TRUSTED_NUMERIC_USAGE_SOURCES = {
    "provider-api-per-profile",
}
VERIFIER_STATUS_AUTH_OK = "AUTH_OK"
VERIFIER_STATUS_RATE = "RATE_LIMITED_OR_EXHAUSTED"
VERIFIER_STATUS_DEAD = "DEAD_OR_UNAUTHORIZED"
VERIFIER_STATUS_UNKNOWN = "UNKNOWN_OR_TIMEOUT"


def run_standalone_profile_verifier(config: Dict[str, Any], profile_id: str, timeout_tier_name: str = "quick") -> Dict[str, Any]:
    script_path = BASE_DIR / "ops" / "scripts" / "oauth_profile_verifier.py"
    if not script_path.exists():
        return {"ok": False, "error": f"missing verifier script: {script_path}", "profileId": profile_id}
    smoke_timeout = max(15, min(90, timeout_tier(config, timeout_tier_name)))
    outer_timeout = max(smoke_timeout + 20, 60)
    cmd = [
        sys.executable or "python3",
        str(script_path),
        "--profile", profile_id,
        "--json",
        "--timeout", str(smoke_timeout),
        "--thinking", "off",
        "--message", "Reply with exactly OK.",
        "--session-id", "oauth-verifier",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=outer_timeout)
    out = {
        "ok": False,
        "profileId": profile_id,
        "status": VERIFIER_STATUS_UNKNOWN,
        "evidence": None,
        "authOrderRestored": False,
        "raw": {"code": rc, "stdout": stdout, "stderr": stderr},
    }
    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()
    if rc != 0 or not stdout.startswith("{"):
        combined = "\n".join([stdout, stderr]).strip()
        out["evidence"] = combined or f"verifier_exec_failed:{rc}"
        return out
    try:
        payload = json.loads(stdout)
    except Exception as exc:
        out["evidence"] = f"verifier_json_parse_failed:{exc}"
        return out
    profiles = payload.get("profiles") if isinstance(payload, dict) else []
    row = profiles[0] if isinstance(profiles, list) and profiles else {}
    if not isinstance(row, dict):
        row = {}
    out.update({
        "ok": True,
        "status": row.get("status") or VERIFIER_STATUS_UNKNOWN,
        "evidence": row.get("evidence") or payload.get("error") or "verifier_no_evidence",
        "authOrderRestored": bool(row.get("authOrderRestored", False)),
        "row": row,
        "payload": payload,
    })
    return out


def usage_background_probe_agent_id(config: Dict[str, Any]) -> str:
    raw = config.get("usageProbe", {}) if isinstance(config.get("usageProbe"), dict) else {}
    return str(raw.get("agentId") or raw.get("statusAgentId") or "main")


def usage_status_probe_agent_id(config: Dict[str, Any]) -> str:
    raw = config.get("usageProbe", {}) if isinstance(config.get("usageProbe"), dict) else {}
    return str(raw.get("statusAgentId") or raw.get("agentId") or "main")


def usage_status_probe_settle_seconds(config: Dict[str, Any]) -> float:
    raw = config.get("usageProbe", {}) if isinstance(config.get("usageProbe"), dict) else {}
    try:
        v = float(raw.get("statusSettleSeconds", 2.0))
    except Exception:
        v = 2.0
    return max(0.0, min(5.0, v))


def usage_probe_max_profiles_per_tick(config: Dict[str, Any]) -> int:
    raw = config.get("usageProbe", {}) if isinstance(config.get("usageProbe"), dict) else {}
    try:
        v = int(raw.get("maxProfilesPerTick", 2))
    except Exception:
        v = 2
    return max(1, min(8, v))


def runtime_auth_agent_id(config: Dict[str, Any]) -> str:
    raw = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
    return str(raw.get("runtimeAgentId") or "main")


def resolve_usage_profile(config: Dict[str, Any], state: Dict[str, Any]) -> Optional[str]:
    # Prefer explicit manual override when set.
    ov = state.get("override", {})
    if ov.get("enabled") and ov.get("profileId"):
        return ov.get("profileId")

    provider = config.get("provider", "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    order = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard"))
    if order and isinstance(order, list) and len(order) > 0:
        return order[0]
    return None


def write_usage_snapshot(state: Dict[str, Any], pid: str, snap: Dict[str, Any], *, source: str, observed_at: Optional[str] = None) -> None:
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    usage = acct.setdefault("usage", {})
    usage.update({
        "available": bool(snap.get("available", False)),
        "fiveHourRemaining": snap.get("fiveHourRemaining"),
        "weekRemaining": snap.get("weekRemaining"),
        "observedAt": observed_at or snap.get("observedAt") or ts(),
        "source": source,
    })


def observe_usage_by_profile(config: Dict[str, Any], state: Dict[str, Any], cli_timeout_tier: str = "standard", agent_id: Optional[str] = None, force_all: bool = False) -> Dict[str, Dict[str, Any]]:
    provider = config.get("provider", "openai-codex")
    agent_id = str(agent_id or usage_background_probe_agent_id(config))

    profile_ids_all = [a.get("profileId") for a in config.get("accounts", []) if a.get("enabled", True)]
    profile_ids = [p for p in profile_ids_all if p]
    if not profile_ids:
        return {}

    max_profiles = len(profile_ids) if force_all else usage_probe_max_profiles_per_tick(config)
    probe_cursor = int((((state.get("monitor", {}) or {}).get("usageProbeCursor")) or 0))
    if (not force_all) and len(profile_ids) > max_profiles:
        start = probe_cursor % len(profile_ids)
        rotated = profile_ids[start:] + profile_ids[:start]
        profile_ids = rotated[:max_profiles]
        state.setdefault("monitor", {})["usageProbeCursor"] = (start + max_profiles) % len(profile_ids_all)
    else:
        state.setdefault("monitor", {})["usageProbeCursor"] = 0

    if provider != "openai-codex":
        results: Dict[str, Dict[str, Any]] = {}
        snap = observe_usage_snapshot(config)
        for pid in profile_ids:
            results[pid] = dict(snap)
        return results

    store = load_auth_store("main")
    profiles = store.get("profiles", {}) if isinstance(store, dict) else {}
    account_owner: Dict[str, str] = {}
    aliases: Dict[str, List[str]] = {}
    targets: List[str] = []
    for pid in profile_ids:
        row = profiles.get(pid) if isinstance(profiles, dict) else None
        account_key = None
        if isinstance(row, dict):
            account_key = str(row.get("accountId") or row.get("providerAccountId") or "").strip() or None
        dedupe_key = account_key or f"profile:{pid}"
        owner = account_owner.get(dedupe_key)
        if owner:
            aliases.setdefault(owner, []).append(pid)
            continue
        account_owner[dedupe_key] = pid
        targets.append(pid)

    timeout_sec = timeout_tier(config, cli_timeout_tier)
    results: Dict[str, Dict[str, Any]] = {}
    for pid in targets:
        snap = fetch_openai_codex_usage_for_profile(pid, timeout_sec=timeout_sec, agent_id="main")
        snap["probeAgentId"] = agent_id
        snap["frontloadedProfileId"] = pid
        results[pid] = snap
        for alias_pid in aliases.get(pid, []):
            alias_snap = dict(snap)
            alias_snap["aliasedFromProfileId"] = pid
            results[alias_pid] = alias_snap
    return results


def record_auth_order_trace(state: Dict[str, Any], *, source: str, reason: str, desired_order: List[str], effective_order: List[str], observed_order: Optional[List[str]] = None, apply_result: Optional[Dict[str, Any]] = None) -> None:
    trace = state.setdefault("authOrderTrace", {})
    trace["desiredOrder"] = list(desired_order or [])
    trace["effectiveOrder"] = list(effective_order or [])
    if observed_order is not None:
        trace["observedOrder"] = list(observed_order or [])
        trace["lastVerifiedAt"] = ts()
    trace["lastAppliedAt"] = ts()
    trace["lastWriter"] = "oauth_pool_router.py"
    trace["lastSource"] = source
    trace["lastReason"] = reason
    tail_noise = [p for p in (observed_order or []) if p not in set(effective_order or [])]
    trace["drift"] = {"activeHead": (observed_order or [None])[0] if observed_order else None, "policyHead": (effective_order or [None])[0] if effective_order else None, "tailNoise": tail_noise, "policyDrift": bool(observed_order is not None and list(observed_order or []) != list(effective_order or [])), "removedIneligible": list((apply_result or {}).get("removedIneligible", [])), "driftAgents": list((apply_result or {}).get("driftAgents", []))}


def control_plane_snapshot(config: Dict[str, Any], state: Dict[str, Any], current_order: Optional[List[str]] = None) -> Dict[str, Any]:
    provider = str(config.get("provider") or "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    observed_order = list(current_order or get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "quick")) or [])
    sanitized_order, _removed = sanitize_runtime_order(config, observed_order)
    preview = build_effective_auth_order(config, state, sanitized_order)
    effective_order = list((preview or {}).get("effectiveOrder") or sanitized_order)
    routing = state.get("routing", {}) if isinstance(state.get("routing"), dict) else {}
    selected_target = routing.get("selectedTarget") or (effective_order[0] if effective_order else None)
    current_target = routing.get("currentTarget") or (sanitized_order[0] if sanitized_order else None)
    last_applied_top = routing.get("lastAppliedTop") or selected_target
    return {
        "runtimeHead": sanitized_order[0] if sanitized_order else (observed_order[0] if observed_order else None),
        "policyHead": effective_order[0] if effective_order else None,
        "controlHead": last_applied_top or current_target or selected_target,
        "rawRuntimeAuthOrder": observed_order,
        "sanitizedRuntimeAuthOrder": sanitized_order,
        "effectiveEligibleOrder": effective_order,
        "selectedTarget": selected_target,
        "currentTarget": current_target,
        "lastAppliedTop": last_applied_top,
    }


def live_canary_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = config.get("liveCanary", {}) if isinstance(config.get("liveCanary"), dict) else {}
    return {"enabled": bool(raw.get("enabled", True)), "intervalMinutes": max(5, int(raw.get("intervalMinutes", 30))), "timeoutTier": str(raw.get("timeoutTier", "quick")), "maxRuntimeSeconds": max(10, int(raw.get("maxRuntimeSeconds", 180))), "onlyWhenIdle": bool(raw.get("onlyWhenIdle", True))}


def canary_candidate_profiles(config: Dict[str, Any], state: Optional[Dict[str, Any]] = None) -> List[str]:
    profiles = [a.get("profileId") for a in config.get("accounts", []) if a.get("profileId") and a.get("enabled", True)]
    if state is None:
        return profiles
    verified = [pid for pid in profiles if account_is_verified(state, pid)]
    return verified or profiles


def run_live_canary_rotation(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    settings = live_canary_settings(config)
    result = {"ran": False, "skipped": None, "profileId": None}
    lc = state.setdefault("liveCanary", {"cursor": 0, "lastRunAt": None, "lastProfileId": None, "lastOutcome": None, "runs": []})
    if not settings["enabled"]:
        result["skipped"] = "disabled"
        return result
    if settings["onlyWhenIdle"] and any(v.get("active") for v in state.get("leases", {}).values()):
        result["skipped"] = "active_leases"
        return result
    last_run = parse_iso(lc.get("lastRunAt"))
    if last_run and (now_utc() - last_run) < dt.timedelta(minutes=settings["intervalMinutes"]):
        result["skipped"] = "interval_not_elapsed"
        return result
    profiles = canary_candidate_profiles(config, state)
    if not profiles:
        result["skipped"] = "no_enabled_profiles"
        return result
    cursor = int(lc.get("cursor", 0)) % len(profiles)
    pid = profiles[cursor]
    lc["cursor"] = (cursor + 1) % len(profiles)
    lc["lastRunAt"] = ts()
    lc["lastProfileId"] = pid
    started = time.monotonic()
    probe = run_standalone_profile_verifier(config, pid, settings["timeoutTier"])
    reason = str(probe.get("evidence") or probe.get("status") or "live_canary_unknown")
    verifier_status = str(probe.get("status") or "")
    dead_reason = dead_reason_from_verifier_probe(probe)
    ok = bool(probe.get("ok")) and verifier_status == VERIFIER_STATUS_AUTH_OK and bool(probe.get("authOrderRestored")) and not dead_reason
    event = {
        "at": ts(),
        "profileId": pid,
        "success": ok,
        "latencyMs": int((time.monotonic() - started) * 1000),
        "reason": reason,
        "status": probe.get("status"),
        "authOrderRestored": bool(probe.get("authOrderRestored")),
        "fiveHourRemaining": None,
        "weekRemaining": None,
        "observedOrder": None,
    }
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    canary = acct.setdefault("canary", {})
    prev_usage = acct.get("usage", {}) if isinstance(acct.get("usage"), dict) else {}
    prev_at = parse_iso(prev_usage.get("observedAt")) if isinstance(prev_usage, dict) else None
    retain_minutes = int((config.get("usageProbe") or {}).get("retainProbeMinutes", 180))
    keep_numeric_usage = bool(
        ok
        and isinstance(prev_usage, dict)
        and prev_usage.get("source") in TRUSTED_NUMERIC_USAGE_SOURCES
        and prev_at is not None
        and (now_utc() - prev_at) <= dt.timedelta(minutes=retain_minutes)
    )
    if not keep_numeric_usage:
        acct["usage"] = {
            "available": bool(ok),
            "fiveHourRemaining": None,
            "weekRemaining": None,
            "observedAt": event["at"],
            "source": "auth-smoke",
        }
    canary.update({"lastRunAt": event["at"], "lastSuccessAt": event["at"] if ok else canary.get("lastSuccessAt"), "success": ok, "latencyMs": event["latencyMs"], "reason": reason, "observedOrder": None})
    if ok:
        set_verification_status(state, pid, "VERIFIED", "live_canary_ok", "live_canary")
    else:
        set_verification_status(state, pid, "FAILED", reason or "live_canary_failed", "live_canary")
        dead_reason = dead_reason_from_verifier_probe(probe)
        if dead_reason:
            apply_terminal_dead_state(config, state, pid, dead_reason, "live_canary", reason or None)
            spec = dead_alert_spec(dead_reason)
            key = f"dead:{pid}:{dead_reason}"
            if should_emit_signal(state, key, dead_alert_cooldown_minutes(dead_reason)) and should_emit_terminal_alert(state, pid, spec["code"], dead_reason, acct):
                send_alert(
                    config,
                    state,
                    "CRITICAL",
                    f"OAuth account {account_name(config, pid)} ({pid}) marked {spec['label']} ({dead_reason}) after live canary failure.",
                    code=spec["code"],
                    impact=spec["impact"],
                    auto_action=spec["auto_action"],
                    your_action=spec["your_action"],
                    status=f"profile={pid}",
                )
                mark_signal(state, key)
    runs = lc.setdefault("runs", [])
    runs.append(event)
    if len(runs) > 100:
        del runs[:len(runs) - 100]
    lc["lastOutcome"] = event
    append_history(state, {"at": event["at"], "type": "live_canary", **event})
    result.update(event)
    result["ran"] = True
    return result


def task_record(state: Dict[str, Any], lane: str, task_id: str) -> Dict[str, Any]:
    k = f"{lane}:{task_id}"
    tasks = state.setdefault("tasks", {})
    if k not in tasks:
        tasks[k] = {
            "lane": lane,
            "taskId": task_id,
            "createdAt": ts(),
            "retryCount": 0,
            "escalationRequired": False,
            "attempts": [],
            "lastResult": None,
        }
    return tasks[k]

def select_profile(config: Dict[str, Any], state: Dict[str, Any], lane: str, task_id: str, project: Optional[str], force_profile: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    lk = f"{lane}:{task_id}"
    existing = state.setdefault("leases", {}).get(lk)
    if existing and existing.get("active"):
        return existing["profileId"], {"reason": "existing_lease"}

    candidates = healthy_profiles(config, state)
    if not candidates:
        raise RuntimeError("No healthy profiles available.")

    # Retry-safe preference: if prior failure scheduled a retry profile, honor it first.
    task = state.get("tasks", {}).get(lk, {})
    preferred_retry = task.get("nextRetryProfile")
    if preferred_retry and preferred_retry in candidates:
        return preferred_retry, {"reason": "retry_preferred", "profile": preferred_retry}

    # Avoid re-using a profile that already failed this task unless there is no alternative.
    failed_profiles = {
        a.get("profileId")
        for a in task.get("attempts", [])
        if a.get("event") == "lease_released" and a.get("result") == "failed" and a.get("profileId")
    }
    filtered_candidates = [p for p in candidates if p not in failed_profiles]
    if filtered_candidates:
        candidates = filtered_candidates

    if force_profile:
        if force_profile in candidates:
            return force_profile, {"reason": "force_profile"}
        raise RuntimeError(f"Forced profile '{force_profile}' is not eligible")

    ov = state.get("override", {})
    if ov.get("enabled") and ov.get("profileId") in candidates:
        return ov["profileId"], {"reason": "manual_override"}

    focus = state.get("focus", {})
    weights = config.get("weights", {})
    cap = int(config.get("concurrencyCapPerAccount", 3))
    ranked = []
    for pid in candidates:
        st = state["accounts"][pid]
        active = active_leases_for_profile(state, pid)
        score = 0
        if focus.get("enabled") and focus.get("project") in account_projects(config, pid):
            score += int(weights.get("focusAffinity", 40))
        if project and project in account_projects(config, pid):
            score += max(1, int(weights.get("focusAffinity", 40)) // 4)

        u = st.get("usage", {}) if isinstance(st.get("usage"), dict) else {}
        telemetry = telemetry_trust_state(u)
        if telemetry.get("state") == "trusted":
            week = float(u.get("weekRemaining")) if isinstance(u.get("weekRemaining"), (int, float)) else 0.0
            five = float(u.get("fiveHourRemaining")) if isinstance(u.get("fiveHourRemaining"), (int, float)) else 0.0
            cap_signal = (week * 4.0) + min(five, 50.0)
            score += int(cap_signal * (int(weights.get("remainingCapacity", 30)) / 100.0))
        else:
            verification = st.get("verification", {}) if isinstance(st.get("verification"), dict) else {}
            if verification.get("status") == "VERIFIED":
                score += int(weights.get("priority", 10)) * 2
        score += (cap - active) * int(weights.get("lowLeases", 20))
        score += account_priority(config, pid) * int(weights.get("priority", 10))
        ranked.append((score, -active, pid))
    ranked.sort(reverse=True)
    return ranked[0][2], {"reason": "scored_selection", "ranked": ranked, "failedExcluded": sorted(list(failed_profiles))}


def can_reorder_auth_for_new_assignments(config: Dict[str, Any], state: Dict[str, Any], preferred_profile: str) -> bool:
    active = [l for l in state.get("leases", {}).values() if l.get("active")]
    if not active:
        allow = bool((config.get("safeSwitch") or {}).get("allowGlobalReorderWithoutLease", False))
        return allow
    return {x.get("profileId") for x in active} == {preferred_profile}


def build_effective_auth_order(config: Dict[str, Any], state: Dict[str, Any], ordered_profiles: List[str]) -> Dict[str, Any]:
    provider = config.get("provider", "openai-codex")
    monitor_known = ((state.get("monitor", {}) or {}).get("knownProfiles", [])) if isinstance(state.get("monitor", {}), dict) else []
    known_profiles = set(monitor_known) if monitor_known else {a.get("profileId") for a in config.get("accounts", []) if a.get("profileId")}

    raw_policy = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
    override = state.get("override", {}) if isinstance(state.get("override"), dict) else {}
    override_enabled = bool(override.get("enabled"))
    override_profile = str(override.get("profileId") or "").strip() or None
    policy = {
        "excludeIneligible": bool(raw_policy.get("excludeIneligible", True)),
        "failOpenOnNoEligible": bool(raw_policy.get("failOpenOnNoEligible", True)),
        "verifyAfterApply": bool(raw_policy.get("verifyAfterApply", True)),
        "verifyRetries": max(0, int(raw_policy.get("verifyRetries", 1))),
    }
    verify_agents_cfg = raw_policy.get("verifyAgents", ["main"])
    if isinstance(verify_agents_cfg, list):
        policy["verifyAgents"] = [str(x) for x in verify_agents_cfg]
    elif isinstance(verify_agents_cfg, str):
        policy["verifyAgents"] = [verify_agents_cfg]
    else:
        policy["verifyAgents"] = ["main"]

    # Deduplicate while preserving order.
    seen = set()
    deduped: List[str] = []
    for p in ordered_profiles:
        if p and p not in seen:
            deduped.append(p)
            seen.add(p)

    filtered_known = [p for p in deduped if (not known_profiles or p in known_profiles)]
    if override_enabled and override_profile and override_profile in known_profiles:
        filtered_known = [override_profile] + [p for p in filtered_known if p != override_profile]

    eligible_profiles = set(healthy_profiles(config, state))
    removed_ineligible: List[str] = []
    effective = list(filtered_known)

    if policy["excludeIneligible"] and eligible_profiles:
        effective = []
        for p in filtered_known:
            if p in eligible_profiles:
                effective.append(p)
            else:
                removed_ineligible.append(p)

    if not effective and policy["failOpenOnNoEligible"]:
        effective = list(filtered_known)

    if override_enabled and override_profile:
        if override_profile in filtered_known:
            effective = [override_profile] + [p for p in effective if p != override_profile]
        else:
            effective = [override_profile] + list(effective)

    return {
        "provider": provider,
        "knownProfiles": sorted(list(known_profiles)),
        "policy": policy,
        "dedupedOrder": deduped,
        "filteredKnownOrder": filtered_known,
        "effectiveOrder": effective,
        "eligibleProfiles": sorted(list(eligible_profiles)),
        "removedIneligible": removed_ineligible,
    }


def apply_auth_order(config: Dict[str, Any], state: Dict[str, Any], ordered_profiles: List[str], timeout_sec: Optional[int] = None, source: str = "router", reason: str = "apply") -> Dict[str, Any]:
    preview = build_effective_auth_order(config, state, ordered_profiles)
    provider = preview["provider"]
    policy = preview["policy"]
    filtered = preview["effectiveOrder"]

    verify_agents = {str(x) for x in policy.get("verifyAgents", ["main"])}
    verify_after_apply = bool(policy.get("verifyAfterApply", True))
    verify_retries = max(0, int(policy.get("verifyRetries", 1)))

    out = {
        "attempted": bool(filtered),
        "order": ordered_profiles,
        "dedupedOrder": preview["dedupedOrder"],
        "effectiveOrder": filtered,
        "eligibleProfiles": preview["eligibleProfiles"],
        "removedIneligible": preview["removedIneligible"],
        "policy": policy,
        "agents": {},
        "driftAgents": [],
    }

    if not filtered:
        out["reason"] = "no_valid_profiles_for_provider"
        return out

    observed_main_order = None
    for agent in auth_order_agents(config):
        cmd = ["openclaw", "models", "auth", "order", "set", "--provider", provider, "--agent", agent, *filtered]
        rc, so, se = run_cmd(cmd, timeout=(timeout_sec or 30))
        agent_out = {"ok": rc == 0, "code": rc, "stdout": so, "stderr": se, "cmd": " ".join(cmd)}

        if rc == 0 and verify_after_apply and (agent in verify_agents):
            verify_ok = False
            observed_order = None
            verify_error = None
            attempts = 0

            while True:
                get_cmd = ["openclaw", "models", "auth", "order", "get", "--provider", provider, "--agent", agent, "--json"]
                rc_g, so_g, se_g = run_cmd(get_cmd, timeout=(timeout_sec or 30))
                if rc_g == 0 and so_g:
                    try:
                        payload = json.loads(so_g)
                        observed_order = payload.get("order") if isinstance(payload, dict) else None
                    except Exception as exc:
                        verify_error = f"json-parse-error: {exc}"
                else:
                    verify_error = se_g or so_g or f"get-order rc={rc_g}"

                verify_ok = isinstance(observed_order, list) and (observed_order == filtered)
                if verify_ok or attempts >= verify_retries:
                    break

                attempts += 1
                run_cmd(cmd, timeout=(timeout_sec or 30))

            agent_out["verify"] = {
                "ok": verify_ok,
                "attempts": attempts,
                "observedOrder": observed_order,
                "expectedOrder": filtered,
                "error": verify_error,
            }
            if agent == "main" and isinstance(observed_order, list):
                observed_main_order = list(observed_order)
            if not verify_ok:
                agent_out["ok"] = False
                agent_out["driftDetected"] = True
                out["driftAgents"].append(agent)

        out["agents"][agent] = agent_out

    if observed_main_order is None:
        observed_main_order = get_auth_order(provider, "main", timeout_sec=(timeout_sec or 30)) or []
    out["source"] = source
    out["reason"] = reason
    out["observedMainOrder"] = observed_main_order
    record_auth_order_trace(state, source=source, reason=reason, desired_order=ordered_profiles, effective_order=filtered, observed_order=observed_main_order, apply_result=out)
    return out


def alert_auth_order_drift(config: Dict[str, Any], state: Dict[str, Any], result: Dict[str, Any], context: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    drift_agents = result.get("driftAgents", []) if isinstance(result, dict) else []
    if not drift_agents:
        return events

    for agent in drift_agents:
        key = f"auth_order_drift:{agent}"
        if should_emit_signal(state, key, 30):
            msg = (
                f"Auth-order drift detected for agent '{agent}' during {context}. "
                f"Expected order did not persist after verification retries. "
                f"Run `/oauth status` and inspect auth order."
            )
            r = send_alert(config, state, "WARNING", msg, code="ORDER_VERIFY_DRIFT", impact="Expected auth order did not persist on at least one managed agent.", auto_action="Router will retry and keep monitoring auth order.", your_action="Run /oauth status if this repeats for the same agent.", status=f"agent={agent} context={context}")
            mark_signal(state, key)
            events.append({"type": key, "alert": r, "context": context, "agent": agent})
    return events

def record_policy_reconcile_event(config: Dict[str, Any], state: Dict[str, Any], context: str, current_order: List[str], expected_order: List[str]) -> None:
    policy = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
    window_min = max(1, int(policy.get("driftAlertWindowMinutes", 60)))
    threshold = max(1, int(policy.get("driftAlertThreshold", 4)))
    cooldown_min = max(5, int(policy.get("driftAlertCooldownMinutes", 180)))

    routing = state.setdefault("routing", {})
    drift = routing.setdefault("orderDrift", {})
    events = drift.setdefault("reconcileEvents", [])

    now = now_utc()
    events.append(ts())
    cutoff = now - dt.timedelta(minutes=window_min)
    trimmed = [x for x in events if (parse_iso(x) or now) >= cutoff]
    drift["reconcileEvents"] = trimmed
    drift["lastReconcileAt"] = ts()
    drift["windowMinutes"] = window_min
    drift["windowCount"] = len(trimmed)
    drift["threshold"] = threshold
    drift["lastContext"] = context
    drift["lastCurrentOrder"] = current_order
    drift["lastExpectedOrder"] = expected_order

    if len(trimmed) >= threshold:
        key = "auth_order_reconcile_burst"
        if should_emit_signal(state, key, cooldown_min):
            msg = (
                f"Auth-order drift reconciled {len(trimmed)} times in the last {window_min}m "
                f"(threshold={threshold}) during {context}. "
                f"Another component may be rewriting auth order unexpectedly."
            )
            send_alert(config, state, "INFO", msg, code="DRIFT_BURST", impact="No immediate outage; drift is being auto-corrected repeatedly.", auto_action="Watchdog keeps failover-safe ordering active.", your_action="No action unless this persists beyond today.", status=f"reconciles={len(trimmed)} window={window_min}m threshold={threshold} context={context}")
            mark_signal(state, key)

def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def cmd_watchdog(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool = False) -> int:
    Path("ops/state/backups").mkdir(parents=True, exist_ok=True)
    ensure_account_state(config, state)
    if is_read_only(config):
        result = {"ok": True, "skipped": "read_only", "at": ts()}
        if json_mode:
            print(json.dumps(result, indent=2))
        else:
            print("watchdog skipped (read-only/emergency lock)")
        return 0
    runtime_info = ingest_runtime_failover_signals(config, state)
    auto_hygiene_info = auto_hygiene_reconcile(config, state, reason="watchdog")
    auth_sync_info = auto_hygiene_info.get("authStoreSync")
    wd = watchdog_settings(config)
    now = ts()

    result = {
        "ok": True,
        "at": now,
        "runtimeFailover": runtime_info,
        "authStoreSync": auth_sync_info,
        "enabled": wd["enabled"],
        "maxTickSeconds": wd["maxTickSeconds"],
        "termGraceSeconds": wd["termGraceSeconds"],
        "scanned": 0,
        "stuck": 0,
        "killed": [],
        "alerted": False,
    }

    if not wd["enabled"]:
        save_json(STATE_PATH, state)
        if json_mode:
            print(json.dumps(result, indent=2))
        else:
            print("watchdog disabled")
        return 0

    rc, out, err = run_cmd(["ps", "-eo", "pid=,etimes=,args="], timeout=timeout_tier(config, "quick"))
    if rc != 0:
        raise RuntimeError(f"watchdog ps failed: {err or out}")

    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    result["scanned"] = len(lines)

    for ln in lines:
        parts = ln.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            etimes = int(parts[1])
        except ValueError:
            continue
        cmdline = parts[2]

        if pid == os.getpid():
            continue
        if "oauth_pool_router.py" not in cmdline or " tick" not in cmdline:
            continue

        if etimes < wd["maxTickSeconds"]:
            continue

        result["stuck"] += 1
        item = {
            "pid": pid,
            "elapsedSec": etimes,
            "cmd": cmdline,
            "termSent": False,
            "killSent": False,
            "killed": False,
        }

        try:
            os.kill(pid, signal.SIGTERM)
            item["termSent"] = True
        except ProcessLookupError:
            item["killed"] = True
        except Exception as exc:
            item["error"] = f"term_error: {exc}"

        if not item["killed"]:
            time.sleep(max(1, wd["termGraceSeconds"]))
            if process_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                    item["killSent"] = True
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    item["error"] = f"kill_error: {exc}"

        item["killed"] = not process_alive(pid)
        result["killed"].append(item)

    if result["killed"]:
        append_history(state, {
            "at": now,
            "type": "watchdog_kill",
            "count": len(result["killed"]),
            "items": result["killed"],
        })
        if wd["autoNotify"]:
            sig_key = "watchdog_tick_kill"
            if should_emit_signal(state, sig_key, wd["alertCooldownMinutes"]):
                detail = ", ".join([f"pid={x['pid']} elapsed={x['elapsedSec']}s" for x in result["killed"]])
                send_alert(config, state, "WARNING", f"Watchdog terminated stuck oauth tick process(es): {detail}", code="TICK_STUCK_KILLED", impact="One or more tick runs exceeded the max runtime and were force-stopped.", auto_action="Watchdog used SIGTERM/SIGKILL and routing continues.", your_action="Review recent tick durations if this repeats.", status=f"killed={len(result['killed'])}")
                mark_signal(state, sig_key)
                result["alerted"] = True

    # Fast source-aware drift guard: enforce failover-safe effective order without
    # full usage probe/tick cycle.
    healthy = healthy_profiles(config, state)
    guard_info = {
        "checked": bool(healthy),
        "applied": False,
        "reason": None,
        "currentOrder": None,
        "effectiveOrder": None,
        "failoverUnsafe": [],
    }
    if healthy:
        provider = config.get("provider", "openai-codex")
        agent_id = runtime_auth_agent_id(config)
        timeout_sec = timeout_tier(config, "quick")
        current_order_raw = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
        current_order, tombstoned_runtime = sanitize_runtime_order(config, current_order_raw)
        if tombstoned_runtime and current_order and can_reorder_auth_for_new_assignments(config, state, current_order[0]):
            apply_auth_order(config, state, current_order, source="watchdog", reason="remove_tombstoned_runtime")
        preferred = preferred_healthy_order(config, state, current_order)
        ordered = list(preferred.get("ordered") or []) + [a.get("profileId") for a in config.get("accounts", []) if a.get("profileId") not in healthy]
        ordered = [p for p in ordered if p]
        preview = build_effective_auth_order(config, state, ordered)
        effective_order = preview.get("effectiveOrder", []) if isinstance(preview, dict) else []

        policy_cfg = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
        safe_depth = max(1, int(policy_cfg.get("failoverSafeDepth", 3)))
        effective_set = set(effective_order)
        current_head = current_order[0] if current_order else None
        expected_head = effective_order[0] if effective_order else None
        failover_chain = current_order[:safe_depth] if current_order else []
        failover_unsafe_raw = [p for p in failover_chain if p not in effective_set]
        failover_unsafe = actionable_failover_unsafe_profiles(config, state, failover_unsafe_raw)
        high_risk = bool(current_order and effective_order and (((not current_head) or (current_head != expected_head) or (current_head not in effective_set)) or failover_unsafe))

        guard_info.update({
            "currentOrder": current_order,
            "effectiveOrder": effective_order,
            "failoverUnsafe": failover_unsafe,
            "highRisk": high_risk,
            "safeDepth": safe_depth,
        })

        if high_risk and can_reorder_auth_for_new_assignments(config, state, expected_head):
            apply_res = apply_auth_order(config, state, ordered, source="watchdog", reason="watchdog_guard")
            append_history(state, {
                "at": ts(),
                "type": "auth_order_apply",
                "reason": "watchdog_guard",
                "top": expected_head,
                "result": apply_res,
            })
            alert_auth_order_drift(config, state, apply_res, "watchdog_guard")
            guard_info["applied"] = True
            guard_info["reason"] = "high_risk_drift"
        else:
            guard_info["reason"] = "no_high_risk" if not high_risk else "reorder_blocked"

    result["guard"] = guard_info
    session_rebind_info = sync_session_auth_overrides(config, state, target_order=(guard_info.get("effectiveOrder") or None), reason="watchdog")
    result["sessionRebind"] = session_rebind_info
    state.setdefault("monitor", {})["watchdogHeartbeat"] = {
        "at": now,
        "ok": bool(result.get("ok")),
        "stuck": int(result.get("stuck", 0)),
        "killed": len(result.get("killed", [])),
        "highRisk": bool((guard_info or {}).get("highRisk", False)),
        "guardReason": (guard_info or {}).get("reason"),
        "alerted": bool(result.get("alerted", False)),
    }

    save_json(STATE_PATH, state)
    if json_mode:
        print(json.dumps(result, indent=2))
    else:
        print(f"watchdog ok: stuck={result['stuck']} killed={len(result['killed'])} alerted={result['alerted']}")
    return 0


def _severity_badge(severity: str) -> str:
    sev = (severity or "INFO").upper().strip()
    return {
        "CRITICAL": "🔴 Critical",
        "WARNING": "🟠 Warning",
        "INFO": "🔵 Info",
    }.get(sev, "🔵 Info")


def _humanize_status_label(key: str) -> str:
    cleaned = str(key or "").replace("_", " ").strip()
    return cleaned[:1].upper() + cleaned[1:] if cleaned else "Status"


def _format_status_lines(status: Optional[str]) -> List[str]:
    if not status:
        return []

    raw = str(status)
    parts = [p.strip() for p in (raw.split(";") if ";" in raw else raw.split()) if p.strip()]

    lines: List[str] = []
    for part in parts:
        if "=" not in part:
            lines.append(f"• {_humanize_status_label(part)}")
            continue
        key, value = part.split("=", 1)
        lines.append(f"• {_humanize_status_label(key)}: {value.strip()}")
    return lines


def _format_operator_alert(
    severity: str,
    code: str,
    what: str,
    impact: Optional[str],
    auto_action: Optional[str],
    your_action: Optional[str],
    status: Optional[str],
) -> str:
    sev = severity.upper().strip() or "INFO"

    default_impact = {
        "CRITICAL": "Potential task disruption if unresolved.",
        "WARNING": "Potential instability; system may auto-recover.",
        "INFO": "Informational only; no immediate risk.",
    }
    lines = [
        f"{_severity_badge(sev)} · OAuth pool",
        f"{what}",
        f"Impact: {impact or default_impact.get(sev, default_impact['INFO'])}",
        f"Auto-action: {auto_action or 'Router monitoring and safeguards are active.'}",
        f"🧠 {your_action or ('None right now.' if sev == 'INFO' else 'Run /oauth status if this repeats.')}",
    ]
    lines.extend(_format_status_lines(status))
    return "\n".join(lines)


def _advisor_brain_text(advisor: Dict[str, Any]) -> str:
    recommendation = advisor.get("recommendation") or {}
    rec_level = str(recommendation.get("level") or "").lower().strip()
    rec_message = str(recommendation.get("message") or "").strip()
    if rec_level == 'critical':
        return rec_message or 'Add 1-2 accounts now.'
    if rec_level == 'warning':
        return rec_message or 'Add capacity soon.'
    if rec_level == 'info' and rec_message:
        return rec_message
    return 'No new accounts needed right now.'


def _advisor_capacity_status(advisor: Dict[str, Any]) -> str:
    pool = advisor.get("poolSummary") or {}
    action = _advisor_brain_text(advisor)
    return "; ".join([
        f"capacity=CPH {float(pool.get('compositeHealthPct', 0.0)):.1f}%",
        f"ready={int(pool.get('eligibleCount', 0))}/{int(pool.get('enabledCount', 0))}",
        f"healthy={int(pool.get('healthyCount', 0))}/{int(pool.get('enabledCount', 0))}",
        f"brain={action}",
    ])


def send_alert(
    config: Dict[str, Any],
    state: Dict[str, Any],
    severity: str,
    message: str,
    *,
    code: str = "GENERAL",
    impact: Optional[str] = None,
    auto_action: Optional[str] = None,
    your_action: Optional[str] = None,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    sev = (severity or "INFO").upper().strip()
    raw = (message or "").strip()
    what = raw.splitlines()[0].strip() if raw else "No additional details."
    full = _format_operator_alert(sev, code, what, impact, auto_action, your_action, status)

    now_at = ts()
    res = {"severity": sev, "code": code, "message": raw, "formatted": full, "channels": {}}
    delivery_update = {
        "delivery": {
            "lastAlertOutboundAt": now_at,
            "lastAlertMessage": what,
            "lastOutboundAt": now_at,
            "lastOutboundKind": "router_alert",
            "lastOutboundMeta": {"severity": sev, "code": code},
        }
    }
    any_success = False
    first_error = None
    for k in ("telegram", "discord"):
        sink = config.get("alerts", {}).get(k, {})
        enabled = bool(sink.get("enabled", False))
        if not enabled:
            res["channels"][k] = {"ok": False, "skipped": True}
            continue
        channel = str(sink.get("channel") or k)
        target = str(sink.get("target") or ("1828174896" if k == "telegram" else ""))
        if not target:
            res["channels"][k] = {"ok": False, "skipped": True, "reason": "missing_target"}
            continue
        cmd = ["openclaw", "message", "send", "--channel", channel, "--target", target, "--message", full]
        rc, so, se = run_cmd(cmd, timeout=30)
        ok = rc == 0
        res["channels"][k] = {"ok": ok, "code": rc, "stdout": so, "stderr": se, "cmd": " ".join(cmd)}
        if ok:
            any_success = True
        elif first_error is None:
            first_error = se or so or f"send_failed:{channel}:{rc}"
    if any_success:
        delivery_update["delivery"]["lastOutboundMeta"] = {
            "severity": sev,
            "code": code,
            "channels": [name for name, meta in res["channels"].items() if meta.get("ok")],
        }
    else:
        delivery_update["delivery"].update({
            "lastFailedOutboundAt": now_at,
            "lastFailedOutboundKind": "router_alert",
            "lastFailedOutboundError": first_error,
            "lastFailedOutboundMeta": {"severity": sev, "code": code},
        })
    try:
        persist_delivery_state(delivery_update)
    except Exception:
        pass
    if sev == "CRITICAL":
        state.setdefault("alerts", {})["lastCriticalAt"] = now_at
        state.setdefault("alerts", {})["count"] = int(state.setdefault("alerts", {}).get("count", 0)) + 1
    append_history(state, {
        "at": now_at,
        "type": "alert",
        "severity": sev,
        "code": code,
        "message": raw,
        "formatted": full,
        "result": res,
    })
    return res


def record_failure_and_maybe_quarantine(config: Dict[str, Any], state: Dict[str, Any], pid: str, reason: str) -> None:
    acc = state["accounts"][pid]
    f = acc.setdefault("failureEvents", [])
    f.append({"at": ts(), "reason": reason})

    rp = config.get("retryPolicy", {})
    window = int(rp.get("rollingWindowMinutes", 15))
    threshold = int(rp.get("quarantineOnFailures", 2))
    qmins = int(rp.get("quarantineMinutes", 30))

    cutoff = now_utc() - dt.timedelta(minutes=window)
    recent = [x for x in f if (parse_iso(x.get("at")) or now_utc()) >= cutoff]
    acc["failureEvents"] = recent
    if len(recent) >= threshold:
        until = now_utc() + dt.timedelta(minutes=qmins)
        acc["quarantine"] = {"active": True, "until": until.isoformat(), "reason": f"{len(recent)} failures/{window}m ({reason})"}


def _profile_hash_map(config: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if not pid:
            continue
        out[f"sha256:{hashlib.sha256(pid.encode()).hexdigest()[:12]}"] = pid
    return out


def live_fail_penalty_active(acc: Dict[str, Any]) -> bool:
    lf = acc.get("liveFailover", {}) if isinstance(acc.get("liveFailover"), dict) else {}
    until = parse_iso(lf.get("until"))
    if not lf.get("active"):
        return False
    if until and now_utc() >= until:
        lf["active"] = False
        return False
    return bool(lf.get("active"))


def scoped_live_failover_message(*, kind: str, raw: Optional[str], diagnostic_only: bool = False, weak_provenance: bool = False) -> str:
    if kind == "rate_limit":
        if diagnostic_only or weak_provenance:
            return "Local diagnostic rate-limit evidence observed for this profile. This does not, by itself, prove global user-facing outage while other profiles may still route."
        return "Profile-local rate-limit evidence is active for this account. Routing is blocked on this profile until reset or failover clears."
    if kind == "timeout":
        if diagnostic_only or weak_provenance:
            return "Local diagnostic timeout evidence observed for this profile. Treat as scoped failover evidence unless corroborated by broader routing failures."
        return "Profile-local timeout failover is active for this account. Routing is blocked on this profile until the hold expires."
    return "Profile-local failover evidence is active for this account."


def apply_live_fail_penalty(acc: Dict[str, Any], *, kind: str, minutes: int, raw: Optional[str], source: str = "runtime_failover") -> None:
    until = now_utc() + dt.timedelta(minutes=max(1, minutes))
    acc["liveFailover"] = {
        "active": True,
        "kind": kind,
        "minutes": int(minutes),
        "until": until.isoformat(),
        "raw": raw,
        "source": source,
        "at": ts(),
        "operatorMessage": scoped_live_failover_message(kind=kind, raw=raw),
    }
    usage = acc.setdefault("usage", {})
    usage["available"] = False
    usage["source"] = "live_failover"
    usage["observedAt"] = ts()
    if kind == "rate_limit":
        usage["fiveHourRemaining"] = 0.0
        usage["weekRemaining"] = 0.0


def _extract_retry_minutes(raw: Optional[str]) -> int:
    if not raw:
        return 30
    m = re.search(r"~\s*(\d+)\s*min", raw)
    if m:
        try:
            return max(1, int(m.group(1)))
        except Exception:
            return 30
    return 30


def scrub_tombstone_values(obj: Any, tombstones: set) -> Tuple[Any, bool]:
    changed = False
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k in tombstones:
                changed = True
                continue
            nv, ch = scrub_tombstone_values(v, tombstones)
            changed = changed or ch
            out[k] = nv
        return out, changed
    if isinstance(obj, list):
        out = []
        seen = set()
        for item in obj:
            if isinstance(item, str) and item in tombstones:
                changed = True
                continue
            ni, ch = scrub_tombstone_values(item, tombstones)
            changed = changed or ch
            key = json.dumps(ni, sort_keys=True) if isinstance(ni, (dict, list)) else ni
            if isinstance(key, str) and key in seen:
                changed = True
                continue
            seen.add(key)
            out.append(ni)
        return out, changed
    return obj, False


def scrub_tombstoned_profiles_from_auth_store(config: Dict[str, Any], store: Dict[str, Any], provider: str) -> Dict[str, Any]:
    tombstones = set(tombstoned_profile_ids(config))
    result = {"changed": False, "removedProfiles": [], "removedUsageStats": [], "removedOrder": [], "removedOther": []}
    if not tombstones:
        return result

    profiles = store.get("profiles") if isinstance(store.get("profiles"), dict) else {}
    for pid in list(profiles.keys()):
        if pid in tombstones:
            profiles.pop(pid, None)
            result["removedProfiles"].append(pid)
            result["changed"] = True

    usage = store.get("usageStats") if isinstance(store.get("usageStats"), dict) else {}
    for pid in list(usage.keys()):
        if pid in tombstones:
            usage.pop(pid, None)
            result["removedUsageStats"].append(pid)
            result["changed"] = True

    order_map = store.get("order") if isinstance(store.get("order"), dict) else {}
    raw_order = order_map.get(provider)
    if isinstance(raw_order, list):
        cleaned, _ = sanitize_runtime_order(config, list(raw_order))
        removed = [pid for pid in raw_order if pid not in cleaned]
        if cleaned != raw_order:
            order_map[provider] = cleaned
            result["removedOrder"] = sorted(set(removed))
            result["changed"] = True

    for key in ["lastGood"]:
        if key in store:
            cleaned, changed = scrub_tombstone_values(store[key], tombstones)
            if changed:
                store[key] = cleaned
                result["removedOther"].append(key)
                result["changed"] = True

    result["removedProfiles"] = sorted(set(result["removedProfiles"]))
    result["removedUsageStats"] = sorted(set(result["removedUsageStats"]))
    result["removedOrder"] = sorted(set(result["removedOrder"]))
    return result


def auto_hygiene_reconcile(config: Dict[str, Any], state: Dict[str, Any], reason: str = "auto") -> Dict[str, Any]:
    provider = config.get("provider", "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    auth_sync = sync_runtime_quarantine_to_auth_store(config, state)
    before_raw = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard")) or []
    desired_base, removed = sanitize_runtime_order(config, list(before_raw))
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if pid and pid not in desired_base:
            desired_base.append(pid)
    preview = build_effective_auth_order(config, state, desired_base)
    desired_effective = list(preview.get("effectiveOrder") or [])
    fail_open = bool((preview.get("policy") or {}).get("failOpenOnNoEligible", True))
    if not desired_effective and fail_open:
        desired_effective = list(desired_base)
    policy = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
    allow_auto_normalize = bool(policy.get("autoNormalizeRuntime", False))
    override_enabled = bool((state.get("override", {}) or {}).get("enabled"))
    mode = "MANUAL" if override_enabled else "AUTO"
    needs_critical = bool(removed) or (not before_raw)
    normalized = False
    if desired_effective and before_raw != desired_effective:
        if mode == "MANUAL" or allow_auto_normalize or needs_critical:
            normalized = set_auth_order(provider, agent_id, desired_effective, timeout_sec=timeout_tier(config, "standard"))
    after_raw = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard")) or list(desired_effective)
    result = {
        "reason": reason,
        "authStoreSync": auth_sync,
        "beforeRawRuntimeAuthOrder": before_raw,
        "removedTombstonedRuntime": removed,
        "desiredEffectiveOrder": desired_effective,
        "normalizedRuntimeOrder": normalized,
        "afterRawRuntimeAuthOrder": after_raw,
    }
    mon = state.setdefault("monitor", {})
    mon["lastAutoHygiene"] = {"at": ts(), **result}
    return result


def sync_runtime_quarantine_to_auth_store(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        "ok": True,
        "updated": False,
        "path": None,
        "updatedProfiles": [],
        "scrubbedTombstones": {"removedProfiles": [], "removedUsageStats": [], "removedOrder": []},
        "runtimeOrderNormalized": False,
    }
    try:
        provider = config.get("provider", "openai-codex")
        agent_id = runtime_auth_agent_id(config)
        auth_path = Path(f"/home/jarvis/.openclaw/agents/{agent_id}/agent/auth-profiles.json")
        out["path"] = str(auth_path)
        if not auth_path.exists():
            out["ok"] = False
            out["error"] = f"auth store not found: {auth_path}"
            return out

        try:
            store = json.loads(auth_path.read_text())
        except Exception as exc:
            out["ok"] = False
            out["error"] = f"read auth store failed: {exc}"
            return out

        scrub = scrub_tombstoned_profiles_from_auth_store(config, store, provider)
        out["scrubbedTombstones"] = {
            "removedProfiles": scrub.get("removedProfiles", []),
            "removedUsageStats": scrub.get("removedUsageStats", []),
            "removedOrder": scrub.get("removedOrder", []),
        }

        usage = store.setdefault("usageStats", {})
        changed = bool(scrub.get("changed"))
        now_ms = int(now_utc().timestamp() * 1000)

        # Ensure every managed profile has a usageStats entry so runtime ordering
        # can rotate across the full pool instead of a partial historical subset.
        for a in config.get("accounts", []):
            pid = a.get("profileId")
            if not pid:
                continue
            if not isinstance(usage.get(pid), dict):
                usage[pid] = {"errorCount": 0, "lastUsed": 0}
                changed = True

        for a in config.get("accounts", []):
            pid = a.get("profileId")
            if not pid:
                continue
            acc = (state.get("accounts", {}) or {}).get(pid, {})
            q = (acc.get("quarantine") or {}) if isinstance(acc, dict) else {}
            if not q.get("active"):
                continue
            reason = str(q.get("reason") or "")
            if not reason.startswith("runtime_"):
                continue
            until_iso = q.get("until")
            until_dt = parse_iso(until_iso) if isinstance(until_iso, str) else None
            if not until_dt:
                continue
            until_ms = int(until_dt.timestamp() * 1000)

            stats = usage.get(pid) if isinstance(usage.get(pid), dict) else {}
            prev = int(stats.get("cooldownUntil") or 0)
            if until_ms > prev:
                stats["cooldownUntil"] = until_ms
                stats["lastFailureAt"] = now_ms
                stats["errorCount"] = max(1, int(stats.get("errorCount") or 0))
                fc = stats.get("failureCounts") if isinstance(stats.get("failureCounts"), dict) else {}
                fail_key = "rate_limit" if reason.startswith("runtime_rate_limit") else "timeout"
                fc[fail_key] = max(1, int(fc.get(fail_key) or 0))
                stats["failureCounts"] = fc
                usage[pid] = stats
                changed = True
                out["updatedProfiles"].append(pid)

        if changed:
            auth_path.write_text(json.dumps(store, indent=2) + "\n")
            out["updated"] = True

        raw_runtime_order = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard")) or []
        sanitized_runtime_order, removed_runtime_order = sanitize_runtime_order(config, list(raw_runtime_order))
        desired_base = list(sanitized_runtime_order)
        for a in config.get("accounts", []):
            pid = a.get("profileId")
            if pid and pid not in desired_base:
                desired_base.append(pid)
        preview = build_effective_auth_order(config, state, desired_base)
        desired_effective = list(preview.get("effectiveOrder") or [])
        fail_open = bool((preview.get("policy") or {}).get("failOpenOnNoEligible", True))
        if not desired_effective and fail_open:
            desired_effective = list(sanitized_runtime_order)
        if not desired_effective and fail_open:
            desired_effective = [a.get("profileId") for a in config.get("accounts", []) if a.get("enabled", True) and a.get("profileId")]
        needs_runtime_reconcile = bool(removed_runtime_order) or (raw_runtime_order != desired_effective)
        if desired_effective and needs_runtime_reconcile and set_auth_order(provider, agent_id, desired_effective, timeout_sec=timeout_tier(config, "standard")):
            out["runtimeOrderNormalized"] = True
    except Exception as exc:
        out["ok"] = False
        out["error"] = str(exc)
    return out


def openclaw_home() -> Path:
    env = os.environ.get("OPENCLAW_HOME")
    candidates = []
    if env:
        candidates.append(Path(env).expanduser())
    candidates.extend([
        Path("/home/jarvis/.openclaw"),
        Path.home() / ".openclaw",
    ])
    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate
        except Exception:
            continue
    return candidates[0]


def session_rebind_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = config.get("sessionRebind", {}) if isinstance(config.get("sessionRebind"), dict) else {}
    agents_raw = raw.get("agents") or raw.get("agentIds")
    configured: List[str] = []
    if isinstance(agents_raw, list):
        configured = [str(x).strip() for x in agents_raw if str(x).strip()]
    elif isinstance(agents_raw, str) and agents_raw.strip():
        configured = [agents_raw.strip()]
    privileged_raw = raw.get("privilegedSessionKeys")
    privileged_session_keys: List[str] = []
    if isinstance(privileged_raw, list):
        privileged_session_keys = [str(x).strip() for x in privileged_raw if str(x).strip()]
    elif isinstance(privileged_raw, str) and privileged_raw.strip():
        privileged_session_keys = [privileged_raw.strip()]
    agents = _dedupe_agents(configured + auth_order_agents(config))
    return {
        "enabled": bool(raw.get("enabled", True)),
        "lookbackMinutes": max(1, int(raw.get("lookbackMinutes", 1440))),
        "respectUserOverride": bool(raw.get("respectUserOverride", True)),
        "disableInAuto": bool(raw.get("disableInAuto", True)),
        "agents": agents,
        "minTargetDwellSeconds": max(0, int(raw.get("minTargetDwellSeconds", 900))),
        "contradictionHoldSeconds": max(0, int(raw.get("contradictionHoldSeconds", 600))),
        "controlSurfacePrimary": bool(raw.get("controlSurfacePrimary", True)),
        "controlSurfaceLeaseSec": max(0, int(raw.get("controlSurfaceLeaseSec", 900))),
        "controlSurfaceStableTargetSeconds": max(0, int(raw.get("controlSurfaceStableTargetSeconds", 30))),
        "privilegedSessionKeys": _dedupe_agents(privileged_session_keys + ["agent:main:telegram:direct:1828174896"]),
    }


def _session_rebind_target_health(config: Dict[str, Any], state: Dict[str, Any], pid: Optional[str]) -> Dict[str, Any]:
    if not pid:
        return {"exists": False, "gate": {}, "effectiveState": None, "routableNow": False, "contradictory": False}
    accounts = state.get("accounts", {}) if isinstance(state.get("accounts"), dict) else {}
    acc = accounts.get(pid, {}) if isinstance(accounts, dict) else {}
    gate = routing_gate_summary(config, acc if isinstance(acc, dict) else {})
    contradiction = gate.get("contradiction") or {}
    return {
        "exists": isinstance(acc, dict) and bool(acc),
        "gate": gate,
        "effectiveState": gate.get("effectiveState"),
        "routableNow": bool(gate.get("routableNow")),
        "contradictory": bool(contradiction.get("active")),
    }


def _session_rebind_stronger_reason(current_health: Dict[str, Any], target_health: Dict[str, Any]) -> bool:
    if not target_health.get("routableNow"):
        return False
    if not current_health.get("exists"):
        return True
    if not current_health.get("routableNow"):
        return True
    if current_health.get("contradictory") and not target_health.get("contradictory"):
        return True
    if current_health.get("effectiveState") in {"REAUTH_REQUIRED", "DEACTIVATED", "AUTH_VALID_BUT_EXHAUSTED", "CONTRADICTORY_HOLD"}:
        return True
    return False


def _rebind_decision_details(state: Dict[str, Any], prior_target: Optional[str], target: Optional[str], target_health: Dict[str, Any], current_health: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "priorTargetProfileId": prior_target,
        "targetProfileId": target,
        "runtimeSnapshot": control_plane_snapshot({}, state) if False else {
            "selectedTarget": ((state.get("routing", {}) or {}).get("selectedTarget")),
            "currentTarget": ((state.get("routing", {}) or {}).get("currentTarget")),
            "lastAppliedTop": ((state.get("routing", {}) or {}).get("lastAppliedTop")),
            "lastAppliedAt": ((state.get("routing", {}) or {}).get("lastAppliedAt")),
        },
        "targetHealth": {
            "effectiveState": target_health.get("effectiveState"),
            "routableNow": target_health.get("routableNow"),
            "contradictory": target_health.get("contradictory"),
        },
        "currentHealth": {
            "effectiveState": current_health.get("effectiveState"),
            "routableNow": current_health.get("routableNow"),
            "contradictory": current_health.get("contradictory"),
        },
    }


def _target_runtime_stable_for_rebind(state: Dict[str, Any], target: Optional[str], stable_seconds: int) -> bool:
    if not target:
        return False
    if stable_seconds <= 0:
        return True
    routing = state.get("routing", {}) if isinstance(state.get("routing"), dict) else {}
    selected_target = routing.get("selectedTarget") or routing.get("currentTarget") or routing.get("lastAppliedTop")
    if selected_target != target:
        return False
    stable_at = parse_iso(routing.get("lastAppliedAt") or routing.get("lastDecisionAt"))
    if stable_at is None:
        return False
    return (now_utc() - stable_at).total_seconds() >= stable_seconds


def _session_is_privileged_control_surface(cfg: Dict[str, Any], agent_id: str, session_key: str, tier: str) -> bool:
    if tier != "control_surface":
        return False
    privileged = set(cfg.get("privilegedSessionKeys") or [])
    if session_key in privileged:
        return True
    if cfg.get("controlSurfacePrimary") and str(agent_id) == "main":
        return session_key in set(control_surface_session_keys(str(agent_id)))
    return False


def session_store_path(agent_id: str) -> Path:
    return openclaw_home() / "agents" / str(agent_id) / "sessions" / "sessions.json"


def session_store_entries(store: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    if isinstance(store.get("sessions"), dict):
        return store["sessions"], store, "nested"
    return store, store, "root"


MANUAL_OVERRIDE_SOURCES = {"user", "manual", "operator"}


def _recent_recovery_boundary(acc: Dict[str, Any]) -> Optional[str]:
    verification = acc.get("verification", {}) if isinstance(acc.get("verification"), dict) else {}
    return verification.get("lastSuccessAt") or verification.get("lastValidAuthAt")


def should_emit_terminal_alert(state: Dict[str, Any], pid: str, code: str, reason: str, acc: Dict[str, Any]) -> bool:
    alerts = state.get("history", []) if isinstance(state.get("history"), list) else []
    boundary = _recent_recovery_boundary(acc)
    boundary_dt = parse_iso(boundary) if isinstance(boundary, str) else None
    wanted_reason = canonical_dead_reason(reason)
    for row in reversed(alerts[-300:]):
        if not isinstance(row, dict) or row.get("type") != "alert":
            continue
        if row.get("code") != code:
            continue
        msg = row.get("message") or ""
        if pid not in msg:
            continue
        prior_at = parse_iso(row.get("at")) if isinstance(row.get("at"), str) else None
        if boundary_dt and prior_at and prior_at < boundary_dt:
            return True
        msg_l = str(msg).lower()
        prior_reason = None
        if "marked dead (" in msg_l:
            try:
                prior_reason = msg_l.split("marked dead (",1)[1].split(")",1)[0]
            except Exception:
                prior_reason = None
        elif "expired" in msg_l:
            prior_reason = "expired"
        if code in {"PROFILE_DEAD", "PROFILE_DEACTIVATED", "PROFILE_EXPIRED"} and canonical_dead_reason(prior_reason) == wanted_reason:
            return False
        return False
    return True


def should_emit_expiry_alert(config: Dict[str, Any], state: Dict[str, Any], pid: str, acc: Dict[str, Any], code: str) -> bool:
    if should_suppress_stale_account_alert(config, acc, code):
        return False
    gate = routing_gate_summary(config, acc)
    auth = acc.get("auth", {}) if isinstance(acc.get("auth"), dict) else {}
    if gate.get("effectiveState") == "REAUTH_REQUIRED" and canonical_dead_reason(auth.get("reason")) == "expired":
        return should_emit_terminal_alert(state, pid, code, "expired", acc)
    return True


def has_semantic_terminal_dead_state(config: Dict[str, Any], state: Dict[str, Any], pid: str, reason: str) -> bool:
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    auth = acct.get("auth", {}) if isinstance(acct.get("auth"), dict) else {}
    verification = acct.get("verification", {}) if isinstance(acct.get("verification"), dict) else {}
    gate = routing_gate_summary(config, acct)
    flags = contradiction_flags(config, acct)
    auth_reason = canonical_dead_reason(auth.get("reason"))
    target_reason = canonical_dead_reason(reason)
    return (
        str(auth.get("status") or "").upper() == "DEAD"
        and auth_reason == target_reason
        and str(verification.get("status") or "").upper() != "VERIFIED"
        and gate.get("effectiveState") == "REAUTH_REQUIRED"
        and not bool(fresh_recovery_truth(config, acct).get("active"))
        and not flags
    )


def control_surface_session_keys(agent_id: str) -> List[str]:
    if str(agent_id) == "main":
        return [
            "agent:main:telegram:direct:1828174896",
            "agent:main:discord:channel:1482706815535022122",
        ]
    return []


def main_privileged_session_keys() -> List[str]:
    return [*control_surface_session_keys("main"), "agent:main:main"]


def read_session_override_snapshot(agent_id: str, session_keys: List[str]) -> Dict[str, Any]:
    path = session_store_path(str(agent_id))
    info: Dict[str, Any] = {"path": str(path), "exists": path.exists(), "sessions": {}}
    if not path.exists():
        return info
    try:
        store = json.loads(path.read_text())
    except Exception as exc:
        info["error"] = f"read_failed:{exc}"
        return info
    if not isinstance(store, dict):
        info["error"] = "invalid_store"
        return info
    entries, _root_store, store_shape = session_store_entries(store)
    info["storeShape"] = store_shape
    for session_key in session_keys:
        entry = entries.get(session_key)
        if not isinstance(entry, dict):
            info["sessions"][session_key] = {"missing": True}
            continue
        info["sessions"][session_key] = {
            "authProfileOverride": entry.get("authProfileOverride"),
            "authProfileOverrideSource": entry.get("authProfileOverrideSource"),
            "authProfileOverrideCompactionCount": entry.get("authProfileOverrideCompactionCount"),
            "updatedAt": entry.get("updatedAt"),
            "compactionCount": entry.get("compactionCount"),
        }
    return info


def classify_session_rebind_tier(session_key: str) -> str:
    s = str(session_key or "")
    if ":run:" in s:
        return "ephemeral_run"
    if ":telegram:direct:" in s or ":discord:channel:" in s:
        return "control_surface"
    if ":cron:" in s:
        return "cron_root"
    return "durable_or_other"


def should_skip_stable_cron_root_rebind(entry: Dict[str, Any], target: Optional[str], now_ms: int, cooldown_ms: int = 60 * 60 * 1000) -> bool:
    current = str(entry.get("authProfileOverride") or "").strip() or None
    source = str(entry.get("authProfileOverrideSource") or "").strip().lower() or None
    updated_at = entry.get("updatedAt")
    stored_compaction = entry.get("authProfileOverrideCompactionCount")
    compaction = entry.get("compactionCount")
    desired_compaction = int(compaction) if isinstance(compaction, (int, float)) else 0
    if not current or source != 'auto':
        return False
    if target and current == target:
        if isinstance(stored_compaction, (int, float)) and int(stored_compaction) == desired_compaction and isinstance(updated_at, (int, float)):
            return int(updated_at) >= (now_ms - cooldown_ms)
    # For watchdog-driven cron root churn, prefer leaving an auto-bound cron root alone for a while
    # unless a separate explicit cron/session fix is applied. This reduces profile thrash/noisy rebinds.
    if isinstance(updated_at, (int, float)):
        return int(updated_at) >= (now_ms - cooldown_ms)
    return False


def update_session_override(agent_id: str, session_keys: List[str], profile_id: Optional[str], source: str, clear: bool = False) -> Dict[str, Any]:
    path = session_store_path(str(agent_id))
    out = {"ok": True, "agentId": str(agent_id), "path": str(path), "updatedSessions": [], "missingSessions": []}
    if not path.exists():
        out["ok"] = False
        out["error"] = "session_store_missing"
        return out
    store = json.loads(path.read_text())
    entries, root_store, _shape = session_store_entries(store)
    now_ms = int(now_utc().timestamp() * 1000)
    changed = False
    for key in session_keys:
        entry = entries.get(key)
        if not isinstance(entry, dict):
            out["missingSessions"].append(key)
            continue
        if clear:
            entry.pop("authProfileOverride", None)
            entry.pop("authProfileOverrideSource", None)
            entry.pop("authProfileOverrideCompactionCount", None)
        else:
            entry["authProfileOverride"] = profile_id
            entry["authProfileOverrideSource"] = source
            compaction = entry.get("compactionCount")
            entry["authProfileOverrideCompactionCount"] = int(compaction) if isinstance(compaction, (int, float)) else 0
        entry["updatedAt"] = max(int(entry.get("updatedAt") or 0), now_ms)
        entries[key] = entry
        changed = True
        out["updatedSessions"].append({"sessionKey": key, "profileId": profile_id, "source": None if clear else source, "cleared": bool(clear)})
    if changed:
        if root_store is not store:
            root_store["sessions"] = entries
            save_json(path, root_store)
        else:
            save_json(path, store)
    out["updated"] = changed
    return out


def cmd_control_surface_pin(config: Dict[str, Any], state: Dict[str, Any], profile: str, session_key: str, json_mode: bool = False) -> int:
    result = update_session_override("main", [session_key], profile, source="user", clear=False)
    append_history(state, {"at": ts(), "type": "control_surface_pin", "profileId": profile, "sessionKey": session_key, "result": result})
    save_json(STATE_PATH, state)
    payload = {"ok": result.get("ok", False), "profileId": profile, "sessionKey": session_key, "result": result}
    print(json.dumps(payload, indent=2) if json_mode else json.dumps(payload, indent=2))
    return 0 if result.get("ok") else 1


def cmd_control_surface_release(config: Dict[str, Any], state: Dict[str, Any], session_key: str, json_mode: bool = False) -> int:
    result = update_session_override("main", [session_key], None, source="auto", clear=True)
    append_history(state, {"at": ts(), "type": "control_surface_release", "sessionKey": session_key, "result": result})
    save_json(STATE_PATH, state)
    payload = {"ok": result.get("ok", False), "released": True, "sessionKey": session_key, "result": result}
    print(json.dumps(payload, indent=2) if json_mode else json.dumps(payload, indent=2))
    return 0 if result.get("ok") else 1


def session_entry_matches_provider(entry: Dict[str, Any], provider: str) -> bool:
    model_provider = str(entry.get("modelProvider") or "").strip().lower()
    provider = str(provider or "").strip().lower()
    if model_provider:
        return model_provider == provider
    model = str(entry.get("model") or "").strip().lower()
    if provider == "openai-codex":
        if model.startswith("gpt-") or model.startswith("openai-codex/"):
            return True
        override = str(entry.get("authProfileOverride") or "").strip().lower()
        if override.startswith("codex-oauth-") or override == "openai-codex:default":
            return True
    return False


def reconcile_routing_state_target(state: Dict[str, Any], target: Optional[str], *, reason: str) -> None:
    if not target:
        return
    override_enabled = bool((state.get("override", {}) or {}).get("enabled"))
    allow_override_reconcile = reason.startswith("manual_override") or reason.startswith("override")
    if override_enabled and not allow_override_reconcile:
        return
    routing = state.setdefault("routing", {})
    now = ts()
    routing["selectedTarget"] = target
    routing["currentTarget"] = target
    routing["actuatedTarget"] = target
    routing["lastAppliedTop"] = target
    routing["lastAppliedAt"] = now
    routing["lastDecisionAt"] = now
    routing["holdReason"] = None
    routing["reconciledBy"] = reason


def sync_session_auth_overrides(config: Dict[str, Any], state: Dict[str, Any], target_order: Optional[List[str]] = None, reason: str = "tick") -> Dict[str, Any]:
    # Guardrail: preserve manual/user overrides and keep same-target no-op paths cheap.
    # This path exists to align persisted session residue, not to invent new routing decisions.
    cfg = session_rebind_settings(config)
    out = {
        "ok": True,
        "enabled": cfg["enabled"],
        "reason": reason,
        "targetProfileId": None,
        "updated": False,
        "lookbackMinutes": cfg["lookbackMinutes"],
        "respectUserOverride": cfg["respectUserOverride"],
        "agents": {},
        "updatedSessions": [],
        "decisionTelemetry": [],
    }
    if not cfg["enabled"]:
        return out
    override_enabled = bool((state.get("override", {}) or {}).get("enabled"))
    manualish_reason = reason.startswith("manual") or reason.startswith("override")
    if cfg.get("disableInAuto") and not override_enabled:
        append_session_rebind_decision(state, reason="auto_mode", target=None, action="skip", details={"reason": reason})
        out["skipped"] = "auto_mode"
        out["decisionTelemetry"].append({"action": "skip", "reason": "auto_mode"})
        return out

    if not cfg.get("agents"):
        append_session_rebind_decision(state, reason="no_agents", target=None, action="skip", details={"reason": reason})
        out["skipped"] = "no_agents"
        out["decisionTelemetry"].append({"action": "skip", "reason": "no_agents"})
        return out

    provider = str(config.get("provider") or "openai-codex")
    candidate_order = list(target_order or [])
    if not candidate_order:
        agent_id = runtime_auth_agent_id(config)
        current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "health")) or []
        preview = build_effective_auth_order(config, state, current_order)
        candidate_order = list(preview.get("effectiveOrder") or current_order)

    target = candidate_order[0] if candidate_order else None
    out["targetProfileId"] = target
    if not target:
        append_session_rebind_decision(state, reason="no_target_profile", target=None, action="skip", details={"reason": reason})
        out["ok"] = False
        out["error"] = "no_target_profile"
        out["decisionTelemetry"].append({"action": "skip", "reason": "no_target_profile"})
        return out

    now_ms = int(now_utc().timestamp() * 1000)
    cutoff = now_ms - (cfg["lookbackMinutes"] * 60 * 1000)
    prior_state = state.get("sessionRebind", {}) if isinstance(state.get("sessionRebind"), dict) else {}
    prior_target = str(prior_state.get("targetProfileId") or "").strip() or None
    last_rebind_at = parse_iso(prior_state.get("lastAt")) if isinstance(prior_state.get("lastAt"), str) else None
    target_health = _session_rebind_target_health(config, state, target)
    current_health = _session_rebind_target_health(config, state, prior_target)
    min_dwell_seconds = int(cfg.get("minTargetDwellSeconds", 0))
    contradiction_hold_seconds = int(cfg.get("contradictionHoldSeconds", 0))
    contradiction_active = bool(target_health.get("contradictory"))
    degraded_target = (not target_health.get("routableNow"))
    stronger_reason = _session_rebind_stronger_reason(current_health, target_health)
    runtime_stable = _target_runtime_stable_for_rebind(state, target, int(cfg.get("controlSurfaceStableTargetSeconds", 0)))
    if reason == "watchdog" and target and not override_enabled:
        reconcile_routing_state_target(state, target, reason="watchdog_session_rebind")
    global_details = _rebind_decision_details(state, prior_target, target, target_health, current_health)
    dwell_hold_active = False
    age_sec = None
    if not override_enabled and not manualish_reason and prior_target and target != prior_target and last_rebind_at and min_dwell_seconds > 0:
        age_sec = int((now_utc() - last_rebind_at).total_seconds())
        dwell_hold_active = age_sec < min_dwell_seconds and not stronger_reason
    if not override_enabled and not manualish_reason:
        if contradiction_active and contradiction_hold_seconds > 0:
            append_session_rebind_decision(state, reason="contradictory_target", target=target, action="skip", details=global_details)
            out["skipped"] = "contradictory_target"
            out["targetHealth"] = target_health
            out["currentHealth"] = current_health
            out["decisionTelemetry"].append({"action": "skip", "reason": "contradictory_target", "targetProfileId": target})
            return out
        if degraded_target and not stronger_reason:
            append_session_rebind_decision(state, reason="degraded_target", target=target, action="skip", details=global_details)
            out["skipped"] = "degraded_target"
            out["targetHealth"] = target_health
            out["currentHealth"] = current_health
            out["decisionTelemetry"].append({"action": "skip", "reason": "degraded_target", "targetProfileId": target})
            return out

    for agent_id in cfg.get("agents", []):
        path = session_store_path(str(agent_id))
        agent_info = {
            "path": str(path),
            "exists": path.exists(),
            "scanned": 0,
            "updated": 0,
            "preservedUser": 0,
            "forcedPrivileged": 0,
            "noopPrivileged": 0,
        }
        if not path.exists():
            out["agents"][str(agent_id)] = agent_info
            continue
        try:
            store = json.loads(path.read_text())
        except Exception as exc:
            agent_info["error"] = f"read_failed:{exc}"
            out["ok"] = False
            out["agents"][str(agent_id)] = agent_info
            continue
        if not isinstance(store, dict):
            agent_info["error"] = "invalid_store"
            out["ok"] = False
            out["agents"][str(agent_id)] = agent_info
            continue

        entries, root_store, store_shape = session_store_entries(store)
        agent_info["storeShape"] = store_shape
        changed = False
        control_surface_keys = set(control_surface_session_keys(str(agent_id)))
        for session_key, entry in entries.items():
            if not isinstance(entry, dict):
                continue
            session_key_s = str(session_key)
            tier = classify_session_rebind_tier(session_key_s)
            main_control_surface = session_key_s in control_surface_keys
            privileged_surface = _session_is_privileged_control_surface(cfg, str(agent_id), session_key_s, tier)
            updated_at = entry.get("updatedAt")
            current = str(entry.get("authProfileOverride") or "").strip() or None
            source = str(entry.get("authProfileOverrideSource") or "").strip() or None
            source_l = source.lower() if isinstance(source, str) else ""
            force_main_auto = (str(agent_id) == 'main' and source_l == 'auto' and tier != 'ephemeral_run')
            force_auto_override = bool(current) and source_l == 'auto' and session_entry_matches_provider(entry, provider) and tier != 'ephemeral_run'
            if tier == 'ephemeral_run' and reason == 'watchdog':
                continue
            if tier == 'ephemeral_run' and ':cron:' in session_key_s:
                continue
            if tier == 'ephemeral_run':
                very_recent = isinstance(updated_at, (int, float)) and int(updated_at) >= (now_ms - 5 * 60 * 1000)
                missing_override = not bool(current)
                if not (very_recent and missing_override):
                    continue
            if tier == 'cron_root':
                # Cron roots are runtime-managed scheduler surfaces, not operator control surfaces.
                # Exclude them entirely from session-rebind influence so router maintenance cannot
                # amplify cron-family churn or treat scheduler lineage like interactive sessions.
                continue
            if (not isinstance(updated_at, (int, float)) or int(updated_at) < cutoff) and not (force_main_auto or force_auto_override or privileged_surface):
                continue
            if not session_entry_matches_provider(entry, provider) and not (main_control_surface or privileged_surface):
                continue
            agent_info["scanned"] += 1
            if source in MANUAL_OVERRIDE_SOURCES and current:
                agent_info["preservedUser"] += 1
                if main_control_surface or privileged_surface:
                    agent_info.setdefault("preservedControlSurfaceManual", 0)
                    agent_info["preservedControlSurfaceManual"] += 1
                continue

            compaction = entry.get("compactionCount")
            desired_compaction = int(compaction) if isinstance(compaction, (int, float)) else 0
            stored_compaction = entry.get("authProfileOverrideCompactionCount")
            same_auto_target = (
                current == target
                and source == "auto"
                and isinstance(stored_compaction, (int, float))
                and int(stored_compaction) == desired_compaction
            )
            privileged_bypass = bool(privileged_surface and runtime_stable and dwell_hold_active)
            if dwell_hold_active and not privileged_bypass:
                append_session_rebind_decision(state, reason="dwell_hold", target=target, action="skip", agent_id=str(agent_id), session_key=session_key_s, details={**global_details, "privilegedControlSurface": privileged_surface})
                out.setdefault("holdAgeSeconds", age_sec)
                out.setdefault("minTargetDwellSeconds", min_dwell_seconds)
                out.setdefault("currentTargetProfileId", prior_target)
                out["targetHealth"] = target_health
                out["currentHealth"] = current_health
                out["decisionTelemetry"].append({"action": "skip", "reason": "dwell_hold", "agentId": str(agent_id), "sessionKey": session_key_s, "targetProfileId": target})
                continue
            if same_auto_target:
                if privileged_surface:
                    agent_info["noopPrivileged"] += 1
                    append_session_rebind_decision(state, reason="already_bound_privileged", target=target, action="noop", agent_id=str(agent_id), session_key=session_key_s, details={**global_details, "privilegedControlSurface": True, "runtimeStable": runtime_stable})
                    out["decisionTelemetry"].append({"action": "noop", "reason": "already_bound_privileged", "agentId": str(agent_id), "sessionKey": session_key_s, "targetProfileId": target})
                continue

            entry["authProfileOverride"] = target
            entry["authProfileOverrideSource"] = "auto"
            entry["authProfileOverrideCompactionCount"] = desired_compaction
            entry["updatedAt"] = max(int(updated_at or 0), now_ms)
            entries[session_key] = entry
            changed = True
            agent_info["updated"] += 1
            if privileged_bypass:
                agent_info["forcedPrivileged"] += 1
                append_session_rebind_decision(state, reason="privileged_runtime_head_change", target=target, action="force", agent_id=str(agent_id), session_key=session_key_s, details={**global_details, "privilegedControlSurface": True, "runtimeStable": runtime_stable, "priorSessionProfileId": current, "dwellBypassed": True})
                out["decisionTelemetry"].append({"action": "force", "reason": "privileged_runtime_head_change", "agentId": str(agent_id), "sessionKey": session_key_s, "targetProfileId": target})
            else:
                append_session_rebind_decision(state, reason="session_rebind_success", target=target, action="update", agent_id=str(agent_id), session_key=session_key_s, details={**global_details, "privilegedControlSurface": privileged_surface, "runtimeStable": runtime_stable, "priorSessionProfileId": current})
                out["decisionTelemetry"].append({"action": "update", "reason": "session_rebind_success", "agentId": str(agent_id), "sessionKey": session_key_s, "targetProfileId": target})
            out["updatedSessions"].append({
                "agentId": str(agent_id),
                "sessionKey": session_key,
                "profileId": target,
                "source": "auto",
                "privilegedControlSurface": privileged_surface,
                "forced": privileged_bypass,
            })

        if changed:
            if root_store is not store:
                root_store["sessions"] = entries
                save_json(path, root_store)
            else:
                save_json(path, store)
        out["agents"][str(agent_id)] = agent_info

    out["updated"] = bool(out["updatedSessions"])
    state["sessionRebind"] = {
        "lastAt": ts(),
        "reason": reason,
        "targetProfileId": target,
        "updatedSessions": len(out["updatedSessions"]),
        "runtimeStable": runtime_stable,
    }
    if out["updatedSessions"]:
        append_history(state, {
            "at": ts(),
            "type": "session_rebind",
            "reason": reason,
            "targetProfileId": target,
            "updatedSessions": out["updatedSessions"],
            "snapshot": control_plane_snapshot(config, state, candidate_order),
        })
    return out


def ingest_runtime_failover_signals(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    info = {
        "ok": True,
        "processed": 0,
        "rateLimited": 0,
        "timedOut": 0,
        "quarantined": [],
        "diagnosticOnly": 0,
        "skippedWeakProvenance": 0,
    }

    runtime_cfg = config.get("runtimeFailover", {}) if isinstance(config.get("runtimeFailover"), dict) else {}
    if not bool(runtime_cfg.get("enabled", True)):
        info["ok"] = True
        info["disabled"] = True
        return info

    now = now_utc()
    scan_state = state.setdefault("runtimeFailover", {})
    seen = scan_state.setdefault("seenEventIds", [])
    seen_set = set(seen)
    logical_seen = scan_state.setdefault("logicalEventKeys", {})

    lookback_min = int(runtime_cfg.get("scanLookbackMinutes", 90))
    recent_keep = int(runtime_cfg.get("keepSeen", 500))
    timeout_quarantine_min = int(runtime_cfg.get("timeoutQuarantineMinutes", 5))

    try:
        today = now.strftime("%Y-%m-%d")
        log_path = Path(f"/tmp/openclaw/openclaw-{today}.log")
        if not log_path.exists():
            return info

        hash_map = _profile_hash_map(config)
        cutoff = now - dt.timedelta(minutes=lookback_min)

        lines = log_path.read_text(errors="ignore").splitlines()
        for ln in lines[-3000:]:
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue

            t = parse_iso(obj.get("time"))
            if not t or t < cutoff:
                continue

            payload = obj.get("1")
            if not isinstance(payload, dict):
                continue
            if payload.get("event") != "embedded_run_failover_decision":
                continue
            if payload.get("provider") != config.get("provider", "openai-codex"):
                continue

            eid = f"{obj.get('time')}|{payload.get('runId')}|{payload.get('profileId')}|{payload.get('failoverReason')}"
            if eid in seen_set:
                continue
            seen_set.add(eid)
            info["processed"] += 1

            decision = str(payload.get("decision") or "")
            session_key = payload.get("sessionKey")
            agent_id = payload.get("agentId")
            raw = payload.get("rawErrorPreview")
            logical_key = "|".join([
                str(payload.get("runId") or ""),
                str(payload.get("profileId") or ""),
                decision,
                str(payload.get("failoverReason") or payload.get("profileFailureReason") or ""),
                str(raw or "")[:160],
            ])
            prev_logical_at = parse_iso(logical_seen.get(logical_key)) if isinstance(logical_seen, dict) else None
            if prev_logical_at and (t - prev_logical_at) < dt.timedelta(minutes=15):
                info["diagnosticOnly"] += 1
                continue
            logical_seen[logical_key] = obj.get("time") or ts()

            pid = hash_map.get(str(payload.get("profileId") or ""))
            if not pid:
                continue
            acc = state.get("accounts", {}).get(pid)
            if not isinstance(acc, dict):
                continue

            reason = str(payload.get("failoverReason") or payload.get("profileFailureReason") or "")
            weak_provenance = not session_key and not agent_id
            diagnostic_only = weak_provenance or decision == "fallback_model"
            try:
                append_jsonl(BYPASS_LOG_PATH, {
                    "at": obj.get("time") or ts(),
                    "profileId": pid,
                    "runId": payload.get("runId"),
                    "sessionKey": session_key,
                    "agentId": agent_id,
                    "provider": payload.get("provider"),
                    "model": payload.get("model"),
                    "decision": decision,
                    "failoverReason": reason,
                    "rawErrorPreview": raw,
                    "diagnosticOnly": diagnostic_only,
                    "weakProvenance": weak_provenance,
                    "scopedOperatorMessage": scoped_live_failover_message(kind=("rate_limit" if reason == "rate_limit" else "timeout" if reason == "timeout" else "failover"), raw=raw, diagnostic_only=diagnostic_only, weak_provenance=weak_provenance),
                })
            except Exception:
                pass

            dead_reason = dead_reason_from_text(reason, raw)
            if diagnostic_only:
                if weak_provenance:
                    info["skippedWeakProvenance"] += 1
                info["diagnosticOnly"] += 1
                append_history(state, {
                    "at": ts(),
                    "type": "runtime_failover_diagnostic",
                    "profileId": pid,
                    "reason": reason,
                    "decision": decision,
                    "weakProvenance": weak_provenance,
                    "sessionKey": session_key,
                    "agentId": agent_id,
                    "operatorMessage": scoped_live_failover_message(kind=("rate_limit" if reason == "rate_limit" else "timeout" if reason == "timeout" else "failover"), raw=raw, diagnostic_only=True, weak_provenance=weak_provenance),
                })
                continue

            if dead_reason:
                mark_auth_dead(state, pid, dead_reason, "runtime_failover", raw)
                spec = dead_alert_spec(dead_reason)
                key = f"dead:{pid}:{dead_reason}"
                if should_emit_signal(state, key, dead_alert_cooldown_minutes(dead_reason)) and should_emit_terminal_alert(state, pid, spec["code"], dead_reason, acc):
                    send_alert(
                        config,
                        state,
                        "CRITICAL",
                        f"OAuth account {account_name(config, pid)} ({pid}) marked {spec['label']} ({dead_reason}).",
                        code=spec["code"],
                        impact=spec["impact"],
                        auto_action=spec["auto_action"],
                        your_action=spec["your_action"],
                        status=f"profile={pid}",
                    )
                    mark_signal(state, key)
                continue

            if reason == "rate_limit":
                info["rateLimited"] += 1
                mins = _extract_retry_minutes(raw)
                mins = min(max(mins, 5), 720)
                until = now + dt.timedelta(minutes=mins)
                prior_q = acc.get("quarantine") if isinstance(acc.get("quarantine"), dict) else {}
                prior_until = parse_iso(prior_q.get("until")) if isinstance(prior_q.get("until"), str) else None
                prior_reason = str(prior_q.get("reason") or "")
                meaningful_quarantine_delta = (
                    not prior_q.get("active")
                    or not prior_reason.startswith("runtime_rate_limit")
                    or (prior_until is not None and until > prior_until + dt.timedelta(minutes=1))
                    or (prior_until is None)
                )
                acc["quarantine"] = {
                    "active": True,
                    "until": until.isoformat(),
                    "reason": f"runtime_rate_limit:{mins}m",
                }
                apply_live_fail_penalty(acc, kind="rate_limit", minutes=mins, raw=raw)
                if meaningful_quarantine_delta:
                    append_history(state, {
                        "at": ts(),
                        "type": "runtime_failover_quarantine",
                        "profileId": pid,
                        "reason": "rate_limit",
                        "minutes": mins,
                        "raw": raw,
                        "snapshot": control_plane_snapshot(config, state),
                    })
                info["quarantined"].append({"profileId": pid, "reason": "rate_limit", "minutes": mins, "logged": meaningful_quarantine_delta})
            elif reason == "timeout":
                info["timedOut"] += 1
                mins = max(1, timeout_quarantine_min)
                until = now + dt.timedelta(minutes=mins)
                prior_q = acc.get("quarantine") if isinstance(acc.get("quarantine"), dict) else {}
                prior_until = parse_iso(prior_q.get("until")) if isinstance(prior_q.get("until"), str) else None
                prior_reason = str(prior_q.get("reason") or "")
                meaningful_quarantine_delta = (
                    not prior_q.get("active")
                    or not prior_reason.startswith("runtime_timeout")
                    or (prior_until is not None and until > prior_until + dt.timedelta(minutes=1))
                    or (prior_until is None)
                )
                acc["quarantine"] = {
                    "active": True,
                    "until": until.isoformat(),
                    "reason": f"runtime_timeout:{mins}m",
                }
                apply_live_fail_penalty(acc, kind="timeout", minutes=mins, raw=raw)
                if meaningful_quarantine_delta:
                    append_history(state, {
                        "at": ts(),
                        "type": "runtime_failover_quarantine",
                        "profileId": pid,
                        "reason": "timeout",
                        "minutes": mins,
                        "snapshot": control_plane_snapshot(config, state),
                    })
                info["quarantined"].append({"profileId": pid, "reason": "timeout", "minutes": mins, "logged": meaningful_quarantine_delta})

        # persist bounded seen list
        seen_list = sorted(list(seen_set))
        scan_state["seenEventIds"] = seen_list[-recent_keep:]
        if isinstance(logical_seen, dict):
            logical_items = sorted(logical_seen.items(), key=lambda kv: kv[1])
            scan_state["logicalEventKeys"] = {k: v for k, v in logical_items[-recent_keep:]}
        scan_state["lastScanAt"] = ts()
    except Exception as exc:
        info["ok"] = False
        info["error"] = str(exc)

    return info


def pool_usage_metrics(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    policy = config.get("poolUsagePolicy", {}) if isinstance(config.get("poolUsagePolicy"), dict) else {}
    w_week = float(policy.get("headroomWeekWeight", 0.7))
    w_five = float(policy.get("headroomFiveHourWeight", 0.3))
    w_head = float(policy.get("compositeHeadroomWeight", 0.5))
    w_cov = float(policy.get("compositeCoverageWeight", 0.25))
    w_health = float(policy.get("compositeHealthWeight", 0.25))
    top_fraction = float(policy.get("topFraction", 0.3))
    min_top_n = max(1, int(policy.get("minTopN", 3)))

    enabled_ids = [a.get("profileId") for a in config.get("accounts", []) if a.get("enabled", True) and a.get("profileId")]
    enabled_ids = [x for x in enabled_ids if x]
    enabled_count = len(enabled_ids)

    eligible_ids = healthy_profiles(config, state)

    healthy_ids: List[str] = []
    rows: List[Dict[str, Any]] = []
    state_counts = {
        "routableNow": 0,
        "exhausted": 0,
        "reauthRequired": 0,
        "hold": 0,
        "deactivated": 0,
    }
    telemetry_scores: List[float] = []
    freshness_counts = {"fresh": 0, "aging": 0, "stale": 0, "very_stale": 0, "unknown": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
    stale_limit = telemetry_recent_limit_seconds(config)
    stale_warning_count = 0

    for pid in enabled_ids:
        acc = (state.get("accounts", {}) or {}).get(pid, {})
        h = acc.get("health", {}) if isinstance(acc, dict) else {}
        if h.get("healthy", True) and not h.get("expired", False) and (not is_quarantined(acc)):
            healthy_ids.append(pid)
        u_en = acc.get("usage", {}) if isinstance(acc, dict) else {}
        telemetry_en = telemetry_freshness(config, u_en if isinstance(u_en, dict) else {})
        if telemetry_en.get("ageSeconds") is None or (telemetry_en.get("ageSeconds") or 0) > stale_limit:
            stale_warning_count += 1
        gate_en = routing_gate_summary(config, acc if isinstance(acc, dict) else {})
        state_label_en = str(gate_en.get("stateLabel") or "").upper()
        if gate_en.get("routableNow"):
            state_counts["routableNow"] += 1
        elif state_label_en == "AUTH_VALID_BUT_EXHAUSTED":
            state_counts["exhausted"] += 1
        elif state_label_en == "REAUTH_REQUIRED":
            state_counts["reauthRequired"] += 1
        elif state_label_en == "HOLD":
            state_counts["hold"] += 1
        else:
            state_counts["deactivated"] += 1

    shared_candidates: List[Dict[str, Any]] = []
    for pid in eligible_ids:
        acc = (state.get("accounts", {}) or {}).get(pid, {})
        gate = routing_gate_summary(config, acc if isinstance(acc, dict) else {})
        u = acc.get("usage", {}) if isinstance(acc, dict) else {}
        telemetry_state = telemetry_trust_state(u if isinstance(u, dict) else {})
        trusted_capacity = telemetry_state.get("state") == "trusted"
        week = float(u.get("weekRemaining")) if trusted_capacity and isinstance(u.get("weekRemaining"), (int, float)) else None
        five = float(u.get("fiveHourRemaining")) if trusted_capacity and isinstance(u.get("fiveHourRemaining"), (int, float)) else None
        base_score = ((w_week * week) if isinstance(week, (int, float)) else 0.0) + ((w_five * five) if isinstance(five, (int, float)) else 0.0)
        telemetry = telemetry_freshness(config, u)
        effective_score = (base_score * float(telemetry.get("scoreFactor") or 0.0)) if trusted_capacity else 0.0
        freshness_counts[str(telemetry.get("freshness") or "unknown")] += 1
        confidence_counts[str(telemetry.get("confidence") or "none")] += 1
        telemetry_scores.append(float(telemetry.get("scoreFactor") or 0.0) * 100.0)
        if telemetry_state.get("state") == "provider_shared" and (isinstance(u.get("weekRemaining"), (int, float)) or isinstance(u.get("fiveHourRemaining"), (int, float))):
            shared_candidates.append({
                "profileId": pid,
                "fiveHourRemaining": float(u.get("fiveHourRemaining")) if isinstance(u.get("fiveHourRemaining"), (int, float)) else None,
                "weekRemaining": float(u.get("weekRemaining")) if isinstance(u.get("weekRemaining"), (int, float)) else None,
                "source": u.get("source"),
                "observedAt": u.get("observedAt"),
                "shared": True,
            })
        rows.append({
            "profileId": pid,
            "name": account_name(config, pid),
            "score": round(effective_score, 2),
            "rawScore": round(base_score, 2) if trusted_capacity else 0.0,
            "weekRemaining": week,
            "fiveHourRemaining": five,
            "source": u.get("source"),
            "telemetry": telemetry,
            "telemetryState": telemetry_state,
            "trustedCapacity": trusted_capacity,
            "gate": gate,
        })

    rows.sort(key=lambda x: x["score"], reverse=True)
    trusted_rows = [x for x in rows if x.get("trustedCapacity")]
    trusted_count = len(trusted_rows)
    eligible_count = len(eligible_ids)
    top_n = min(trusted_count, max(min_top_n, int(math.ceil(top_fraction * trusted_count)))) if trusted_count > 0 else 0
    top_rows = trusted_rows[:top_n]
    routing_headroom = sum(x["score"] for x in top_rows) / top_n if top_n > 0 else 0.0
    raw_routing_headroom = sum(x["rawScore"] for x in top_rows) / top_n if top_n > 0 else 0.0
    coverage_pct = (eligible_count / enabled_count * 100.0) if enabled_count > 0 else 0.0
    health_pct = (len(healthy_ids) / enabled_count * 100.0) if enabled_count > 0 else 0.0
    telemetry_confidence_pct = sum(telemetry_scores) / len(telemetry_scores) if telemetry_scores else 0.0
    fully_ready_count = sum(1 for x in rows if bool((x.get("gate") or {}).get("routableNow")))
    auth_only_count = sum(
        1
        for x in rows
        if str((x.get("gate") or {}).get("stateLabel") or "").upper() == "AUTH_VALID_BUT_EXHAUSTED"
    )
    headroom_proven = trusted_count > 0
    shared_candidates.sort(key=lambda x: (str(x.get("observedAt") or ""), str(x.get("profileId") or "")))
    global_usage = shared_candidates[-1] if shared_candidates else None

    composite = ((w_head * routing_headroom) + (w_cov * coverage_pct) + (w_health * health_pct)) if enabled_count > 0 else 0.0
    composite = max(0.0, min(100.0, composite))
    used_pct = max(0.0, min(100.0, 100.0 - composite))

    return {
        "enabledCount": enabled_count,
        "healthyCount": len(healthy_ids),
        "eligibleCount": eligible_count,
        "fullyReadyCount": fully_ready_count,
        "authOnlyCount": auth_only_count,
        "coveragePct": round(coverage_pct, 2),
        "healthPct": round(health_pct, 2),
        "routingHeadroomPct": round(routing_headroom, 2),
        "rawRoutingHeadroomPct": round(raw_routing_headroom, 2),
        "headroomProven": headroom_proven,
        "trustedCapacityCount": trusted_count,
        "globalUsage": global_usage,
        "telemetryConfidencePct": round(telemetry_confidence_pct, 2),
        "telemetryFreshnessCounts": freshness_counts,
        "telemetryConfidenceCounts": confidence_counts,
        "telemetryStaleCount": stale_warning_count,
        "telemetryStaleWarning": "Telemetry stale: Cron jobs may be down." if stale_warning_count > 0 else None,
        "compositeHealthPct": round(composite, 2),
        "compositeUsedPct": round(used_pct, 2),
        "topN": top_n,
        "scoredEligible": rows,
        "topEligible": top_rows,
        "stateCounts": state_counts,
        "weights": {
            "headroomWeek": w_week,
            "headroomFiveHour": w_five,
            "compositeHeadroom": w_head,
            "compositeCoverage": w_cov,
            "compositeHealth": w_health,
        },
    }


def pool_summary(metrics: Dict[str, Any], recommendation: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    enabled = int(metrics.get("enabledCount", 0))
    healthy = int(metrics.get("healthyCount", 0))
    eligible = int(metrics.get("eligibleCount", 0))
    headroom = float(metrics.get("routingHeadroomPct", 0.0))
    headroom_proven = bool(metrics.get("headroomProven", False))
    headroom_label = f"{headroom:.0f}%" if headroom_proven else "unproven"
    cph = float(metrics.get("compositeHealthPct", 0.0))
    fully_ready = int(metrics.get("fullyReadyCount", 0))
    auth_only = int(metrics.get("authOnlyCount", 0))
    split = f"full {fully_ready} · auth-only {auth_only}"
    rec_code = str((recommendation or {}).get("code") or "")

    if enabled == 0 or eligible == 0 or ((recommendation or {}).get("level") == "critical"):
        state_label = "critical"
        headline = f"Pool critical · {eligible}/{enabled} ready ({split}) · {healthy}/{enabled} healthy · headroom {headroom_label} · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"
    elif rec_code == "POOL_CAPACITY_UNPROVEN":
        state_label = "observing"
        headline = f"Pool observing · {eligible}/{enabled} ready ({split}) · {healthy}/{enabled} healthy · headroom {headroom_label} · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"
    elif (recommendation or {}).get("level") == "info":
        state_label = "tightening"
        headline = f"Pool tightening · {eligible}/{enabled} ready ({split}) · {healthy}/{enabled} healthy · headroom {headroom_label} · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"
    else:
        state_label = "healthy"
        headline = f"Pool healthy · {eligible}/{enabled} ready ({split}) · {healthy}/{enabled} healthy · headroom {headroom_label} · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"

    return {
        "state": state_label,
        "headline": headline,
        "compositeHealthPct": round(cph, 2),
        "routingHeadroomPct": round(headroom, 2),
        "headroomProven": headroom_proven,
        "eligibleCount": eligible,
        "fullyReadyCount": fully_ready,
        "authOnlyCount": auth_only,
        "healthyCount": healthy,
        "enabledCount": enabled,
        "action": (recommendation or {}).get("message"),
        "telemetryWarning": metrics.get("telemetryStaleWarning"),
        "globalUsage": metrics.get("globalUsage"),
    }


def tombstoned_profile_ids(config: Dict[str, Any]) -> List[str]:
    aps = config.get("autoProfileSync", {}) if isinstance(config.get("autoProfileSync"), dict) else {}
    raw = aps.get("removedProfileIds", [])
    return sorted([str(x) for x in raw if str(x).strip()]) if isinstance(raw, list) else []


def sanitize_runtime_order(config: Dict[str, Any], order: List[str]) -> Tuple[List[str], List[str]]:
    tombstones = set(tombstoned_profile_ids(config))
    cleaned: List[str] = []
    removed: List[str] = []
    seen = set()
    for pid in order or []:
        if not pid or pid in seen:
            continue
        seen.add(pid)
        if pid in tombstones:
            removed.append(pid)
            continue
        cleaned.append(pid)
    return cleaned, removed


def _expiry_truth_for_account(st: Dict[str, Any], observed_health: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    health = observed_health if isinstance(observed_health, dict) else (st.get("health", {}) if isinstance(st.get("health"), dict) else {})
    auth = st.get("auth", {}) if isinstance(st.get("auth"), dict) else {}
    expires_dt = parse_any_datetime(health.get("expiresAt"))
    now = now_utc()
    days_left = None
    if expires_dt is not None:
        days_left = round((expires_dt - now).total_seconds() / 86400.0, 2)
    expired = bool(health.get("expired", False)) or (days_left is not None and days_left <= 0)
    auth_status = str(auth.get("status") or "UNKNOWN").upper()
    auth_reason = str(auth.get("reason") or "").strip().lower()
    refresh_failed = any(token in auth_reason for token in ["refresh", "reauth", "unauthorized", "invalid", "expired"])
    if expired:
        expiry_state = "expired"
    elif days_left is not None and days_left <= 1:
        expiry_state = "expires_1d"
    elif days_left is not None and days_left <= 2:
        expiry_state = "expires_2d"
    elif days_left is not None and days_left <= 7:
        expiry_state = "expires_7d"
    elif expires_dt is not None:
        expiry_state = "healthy"
    else:
        expiry_state = "unknown"
    reauth_needed = bool(expired or refresh_failed or auth_status in {"DEAD", "UNAUTHORIZED", "AUTH"})
    reminder_level = None
    if reauth_needed:
        reminder_level = "expired"
    elif expiry_state == "expires_1d":
        reminder_level = "1d"
    elif expiry_state == "expires_2d":
        reminder_level = "2d"
    return {
        "expiresAt": expires_dt.isoformat() if expires_dt else None,
        "daysLeft": days_left,
        "expiryState": expiry_state,
        "expired": expired,
        "reauthNeeded": reauth_needed,
        "refreshFailed": refresh_failed,
        "reminderLevel": reminder_level,
    }


def _capacity_truth_for_account(st: Dict[str, Any]) -> Dict[str, Any]:
    usage = st.get("usage", {}) if isinstance(st.get("usage"), dict) else {}
    five = usage.get("fiveHourRemaining")
    week = usage.get("weekRemaining")
    if isinstance(week, (int, float)) and week <= 0:
        state = "capacity_exhausted"
    elif isinstance(five, (int, float)) and five <= 0:
        state = "capacity_exhausted"
    elif ((isinstance(week, (int, float)) and week <= 15) or (isinstance(five, (int, float)) and five <= 15)):
        state = "capacity_tight"
    elif isinstance(week, (int, float)) or isinstance(five, (int, float)):
        state = "capacity_ok"
    else:
        state = "capacity_unknown"
    return {
        "fiveHourRemaining": five,
        "weekRemaining": week,
        "capacityState": state,
        "usageSource": usage.get("source"),
        "usageTrust": usage.get("trust"),
        "usageObservedAt": usage.get("observedAt"),
    }


def _truth_row_for_account(config: Dict[str, Any], state: Dict[str, Any], pid: str, st: Dict[str, Any], gate: Dict[str, Any], telemetry: Dict[str, Any], current_head: Optional[str], effective_head: Optional[str], enabled: bool, observed_health: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    auth = st.get("auth", {}) if isinstance(st.get("auth"), dict) else {}
    expiry = _expiry_truth_for_account(st, observed_health=observed_health)
    capacity = _capacity_truth_for_account(st)
    return {
        "profileId": pid,
        "name": account_name(config, pid),
        "enabled": enabled,
        "authStatus": str(auth.get("status") or "UNKNOWN").upper(),
        "authReason": auth.get("reason"),
        "authSource": auth.get("source"),
        "expiresAt": expiry.get("expiresAt"),
        "daysLeft": expiry.get("daysLeft"),
        "expiryState": expiry.get("expiryState"),
        "expired": expiry.get("expired"),
        "refreshFailed": expiry.get("refreshFailed"),
        "reauthNeeded": expiry.get("reauthNeeded"),
        "reauthReminderLevel": expiry.get("reminderLevel"),
        "routingEligible": bool(gate.get("eligible")),
        "routingState": gate.get("stateLabel"),
        "routingReason": gate.get("reason"),
        "effectiveState": gate.get("effectiveState"),
        "effectiveReason": gate.get("effectiveReason"),
        "routableNow": bool(gate.get("routableNow")),
        "contradiction": gate.get("contradiction"),
        "capacityState": capacity.get("capacityState"),
        "fiveHourRemaining": capacity.get("fiveHourRemaining"),
        "weekRemaining": capacity.get("weekRemaining"),
        "usageSource": capacity.get("usageSource"),
        "usageTrust": capacity.get("usageTrust"),
        "usageObservedAt": capacity.get("usageObservedAt"),
        "telemetryTrust": gate.get("telemetry"),
        "telemetryFreshness": gate.get("telemetryFreshness"),
        "telemetry": telemetry,
        "healthLabel": gate.get("healthLabel"),
        "verified": account_is_verified(state, pid),
        "verification": verification_record(state, pid),
        "quarantined": bool(((st.get("quarantine") if isinstance(st.get("quarantine"), dict) else {}) or {}).get("active", False)),
        "quarantineReason": (((st.get("quarantine") if isinstance(st.get("quarantine"), dict) else {}) or {}).get("reason")),
        "liveFailover": st.get("liveFailover"),
        "suspiciousWeeklyZero": suspicious_weekly_zero((st.get("usage") if isinstance(st.get("usage"), dict) else {}) or {}),
        "isRuntimeHead": pid == current_head,
        "isPolicyHead": pid == effective_head,
    }


def build_account_inventory(config: Dict[str, Any], state: Dict[str, Any], eligible_profiles: set, current_head: Optional[str], effective_head: Optional[str], observed_health_map: Optional[Dict[str, Dict[str, Any]]] = None) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    inventory: List[Dict[str, Any]] = []
    configured_ids: List[str] = []
    configured_set = set()
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if not pid:
            continue
        configured_ids.append(pid)
        configured_set.add(pid)
        st = (state.get("accounts", {}) or {}).get(pid, {})
        h = st.get("health", {}) if isinstance(st, dict) else {}
        q = st.get("quarantine", {}) if isinstance(st, dict) else {}
        u = st.get("usage", {}) if isinstance(st, dict) else {}
        telemetry = telemetry_freshness(config, u if isinstance(u, dict) else {})
        gate = routing_gate_summary(config, st)
        row = _truth_row_for_account(config, state, pid, st if isinstance(st, dict) else {}, gate, telemetry, current_head, effective_head, bool(a.get("enabled", True)), observed_health=(observed_health_map or {}).get(pid))
        row.update({
            "eligible": row.get("routingEligible"),
            "tokenStatus": row.get("authStatus"),
            "tokenReason": row.get("authReason"),
            "healthy": bool(h.get("healthy", True)),
            "healthStage": h.get("stage"),
            "healthReason": h.get("reason"),
        })
        inventory.append(row)
    state_only = sorted([pid for pid in (state.get("accounts", {}) or {}).keys() if pid not in configured_set])
    tombstones = sorted(list(set(((config.get("autoProfileSync", {}) or {}).get("removedProfileIds", [])))) if isinstance(config.get("autoProfileSync", {}), dict) else [])
    return inventory, state_only, tombstones


def contradiction_report(config: Dict[str, Any], state: Dict[str, Any], current_head: Optional[str], effective_head: Optional[str], eligible_profiles: set, state_only_profiles: List[str], current_order: Optional[List[str]] = None, effective_order: Optional[List[str]] = None, provider_raw_order: Optional[List[str]] = None) -> Dict[str, Any]:
    issues: List[str] = []
    sev = "ok"
    override = state.get("override", {}) if isinstance(state.get("override"), dict) else {}
    tombstones = set(tombstoned_profile_ids(config))
    runtime_order = list(current_order or [])
    policy_order = list(effective_order or [])
    provider_order = list(provider_raw_order or runtime_order)
    runtime_tombstones = [p for p in provider_order if p in tombstones]
    policy_tombstones = [p for p in policy_order if p in tombstones]
    if override.get("enabled") and override.get("profileId") and current_head and override.get("profileId") != current_head:
        issues.append(f"override_target_mismatch:{override.get('profileId')}!=runtime:{current_head}")
    if current_head and current_head not in {a.get('profileId') for a in config.get('accounts', []) if a.get('profileId')}:
        issues.append(f"runtime_head_not_in_config:{current_head}")
    if current_head and current_head in tombstones:
        issues.append(f"runtime_head_tombstoned:{current_head}")
    if effective_head and eligible_profiles and effective_head not in eligible_profiles:
        issues.append(f"policy_head_not_eligible:{effective_head}")
    if effective_head and effective_head in tombstones:
        issues.append(f"policy_head_tombstoned:{effective_head}")
    if runtime_tombstones:
        issues.append("runtime_order_contains_tombstoned:" + ",".join(runtime_tombstones))
    if provider_order != runtime_order:
        issues.append("provider_runtime_mismatch:" + ",".join(provider_order) + "!=" + ",".join(runtime_order))
    if policy_tombstones:
        issues.append("policy_order_contains_tombstoned:" + ",".join(policy_tombstones))
    if state_only_profiles:
        issues.append("state_contains_unconfigured_profiles")
    if issues:
        sev = "warning"
    critical_prefixes = ('override_target_mismatch','runtime_head_not_in_config','runtime_head_tombstoned','policy_head_not_eligible','policy_head_tombstoned','runtime_order_contains_tombstoned','policy_order_contains_tombstoned','provider_runtime_mismatch')
    if any(x.startswith(critical_prefixes) for x in issues):
        sev = "critical"
    return {"ok": not issues, "severity": sev, "issues": issues}


def capacity_recommendation(config: Dict[str, Any], state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    metrics = pool_usage_metrics(config, state)
    policy = config.get("poolUsagePolicy", {}) if isinstance(config.get("poolUsagePolicy"), dict) else {}
    warn_below = float(policy.get("warnBelow", 75.0))
    critical_below = float(policy.get("criticalBelow", 55.0))
    critical_clear_above = float(policy.get("criticalClearAbove", critical_below + 3.0))
    warn_clear_above = float(policy.get("warnClearAbove", warn_below + 5.0))
    weekly_tight_below = float(policy.get("weeklyTightBelow", 15.0))
    weekly_critical_below = float(policy.get("weeklyCriticalBelow", 8.0))

    enabled = int(metrics.get("enabledCount", 0))
    eligible = int(metrics.get("eligibleCount", 0))
    cph = float(metrics.get("compositeHealthPct", 0.0))
    headroom_proven = bool(metrics.get("headroomProven", False))
    state_counts = metrics.get("stateCounts", {}) if isinstance(metrics.get("stateCounts"), dict) else {}
    exhausted_count = int(state_counts.get("exhausted", 0) or 0)
    reauth_required_count = int(state_counts.get("reauthRequired", 0) or 0)
    hold_count = int(state_counts.get("hold", 0) or 0)
    alerts_state = state.get("alerts", {}) if isinstance(state.get("alerts"), dict) else {}
    previous_level = str(alerts_state.get("lastAdvisorLevel") or "").strip().lower()

    eligible_set = set(healthy_profiles(config, state))
    week_rows = []
    exhausted_week_rows = []
    exhausted_five_rows = []
    if headroom_proven:
        for pid in eligible_set:
            acc = (state.get("accounts", {}) or {}).get(pid, {})
            usage = acc.get("usage", {}) if isinstance(acc, dict) else {}
            if telemetry_trust_state(usage if isinstance(usage, dict) else {}).get("state") != "trusted":
                continue
            week = usage.get("weekRemaining")
            five = usage.get("fiveHourRemaining")
            if isinstance(week, (int, float)):
                week_val = float(week)
                week_rows.append((week_val, pid))
                if week_val <= 0.0 and not suspicious_weekly_zero(usage):
                    exhausted_week_rows.append((week_val, pid))
            if isinstance(five, (int, float)) and float(five) <= 0.0:
                exhausted_five_rows.append((float(five), pid))
    weak_week = min(week_rows, default=(None, None))
    weakest_week = weak_week[0]
    weakest_pid = weak_week[1]

    if enabled == 0:
        return {"level": "critical", "code": "POOL_NO_ENABLED", "message": "No enabled OAuth accounts configured. Add/enable accounts now."}
    if eligible == 0:
        if exhausted_count > 0 and reauth_required_count == 0:
            return {"level": "critical", "code": "POOL_NO_ROUTABLE_CAPACITY", "message": f"No routable OAuth accounts available right now. {exhausted_count} account(s) are auth-valid but temporarily exhausted/held; add capacity or wait for reset instead of treating this as reauth-only."}
        if reauth_required_count > 0 and exhausted_count == 0 and hold_count == 0:
            return {"level": "critical", "code": "POOL_NO_ELIGIBLE_REAUTH", "message": f"No eligible OAuth accounts available. {reauth_required_count} account(s) require reauth/expiry recovery now."}
        return {"level": "critical", "code": "POOL_NO_ELIGIBLE_MIXED", "message": f"No eligible OAuth accounts available. Reauth-required={reauth_required_count}, exhausted/held={exhausted_count + hold_count}; restore auth and/or add capacity now."}
    if not headroom_proven:
        return {"level": "info", "code": "POOL_CAPACITY_UNPROVEN", "message": "Per-account capacity unproven; provider-shared telemetry only."}
    if exhausted_week_rows and eligible <= max(1, min(2, enabled // 4 or 1)):
        return {"level": "critical", "code": "POOL_WEEKLY_NEAR_DEAD", "message": f"Weekly routable capacity is near-dead (eligible={eligible}/{enabled}; weakest eligible week={weakest_week:.1f}% on {account_name(config, weakest_pid)}). Add 1-2 accounts now."}
    if exhausted_five_rows and eligible <= 2:
        return {"level": "critical", "code": "POOL_5H_NEAR_DEAD", "message": f"5h routable capacity is near-dead (eligible={eligible}/{enabled}; {len(exhausted_five_rows)} trusted eligible account(s) are at 0% 5h headroom). Add capacity or wait for reset now."}
    sticky_critical = previous_level == "critical" and cph < critical_clear_above
    sticky_info = previous_level == "info" and cph < warn_clear_above

    if cph < critical_below or sticky_critical:
        qualifier = "critical" if cph < critical_below else "still critical"
        return {"level": "critical", "code": "POOL_CAPACITY_CRITICAL", "message": f"Pool health {qualifier} (CPH={cph:.1f}%). Routable {eligible}/{enabled}; exhausted/held={exhausted_count + hold_count}. Add 1-2 accounts now."}
    if weakest_week is not None and weakest_week <= weekly_tight_below:
        return {"level": "info", "code": "POOL_WEEKLY_TIGHT", "message": f"Weekly headroom tightening on routable capacity (weakest eligible week={weakest_week:.1f}% on {account_name(config, weakest_pid)}). Add 1 account before AUTO degrades."}
    if cph < warn_below or sticky_info:
        qualifier = "tightening" if cph < warn_below else "still tightening"
        return {"level": "info", "code": "POOL_CAPACITY_TIGHT", "message": f"Pool health {qualifier} (CPH={cph:.1f}%). Routable {eligible}/{enabled}; exhausted/held={exhausted_count + hold_count}. Recommend adding 1 account soon."}
    return None


def sync_discovered_profiles(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    opts = config.get("autoProfileSync", {}) if isinstance(config.get("autoProfileSync"), dict) else {}
    if not opts.get("enabled", True):
        return {"changed": False, "added": [], "suppressed": [], "discovered": []}

    discovered = discover_provider_profile_ids(config)
    ignored = set(opts.get("ignoreProfileIds", []))
    tombstones = set(opts.get("removedProfileIds", []))
    discovered = [pid for pid in discovered if pid not in ignored]

    existing = {a.get("profileId") for a in config.get("accounts", [])}
    added: List[str] = []
    suppressed: List[str] = []
    explicit_only = bool(opts.get("requireExplicitRegistration", True))

    for pid in discovered:
        if pid in existing:
            continue
        if pid in tombstones or explicit_only:
            suppressed.append(pid)
            continue
        config.setdefault("accounts", []).append({
            "profileId": pid,
            "name": pid,
            "enabled": bool(opts.get("autoEnableNewProfiles", False)),
            "priority": int(opts.get("defaultPriority", 1)),
            "projects": list(opts.get("defaultProjects", ["mb", "autopit4", "temp"])),
            "source": "auto-sync",
        })
        existing.add(pid)
        added.append(pid)

    changed = bool(added)
    append_history(state, {"at": ts(), "type": "profile_sync", "added": added, "suppressed": suppressed, "discovered": discovered, "explicitOnly": explicit_only, "tombstones": sorted(list(tombstones))})
    mon = state.setdefault("monitor", {})
    mon["lastProfileDiscovery"] = {"at": ts(), "discovered": discovered, "added": added, "suppressed": suppressed, "explicitOnly": explicit_only, "tombstones": sorted(list(tombstones))}

    if changed:
        save_json(CONFIG_PATH, config)

    if changed and opts.get("alertOnNewProfile", True):
        named = [f"{account_name(config, pid)} ({pid})" for pid in added]
        send_alert(config, state, "INFO", f"Registered new OAuth profile(s): {', '.join(named)}", code="PROFILE_DISCOVERED", impact="Routing pool inventory changed.", auto_action="Router registered explicitly allowed discovered profile(s).", your_action="Review priorities/projects when convenient.")

    return {"changed": changed, "added": added, "suppressed": suppressed, "discovered": discovered, "requireExplicitRegistration": explicit_only, "removedProfileIds": sorted(list(tombstones))}


def cmd_sync_profiles(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    if is_read_only(config):
        return 0
    ensure_account_state(config, state)
    info = sync_discovered_profiles(config, state)
    ensure_account_state(config, state)
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "sync": info}, indent=2))
    return 0



def should_emit_signal(state: Dict[str, Any], key: str, cooldown_minutes: int) -> bool:
    mon = state.setdefault("monitor", {})
    signals = mon.setdefault("signals", {})
    last = parse_iso(signals.get(key))
    if not last:
        return True
    return now_utc() - last >= dt.timedelta(minutes=cooldown_minutes)


def mark_signal(state: Dict[str, Any], key: str) -> None:
    mon = state.setdefault("monitor", {})
    signals = mon.setdefault("signals", {})
    signals[key] = ts()


def _alert_family_store(state: Dict[str, Any]) -> Dict[str, Any]:
    alerts = state.setdefault("alerts", {})
    families = alerts.get("families")
    if not isinstance(families, dict):
        families = {}
        alerts["families"] = families
    return families


def should_emit_alert_family(
    state: Dict[str, Any],
    family: str,
    fingerprint: str,
    *,
    active: bool = True,
    reminder_minutes: int = 180,
    severity_rank: int = 0,
    metric: Optional[float] = None,
    metric_delta: float = 0.0,
    emit_on_change: bool = True,
) -> bool:
    families = _alert_family_store(state)
    row = families.get(family) if isinstance(families.get(family), dict) else {}
    now = now_utc()
    if not active:
        if row:
            row["active"] = False
            row["clearedAt"] = ts()
            families[family] = row
        return False

    last_at = parse_iso(row.get("lastAt")) if isinstance(row.get("lastAt"), str) else None
    last_fingerprint = str(row.get("fingerprint") or "")
    last_severity_rank = int(row.get("severityRank") or 0)
    last_metric_raw = row.get("metric")
    last_metric = float(last_metric_raw) if isinstance(last_metric_raw, (int, float)) else None

    if not row or not row.get("active"):
        return True
    if severity_rank > last_severity_rank:
        return True
    if metric is not None:
        if last_metric is None:
            return True
        if metric_delta > 0 and metric >= (last_metric + metric_delta):
            return True
    if emit_on_change and fingerprint != last_fingerprint:
        return True
    if reminder_minutes <= 0 or last_at is None:
        return True
    return now - last_at >= dt.timedelta(minutes=reminder_minutes)


def mark_alert_family(
    state: Dict[str, Any],
    family: str,
    fingerprint: str,
    *,
    active: bool = True,
    severity_rank: int = 0,
    metric: Optional[float] = None,
) -> None:
    families = _alert_family_store(state)
    families[family] = {
        "active": bool(active),
        "fingerprint": str(fingerprint or ""),
        "lastAt": ts(),
        "severityRank": int(severity_rank),
        "metric": metric,
    }


def build_lifecycle_advisor(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    metrics = pool_usage_metrics(config, state)
    recommendation = capacity_recommendation(config, state)
    policy = config.get("lifecycleAdvisor", {}) if isinstance(config.get("lifecycleAdvisor"), dict) else {}
    low_value_days = max(1, int(policy.get("lowValueDays", 14)))
    issue_window_days = max(1, int(policy.get("reviewIssueWindowDays", 7)))
    issue_threshold = max(1, int(policy.get("reviewIssueThreshold", 3)))
    now = now_utc()

    eligible = set(healthy_profiles(config, state))
    reviews: List[Dict[str, Any]] = []
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if not pid or not a.get("enabled", True):
            continue
        acc = (state.get("accounts", {}) or {}).get(pid, {})
        h = acc.get("health", {}) if isinstance(acc, dict) else {}
        q = acc.get("quarantine", {}) if isinstance(acc, dict) else {}
        reasons: List[str] = []

        if h.get("stage") == "missing" or h.get("reason") == "not_reported_by_models_status":
            reasons.append("missing/unusable")
        elif h.get("stage") in {"suspect", "confirm"}:
            reasons.append(f"{h.get('stage')} missing-signal")
        elif h.get("healthy") is False:
            reasons.append("unhealthy")

        failure_events = acc.get("failureEvents", []) if isinstance(acc, dict) else []
        cutoff = now - dt.timedelta(days=issue_window_days)
        recent_failures = [x for x in failure_events if (parse_iso(x.get("at")) or now) >= cutoff]
        issue_count = len(recent_failures)
        if q.get("active"):
            issue_count += 1
        if issue_count >= issue_threshold:
            reasons.append(f"{issue_count} issues/{issue_window_days}d")

        last_assigned = parse_iso(acc.get("lastAssignedAt")) if isinstance(acc, dict) else None
        if last_assigned and last_assigned <= (now - dt.timedelta(days=low_value_days)) and pid not in eligible:
            reasons.append(f"unused {low_value_days}+d and not eligible")

        if reasons:
            reviews.append({
                "profileId": pid,
                "name": account_name(config, pid),
                "reasons": reasons,
                "enabled": True,
            })

    rec_level = (recommendation or {}).get("level")
    if rec_level in {"critical", "info"}:
        primary = "ADD"
    elif reviews:
        primary = "REVIEW"
    else:
        primary = "HOLD"

    if primary == "ADD":
        headline = (recommendation or {}).get("message") or "Pool suggests adding accounts."
    elif primary == "REVIEW":
        names = ", ".join([r["name"] for r in reviews[:3]])
        headline = f"Review account set: {names}" if names else "Review account set."
    else:
        ps = pool_summary(metrics, recommendation)
        headline = ps.get("headline") or "Pool healthy."

    return {
        "primary": primary,
        "headline": headline,
        "recommendation": recommendation,
        "reviews": reviews,
        "poolSummary": pool_summary(metrics, recommendation),
        "poolUsage": metrics,
    }


def _sync_lifecycle_advisor_state(state: Dict[str, Any], advisor: Dict[str, Any]) -> Dict[str, Any]:
    mon = state.setdefault("monitor", {})
    prev = mon.setdefault("lifecycleAdvisor", {})
    recommendation = advisor.get("recommendation") or {}
    prev["primary"] = str(advisor.get("primary") or "HOLD")
    prev["headline"] = str(advisor.get("headline") or "")
    prev["reviewProfiles"] = sorted([r.get("profileId") for r in advisor.get("reviews", []) if r.get("profileId")])
    prev["recommendationLevel"] = str(recommendation.get("level") or "").lower()
    prev["recommendationCode"] = str(recommendation.get("code") or "").strip()
    prev["updatedAt"] = ts()
    return prev


def emit_lifecycle_advisor_alerts(config: Dict[str, Any], state: Dict[str, Any], advisor: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    mon = state.setdefault("monitor", {})
    prev = mon.setdefault("lifecycleAdvisor", {})
    current_primary = str(advisor.get("primary") or "HOLD")
    current_reviews = sorted([r.get("profileId") for r in advisor.get("reviews", []) if r.get("profileId")])
    recommendation = advisor.get("recommendation") or {}
    current_level = str(recommendation.get("level") or "").lower()
    current_code = str(recommendation.get("code") or "").strip()
    previous_primary = str(prev.get("primary") or "HOLD")
    previous_reviews = sorted(prev.get("reviewProfiles") or [])
    previous_level = str(prev.get("recommendationLevel") or "").lower()
    previous_code = str(prev.get("recommendationCode") or "").strip()

    changed_primary = current_primary != previous_primary
    changed_reviews = current_reviews != previous_reviews
    level_rank = {"": 0, "info": 1, "warning": 2, "critical": 3}
    recommendation_changed_within_add = current_primary == "ADD" and previous_primary == "ADD" and (current_level != previous_level or current_code != previous_code)
    escalation_within_add = current_primary == "ADD" and previous_primary == "ADD" and (
        level_rank.get(current_level, 0) > level_rank.get(previous_level, 0)
    )
    downgrade_within_add = current_primary == "ADD" and previous_primary == "ADD" and (
        level_rank.get(current_level, 0) < level_rank.get(previous_level, 0)
    )

    alerts_state = state.setdefault("alerts", {})
    last_advisor_code = str(alerts_state.get("lastAdvisorCode") or "").strip()
    last_advisor_level = str(alerts_state.get("lastAdvisorLevel") or "").lower().strip()
    last_advisor_at = parse_iso(alerts_state.get("lastAdvisorAlertAt"))
    cooldown_floor = now_utc() - dt.timedelta(minutes=max(5, int((config.get("lifecycleAdvisor", {}) or {}).get("alertCooldownMinutes", 180))))
    missing_recent_alert_proof = current_primary == "ADD" and current_level in {"critical", "warning"} and (
        last_advisor_code != current_code or last_advisor_level != current_level or last_advisor_at is None or last_advisor_at < cooldown_floor
    )

    if not (changed_primary or changed_reviews or escalation_within_add or missing_recent_alert_proof):
        _sync_lifecycle_advisor_state(state, advisor)
        return events

    advisor_cfg = config.get("lifecycleAdvisor", {}) if isinstance(config.get("lifecycleAdvisor"), dict) else {}
    cooldown_min = max(5, int(advisor_cfg.get("alertCooldownMinutes", 180)))
    key = "lifecycle_advisor_state"
    if downgrade_within_add and not should_emit_signal(state, key="lifecycle_advisor_downgrade_guard", cooldown_minutes=max(15, cooldown_min)):
        _sync_lifecycle_advisor_state(state, advisor)
        return events
    pool_usage = advisor.get("poolUsage") or {}
    weakest_week = recommendation.get("code") == "POOL_WEEKLY_NEAR_DEAD" and str(recommendation.get("message") or "") or current_code
    advisor_fingerprint = "|".join([
        current_primary,
        current_level,
        current_code,
        str(int(pool_usage.get("eligibleCount", 0))),
        str(int(pool_usage.get("healthyCount", 0))),
        str(round(float(pool_usage.get("compositeHealthPct", 0.0)), 1)),
        weakest_week,
    ])
    advisor_metric = float(pool_usage.get("compositeHealthPct", 0.0))
    if (not escalation_within_add) and (not missing_recent_alert_proof) and (not should_emit_signal(state, key, cooldown_min)):
        _sync_lifecycle_advisor_state(state, advisor)
        return events

    if current_primary == "ADD":
        sev = "CRITICAL" if recommendation.get("level") == "critical" else ("WARNING" if recommendation.get("level") == "warning" else "INFO")
        sev_rank = 2 if sev == "CRITICAL" else 1
        code = "ADVISOR_ADD_NOW" if recommendation.get("level") == "critical" else "ADVISOR_ADD_SOON"
        if not (
            escalation_within_add
            or missing_recent_alert_proof
            or should_emit_alert_family(
                state,
                "advisor_add",
                advisor_fingerprint,
                reminder_minutes=cooldown_min,
                severity_rank=sev_rank,
                metric=(-1.0 * advisor_metric),
                metric_delta=5.0,
                emit_on_change=False,
            )
        ):
            _sync_lifecycle_advisor_state(state, advisor)
            return events
        r = send_alert(
            config,
            state,
            sev,
            "Capacity pressure in OAuth pool",
            code=code,
            impact="Pool lifecycle advisor detected capacity pressure.",
            auto_action="Router continues balancing across healthy eligible profiles.",
            your_action=_advisor_brain_text(advisor),
            status=_advisor_capacity_status(advisor),
        )
        alerts_state = state.setdefault("alerts", {})
        alerts_state["lastAdvisorAlertAt"] = ts()
        alerts_state["lastAdvisorCode"] = current_code or code
        alerts_state["lastAdvisorLevel"] = current_level or recommendation.get("level") or ""
        mark_alert_family(state, "advisor_add", advisor_fingerprint, severity_rank=sev_rank, metric=(-1.0 * advisor_metric))
        events.append({"type": code, "alert": r})
    elif current_primary == "REVIEW":
        review_text = "; ".join([
            f"{r.get('name')} ({', '.join(r.get('reasons', []))})" for r in advisor.get("reviews", [])[:4]
        ])
        r = send_alert(
            config,
            state,
            "INFO",
            f"Review account set: {review_text}" if review_text else "Review account set.",
            code="ADVISOR_REVIEW",
            impact="Some enabled accounts look low-value or issue-prone.",
            auto_action="No automatic disable/remove will occur.",
            your_action="Review those accounts when convenient and decide whether to keep/disable them.",
            status=f"reviewCount={len(current_reviews)}",
        )
        mark_alert_family(state, "advisor_add", "cleared", active=False)
        events.append({"type": "ADVISOR_REVIEW", "alert": r})
    elif previous_primary in {"ADD", "REVIEW"}:
        r = send_alert(
            config,
            state,
            "INFO",
            "Pool no longer needs extra accounts or account review right now.",
            code="ADVISOR_HOLD",
            impact="Capacity and account-health pressure have cleared for now.",
            auto_action="Monitoring continues in the background.",
            your_action="None right now.",
            status=f"primary={current_primary}",
        )
        mark_alert_family(state, "advisor_add", "cleared", active=False)
        events.append({"type": "ADVISOR_HOLD", "alert": r})

    mark_signal(state, key)
    _sync_lifecycle_advisor_state(state, advisor)
    return events

def emit_monitor_alerts(config: Dict[str, Any], state: Dict[str, Any], cli_timeout_tier: str = "standard") -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    enabled_profiles = [a["profileId"] for a in config.get("accounts", []) if a.get("enabled", True)]
    healthy = healthy_profiles(config, state)
    mon = state.setdefault("monitor", {})
    exhaustion = mon.setdefault("exhaustion", {})
    enabled_state = mon.setdefault("enabledState", {})
    transition_state = mon.setdefault("transitionState", {}) if isinstance(mon.get("transitionState"), dict) else {}
    mon["transitionState"] = transition_state

    health_truth = cached_health_truth_summary(config, state)
    health_missing = len(health_truth.get('missingTruthProfiles') or [])
    health_unhealthy = len(health_truth.get('unhealthyProfiles') or [])
    if health_truth.get("truthDegraded"):
        sev = "CRITICAL" if health_truth.get("state") == "failed" else "WARNING"
        sev_rank = 2 if sev == "CRITICAL" else 1
        fingerprint = f"{health_truth.get('truthState')}|{health_truth.get('truthFreshness')}|{health_missing}"
        key = f"health_truth:{health_truth.get('truthFreshness')}:{health_missing}"
        should_emit = should_emit_signal(state, key, 60) and should_emit_alert_family(state, "health_truth_degraded", fingerprint, reminder_minutes=180, severity_rank=sev_rank, metric=float(health_missing), metric_delta=1.0)
        if should_emit:
            r = send_alert(
                config,
                state,
                sev,
                "OAuth health truth is degraded." if sev == "WARNING" else "OAuth health truth failed and pool safety is at risk.",
                code="HEALTH_TRUTH_DEGRADED",
                impact="Operator view may lag fresh provider truth or some accounts may be missing from health checks." if sev == "WARNING" else "Fresh provider truth is unavailable while no healthy safe pool is available.",
                auto_action="Health sentinel keeps refreshing live provider truth.",
                your_action="Check `/oauth health` if this persists or the missing count grows.",
                status=f"truth={health_truth.get('truthFreshness')}; missing={health_missing}; unhealthy={health_unhealthy}",
            )
            mark_signal(state, key)
            mark_alert_family(state, "health_truth_degraded", fingerprint, severity_rank=sev_rank, metric=float(health_missing))
            events.append({"type": key, "alert": r})
    else:
        should_emit_alert_family(state, "health_truth_degraded", "cleared", active=False)

    if health_truth.get("accountHealthDegraded") and not health_truth.get("truthDegraded"):
        sev = "CRITICAL" if not healthy else "WARNING"
        sev_rank = 2 if sev == "CRITICAL" else 1
        missing_profiles = sorted([str(x) for x in (health_truth.get('missingProfiles') or []) if str(x)])
        unhealthy_profiles = sorted([str(x) for x in (health_truth.get('unhealthyProfiles') or []) if str(x)])
        missing_profiles_count = len(missing_profiles)
        fingerprint = f"account_health|unhealthy={','.join(unhealthy_profiles)}|missing={','.join(missing_profiles)}"
        key = f"account_health:{health_unhealthy}:{missing_profiles_count}"
        should_emit = should_emit_signal(state, key, 60) and should_emit_alert_family(state, "health_account_degraded", fingerprint, reminder_minutes=180, severity_rank=sev_rank, metric=float(health_unhealthy + missing_profiles_count), metric_delta=1.0)
        if should_emit:
            r = send_alert(
                config,
                state,
                sev,
                "OAuth account health is degraded, but health truth is still fresh.",
                code="HEALTH_ACCOUNT_DEGRADED",
                impact="Fresh health truth is available; one or more accounts are unhealthy, expired, or missing from safe routing.",
                auto_action="Router keeps excluding unhealthy accounts from safe routing.",
                your_action="Reauth, disable, or replace the unhealthy accounts if pool pressure grows.",
                status=f"truth={health_truth.get('truthFreshness')}; unhealthy={health_unhealthy}; missing_profiles={missing_profiles_count}",
            )
            mark_signal(state, key)
            mark_alert_family(state, "health_account_degraded", fingerprint, severity_rank=sev_rank, metric=float(health_unhealthy + missing_profiles_count))
            events.append({"type": key, "alert": r})
    else:
        should_emit_alert_family(state, "health_account_degraded", "cleared", active=False)
    prev_truth_degraded = bool(transition_state.get("truthDegraded"))
    prev_account_health_degraded = bool(transition_state.get("accountHealthDegraded"))
    if prev_truth_degraded and not health_truth.get("truthDegraded"):
        r = send_alert(
            config,
            state,
            "INFO",
            "OAuth health truth recovered and is fresh again.",
            code="HEALTH_TRUTH_RECOVERED",
            impact="Operator health view is back to fresh provider-backed truth.",
            auto_action="Monitoring continues with fresh truth.",
            your_action="No action right now.",
            status=f"truth={health_truth.get('truthFreshness')}; unhealthy={health_unhealthy}",
        )
        events.append({"type": "health_truth_recovered", "alert": r})
    if prev_account_health_degraded and not health_truth.get("accountHealthDegraded") and not health_truth.get("truthDegraded"):
        r = send_alert(
            config,
            state,
            "INFO",
            "OAuth pool account health recovered.",
            code="POOL_RECOVERED",
            impact="Fresh truth now shows the pool back in a healthy state.",
            auto_action="Router resumed normal healthy-pool operation.",
            your_action="No action right now.",
            status=f"healthy={len(healthy)}/{len(enabled_profiles)}; truth={health_truth.get('truthFreshness')}",
        )
        events.append({"type": "pool_recovered", "alert": r})
    transition_state["truthDegraded"] = bool(health_truth.get("truthDegraded"))
    transition_state["accountHealthDegraded"] = bool(health_truth.get("accountHealthDegraded"))

    runtime_quarantined = []
    for pid in enabled_profiles:
        st = state.get("accounts", {}).get(pid, {})
        q = st.get("quarantine", {}) if isinstance(st.get("quarantine"), dict) else {}
        if q.get("active") and str(q.get("reason") or "").startswith("runtime_"):
            runtime_quarantined.append(pid)

    if len(healthy) == 1 and enabled_profiles:
        lone = healthy[0]
        key = f"pool_single_healthy:{lone}:{len(enabled_profiles)}"
        if should_emit_signal(state, key, 30):
            r = send_alert(
                config,
                state,
                "WARNING",
                f"Only one healthy OAuth account remains available: {account_name(config, lone)} ({lone}).",
                code="POOL_SINGLE_HEALTHY",
                impact="Another limit hit or invalidation can silence Telegram and destabilize cron quickly.",
                auto_action="Router keeps all live traffic on the surviving healthy head.",
                your_action="Prepare/add another ChatGPT account now before the remaining head degrades.",
                status=f"healthy=1/{len(enabled_profiles)}; head={lone}",
            )
            mark_signal(state, key)
            events.append({"type": key, "alert": r})

    if len(runtime_quarantined) >= 2:
        q_key = ",".join(sorted(runtime_quarantined[:6]))
        key = f"pool_runtime_quarantine_cluster:{len(runtime_quarantined)}:{q_key}"
        fingerprint = f"count={len(runtime_quarantined)}|members={q_key}"
        if should_emit_signal(state, key, 30) and should_emit_alert_family(state, "runtime_quarantine_cluster", fingerprint, reminder_minutes=180, severity_rank=1, metric=float(len(runtime_quarantined)), metric_delta=1.0):
            names = ", ".join([f"{account_name(config, pid)} ({pid})" for pid in runtime_quarantined[:4]])
            more = "" if len(runtime_quarantined) <= 4 else f" +{len(runtime_quarantined)-4} more"
            r = send_alert(
                config,
                state,
                "WARNING",
                f"Multiple OAuth accounts are under active runtime quarantine: {names}{more}.",
                code="POOL_RUNTIME_QUARANTINE_CLUSTER",
                impact="The pool is consuming backup accounts under provider pressure and may collapse further soon.",
                auto_action="Router excludes quarantined accounts and concentrates traffic on survivors.",
                your_action="Add/refresh accounts now if you want to avoid emergency manual recovery.",
                status=f"runtimeQuarantined={len(runtime_quarantined)}; healthy={len(healthy)}/{len(enabled_profiles)}",
            )
            mark_signal(state, key)
            mark_alert_family(state, "runtime_quarantine_cluster", fingerprint, severity_rank=1, metric=float(len(runtime_quarantined)))
            events.append({"type": key, "alert": r})
    else:
        should_emit_alert_family(state, "runtime_quarantine_cluster", "cleared", active=False)

    try:
        main_sessions_path = session_store_path("main")
        if main_sessions_path.exists():
            main_store = json.loads(main_sessions_path.read_text())
            main_entries, _root, _shape = session_store_entries(main_store)
            tg_key = "agent:main:telegram:direct:1828174896"
            tg_entry = main_entries.get(tg_key) if isinstance(main_entries, dict) else None
            if isinstance(tg_entry, dict):
                tg_profile = str(tg_entry.get("authProfileOverride") or "").strip() or None
                tg_source = str(tg_entry.get("authProfileOverrideSource") or "").strip() or None
                routing_state = (state.get("routing", {}) or {})
                runtime_target = (
                    routing_state.get("selectedTarget")
                    or routing_state.get("lastAppliedTop")
                    or head
                    or routing_state.get("currentTarget")
                    or (healthy[0] if healthy else None)
                )
                recent_rebind = (state.get("sessionRebind", {}) or {}) if isinstance(state.get("sessionRebind", {}), dict) else {}
                recent_rebind_at = parse_iso(recent_rebind.get("lastAt")) if recent_rebind.get("lastAt") else None
                recent_rebind_age = (now_utc() - recent_rebind_at).total_seconds() if recent_rebind_at else None
                recent_rebind_target = str(recent_rebind.get("targetProfileId") or "").strip() or None
                recent_rebind_reason = str(recent_rebind.get("reason") or "").strip() or None
                rebind_reconciling = bool(
                    tg_profile
                    and runtime_target
                    and recent_rebind_target == tg_profile == runtime_target
                    and recent_rebind_reason in {"tick", "watchdog"}
                    and recent_rebind_age is not None
                    and recent_rebind_age <= 30
                )
                if tg_profile and runtime_target and tg_source != "user" and tg_profile != runtime_target and not rebind_reconciling:
                    key = f"telegram_binding_drift:{tg_profile}:{runtime_target}:{tg_source or 'none'}"
                    fingerprint = f"{tg_profile}|{runtime_target}|{tg_source or 'none'}"
                    monitor = state.setdefault("monitor", {}) if isinstance(state, dict) else {}
                    drift = monitor.setdefault("telegramBindingDrift", {}) if isinstance(monitor, dict) else {}
                    first_seen = drift.get(fingerprint)
                    now_iso = ts()
                    if not isinstance(first_seen, str):
                        drift[fingerprint] = now_iso
                        first_seen = now_iso
                    first_seen_dt = parse_iso(first_seen) if isinstance(first_seen, str) else None
                    persistent = bool(first_seen_dt and (now_utc() - first_seen_dt).total_seconds() >= 180)
                    if persistent and should_emit_signal(state, key, 10) and should_emit_alert_family(state, "telegram_binding_drift", fingerprint, reminder_minutes=60, severity_rank=2, emit_on_change=False):
                        r = send_alert(
                            config,
                            state,
                            "CRITICAL",
                            f"Telegram direct session is bound to {tg_profile} while runtime target is {runtime_target}.",
                            code="TELEGRAM_SESSION_BINDING_DRIFT",
                            impact="Telegram can go silent even while the switching system partially recovers on another account.",
                            auto_action="Watchdog should rebind auto-managed sessions to the current runtime target.",
                            your_action="If this repeats after the patch, stop and inspect session override truth immediately.",
                            status=f"session={tg_key}; source={tg_source or 'none'}; persistentSec>=180",
                        )
                        mark_signal(state, key)
                        mark_alert_family(state, "telegram_binding_drift", fingerprint, severity_rank=2)
                        events.append({"type": key, "alert": r})
                else:
                    monitor = state.setdefault("monitor", {}) if isinstance(state, dict) else {}
                    drift = monitor.setdefault("telegramBindingDrift", {}) if isinstance(monitor, dict) else {}
                    if isinstance(drift, dict):
                        drift.clear()
                    should_emit_alert_family(state, "telegram_binding_drift", "cleared", active=False)
    except Exception as exc:
        append_history(state, {"at": ts(), "type": "monitor_alert_check_error", "scope": "telegram_binding_drift", "error": safe_reason(exc)})

    # Explicit transition alerts when an account is disabled in pool config.
    for a in config.get("accounts", []):
        pid0 = a.get("profileId")
        if not pid0:
            continue
        now_enabled = bool(a.get("enabled", True))
        prev_enabled = enabled_state.get(pid0)
        if prev_enabled is None:
            enabled_state[pid0] = now_enabled
            if not now_enabled:
                r = send_alert(
                    config,
                    state,
                    "INFO",
                    f"OAuth account {account_name(config, pid0)} ({pid0}) is disabled in pool config.",
                    code="PROFILE_DISABLED",
                    impact="This profile is removed from routing decisions until re-enabled.",
                    auto_action="Router excludes the disabled profile.",
                    your_action="Re-enable it only if you intentionally want it back in rotation.",
                    status=f"profile={pid0}",
                )
                events.append({"type": f"disabled:{pid0}", "alert": r})
            continue
        if prev_enabled and (not now_enabled):
            r = send_alert(
                config,
                state,
                "INFO",
                f"OAuth account {account_name(config, pid0)} ({pid0}) was disabled.",
                code="PROFILE_DISABLED",
                impact="This profile is removed from routing decisions until re-enabled.",
                auto_action="Router excludes the disabled profile.",
                your_action="Verify the disable was intentional.",
                status=f"profile={pid0}",
            )
            events.append({"type": f"disabled:{pid0}", "alert": r})
        elif (prev_enabled is False) and now_enabled:
            r = send_alert(
                config,
                state,
                "INFO",
                f"OAuth account {account_name(config, pid0)} ({pid0}) was re-enabled.",
                code="PROFILE_REENABLED",
                impact="This profile is eligible to re-enter routing once its health/routability is proven.",
                auto_action="Router will reassess the account on the next monitor cycle.",
                your_action="No action unless the account stays non-routable.",
                status=f"profile={pid0}",
            )
            events.append({"type": f"reenabled:{pid0}", "alert": r})
        enabled_state[pid0] = now_enabled
        transition_state[f"profile:{pid0}:enabled"] = now_enabled

    # Keep auth head aligned with usable pool. If current head becomes unusable
    # (exhausted/quarantined/unhealthy/expired), auto-evict it in the same monitor pass.
    provider = config.get("provider", "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    timeout_sec = timeout_tier(config, "standard")
    current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
    head = current_order[0] if current_order else None
    active_profile = resolve_usage_profile(config, state)
    if head and healthy and head not in healthy:
        preferred = healthy[0]
        if can_reorder_auth_for_new_assignments(config, state, preferred):
            new_order = list(healthy)
            for p in current_order:
                if p not in new_order:
                    new_order.append(p)
            for a in config.get("accounts", []):
                pid2 = a.get("profileId")
                if pid2 and pid2 not in new_order:
                    new_order.append(pid2)
            res = apply_auth_order(config, state, new_order, timeout_sec=timeout_sec, source="monitor", reason="auto_evict_unusable_head")
            append_history(state, {
                "at": ts(),
                "type": "auth_order_apply",
                "reason": "auto_evict_unusable_head",
                "oldHead": head,
                "newHead": preferred,
                "result": res,
            })
            events.append({"type": "auto_evict_unusable_head", "oldHead": head, "newHead": preferred})
            events.extend(alert_auth_order_drift(config, state, res, "auto_evict_unusable_head"))

    for pid in enabled_profiles:
        st = state.get("accounts", {}).get(pid, {})
        h = st.get("health", {})
        q = st.get("quarantine", {})
        suppress_stale_alerts = bool(fresh_recovery_truth(config, st).get("active"))

        expiry_truth = _expiry_truth_for_account(st)
        expiry_family = f"{pid}|{expiry_truth.get('expiryState')}"
        if expiry_truth.get("expired") and not suppress_stale_alerts:
            key = f"expired:{pid}"
            should_emit_expired = (
                should_emit_signal(state, key, 10)
                and should_emit_expiry_alert(config, state, pid, st, "PROFILE_EXPIRED")
                and should_emit_alert_family(state, f"profile_expired:{pid}", expiry_family, reminder_minutes=720, severity_rank=2, metric=1.0, metric_delta=1.0, emit_on_change=False)
            )
            if should_emit_expired:
                r = send_alert(config, state, "CRITICAL", f"OAuth account {account_name(config, pid)} ({pid}) expired.", code="PROFILE_EXPIRED", impact="This profile cannot be used for routing until re-authenticated.", auto_action="Router excluded the expired profile.", your_action=f"Run `/oauth reauth {account_name(config, pid)}` now.", status=f"profile={pid}; expiryState={expiry_truth.get('expiryState')}; daysLeft={expiry_truth.get('daysLeft')}; command=/oauth reauth {account_name(config, pid)}")
                mark_signal(state, key)
                mark_alert_family(state, f"profile_expired:{pid}", expiry_family, severity_rank=2, metric=1.0)
                events.append({"type": key, "alert": r})
        else:
            should_emit_alert_family(state, f"profile_expired:{pid}", "cleared", active=False)
        if expiry_truth.get("reminderLevel") == "1d" and not suppress_stale_alerts:
            key = f"expiry_1d:{pid}"
            if should_emit_signal(state, key, 720):
                r = send_alert(config, state, "WARNING", f"OAuth account {account_name(config, pid)} ({pid}) expires within 1 day.", code="PROFILE_EXPIRY_1D", impact="Profile is still usable now but needs prompt re-auth to avoid sudden routing loss.", auto_action="Router keeps using the profile while it remains valid.", your_action=f"Run `/oauth reauth {account_name(config, pid)}` today.", status=f"profile={pid}; daysLeft={expiry_truth.get('daysLeft')}; command=/oauth reauth {account_name(config, pid)}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})
        elif expiry_truth.get("reminderLevel") == "2d" and not suppress_stale_alerts:
            key = f"expiry_2d:{pid}"
            if should_emit_signal(state, key, 1440):
                r = send_alert(config, state, "INFO", f"OAuth account {account_name(config, pid)} ({pid}) expires within 2 days.", code="PROFILE_EXPIRY_2D", impact="No immediate outage, but re-auth should be scheduled before expiry.", auto_action="Router keeps using the profile while it remains valid.", your_action=f"Queue `/oauth reauth {account_name(config, pid)}` for this profile.", status=f"profile={pid}; daysLeft={expiry_truth.get('daysLeft')}; command=/oauth reauth {account_name(config, pid)}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})

        unhealthy_reason = str(h.get("reason") or "")
        unhealthy_but_not_expired = h.get("healthy") is False and not expiry_truth.get("expired")
        if unhealthy_but_not_expired and not suppress_stale_alerts:
            key = f"unhealthy:{pid}"
            if should_emit_signal(state, key, 10):
                if unhealthy_reason == "not_reported_by_models_status":
                    r = send_alert(
                        config,
                        state,
                        "CRITICAL",
                        f"OAuth account {account_name(config, pid)} ({pid}) is missing/unusable (not reported by provider status).",
                        code="PROFILE_MISSING_OR_UNUSABLE",
                        impact="Profile likely deleted/unauthorized/unsubscribed and is excluded from routing.",
                        auto_action="Router removed this profile from safe routing decisions.",
                        your_action=f"Run `/oauth reauth {account_name(config, pid)}` now or keep it disabled.",
                        status=f"profile={pid}; command=/oauth reauth {account_name(config, pid)}",
                    )
                else:
                    r = send_alert(config, state, "CRITICAL", f"OAuth account {account_name(config, pid)} ({pid}) is unhealthy.", code="PROFILE_UNHEALTHY", impact="Profile is excluded from safe routing.", auto_action="Router auto-routed away from this profile.", your_action=f"Run `/oauth reauth {account_name(config, pid)}` or inspect the account immediately.", status=f"profile={pid}; command=/oauth reauth {account_name(config, pid)}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})

        runtime_quarantine = str(q.get("reason") or "").startswith("runtime_")
        if q.get("active") and (not runtime_quarantine) and not suppress_stale_alerts:
            key = f"quarantine:{pid}:{q.get('reason')}"
            if should_emit_signal(state, key, 15):
                r = send_alert(config, state, "CRITICAL", f"OAuth account {account_name(config, pid)} ({pid}) quarantined ({q.get('reason')}).", code="PROFILE_QUARANTINED", impact="Profile temporarily removed from routing due to repeated failures.", auto_action="Router will re-allow after quarantine expiry.", your_action="Check cause only if quarantine keeps repeating.", status=f"profile={pid}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})

        usage_state = st.get("usage", {}) if isinstance(st.get("usage"), dict) else {}
        gate = routing_gate_summary(config, st)
        effective_state = str(gate.get("effectiveState") or "UNKNOWN")
        prev_profile_state = transition_state.get(f"profile:{pid}:effectiveState")
        recovery_truth = fresh_recovery_truth(config, st)
        recoverable_prior_states = {"REAUTH_REQUIRED", "DEACTIVATED", "CONTRADICTORY_HOLD", "AUTH_VALID_BUT_EXHAUSTED"}
        if effective_state == "ROUTABLE" and recovery_truth.get("active"):
            if prev_profile_state in recoverable_prior_states:
                code = "PROFILE_REAUTH_SUCCESS" if prev_profile_state in {"REAUTH_REQUIRED", "DEACTIVATED", "CONTRADICTORY_HOLD"} else "PROFILE_RECOVERED"
                msg = (
                    f"OAuth account {account_name(config, pid)} ({pid}) reauthenticated successfully and is routable again."
                    if code == "PROFILE_REAUTH_SUCCESS"
                    else f"OAuth account {account_name(config, pid)} ({pid}) recovered and is routable again."
                )
                r = send_alert(
                    config,
                    state,
                    "INFO",
                    msg,
                    code=code,
                    impact="This account is back in the healthy routable pool.",
                    auto_action="Router may use the account again for safe routing.",
                    your_action="No action right now.",
                    status=f"profile={pid}; priorState={prev_profile_state}; 5h={usage_state.get('fiveHourRemaining')}; week={usage_state.get('weekRemaining')}",
                )
                events.append({"type": f"recovered:{pid}", "alert": r})
            elif prev_profile_state in {None, "UNKNOWN"}:
                r = send_alert(
                    config,
                    state,
                    "INFO",
                    f"OAuth account {account_name(config, pid)} ({pid}) is verified and routable.",
                    code="PROFILE_ONBOARDED_SUCCESS",
                    impact="A newly available account is now part of the healthy routable pool.",
                    auto_action="Router can use this account for safe routing.",
                    your_action="No action right now.",
                    status=f"profile={pid}; 5h={usage_state.get('fiveHourRemaining')}; week={usage_state.get('weekRemaining')}",
                )
                events.append({"type": f"onboarded:{pid}", "alert": r})
        transition_state[f"profile:{pid}:effectiveState"] = effective_state
        transition_state[f"profile:{pid}:enabled"] = True

        # Runtime failover quarantines already represent known provider caps/timeouts.
        # Avoid duplicate per-profile weekly/5h alerts for those while quarantine is active.
        if runtime_quarantine:
            continue

        wk = usage_state.get("weekRemaining")
        fh = usage_state.get("fiveHourRemaining")
        # Warn on exhaustion transitions (not every cooldown window) to avoid
        # repetitive noise while an account remains exhausted.
        relevant = (pid == head) or (pid == active_profile) or (len(healthy) <= 2)

        week_flag = f"{pid}:week"
        if isinstance(wk, (int, float)) and float(wk) <= 0.0:
            if relevant and not exhaustion.get(week_flag, False):
                key = f"usage_weekly_exhausted:{pid}"
                if should_emit_signal(state, key, 180):
                    r = send_alert(config, state, "INFO", f"OAuth account {account_name(config, pid)} ({pid}) reached 0% weekly remaining and is excluded from routing.", code="PROFILE_WEEKLY_CAP", impact="Temporary capacity reduction only.", auto_action="Router excludes this profile until quota recovers.", your_action="No action unless pool capacity becomes tight.", status=f"profile={pid}")
                    mark_signal(state, key)
                    events.append({"type": key, "alert": r})
                exhaustion[week_flag] = True
        else:
            exhaustion.pop(week_flag, None)

        five_flag = f"{pid}:5h"
        if isinstance(fh, (int, float)) and float(fh) <= 0.0:
            if relevant and not exhaustion.get(five_flag, False):
                key = f"usage_5h_exhausted:{pid}"
                if should_emit_signal(state, key, 30):
                    r = send_alert(config, state, "INFO", f"OAuth account {account_name(config, pid)} ({pid}) reached 0% 5h remaining and is temporarily excluded.", code="PROFILE_5H_CAP", impact="Short-term capacity dip only.", auto_action="Router excludes this profile until 5h window recovers.", your_action="No action unless multiple profiles hit this together.", status=f"profile={pid}")
                    mark_signal(state, key)
                    events.append({"type": key, "alert": r})
                exhaustion[five_flag] = True
        else:
            exhaustion.pop(five_flag, None)
    if not healthy:
        key = "pool:no_healthy"
        if should_emit_signal(state, key, 5):
            r = send_alert(config, state, "CRITICAL", "No healthy OAuth accounts are currently available.", code="POOL_DOWN", impact="Routing cannot safely assign profiles.", auto_action="Router paused unsafe assignments.", your_action="Restore/re-auth at least one healthy profile now.")
            mark_signal(state, key)
            events.append({"type": key, "alert": r})

    advisor = build_lifecycle_advisor(config, state)

    rec = capacity_recommendation(config, state)
    suppress_capacity_alert = str(advisor.get("primary") or "HOLD") == "ADD"
    if rec and not suppress_capacity_alert:
        level = str(rec.get("level") or "info")
        key = f"capacity:{level}"
        if should_emit_signal(state, key, 60):
            sev = "CRITICAL" if level == "critical" else "INFO"
            r = send_alert(
                config,
                state,
                sev,
                "Capacity pressure in OAuth pool",
                code=str(rec.get("code") or "CAPACITY_RECOMMENDATION"),
                impact="Pool-level usage telemetry detected a capacity threshold.",
                auto_action="Router keeps balancing across eligible healthy profiles.",
                your_action="Add/refresh accounts when threshold remains low.",
                status=_advisor_capacity_status(advisor),
            )
            mark_signal(state, key)
            events.append({"type": key, "alert": r})

    events.extend(emit_lifecycle_advisor_alerts(config, state, advisor))

    return events


def cached_health_truth_summary(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    settings = health_settings(config)
    monitor = state.get("monitor", {}) if isinstance(state.get("monitor"), dict) else {}
    truth = monitor.get("healthTruth", {}) if isinstance(monitor.get("healthTruth"), dict) else {}
    progress = load_control_loop_progress()
    health_progress = ((progress.get("commands", {}) or {}).get("health-check") or {}) if isinstance(progress, dict) else {}

    enabled_ids = [a.get("profileId") for a in config.get("accounts", []) if a.get("enabled", True) and a.get("profileId")]
    missing_truth: List[str] = []
    unhealthy_profiles: List[str] = []
    missing_profiles: List[str] = []

    for pid in enabled_ids:
        acc = (state.get("accounts", {}) or {}).get(pid, {}) if isinstance(state.get("accounts", {}), dict) else {}
        h = acc.get("health", {}) if isinstance(acc, dict) else {}
        if not parse_iso(h.get("observedAt")) if isinstance(h, dict) else True:
            missing_truth.append(pid)
        if h.get("healthy") is False:
            unhealthy_profiles.append(pid)
        if h.get("stage") in {"suspect", "confirm", "missing"}:
            missing_profiles.append(pid)

    fresh_sec = int(settings.get("truthFreshSeconds", 900))
    stale_sec = int(settings.get("truthStaleSeconds", 1800))
    last_status = str(truth.get("lastStatus") or "unknown")
    last_truth_at = truth.get("lastRefreshAt")
    last_truth_dt = parse_iso(last_truth_at) if isinstance(last_truth_at, str) else None
    truth_age = (now_utc() - last_truth_dt).total_seconds() if last_truth_dt else None
    observed_profiles = list(truth.get("observedProfiles") or []) if isinstance(truth.get("observedProfiles"), list) else []

    progress_at = parse_iso(health_progress.get("updatedAt")) if isinstance(health_progress, dict) else None
    progress_age = (now_utc() - progress_at).total_seconds() if progress_at else None

    if truth_age is None:
        freshness = "missing"
        truth_state = "degraded"
    elif truth_age <= fresh_sec and last_status == "ok":
        freshness = "fresh"
        truth_state = "healthy"
    elif truth_age <= stale_sec and last_status in {"ok", "degraded"}:
        freshness = "aging"
        truth_state = "degraded"
    else:
        freshness = "stale"
        truth_state = "degraded"

    account_state = "degraded" if (unhealthy_profiles or missing_profiles) else "healthy"
    state_label = truth_state
    if not healthy_profiles(config, state):
        state_label = "failed"

    return {
        "state": state_label,
        "truthState": truth_state,
        "accountState": account_state,
        "lastTruthAt": last_truth_at,
        "truthAgeSec": round(truth_age, 2) if truth_age is not None else None,
        "truthFreshness": freshness,
        "healthCheckProgress": health_progress,
        "healthCheckProgressAgeSec": round(progress_age, 2) if progress_age is not None else None,
        "lastTruthStatus": last_status,
        "missingTruthProfiles": missing_truth,
        "observedProfiles": observed_profiles,
        "missingProfiles": missing_profiles,
        "unhealthyProfiles": unhealthy_profiles,
        "degraded": truth_state != "healthy",
        "truthDegraded": truth_state != "healthy",
        "accountHealthDegraded": account_state != "healthy",
    }


def cached_watchdog_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    hb = ((state.get("monitor", {}) or {}).get("watchdogHeartbeat") or {})
    progress = load_control_loop_progress()
    watchdog_progress = ((progress.get("commands", {}) or {}).get("watchdog") or {}) if isinstance(progress, dict) else {}
    at = parse_iso(hb.get("at")) if isinstance(hb, dict) else None
    progress_at = parse_iso(watchdog_progress.get("updatedAt")) if isinstance(watchdog_progress, dict) else None
    best_at = max([x for x in [at, progress_at] if x is not None], default=None)
    age = (now_utc() - best_at).total_seconds() if best_at else None
    fresh = age is not None and age <= 300 and bool((hb.get("ok") if isinstance(hb, dict) else False) or watchdog_progress.get("status") in {"success", "lock_busy", "start"})
    return {
        "ok": fresh,
        "cached": True,
        "at": ts(),
        "heartbeat": hb,
        "progress": watchdog_progress,
        "ageSec": round(age, 2) if age is not None else None,
        "fresh": fresh,
    }


def cmd_watchdog_cached(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool) -> int:
    out = cached_watchdog_summary(state)
    if json_mode:
        print(json.dumps(out, indent=2))
    else:
        print(f"watchdog cached: fresh={out['fresh']} age={out['ageSec']}s")
    return 0 if out.get('ok') else 1


def cmd_health_check(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool = False) -> int:
    settings = health_settings(config)
    lock_fh = acquire_file_lock(HEALTH_LOCK_PATH, wait_seconds=float(settings.get("healthLockWaitSeconds", 0.0)))
    if lock_fh is None:
        update_control_loop_progress("health-check", "lock_busy", error="health lock busy", lockPath=str(HEALTH_LOCK_PATH))
        latest_state = load_json(STATE_PATH, default_state())
        ensure_account_state(config, latest_state)
        summary = cached_health_truth_summary(config, latest_state)
        out = {
            "ok": True,
            "skipped": "health_lock_busy",
            "fastPath": True,
            "lockPath": str(HEALTH_LOCK_PATH),
            "state": summary["state"],
            "lastTruthAt": summary["lastTruthAt"],
            "truthAgeSec": summary["truthAgeSec"],
            "truthFreshness": summary["truthFreshness"],
            "lastTruthStatus": summary["lastTruthStatus"],
            "observedProfiles": summary["observedProfiles"],
            "missingTruthProfiles": summary["missingTruthProfiles"],
            "missingProfiles": summary["missingProfiles"],
            "unhealthyProfiles": summary["unhealthyProfiles"],
            "alertsTriggered": 0,
            "degraded": summary["degraded"],
            "persistResult": "skipped_lock_busy",
        }
        print(json.dumps(out, indent=2))
        return 0

    try:
        latest_state = load_json(STATE_PATH, default_state())
        ensure_account_state(config, latest_state)
        rc_models, out_models, err_models = run_models_status_json(config, "truth")
        observed = {}
        models_status = {
            "ok": rc_models == 0,
            "code": rc_models,
            "timeoutSec": timeout_tier(config, "health"),
            "stderr": err_models,
            "stdoutBytes": len(out_models or ""),
            "source": "live_truth",
        }
        mon = latest_state.setdefault("monitor", {})
        if rc_models == 0 and out_models:
            try:
                observed = parse_models_status_payload(config, json.loads(out_models))
            except Exception as exc:
                models_status.update({"ok": False, "code": 1, "parseError": str(exc)})
                observed = {}
        if models_status.get("ok"):
            mon["knownProfiles"] = sorted(list(observed.keys()))
            mon["healthTruth"] = {
                "lastStatus": "ok",
                "lastRefreshAt": ts(),
                "observedProfiles": sorted(list(observed.keys())),
                "code": models_status.get("code"),
            }
            merge_health_update(config, latest_state, observed)
        else:
            prior_truth = (mon.get("healthTruth", {}) or {}) if isinstance(mon.get("healthTruth"), dict) else {}
            mon["lastModelsStatusFailure"] = {
                "at": ts(),
                "code": models_status.get("code"),
                "stderr": models_status.get("stderr"),
                "parseError": models_status.get("parseError"),
            }
            mon["healthTruth"] = {
                "lastStatus": "failed",
                "lastRefreshAt": prior_truth.get("lastRefreshAt"),
                "lastFailureAt": ts(),
                "code": models_status.get("code"),
                "stderr": models_status.get("stderr"),
                "observedProfiles": prior_truth.get("observedProfiles", []),
            }
        router_lock_fh = acquire_router_lock(wait_seconds=15.0)
        if router_lock_fh is None:
            update_control_loop_progress("health-check", "lock_busy", error="router lock busy during health-check", lockPath=str(LOCK_PATH))
            summary = cached_health_truth_summary(config, latest_state)
            out = {
                "ok": True,
                "skipped": "router_lock_busy",
                "fastPath": False,
                "lockPath": str(HEALTH_LOCK_PATH),
                "state": summary["state"],
                "lastTruthAt": summary["lastTruthAt"],
                "truthAgeSec": summary["truthAgeSec"],
                "truthFreshness": summary["truthFreshness"],
                "lastTruthStatus": summary["lastTruthStatus"],
                "modelsStatus": models_status,
                "observedProfiles": summary["observedProfiles"],
                "missingTruthProfiles": summary["missingTruthProfiles"],
                "missingProfiles": summary["missingProfiles"],
                "unhealthyProfiles": summary["unhealthyProfiles"],
                "alertsTriggered": 0,
                "degraded": summary["degraded"],
                "persistResult": "skipped_router_lock_busy",
            }
            print(json.dumps(out, indent=2))
            return 0
        try:
            current_state = load_json(STATE_PATH, default_state())
            ensure_account_state(config, current_state)
            current_mon = current_state.setdefault("monitor", {})
            current_mon["knownProfiles"] = mon.get("knownProfiles", current_mon.get("knownProfiles", []))
            current_mon["healthTruth"] = mon.get("healthTruth", current_mon.get("healthTruth", {}))
            if mon.get("lastModelsStatusFailure") is not None:
                current_mon["lastModelsStatusFailure"] = mon.get("lastModelsStatusFailure")
            if models_status.get("ok"):
                merge_health_update(config, current_state, observed)
            save_json(STATE_PATH, current_state)
            latest_state = current_state
        finally:
            release_router_lock(router_lock_fh)
        summary = cached_health_truth_summary(config, latest_state)
        out = {
            "ok": True,
            "fastPath": False,
            "lockPath": str(HEALTH_LOCK_PATH),
            "state": summary["state"],
            "lastTruthAt": summary["lastTruthAt"],
            "truthAgeSec": summary["truthAgeSec"],
            "truthFreshness": summary["truthFreshness"],
            "lastTruthStatus": summary["lastTruthStatus"],
            "modelsStatus": models_status,
            "observedProfiles": summary["observedProfiles"],
            "missingTruthProfiles": summary["missingTruthProfiles"],
            "missingProfiles": summary["missingProfiles"],
            "unhealthyProfiles": summary["unhealthyProfiles"],
            "alertsTriggered": 0,
            "degraded": summary["degraded"],
            "persistResult": "state_saved",
        }
        if json_mode:
            print(json.dumps(out, indent=2))
        else:
            print(f"health-check {summary['state']}: freshness={summary['truthFreshness']} age={summary['truthAgeSec']}s observed={len(summary['observedProfiles'])}")
        return 0
    finally:
        release_router_lock(lock_fh)


def cmd_status(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool) -> int:
    # Guardrail: status is observational only. It must never persist state,
    # apply auth order, run session rebind, or perform repair/reconcile writes.
    # Any richer reporting must operate on a cloned working state only, leaving live state untouched.
    working_state = copy.deepcopy(state)
    ensure_account_state(config, working_state)
    provider = config.get("provider", "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    override_enabled = bool((working_state.get("override", {}) or {}).get("enabled"))
    mode = "MANUAL" if override_enabled else "AUTO"
    runtime_info = {
        "ok": True,
        "readOnly": True,
        "skipped": ["runtime_failover_ingest", "auto_hygiene_reconcile", "status_policy_reconcile"],
    }
    auto_hygiene_info = {
        "authStoreSync": {"ok": True, "updated": False, "skipped": "status_read_only"},
        "beforeRawRuntimeAuthOrder": [],
        "removedTombstonedRuntime": [],
        "normalizedRuntimeOrder": False,
        "afterRawRuntimeAuthOrder": [],
        "skipped": "status_read_only",
    }
    auth_sync_info = auto_hygiene_info.get("authStoreSync")
    provider_raw_runtime = auto_hygiene_info.get("beforeRawRuntimeAuthOrder") or []
    removed_tombstoned_runtime = auto_hygiene_info.get("removedTombstonedRuntime") or []
    status_runtime_normalized = bool(auto_hygiene_info.get("normalizedRuntimeOrder"))
    reconciled_runtime = auto_hygiene_info.get("afterRawRuntimeAuthOrder") or []
    for pid in working_state.get("accounts", {}):
        working_state["accounts"][pid]["activeLeaseCount"] = active_leases_for_profile(working_state, pid)
        usage = working_state["accounts"][pid].get("usage") or {}
        if str(usage.get("weekResetSource") or "").startswith("derived"):
            usage["weekResetAt"] = None
            usage["weekResetSource"] = "unknown-unproven"
            usage["weekResetObservedAt"] = None
        if str(usage.get("fiveHourResetSource") or "").startswith("derived"):
            usage["fiveHourResetAt"] = None
            usage["fiveHourResetSource"] = "unknown-unproven"
            usage["fiveHourResetObservedAt"] = None
        usage.update(infer_reset_windows_from_usage_log(pid, usage))
        working_state["accounts"][pid]["usage"] = usage
    eligible_profiles = set(healthy_profiles(config, working_state))
    pool_state = "PAUSED" if not eligible_profiles else "ACTIVE"
    pause_message = "⏸️ System Paused: All accounts are exhausted or dead. Please add a new account via terminal to resume." if pool_state == "PAUSED" else None

    rc_o, out_o, _ = run_cmd(["openclaw", "models", "auth", "order", "get", "--provider", provider, "--agent", agent_id, "--json"])
    order_info = None
    if rc_o == 0 and out_o:
        try:
            order_info = json.loads(out_o)
        except Exception:
            order_info = {"raw": out_o}

    raw_runtime_order = []
    reconciled_runtime_order = list(reconciled_runtime)
    current_order = []
    tombstoned_in_runtime_order: List[str] = []
    if isinstance(order_info, dict) and isinstance(order_info.get("order"), list):
        raw_runtime_order = list(order_info.get("order") or [])
        observed_after = list(order_info.get("order") or reconciled_runtime)
        current_order, tombstoned_in_runtime_order = sanitize_runtime_order(config, observed_after)
        order_info["providerRawOrder"] = list(raw_runtime_order)
        order_info["preStatusAutoHygieneRawOrder"] = list(provider_raw_runtime)
        order_info["reconciledObservedOrder"] = list(observed_after)
        order_info["order"] = list(current_order)
        order_info["sanitizedOrder"] = list(current_order)
        if tombstoned_in_runtime_order:
            order_info["removedTombstoned"] = list(tombstoned_in_runtime_order)

    preferred = preferred_healthy_order(config, state, current_order)
    preview_base = list(preferred.get("ordered") or [])
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if pid and pid not in preview_base:
            preview_base.append(pid)

    order_preview = build_effective_auth_order(config, state, preview_base)
    effective_order = order_preview.get("effectiveOrder", []) if isinstance(order_preview, dict) else []
    effective_order, removed_tombstoned_effective = sanitize_runtime_order(config, list(effective_order))
    if eligible_profiles:
        effective_order = [p for p in effective_order if p in eligible_profiles]
    elif current_order:
        effective_order = list(current_order)
    status_reconciled = False
    post_reconcile_read_failed = False
    current_prefix = effective_order[:len(current_order)] if current_order else []
    tail_truncation_only = bool(current_order) and (current_order == current_prefix)
    unknown_profiles = {
        p for p in effective_order
        if ((working_state.get("accounts", {}).get(p, {}) or {}).get("usage", {}) or {}).get("source") == "unknown"
    }
    effective_without_unknown = [p for p in effective_order if p not in unknown_profiles]
    unknown_trim_only = bool(current_order) and (current_order == effective_without_unknown)
    policy_drift = bool(current_order and (current_order != effective_order) and (not tail_truncation_only) and (not unknown_trim_only))
    effective_head = effective_order[0] if effective_order else None
    current_head = current_order[0] if current_order else None
    policy_cfg = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
    safe_depth = max(1, int(policy_cfg.get("failoverSafeDepth", 3)))
    effective_set = set(effective_order)
    failover_chain = current_order[:safe_depth] if current_order else []
    failover_unsafe_raw = [p for p in failover_chain if p not in effective_set]
    failover_unsafe = actionable_failover_unsafe_profiles(config, state, failover_unsafe_raw)
    order_risk_drift = bool(policy_drift and (((not current_head) or (current_head != effective_head) or (current_head not in effective_set)) or failover_unsafe))

    observed_models = observe_models_status(config, "health")
    if observed_models:
        for pid, observed in observed_models.items():
            if pid in (working_state.get("accounts", {}) or {}) and isinstance((working_state.get("accounts", {}) or {}).get(pid), dict):
                acc = working_state["accounts"][pid]
                prev_h = acc.get("health", {}) if isinstance(acc.get("health"), dict) else {}
                acc["health"] = evaluate_profile_health(config, prev_h, observed)
    rec = capacity_recommendation(config, working_state)
    pool_metrics = pool_usage_metrics(config, working_state)
    pool_simple = pool_summary(pool_metrics, rec)

    order_trace = working_state.get("authOrderTrace", {}) if isinstance(working_state.get("authOrderTrace"), dict) else {}
    order_trace = {
        **order_trace,
        "desiredOrder": list(effective_order),
        "effectiveOrder": list(effective_order),
        "observedOrder": list(current_order),
        "drift": {
            "activeHead": current_head,
            "policyHead": effective_head,
            "tailNoise": [p for p in (current_order[1:] if len(current_order) > 1 else []) if p not in set(effective_order)],
            "policyDrift": policy_drift,
            "removedIneligible": order_preview.get("removedIneligible", []) if isinstance(order_preview, dict) else [],
            "driftAgents": []
        }
    }
    runtime_tail = current_order[1:] if len(current_order) > 1 else []
    policy_tail = effective_order[1:] if len(effective_order) > 1 else []
    runtime_tail_noise = [p for p in runtime_tail if p not in set(effective_order)]
    account_inventory, state_only_profiles, tombstoned_profiles = build_account_inventory(config, working_state, eligible_profiles, current_head, effective_head, observed_health_map=observed_models)
    reauth_queue = [
        {
            "profileId": row.get("profileId"),
            "name": row.get("name"),
            "reauthNeeded": row.get("reauthNeeded"),
            "reminderLevel": row.get("reauthReminderLevel"),
            "expiryState": row.get("expiryState"),
            "daysLeft": row.get("daysLeft"),
            "authStatus": row.get("authStatus"),
            "authReason": row.get("authReason"),
        }
        for row in account_inventory
        if row.get("reauthNeeded") or row.get("reauthReminderLevel") in {"2d", "1d", "expired"}
    ]
    reauth_queue.sort(key=lambda row: (0 if row.get("reauthNeeded") else 1, row.get("daysLeft") if isinstance(row.get("daysLeft"), (int, float)) else 9999, str(row.get("profileId") or "")))
    contradictions = contradiction_report(config, working_state, current_head, effective_head, eligible_profiles, state_only_profiles, current_order=current_order, effective_order=effective_order, provider_raw_order=raw_runtime_order)
    if post_reconcile_read_failed:
        contradictions['ok'] = False
        contradictions['severity'] = 'critical'
        contradictions.setdefault('issues', []).append('post_reconcile_provider_read_failed')
    routing_state = working_state.get("routing", {}) if isinstance(working_state.get("routing"), dict) else {}
    advisor = build_lifecycle_advisor(config, working_state)
    override = working_state.get("override", {}) if isinstance(working_state.get("override"), dict) else {}
    override_enabled = bool(override.get("enabled"))
    override_profile = str(override.get("profileId") or "").strip() or None
    # mode computed earlier
    runtime_head = current_order[0] if current_order else (raw_runtime_order[0] if raw_runtime_order else None)
    policy_head = override_profile if override_enabled and override_profile else effective_head
    selected_target = override_profile if override_enabled and override_profile else (routing_state.get("selectedTarget") or effective_head)
    current_target = override_profile if override_enabled and override_profile else (routing_state.get("currentTarget") or runtime_head)
    last_applied_top = routing_state.get("lastAppliedTop")
    last_decision_at = parse_iso(routing_state.get("lastDecisionAt"))
    last_applied_at = parse_iso(routing_state.get("lastAppliedAt"))
    stale_last_applied = bool(last_applied_top and last_decision_at and last_applied_at and last_applied_at < last_decision_at)
    if stale_last_applied:
        control_head = current_target or selected_target or policy_head or runtime_head
        control_head_source = "currentTarget"
    else:
        control_head = last_applied_top or current_target or selected_target or policy_head or runtime_head
        control_head_source = "lastAppliedTop" if last_applied_top else ("currentTarget" if current_target else "selectedTarget")
    routing_decision = {
        "selectedTarget": selected_target,
        "currentTarget": current_target,
        "lastAppliedTop": last_applied_top or effective_head,
        "lastTopScore": routing_state.get("lastTopScore"),
        "holdReason": routing_state.get("holdReason"),
        "challenger": routing_state.get("challenger"),
        "scoreDelta": routing_state.get("scoreDelta"),
        "switchThreshold": routing_state.get("switchThreshold"),
        "lastDecisionAt": routing_state.get("lastDecisionAt") or routing_state.get("lastAppliedAt"),
        "lastAppliedAt": routing_state.get("lastAppliedAt"),
        "controlHeadSource": control_head_source,
        "controlHeadStaleLastApplied": stale_last_applied,
    }
    transition_state = {
        "selectedTarget": selected_target,
        "currentTarget": current_target,
        "controlHead": control_head,
        "lastAppliedTop": last_applied_top or effective_head,
        "controlHeadSource": control_head_source,
        "privilegedSurfacesTarget": None,
        "privilegedSurfacesAligned": None,
        "runtimeAligned": None,
        "inProgress": False,
        "phase": "steady",
    }
    head_mismatch = len({x for x in [runtime_head, policy_head, control_head] if x}) > 1
    unresolved_head_drift = bool(head_mismatch and (order_risk_drift or stale_last_applied or not contradictions.get('ok', True) or runtime_head != policy_head))
    auto_split_brain = bool(mode == "AUTO" and unresolved_head_drift)
    status_label = f"{mode} DEGRADED" if auto_split_brain else mode
    session_rebind_info = copy.deepcopy(working_state.get("sessionRebind", {})) if isinstance(working_state.get("sessionRebind"), dict) else {}
    main_session_store = read_session_override_snapshot("main", main_privileged_session_keys())
    try:
        main_store_path = session_store_path('main')
        if main_store_path.exists():
            main_store = json.loads(main_store_path.read_text())
            main_entries, _main_root, _main_shape = session_store_entries(main_store)
            privileged_keys = control_surface_session_keys('main')
            privileged_targets = []
            for sk in privileged_keys:
                entry = main_entries.get(sk) if isinstance(main_entries, dict) else None
                if isinstance(entry, dict):
                    val = str(entry.get('authProfileOverride') or '').strip() or None
                    if val:
                        privileged_targets.append(val)
            unique_targets = sorted({x for x in privileged_targets if x})
            if len(unique_targets) == 1:
                transition_state['privilegedSurfacesTarget'] = unique_targets[0]
                transition_state['privilegedSurfacesAligned'] = True
            elif len(unique_targets) > 1:
                transition_state['privilegedSurfacesTarget'] = unique_targets
                transition_state['privilegedSurfacesAligned'] = False
    except Exception:
        pass
    runtime_aligned = bool(selected_target and current_target and selected_target == current_target)
    transition_state['runtimeAligned'] = runtime_aligned
    priv_target = transition_state.get('privilegedSurfacesTarget')
    priv_aligned = transition_state.get('privilegedSurfacesAligned')
    if isinstance(priv_target, str) and selected_target and priv_target == selected_target and not runtime_aligned:
        transition_state['inProgress'] = True
        transition_state['phase'] = 'privileged_surfaces_moved_waiting_for_runtime'
    elif runtime_aligned and isinstance(priv_target, str) and priv_target == current_target:
        transition_state['inProgress'] = False
        transition_state['phase'] = 'steady'
    elif priv_aligned is False:
        transition_state['inProgress'] = True
        transition_state['phase'] = 'privileged_surfaces_split'
    elif selected_target and current_target and selected_target != current_target:
        transition_state['inProgress'] = True
        transition_state['phase'] = 'target_selected_waiting_for_runtime'

    summary = {
        "at": ts(),
        "provider": config.get("provider"),
        "runtimeFailover": runtime_info,
        "mode": mode,
        "statusLabel": status_label,
        "runtimeHead": runtime_head,
        "policyHead": policy_head,
        "controlHead": control_head,
        "controlHeadSource": control_head_source,
        "controlHeadStaleLastApplied": stale_last_applied,
        "routingDecision": routing_decision,
        "targetTransition": transition_state,
        "override": working_state.get("override", {}),
        "focus": working_state.get("focus", {}),
        "accounts": working_state.get("accounts", {}),
        "accountInventory": account_inventory,
        "reauthReminderQueue": reauth_queue,
        "stateOnlyProfiles": state_only_profiles,
        "tombstonedProfiles": tombstoned_profiles,
        "contradictions": contradictions,
        "activeTargetProfileId": control_head if control_head else ((state.get("override", {}) or {}).get("profileId") if (state.get("override", {}) or {}).get("enabled") else effective_head),
        "rawRuntimeAuthOrder": raw_runtime_order,
        "preStatusAutoHygieneRawOrder": provider_raw_runtime,
        "reconciledRuntimeAuthOrder": reconciled_runtime_order,
        "sanitizedRuntimeAuthOrder": current_order,
        "degraded": auto_split_brain,
        "activeLeases": {k: v for k, v in working_state.get("leases", {}).items() if v.get("active")},
        "tasks": working_state.get("tasks", {}),
        "poolUsage": pool_metrics,
        "poolSummary": pool_simple,
        "poolState": pool_state,
        "pauseMessage": pause_message,
        "telemetrySummary": {
            "confidencePct": pool_metrics.get("telemetryConfidencePct"),
            "freshnessCounts": pool_metrics.get("telemetryFreshnessCounts"),
            "confidenceCounts": pool_metrics.get("telemetryConfidenceCounts"),
            "rawRoutingHeadroomPct": pool_metrics.get("rawRoutingHeadroomPct"),
            "effectiveRoutingHeadroomPct": pool_metrics.get("routingHeadroomPct"),
        },
        "lifecycleAdvisor": advisor,
        "capacityRecommendation": (rec.get("message") if rec else None),
        "capacityRecommendationLevel": (rec.get("level") if rec else None),
        "authStoreSync": auth_sync_info,
        "statusAutoHygiene": {
            "beforeRawRuntimeAuthOrder": provider_raw_runtime,
            "removedTombstonedRuntime": removed_tombstoned_runtime,
            "normalizedRuntimeOrder": status_runtime_normalized,
            "afterRawRuntimeAuthOrder": reconciled_runtime,
        },
        "statusPolicyReconciled": status_reconciled,
        "postReconcileProviderReadFailed": post_reconcile_read_failed,
        "sessionRebind": session_rebind_info,
        "mainSessionStore": main_session_store,
        "currentAuthOrder": order_info,
        "effectiveAuthOrder": effective_order,
        "removedTombstonedEffectiveOrder": removed_tombstoned_effective,
        "orderPolicyDrift": policy_drift,
        "orderRiskDrift": order_risk_drift,
        "orderRemovedIneligible": order_preview.get("removedIneligible", []) if isinstance(order_preview, dict) else [],
        "orderFailoverSafeDepth": safe_depth,
        "orderFailoverUnsafeProfiles": failover_unsafe,
        "routingEligibleProfiles": sorted(list(eligible_profiles)),
        "authOrderTrace": order_trace,
        "orderPresentation": {"activeHead": current_head, "policyHead": effective_head, "policySafeOrder": effective_order, "runtimeTail": runtime_tail, "policyTail": policy_tail, "runtimeTailNoise": runtime_tail_noise, "removedIneligible": order_preview.get("removedIneligible", []) if isinstance(order_preview, dict) else [], "removedTombstoned": tombstoned_in_runtime_order},
        "liveCanary": working_state.get("liveCanary", {}),
        "recovery": working_state.get("recovery", {}),
    }
    if json_mode:
        print(json.dumps(summary, indent=2))
    else:
        print(f"OAuth Pool Status @ {summary['at']}")
        print(f"Provider: {summary['provider']}")
        print(f"Override: {summary['override']}")
        print(f"Focus: {summary['focus']}")
        op = summary.get("orderPresentation") or {}
        if summary.get("currentAuthOrder"):
            print(f"Runtime auth order (main): {summary['currentAuthOrder']}")
        print(f"Mode: {summary.get('statusLabel')} | Active target: {summary.get('activeTargetProfileId')}")
        print(f"Active head: runtime={summary.get('runtimeHead')} policy={summary.get('policyHead')} control={summary.get('controlHead')} source={summary.get('controlHeadSource')}")
        tt = summary.get('targetTransition') or {}
        print(f"Target transition: phase={tt.get('phase')} inProgress={tt.get('inProgress')} selected={tt.get('selectedTarget')} current={tt.get('currentTarget')} privileged={tt.get('privilegedSurfacesTarget')}")
        if summary.get('controlHeadStaleLastApplied'):
            print("⚠️ Control head is ignoring stale lastAppliedTop and using the newer routing target.")
        if summary.get('degraded'):
            print("⚠️ Divergence detected: runtime/control/policy are not aligned.")
        print(f"Provider raw runtime order: {summary.get('rawRuntimeAuthOrder')}")
        print(f"Reconciled runtime order: {summary.get('reconciledRuntimeAuthOrder')}")
        print(f"Sanitized runtime order: {summary.get('sanitizedRuntimeAuthOrder')}")
        print(f"Policy-safe order: {op.get('policySafeOrder')}")
        print(f"Runtime tail noise: {op.get('runtimeTailNoise')}")
        if summary.get('contradictions', {}).get('issues'):
            print(f"Contradictions: {summary.get('contradictions')}")
        if summary.get('stateOnlyProfiles'):
            print(f"State-only profiles (not in config): {summary.get('stateOnlyProfiles')}")
        if summary.get('tombstonedProfiles'):
            print(f"Tombstoned profiles: {summary.get('tombstonedProfiles')}")
        ps = summary.get("poolSummary") or {}
        pu = summary.get("poolUsage") or {}
        if ps:
            print(f"Pool: {ps.get('headline')}")
            if ps.get("telemetryWarning"):
                print(ps.get("telemetryWarning"))
        if summary.get("poolState") == "PAUSED" and summary.get("pauseMessage"):
            print(summary.get("pauseMessage"))
        if pu:
            print(
                f"Pool detail: CPH={pu.get('compositeHealthPct')}% used={pu.get('compositeUsedPct')}% "
                f"coverage={pu.get('coveragePct')}% health={pu.get('healthPct')}% telemetry={pu.get('telemetryConfidencePct')}% topN={pu.get('topN')}"
            )
            print(
                f"Telemetry detail: raw_headroom={pu.get('rawRoutingHeadroomPct')}% effective_headroom={pu.get('routingHeadroomPct')}% "
                f"freshness={pu.get('telemetryFreshnessCounts')} confidence={pu.get('telemetryConfidenceCounts')}"
            )
        advisor = summary.get("lifecycleAdvisor") or {}
        if advisor:
            print(f"Advisor: {advisor.get('primary')} · {advisor.get('headline')}")
        trace = summary.get("authOrderTrace") or {}
        if trace:
            print(f"Auth trace: writer={trace.get('lastWriter')} source={trace.get('lastSource')} reason={trace.get('lastReason')}")
        canary = summary.get("liveCanary") or {}
        if canary.get("lastOutcome"):
            last = canary.get("lastOutcome") or {}
            print(f"Live canary: profile={last.get('profileId')} success={last.get('success')} latencyMs={last.get('latencyMs')} reason={last.get('reason')}")
        if summary.get("orderPolicyDrift"):
            if summary.get("orderRiskDrift"):
                print(f"Order policy drift: RISK (removedIneligible={summary.get('orderRemovedIneligible')}, failoverUnsafe={summary.get('orderFailoverUnsafeProfiles')})")
            else:
                print(f"Order policy drift: benign-tail (runtime-managed), removedIneligible={summary.get('orderRemovedIneligible')}, failoverUnsafe={summary.get('orderFailoverUnsafeProfiles')}")
        print("Accounts:")
        for row in summary.get("accountInventory", []):
            print(f"- {row.get('name')} ({row.get('profileId')}): enabled={row.get('enabled')} eligible={row.get('eligible')} state={row.get('routingState')} reason={row.get('routingReason')} token={row.get('tokenStatus')} healthy={row.get('healthy')} stage={row.get('healthStage')} expired={row.get('expired')} quarantine={row.get('quarantined')} 5h={row.get('fiveHourRemaining')} week={row.get('weekRemaining')} source={row.get('usageSource')} freshness={(row.get('telemetry') or {}).get('freshness')} confidence={(row.get('telemetry') or {}).get('confidence')} runtimeHead={row.get('isRuntimeHead')} policyHead={row.get('isPolicyHead')}")
        print("Active Leases:")
        if summary["activeLeases"]:
            for k, v in summary["activeLeases"].items():
                print(f"- {k} -> {v.get('profileId')} (project={v.get('project')}, acquiredAt={v.get('acquiredAt')})")
        else:
            print("- none")
        if summary["capacityRecommendation"]:
            print(f"Recommendation: {summary['capacityRecommendation']}")
    return 0


def _retired_accounts_ledger(config: Dict[str, Any], state: Dict[str, Any]) -> List[Dict[str, Any]]:
    removed = set(((config.get("autoProfileSync") or {}).get("removedProfileIds") or []))
    config_accounts = {a.get("profileId"): a for a in config.get("accounts", []) if a.get("profileId")}
    state_accounts = state.get("accounts") or {}
    ledger = []
    for pid in sorted(removed):
        acct = config_accounts.get(pid) or state_accounts.get(pid) or {}
        usage = acct.get("usage") or {}
        ledger.append({
            "profileId": pid,
            "label": acct.get("name") or pid.replace("codex-oauth-", ""),
            "retiredAt": usage.get("weekResetObservedAt") or usage.get("observedAt") or state.get("lastTickAt") or ts(),
            "reason": "manual_retired_or_removed",
            "retiredBy": "operator",
            "source": "config.removedProfileIds",
        })
    return ledger


def _membership_audit(config: Dict[str, Any], state: Dict[str, Any], retired_ledger: List[Dict[str, Any]]) -> Dict[str, Any]:
    config_ids = {a.get("profileId") for a in config.get("accounts", []) if a.get("profileId")}
    state_ids = set((state.get("accounts") or {}).keys())
    removed = set(((config.get("autoProfileSync") or {}).get("removedProfileIds") or []))
    retired = {row.get("profileId") for row in retired_ledger if row.get("profileId")}
    live_only_state = sorted(state_ids - config_ids - removed)
    removed_still_in_state = sorted((removed | retired) & state_ids)
    auth_order = []
    for key in ["authOrder", "effectiveAuthOrder", "providerAuthOrder"]:
        if isinstance(state.get(key), list):
            auth_order.extend(state.get(key))
    removed_still_in_orders = sorted({pid for pid in auth_order if pid in removed or pid in retired})
    return {
        "generatedAt": ts(),
        "configCount": len(config_ids),
        "stateCount": len(state_ids),
        "removedCount": len(removed),
        "retiredCount": len(retired),
        "liveOnlyState": live_only_state,
        "removedStillInState": removed_still_in_state,
        "removedStillInOrders": removed_still_in_orders,
        "ok": not (live_only_state or removed_still_in_orders),
    }


def _refresh_integrity_artifacts(config: Dict[str, Any], state: Dict[str, Any]) -> None:
    retired = _retired_accounts_ledger(config, state)
    audit = _membership_audit(config, state, retired)
    save_json(STATE_PATH.parent / 'oauth-retired-accounts.json', retired)
    save_json(STATE_PATH.parent / 'oauth-membership-audit.json', audit)


def cmd_tick(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    ensure_account_state(config, state)
    if is_read_only(config):
        return 0
    runtime_info = ingest_runtime_failover_signals(config, state)
    auth_sync_info = sync_runtime_quarantine_to_auth_store(config, state)
    sync_info = sync_discovered_profiles(config, state)
    ensure_account_state(config, state)

    rc_models, out_models, err_models = run_models_status_json(config, "truth")
    observed = {}
    models_status = {
        "ok": rc_models == 0,
        "code": rc_models,
        "timeoutSec": timeout_tier(config, "health"),
        "stderr": err_models,
        "stdoutBytes": len(out_models or ""),
    }
    if rc_models == 0 and out_models:
        try:
            observed = parse_models_status_payload(config, json.loads(out_models))
        except Exception as exc:
            models_status.update({"ok": False, "code": 1, "parseError": str(exc)})
            observed = {}
    mon = state.setdefault("monitor", {})
    if models_status.get("ok"):
        mon["knownProfiles"] = sorted(list(observed.keys()))
        mon["healthTruth"] = {
            "lastStatus": "ok",
            "lastRefreshAt": ts(),
            "observedProfiles": sorted(list(observed.keys())),
            "code": models_status.get("code"),
        }
    else:
        mon["lastModelsStatusFailure"] = {
            "at": ts(),
            "code": models_status.get("code"),
            "stderr": models_status.get("stderr"),
            "parseError": models_status.get("parseError"),
        }
        mon["healthTruth"] = {
            "lastStatus": "failed",
            "lastRefreshAt": (mon.get("healthTruth", {}) or {}).get("lastRefreshAt"),
            "lastFailureAt": ts(),
            "code": models_status.get("code"),
            "stderr": models_status.get("stderr"),
            "observedProfiles": (mon.get("healthTruth", {}) or {}).get("observedProfiles", []),
        }

    usage_global = observe_usage_snapshot(config)
    usage_by_profile = {}
    if (config.get("usageProbe") or {}).get("perProfileWhenIdle", True):
        usage_by_profile = observe_usage_by_profile(config, state)

    usage_profile = resolve_usage_profile(config, state)
    canary_info = run_live_canary_rotation(config, state)

    if models_status.get("ok"):
        merge_health_update(config, state, observed)

    for a in config.get("accounts", []):
        pid = a["profileId"]
        st = state["accounts"][pid]
        prev_u = st.get("usage", {}) if isinstance(st.get("usage"), dict) else {}
        prev_at = parse_iso(prev_u.get("observedAt"))
        retain_minutes = int((config.get("usageProbe") or {}).get("retainProbeMinutes", 180))
        snap = usage_by_profile.get(pid)
        if isinstance(snap, dict) and snap.get("available") and snap.get("trust") in (None, "verified", "conditional"):
            st["usage"] = _update_week_exhaustion_state(
                st.get("usage"),
                _stabilize_usage_reset_anchors(st.get("usage"), {
                    "available": True,
                    "fiveHourRemaining": snap.get("fiveHourRemaining"),
                    "weekRemaining": snap.get("weekRemaining"),
                    "observedAt": snap.get("observedAt", ts()),
                    "source": snap.get("source") or "status-main-probe",
                    "probeAgentId": snap.get("probeAgentId"),
                    "frontloadedProfileId": snap.get("frontloadedProfileId"),
                    "trust": snap.get("trust", "verified"),
                    "observedHeadBeforeSample": snap.get("observedHeadBeforeSample"),
                    "observedHeadAfterSample": snap.get("observedHeadAfterSample"),
                    "reason": snap.get("reason"),
                    "accountId": snap.get("accountId"),
                    "providerReturnedAccountId": snap.get("providerReturnedAccountId"),
                }),
                snap.get("observedAt", ts()),
            )
        elif isinstance(snap, dict) and snap.get("source") == "rejected-order-drift-before-sample":
            st["usage"] = {
                "available": False,
                "fiveHourRemaining": None,
                "weekRemaining": None,
                "observedAt": snap.get("observedAt", ts()),
                "source": snap.get("source"),
                "probeAgentId": snap.get("probeAgentId"),
                "frontloadedProfileId": snap.get("frontloadedProfileId"),
                "trust": "rejected",
                "observedHeadBeforeSample": snap.get("observedHeadBeforeSample"),
                "reason": snap.get("reason"),
            }
        else:
            retain_numeric_probe = (
                prev_u.get("source") in TRUSTED_NUMERIC_USAGE_SOURCES
                and prev_at is not None
                and (now_utc() - prev_at) <= dt.timedelta(minutes=retain_minutes)
            )
            retain_auth_smoke = (
                prev_u.get("source") in AUTH_ONLY_USAGE_SOURCES
                and prev_at is not None
                and (now_utc() - prev_at) <= dt.timedelta(minutes=retain_minutes)
            )
            if retain_numeric_probe:
                st["usage"] = _update_week_exhaustion_state(
                    st.get("usage"),
                    _stabilize_usage_reset_anchors(st.get("usage"), {
                        "available": bool(prev_u.get("available", False)),
                        "fiveHourRemaining": prev_u.get("fiveHourRemaining"),
                        "weekRemaining": prev_u.get("weekRemaining"),
                        "observedAt": prev_u.get("observedAt", ts()),
                        "source": prev_u.get("source", "provider-api-per-profile"),
                        "probeAgentId": prev_u.get("probeAgentId"),
                        "frontloadedProfileId": prev_u.get("frontloadedProfileId"),
                        "trust": prev_u.get("trust", "verified"),
                        "observedHeadBeforeSample": prev_u.get("observedHeadBeforeSample"),
                        "observedHeadAfterSample": prev_u.get("observedHeadAfterSample"),
                        "reason": prev_u.get("reason"),
                        "weekResetAt": prev_u.get("weekResetAt"),
                        "fiveHourResetAt": prev_u.get("fiveHourResetAt"),
                    }),
                    prev_u.get("observedAt", ts()),
                )
            elif retain_auth_smoke:
                st["usage"] = {
                    "available": bool(prev_u.get("available", False)),
                    "fiveHourRemaining": None,
                    "weekRemaining": None,
                    "observedAt": prev_u.get("observedAt", ts()),
                    "source": prev_u.get("source", "auth-smoke"),
                }
            else:
                st["usage"] = {
                    "available": False,
                    "fiveHourRemaining": None,
                    "weekRemaining": None,
                    "observedAt": usage_global.get("observedAt", ts()),
                    "source": "provider-global-unmapped" if usage_global.get("observedAt") else "unknown",
                }
        _ = is_quarantined(st)

    state["lastTickAt"] = ts()
    append_history(state, {"at": ts(), "type": "tick", "observedProfiles": list(observed.keys()), "usage": usage_global, "usageByProfileCount": len(usage_by_profile)})

    healthy = healthy_profiles(config, state)
    if healthy:
        ov = state.get("override", {})
        if ov.get("enabled") and ov.get("profileId") in healthy:
            override_pid = ov.get("profileId")
            ordered = [override_pid] + [x for x in healthy if x != override_pid] + [x["profileId"] for x in config.get("accounts", []) if x["profileId"] not in healthy and x["profileId"] != override_pid]
            if can_reorder_auth_for_new_assignments(config, state, override_pid):
                result = apply_auth_order(config, state, ordered, source="tick", reason="override")
                append_history(state, {"at": ts(), "type": "auth_order_apply", "reason": "override", "result": result})
                alert_auth_order_drift(config, state, result, "override")
        else:
            provider = config.get("provider", "openai-codex")
            agent_id = runtime_auth_agent_id(config)
            timeout_sec = timeout_tier(config, "standard")
            current_order_hint_raw = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
            current_order_hint, tombstoned_runtime = sanitize_runtime_order(config, current_order_hint_raw)
            if tombstoned_runtime and current_order_hint and can_reorder_auth_for_new_assignments(config, state, current_order_hint[0]):
                apply_auth_order(config, state, current_order_hint, source="tick", reason="remove_tombstoned_runtime")
            preferred = preferred_healthy_order(config, state, current_order_hint)
            score_map: Dict[str, float] = {row["profileId"]: float(row.get("rawScore") or 0.0) for row in (preferred.get("details") or [])}
            ordered = list(preferred.get("ordered") or []) + [x["profileId"] for x in config.get("accounts", []) if x["profileId"] not in healthy]

            order_preview = build_effective_auth_order(config, state, ordered)
            effective_order = order_preview.get("effectiveOrder", [])
            if not effective_order:
                append_history(state, {
                    "at": ts(),
                    "type": "auth_order_skip",
                    "reason": "no_effective_order",
                    "top": None,
                    "currentTop": None,
                    "delta": None,
                })
            elif can_reorder_auth_for_new_assignments(config, state, effective_order[0]):
                current_order = list(current_order_hint)

                # Treat current order as acceptable for two benign cases:
                # 1) exact prefix truncation of effective order
                # 2) unknown-usage profiles trimmed away by underlying runtime
                current_prefix = effective_order[:len(current_order)] if current_order else []
                tail_truncation_only = bool(current_order) and (current_order == current_prefix)

                unknown_profiles = {
                    p for p in effective_order
                    if ((state.get("accounts", {}).get(p, {}) or {}).get("usage", {}) or {}).get("source") == "unknown"
                }
                effective_without_unknown = [p for p in effective_order if p not in unknown_profiles]
                unknown_trim_only = bool(current_order) and (current_order == effective_without_unknown)

                no_change = (current_order == effective_order) or tail_truncation_only or unknown_trim_only
                policy_drift = not no_change

                candidate_top = effective_order[0]
                current_top = current_order[0] if current_order else None

                # Drift risk model: treat drift as high-risk when failover chain
                # includes ineligible profiles (can cause needless caps/timeouts),
                # or when head deviates from policy top.
                policy_cfg = config.get("authOrderPolicy", {}) if isinstance(config.get("authOrderPolicy"), dict) else {}
                safe_depth = max(1, int(policy_cfg.get("failoverSafeDepth", 3)))
                effective_set = set(effective_order)
                failover_chain = current_order[:safe_depth] if current_order else []
                failover_unsafe_raw = [p for p in failover_chain if p not in effective_set]
                failover_unsafe = actionable_failover_unsafe_profiles(config, state, failover_unsafe_raw)

                high_risk_drift = bool(policy_drift)
                if policy_drift:
                    head_mismatch = (not current_top) or (current_top != candidate_top) or (current_top not in effective_set)
                    high_risk_drift = bool(head_mismatch or failover_unsafe)

                routing_cfg = config.get("routing", {}) if isinstance(config.get("routing"), dict) else {}
                min_delta = float(routing_cfg.get("hysteresisMinScoreDelta", 25.0))
                hold_min = int(routing_cfg.get("hysteresisMinHoldMinutes", 10))

                rstate = state.setdefault("routing", {})
                last_apply = parse_iso(rstate.get("lastAppliedAt"))
                within_hold = bool(last_apply and (now_utc() - last_apply) < dt.timedelta(minutes=hold_min))

                candidate_score = score_map.get(candidate_top)
                current_score = score_map.get(current_top) if current_top else None
                delta = (candidate_score - current_score) if (candidate_score is not None and current_score is not None) else None

                apply_order = True
                skip_reason = None

                if no_change:
                    apply_order = False
                    if unknown_trim_only:
                        skip_reason = "no_change_unknown_trim"
                    elif tail_truncation_only:
                        skip_reason = "no_change_tail_ok"
                    else:
                        skip_reason = "no_change"
                elif (not high_risk_drift):
                    apply_order = False
                    skip_reason = "tail_drift_runtime_managed"
                elif (not policy_drift) and current_top and candidate_top != current_top and delta is not None:
                    if within_hold and delta < (min_delta * 2.0):
                        apply_order = False
                        skip_reason = "hysteresis_hold"
                    elif delta < min_delta:
                        apply_order = False
                        skip_reason = "hysteresis_delta"

                decision_at = ts()
                rstate["selectedTarget"] = candidate_top
                rstate["currentTarget"] = current_top
                rstate["challenger"] = candidate_top if (candidate_top and current_top and candidate_top != current_top) else None
                rstate["scoreDelta"] = delta
                rstate["switchThreshold"] = min_delta
                rstate["lastDecisionAt"] = decision_at
                stale_last_applied = bool(
                    rstate.get("lastAppliedTop")
                    and parse_iso(rstate.get("lastAppliedAt"))
                    and parse_iso(rstate.get("lastDecisionAt"))
                    and parse_iso(rstate.get("lastAppliedAt")) < parse_iso(rstate.get("lastDecisionAt"))
                )
                if stale_last_applied:
                    rstate["actuatedTarget"] = current_top or candidate_top
                if apply_order:
                    if policy_drift and high_risk_drift:
                        record_policy_reconcile_event(config, state, "dynamic", current_order, effective_order)
                    result = apply_auth_order(config, state, ordered, source="tick", reason="dynamic")
                    append_history(state, {
                        "at": decision_at,
                        "type": "auth_order_apply",
                        "reason": "dynamic",
                        "top": candidate_top,
                        "delta": delta,
                        "plannedEffectiveOrder": effective_order,
                        "result": result,
                    })
                    alert_auth_order_drift(config, state, result, "dynamic")
                    rstate["holdReason"] = None
                    rstate["lastAppliedAt"] = decision_at
                    rstate["lastAppliedTop"] = candidate_top
                    rstate["lastAppliedOrder"] = effective_order
                    rstate["actuatedTarget"] = candidate_top
                    rstate["lastTopScore"] = candidate_score
                else:
                    rstate["holdReason"] = skip_reason
                    if skip_reason in {"no_change", "no_change_unknown_trim", "no_change_tail_ok", "tail_drift_runtime_managed"}:
                        stable_target = current_top or candidate_top
                        rstate["actuatedTarget"] = stable_target
                        if stable_target:
                            rstate["lastAppliedTop"] = stable_target
                            rstate["lastAppliedAt"] = decision_at
                            rstate["lastAppliedOrder"] = list(current_order or effective_order)
                    append_history(state, {
                        "at": decision_at,
                        "type": "auth_order_skip",
                        "reason": skip_reason,
                        "top": candidate_top,
                        "currentTop": current_top,
                        "delta": delta,
                        "failoverUnsafe": failover_unsafe,
                    })
    session_rebind_info = sync_session_auth_overrides(config, state, reason="tick")
    rec = capacity_recommendation(config, state)
    pool_metrics = pool_usage_metrics(config, state)
    pool_simple = pool_summary(pool_metrics, rec)
    if rec:
        append_history(state, {
            "at": ts(),
            "type": "capacity_recommendation",
            "level": rec.get("level"),
            "code": rec.get("code"),
            "message": rec.get("message"),
            "poolUsage": pool_metrics,
        })

    monitor_events = emit_monitor_alerts(config, state)

    _refresh_integrity_artifacts(config, state)
    save_json(STATE_PATH, state)
    print(json.dumps({
        "ok": True,
        "lastTickAt": state.get("lastTickAt"),
        "runtimeFailover": runtime_info,
        "authStoreSync": auth_sync_info,
        "observedProfiles": list(observed.keys()),
        "usageAvailable": usage_global.get("available", False),
        "usageByProfile": len(usage_by_profile),
        "usageProfile": usage_profile,
        "poolUsage": pool_metrics,
        "poolSummary": pool_simple,
        "lifecycleAdvisor": build_lifecycle_advisor(config, state),
        "capacityRecommendation": (rec.get("message") if rec else None),
        "capacityRecommendationLevel": (rec.get("level") if rec else None),
        "alertsTriggered": len(monitor_events),
        "profilesAdded": sync_info.get("added", []),
        "sessionRebind": session_rebind_info,
        "liveCanary": canary_info,
    }, indent=2))
    return 0

def cmd_lease_acquire(config: Dict[str, Any], state: Dict[str, Any], lane: str, task_id: str, project: Optional[str], force_profile: Optional[str]) -> int:
    if is_read_only(config, respect_main_lock=False):
        message = "LEASE ACQUIRE BLOCKED | emergency lock active"
        print(json.dumps({"ok": False, "blocked": "emergency_lock", "message": message}, indent=2))
        return 2
    ensure_account_state(config, state)
    task = task_record(state, lane, task_id)
    try:
        pid, meta = select_profile(config, state, lane, task_id, project, force_profile)
    except RuntimeError as exc:
        pause_message = "⏸️ System Paused: All accounts are exhausted or dead. Please add a new account via terminal to resume."
        state["poolPause"] = {"active": True, "reason": str(exc), "at": ts(), "message": pause_message}
        save_json(STATE_PATH, state)
        print(json.dumps({"ok": False, "paused": True, "message": pause_message, "error": str(exc)}, indent=2))
        return 3

    lk = f"{lane}:{task_id}"
    lease = {"lane": lane, "taskId": task_id, "project": project, "profileId": pid, "acquiredAt": ts(), "active": True}
    state.setdefault("leases", {})[lk] = lease
    state["accounts"][pid]["lastAssignedAt"] = ts()
    state["accounts"][pid]["activeLeaseCount"] = active_leases_for_profile(state, pid)
    task.setdefault("attempts", []).append({"at": ts(), "event": "lease_acquired", "profileId": pid, "meta": meta})
    # Clear retry preference once it is consumed.
    if task.get("nextRetryProfile") == pid:
        task["nextRetryProfile"] = None

    auth_applied = None
    if can_reorder_auth_for_new_assignments(config, state, pid):
        # Preserve dynamic order; only front-load the leased profile.
        provider = config.get("provider", "openai-codex")
        agent_id = runtime_auth_agent_id(config)
        timeout_sec = timeout_tier(config, "standard")
        current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
        ordered = [pid] + [p for p in current_order if p != pid]
        # Ensure all configured accounts are present.
        for a in config.get("accounts", []):
            p2 = a.get("profileId")
            if p2 and p2 not in ordered:
                ordered.append(p2)
        auth_applied = apply_auth_order(config, state, ordered, source="lease-acquire", reason="lease_frontload")
        if auth_applied:
            alert_auth_order_drift(config, state, auth_applied, "lease_acquire")

    append_history(state, {"at": ts(), "type": "lease_acquire", "lease": lease, "meta": meta, "authApply": auth_applied})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "leaseKey": lk, "profileId": pid, "selection": meta, "authOrderApplied": bool(auth_applied)}, indent=2))
    return 0


def cmd_lease_release(config: Dict[str, Any], state: Dict[str, Any], lane: str, task_id: str, result: str) -> int:
    if is_read_only(config, respect_main_lock=False):
        message = "LEASE RELEASE BLOCKED | emergency lock active"
        print(json.dumps({"ok": False, "blocked": "emergency_lock", "message": message}, indent=2))
        return 2
    ensure_account_state(config, state)
    lk = f"{lane}:{task_id}"
    lease = state.setdefault("leases", {}).get(lk)
    if not lease or not lease.get("active"):
        raise RuntimeError(f"No active lease for {lk}")

    pid = lease["profileId"]
    lease.update({"active": False, "releasedAt": ts(), "result": result})

    task = task_record(state, lane, task_id)
    task["lastResult"] = result
    task.setdefault("attempts", []).append({"at": ts(), "event": "lease_released", "profileId": pid, "result": result})

    if result == "success":
        state["accounts"][pid].setdefault("successEvents", []).append({"at": ts(), "lane": lane, "taskId": task_id})
    else:
        record_failure_and_maybe_quarantine(config, state, pid, f"task_failed:{lane}:{task_id}")
        retries = int(task.get("retryCount", 0)) + 1
        task["retryCount"] = retries
        append_history(state, {"at": ts(), "type": "task_failure", "lane": lane, "taskId": task_id, "profileId": pid, "retryCount": retries})

        max_retries = int(config.get("retryPolicy", {}).get("maxRetriesPerTask", 2))
        if retries > max_retries:
            task["escalationRequired"] = True
            task["nextRetryProfile"] = None
            send_alert(config, state, "CRITICAL", f"Task {lane}:{task_id} exceeded retry budget ({max_retries}).", code="TASK_RETRY_BUDGET_EXCEEDED", impact="Task cannot auto-recover safely.", auto_action="Router marked escalation_required=true.", your_action="Investigate task + profile before retrying.", status=f"profile={pid}")
        else:
            failed_for_task = {
                a.get("profileId")
                for a in task.get("attempts", [])
                if a.get("event") == "lease_released" and a.get("result") == "failed" and a.get("profileId")
            }
            alternates = [x for x in healthy_profiles(config, state) if x != pid and x not in failed_for_task]
            if not alternates:
                alternates = [x for x in healthy_profiles(config, state) if x != pid]

            if not alternates:
                task["escalationRequired"] = True
                task["nextRetryProfile"] = None
                send_alert(config, state, "CRITICAL", f"Task {lane}:{task_id} failed and no alternate healthy profile is available.", code="TASK_NO_ALTERNATE_PROFILE", impact="Task is blocked by pool capacity/health constraints.", auto_action="Router marked escalation_required=true.", your_action="Restore at least one alternate healthy profile.", status=f"profile={pid}")
            else:
                task["nextRetryProfile"] = alternates[0]
                task.setdefault("attempts", []).append({"at": ts(), "event": "retry_scheduled", "from": pid, "to": alternates[0], "retryCount": retries, "failedExcluded": sorted(list(failed_for_task))})

    for pid2 in state.get("accounts", {}):
        state["accounts"][pid2]["activeLeaseCount"] = active_leases_for_profile(state, pid2)

    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "leaseKey": lk, "releasedResult": result, "task": task}, indent=2))
    return 0


def cmd_override_set(config: Dict[str, Any], state: Dict[str, Any], profile: str) -> int:
    if is_read_only(config):
        return 0
    known = {a["profileId"] for a in config.get("accounts", [])}
    if profile not in known:
        raise RuntimeError(f"Unknown profile: {profile}")
    now = ts()
    state["override"] = {"enabled": True, "profileId": profile, "setAt": now}
    reconcile_routing_state_target(state, profile, reason="manual_override_set")
    apply_res = apply_auth_order(config, state, [profile], timeout_sec=timeout_tier(config, "standard"), source="override", reason="manual_override")
    session_rebind_info = sync_session_auth_overrides(config, state, target_order=[profile], reason="override")
    append_history(state, {
        "at": now,
        "type": "override_set",
        "profileId": profile,
        "authOrderApply": apply_res,
        "sessionRebind": session_rebind_info,
        "snapshot": control_plane_snapshot(config, state, [profile]),
    })
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "override": state["override"], "authOrderApply": apply_res, "sessionRebind": session_rebind_info}, indent=2))
    return 0


def cmd_override_clear(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    if is_read_only(config):
        return 0
    now = ts()
    state["override"] = {"enabled": False, "profileId": None, "setAt": now}
    provider = config.get("provider", "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "quick")) or []
    preferred = preferred_healthy_order(config, state, current_order)
    preview_base = list(preferred.get("ordered") or [])
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if pid and pid not in preview_base:
            preview_base.append(pid)
    preview = build_effective_auth_order(config, state, preview_base)
    effective_order = list(preview.get("effectiveOrder") or preview_base or current_order)
    if effective_order:
        reconcile_routing_state_target(state, effective_order[0], reason="manual_override_clear")
    apply_res = apply_auth_order(config, state, effective_order, timeout_sec=timeout_tier(config, "standard"), source="override", reason="manual_override_clear") if effective_order else {"attempted": False, "reason": "no_effective_order"}
    session_rebind_info = sync_session_auth_overrides(config, state, target_order=effective_order, reason="override_clear") if effective_order else {"ok": True, "updated": False, "targetProfileId": None}
    append_history(state, {
        "at": now,
        "type": "override_clear",
        "authOrderApply": apply_res,
        "sessionRebind": session_rebind_info,
        "snapshot": control_plane_snapshot(config, state, effective_order),
    })
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "override": state["override"], "authOrderApply": apply_res, "sessionRebind": session_rebind_info}, indent=2))
    return 0


def cmd_focus_set(config: Dict[str, Any], state: Dict[str, Any], project: str) -> int:
    if is_read_only(config):
        return 0
    state["focus"] = {"enabled": True, "project": project, "setAt": ts()}
    append_history(state, {"at": ts(), "type": "focus_set", "project": project})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "focus": state["focus"]}, indent=2))
    return 0


def cmd_focus_clear(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    if is_read_only(config):
        return 0
    state["focus"] = {"enabled": False, "project": None, "setAt": ts()}
    append_history(state, {"at": ts(), "type": "focus_clear"})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "focus": state["focus"]}, indent=2))
    return 0


def cmd_hygiene(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool = False) -> int:
    if is_read_only(config):
        return 0
    ensure_account_state(config, state)
    provider = config.get("provider", "openai-codex")
    agent_id = runtime_auth_agent_id(config)
    before_raw = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard")) or []
    auth_sync = sync_runtime_quarantine_to_auth_store(config, state)
    sanitized_before, removed_runtime = sanitize_runtime_order(config, list(before_raw))
    normalized = False
    if removed_runtime:
        normalized = set_auth_order(provider, agent_id, sanitized_before, timeout_sec=timeout_tier(config, "standard"))
    after_raw = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard")) or []
    status = json.loads(subprocess.run(["python3", str(Path(__file__).resolve()), "status", "--json"], capture_output=True, text=True, timeout=timeout_tier(config, "quick")).stdout or '{}')
    out = {"ok": True, "beforeRawRuntimeAuthOrder": before_raw, "removedTombstonedRuntime": removed_runtime, "normalizedRuntimeOrder": normalized, "afterRawRuntimeAuthOrder": after_raw, "authStoreSync": auth_sync, "contradictions": status.get("contradictions"), "rawRuntimeAuthOrder": status.get("rawRuntimeAuthOrder"), "sanitizedRuntimeAuthOrder": status.get("sanitizedRuntimeAuthOrder"), "effectiveAuthOrder": status.get("effectiveAuthOrder")}
    save_json(STATE_PATH, state)
    print(json.dumps(out, indent=2) if json_mode else json.dumps(out, indent=2))
    return 0


def cmd_alert_test(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    r = send_alert(config, state, "CRITICAL", "Alert test from oauth_pool_router.py", code="ALERT_TEST", impact="Synthetic test alert only.", auto_action="No runtime action taken.", your_action="No action.")
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "alert": r}, indent=2))
    return 0

def cmd_account_name_set(config: Dict[str, Any], state: Dict[str, Any], profile: str, name: str) -> int:
    if is_read_only(config):
        return 0
    target = None
    for a in config.get("accounts", []):
        if a.get("profileId") == profile:
            target = a
            break
    if target is None:
        raise RuntimeError(f"Unknown profile: {profile}")
    target["name"] = name.strip()
    save_json(CONFIG_PATH, config)
    append_history(state, {"at": ts(), "type": "account_name_set", "profileId": profile, "name": target["name"]})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "profileId": profile, "name": target["name"]}, indent=2))
    return 0


def verify_profile_now(config: Dict[str, Any], state: Dict[str, Any], pid: str, *, source: str = "manual_verify", read_only: bool = False) -> Dict[str, Any]:
    started = time.monotonic()
    sync_result = None
    if not read_only:
        sync_result = sync_auth_profile_from_main(pid)
        append_history(state, {"at": ts(), "type": "auth_store_sync", "profileId": pid, "result": sync_result})
    probe = run_standalone_profile_verifier(config, pid, "quick")
    reason = str(probe.get("evidence") or probe.get("status") or "verification_unknown")
    dead_reason = dead_reason_from_verifier_probe(probe)
    ok = bool(probe.get("ok")) and probe.get("status") == VERIFIER_STATUS_AUTH_OK and bool(probe.get("authOrderRestored")) and not dead_reason
    vr = None
    if read_only:
        vr = {"status": "SKIPPED_READONLY", "reason": "emergency_lock", "source": source}
    else:
        vr = set_verification_status(state, pid, "VERIFIED" if ok else "FAILED", reason or "unknown", source)
        acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
        prev_usage = acct.get("usage") if isinstance(acct.get("usage"), dict) else {}
        preserve_numeric_usage = prev_usage.get("source") in TRUSTED_NUMERIC_USAGE_SOURCES and isinstance(prev_usage.get("observedAt"), str)
        if dead_reason:
            # Do not re-contaminate already-terminal/dead verify paths with auth-smoke usage.
            # Let apply_terminal_dead_state() own the terminal usage shape directly.
            pass
        elif preserve_numeric_usage:
            merged_usage = dict(prev_usage)
            merged_usage["available"] = bool(prev_usage.get("available", False)) or bool(ok)
            acct["usage"] = _update_week_exhaustion_state(acct.get("usage"), _stabilize_usage_reset_anchors(acct.get("usage"), merged_usage), (merged_usage or {}).get("observedAt") or (merged_usage or {}).get("sampledAt"))
        else:
            acct["usage"] = {
                "available": bool(ok),
                "fiveHourRemaining": None,
                "weekRemaining": None,
                "observedAt": ts(),
                "source": "auth-smoke",
            }
        if ok:
            quarantine = acct.get("quarantine") if isinstance(acct.get("quarantine"), dict) else {}
            if quarantine.get("active"):
                acct["quarantine"] = {"active": False, "until": None, "reason": None}
            live_failover = acct.get("liveFailover") if isinstance(acct.get("liveFailover"), dict) else {}
            if live_failover.get("active"):
                acct["liveFailover"] = {
                    "active": False,
                    "kind": live_failover.get("kind"),
                    "minutes": live_failover.get("minutes"),
                    "until": live_failover.get("until"),
                    "raw": live_failover.get("raw"),
                    "source": "verify_success_reset",
                    "at": ts(),
                }
        else:
            if dead_reason:
                apply_terminal_dead_state(config, state, pid, dead_reason, source, reason or None)
                spec = dead_alert_spec(dead_reason)
                key = f"dead:{pid}:{dead_reason}"
                if should_emit_signal(state, key, dead_alert_cooldown_minutes(dead_reason)) and should_emit_terminal_alert(state, pid, spec["code"], dead_reason, acct):
                    send_alert(
                        config,
                        state,
                        "CRITICAL",
                        f"OAuth account {account_name(config, pid)} ({pid}) marked {spec['label']} ({dead_reason}) after verify failure.",
                        code=spec["code"],
                        impact=spec["impact"],
                        auto_action=spec["auto_action"],
                        your_action=spec["your_action"],
                        status=f"profile={pid}",
                    )
                    mark_signal(state, key)
    event = {
        "at": ts(),
        "profileId": pid,
        "success": ok,
        "latencyMs": int((time.monotonic()-started)*1000),
        "reason": reason,
        "status": probe.get("status"),
        "fiveHourRemaining": None,
        "weekRemaining": None,
        "observedOrder": None,
        "authOrderRestored": bool(probe.get("authOrderRestored")),
        "verification": vr,
        "authStoreSync": sync_result,
        "readOnly": bool(read_only),
    }
    if not read_only:
        append_history(state, {"at": event['at'], "type": 'verification_probe', **event})
    return event


def reconcile_profile_truth(config: Dict[str, Any], state: Dict[str, Any], pid: str, *, source: str = "manual_reconcile") -> Dict[str, Any]:
    verify_result = verify_profile_now(config, state, pid, source=source, read_only=False)
    sync_result = verify_result.get("authStoreSync")
    usage_snap = fetch_openai_codex_usage_for_profile(pid, timeout_sec=timeout_tier(config, "standard"), agent_id="main")
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    auth = acct.get("auth", {}) if isinstance(acct.get("auth"), dict) else {}
    gate_pre = routing_gate_summary(config, acct)
    terminal_dead = (
        str(auth.get("status") or "").upper() == "DEAD"
        or gate_pre.get("effectiveState") == "REAUTH_REQUIRED"
    )
    if (not terminal_dead) and isinstance(usage_snap, dict) and usage_snap.get("available") and usage_snap.get("trust") in (None, "verified", "conditional"):
        acct["usage"] = _update_week_exhaustion_state(
            acct.get("usage"),
            _stabilize_usage_reset_anchors(acct.get("usage"), {
                "available": True,
                "fiveHourRemaining": usage_snap.get("fiveHourRemaining"),
                "weekRemaining": usage_snap.get("weekRemaining"),
                "observedAt": usage_snap.get("observedAt", ts()),
                "source": usage_snap.get("source") or "provider-api-per-profile",
                "probeAgentId": "main",
                "frontloadedProfileId": pid,
                "trust": usage_snap.get("trust", "verified"),
                "observedHeadBeforeSample": usage_snap.get("observedHeadBeforeSample"),
                "observedHeadAfterSample": usage_snap.get("observedHeadAfterSample"),
                "reason": usage_snap.get("reason"),
                "accountId": usage_snap.get("accountId"),
                "providerReturnedAccountId": usage_snap.get("providerReturnedAccountId"),
            }),
            usage_snap.get("observedAt", ts()),
        )
    normalization = normalize_terminal_account_state(config, state, pid, source=source)
    gate = routing_gate_summary(config, acct)
    result = {
        "ok": True,
        "profileId": pid,
        "sync": sync_result,
        "verify": verify_result,
        "normalization": normalization,
        "usage": acct.get("usage"),
        "gate": {
            "eligible": gate.get("eligible"),
            "effectiveState": gate.get("effectiveState"),
            "effectiveReason": gate.get("effectiveReason"),
        },
        "expiry": _expiry_truth_for_account(acct),
        "freshRecoveryTruth": fresh_recovery_truth(config, acct),
    }
    append_history(state, {"at": ts(), "type": "profile_reconcile", **result})
    return result


def cmd_reconcile(config: Dict[str, Any], state: Dict[str, Any], profile: str, json_mode: bool = False) -> int:
    result = reconcile_profile_truth(config, state, profile, source="manual_reconcile")
    save_json(STATE_PATH, state)
    print(json.dumps(result, indent=2))
    return 0 if result.get("gate", {}).get("eligible") else 2


def audit_contradictions(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    ensure_account_state(config, state)
    rows = []
    for account in config.get("accounts", []) or []:
        if not isinstance(account, dict):
            continue
        pid = str(account.get("profileId") or "").strip()
        if not pid:
            continue
        acc = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
        flags = contradiction_flags(config, acc)
        gate = routing_gate_summary(config, acc)
        if flags:
            rows.append({
                "profileId": pid,
                "flags": flags,
                "gate": {
                    "eligible": gate.get("eligible"),
                    "state": gate.get("effectiveState"),
                    "reason": gate.get("effectiveReason"),
                },
                "auth": acc.get("auth"),
                "verification": acc.get("verification"),
                "usage": acc.get("usage"),
                "quarantine": acc.get("quarantine"),
                "liveFailover": acc.get("liveFailover"),
                "health": acc.get("health"),
            })
    return {"ok": True, "count": len(rows), "contradictions": rows}


def cmd_audit(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool = False) -> int:
    result = audit_contradictions(config, state)
    print(json.dumps(result, indent=2))
    return 0 if not result.get("count") else 3


def cmd_verify(config: Dict[str, Any], state: Dict[str, Any], profile: str, json_mode: bool = False) -> int:
    read_only = is_read_only(config)
    if not read_only:
        ensure_account_state(config, state)
    pid = profile
    if pid not in {a.get('profileId') for a in config.get('accounts', [])}:
        raise RuntimeError(f'Unknown profile: {pid}')
    result = verify_profile_now(config, state, pid, source='manual_verify', read_only=read_only)
    if not read_only:
        save_json(STATE_PATH, state)
    print(json.dumps(result, indent=2) if json_mode else json.dumps(result, indent=2))
    return 0 if result.get('success') else 2


def cmd_probe_usage(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool = False) -> int:
    if is_read_only(config):
        provider = config.get("provider", "openai-codex")
        agent_id = usage_status_probe_agent_id(config)
        timeout_sec = timeout_tier(config, "standard")
        current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
        target_pid = current_order[0] if current_order else None
        snap = observe_usage_snapshot(config)
        observed_at = snap.get("observedAt") or ts()

        rows = []
        for a in config.get("accounts", []):
            pid = a.get("profileId")
            entry = {
                "name": account_name(config, pid),
                "profileId": pid,
                "fiveHourRemaining": None,
                "weekRemaining": None,
                "source": None,
                "observedAt": None,
            }
            if pid and pid == target_pid:
                entry["fiveHourRemaining"] = snap.get("fiveHourRemaining")
                entry["weekRemaining"] = snap.get("weekRemaining")
                entry["source"] = "probe-readonly"
                entry["observedAt"] = observed_at
            rows.append(entry)

        out = {
            "ok": True,
            "mode": "manual-probe",
            "readOnly": True,
            "note": "emergency_lock",
            "agent": agent_id,
            "provider": provider,
            "observedProfileId": target_pid,
            "rows": rows,
            "probedProfiles": [target_pid] if target_pid else [],
            "probedCount": 1 if target_pid else 0,
            "snapshot": snap,
        }

        if json_mode:
            print(json.dumps(out, indent=2))
        else:
            print(f"OAuth Probe (READ-ONLY) @ {observed_at}")
            print(f"Provider: {provider} · Agent: {agent_id}")
            print(f"Observed profile: {target_pid or 'unknown'}")
            print("Accounts:")
            for r in rows:
                print(f"- {r['name']} ({r['profileId']}): 5h={r['fiveHourRemaining']} week={r['weekRemaining']} source={r['source']}")
            print(f"Probed profiles: {out.get('probedCount')}")
        return 0

    ensure_account_state(config, state)

    provider = config.get("provider", "openai-codex")
    agent_id = usage_status_probe_agent_id(config)
    timeout_sec = timeout_tier(config, "standard")
    original_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec)
    override_before = dict(state.get("override", {}))

    # Force explicit per-profile probe regardless of background mode.
    probe = observe_usage_by_profile(config, state, agent_id=agent_id, force_all=True)
    observed_at = ts()

    # Update state with probe results for instant operator visibility.
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        st = state.get("accounts", {}).get(pid, {})
        snap = probe.get(pid)
        if snap:
            st["usage"] = _update_week_exhaustion_state(
                st.get("usage"),
                _stabilize_usage_reset_anchors(st.get("usage"), {
                    "available": bool(snap.get("available", False)),
                    "fiveHourRemaining": snap.get("fiveHourRemaining"),
                    "weekRemaining": snap.get("weekRemaining"),
                    "observedAt": snap.get("observedAt", observed_at),
                    "source": "manual-status-main-probe" if agent_id == "main" and snap.get("trust") != "rejected" else (snap.get("source") or "probe"),
                    "trust": snap.get("trust", "verified" if snap.get("available") else "rejected"),
                    "probeAgentId": snap.get("probeAgentId"),
                    "frontloadedProfileId": snap.get("frontloadedProfileId"),
                    "observedHeadBeforeSample": snap.get("observedHeadBeforeSample"),
                    "observedHeadAfterSample": snap.get("observedHeadAfterSample"),
                    "reason": snap.get("reason"),
                }),
                snap.get("observedAt", observed_at),
            )
            state["accounts"][pid] = st

    # Restore sanitized auth order and preserve override metadata.
    if original_order:
        sanitized_original, _removed = sanitize_runtime_order(config, list(original_order))
        restore_order = sanitized_original if sanitized_original else [a.get("profileId") for a in config.get("accounts", []) if a.get("enabled", True) and a.get("profileId")]
        set_auth_order(provider, agent_id, restore_order, timeout_sec=timeout_sec)
    state["override"] = override_before

    append_history(state, {
        "at": observed_at,
        "type": "probe_usage",
        "agent": agent_id,
        "profiles": list(probe.keys()),
    })
    save_json(STATE_PATH, state)

    rows = []
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        u = (state.get("accounts", {}).get(pid, {}) or {}).get("usage", {})
        rows.append({
            "name": account_name(config, pid),
            "profileId": pid,
            "fiveHourRemaining": u.get("fiveHourRemaining"),
            "weekRemaining": u.get("weekRemaining"),
            "source": u.get("source"),
            "observedAt": u.get("observedAt"),
        })

    out = {
        "ok": True,
        "mode": "manual-probe",
        "agent": agent_id,
        "provider": provider,
        "override": state.get("override", {}),
        "rows": rows,
        "probedProfiles": list(probe.keys()),
        "probedCount": len(probe),
    }

    if json_mode:
        print(json.dumps(out, indent=2))
    else:
        print(f"OAuth Probe @ {observed_at}")
        print(f"Provider: {provider} · Agent: {agent_id}")
        print(f"Override preserved: {state.get('override')}")
        print("Accounts:")
        for r in rows:
            print(f"- {r['name']} ({r['profileId']}): 5h={r['fiveHourRemaining']} week={r['weekRemaining']} source={r['source']}")
        print(f"Probed profiles: {len(probe)}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="OAuth account pool router")
    sub = p.add_subparsers(dest="command", required=True)

    st = sub.add_parser("status")
    st.add_argument("--json", action="store_true")

    sub.add_parser("tick")

    acq = sub.add_parser("lease-acquire")
    acq.add_argument("--lane", required=True)
    acq.add_argument("--task-id", required=True)
    acq.add_argument("--project", choices=["mb", "autopit4", "temp"], default=None)
    acq.add_argument("--force-profile", default=None)

    rel = sub.add_parser("lease-release")
    rel.add_argument("--lane", required=True)
    rel.add_argument("--task-id", required=True)
    rel.add_argument("--result", required=True, choices=["success", "failed"])

    ov = sub.add_parser("override")
    ovsub = ov.add_subparsers(dest="ov_cmd", required=True)
    ovs = ovsub.add_parser("set")
    ovs.add_argument("--profile", required=True)
    ovsub.add_parser("clear")

    cp = sub.add_parser("control-pin")
    cp.add_argument("--profile", required=True)
    cp.add_argument("--session-key", required=True)
    cp.add_argument("--json", action="store_true")

    cr = sub.add_parser("control-release")
    cr.add_argument("--session-key", required=True)
    cr.add_argument("--json", action="store_true")

    fo = sub.add_parser("focus")
    fosub = fo.add_subparsers(dest="fo_cmd", required=True)
    fos = fosub.add_parser("set")
    fos.add_argument("--project", required=True, choices=["mb", "autopit4", "temp"])
    fosub.add_parser("clear")

    sub.add_parser("alert-test")
    sub.add_parser("sync-profiles")

    hg = sub.add_parser("hygiene")
    hg.add_argument("--json", action="store_true")

    pr = sub.add_parser("probe")
    pr.add_argument("--json", action="store_true")

    vr = sub.add_parser("verify")
    vr.add_argument("--profile", required=True)
    vr.add_argument("--json", action="store_true")

    rc = sub.add_parser("reconcile")
    rc.add_argument("--profile", required=True)
    rc.add_argument("--json", action="store_true")

    ad = sub.add_parser("audit")
    ad.add_argument("--json", action="store_true")

    wd = sub.add_parser("watchdog")
    wd.add_argument("--json", action="store_true")
    wd.add_argument("--run-live", action="store_true")

    hc = sub.add_parser("health-check")
    hc.add_argument("--json", action="store_true")

    an = sub.add_parser("account-name")
    ansub = an.add_subparsers(dest="an_cmd", required=True)
    anset = ansub.add_parser("set")
    anset.add_argument("--profile", required=True)
    anset.add_argument("--name", required=True)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    nonblocking_lock_commands = {"tick", "watchdog", "probe", "sync-profiles"}
    mutating_commands = {
        "tick",
        "lease-acquire",
        "lease-release",
        "override",
        "control-pin",
        "control-release",
        "focus",
        "alert-test",
        "sync-profiles",
        "probe",
        "verify",
        "reconcile",
        "audit",
        "watchdog",
        "account-name",
    }

    tracked_loop_commands = {"tick", "watchdog", "health-check", "audit", "verify"}
    if args.command in tracked_loop_commands:
        update_control_loop_progress(args.command, "start")

    lock_fh: Optional[TextIO] = None
    if args.command in mutating_commands:
        if args.command == "watchdog":
            wait_seconds = 3.0 if getattr(args, "run_live", False) else 0.0
        elif args.command in nonblocking_lock_commands:
            wait_seconds = 0.0
        else:
            wait_seconds = 15.0
        lock_fh = acquire_router_lock(wait_seconds=wait_seconds)
        if lock_fh is None:
            if args.command in tracked_loop_commands:
                update_control_loop_progress(args.command, "lock_busy", error="router lock busy", waitSeconds=wait_seconds)
            if args.command in nonblocking_lock_commands:
                payload = {
                    "ok": True,
                    "skipped": "lock_busy",
                    "command": args.command,
                    "at": ts(),
                }
                if args.command == "watchdog":
                    try:
                        cached_state = load_json(STATE_PATH, default_state())
                        hb = ((cached_state.get("monitor", {}) or {}).get("watchdogHeartbeat") or {})
                        payload["watchdogHeartbeat"] = hb
                        at = parse_iso(hb.get("at")) if isinstance(hb, dict) else None
                        age = (now_utc() - at).total_seconds() if at else None
                        payload["watchdogHeartbeatFresh"] = bool(hb.get("ok")) and age is not None and age <= 300
                        payload["watchdogHeartbeatAgeSec"] = round(age, 2) if age is not None else None
                    except Exception:
                        pass
                print(json.dumps(payload, indent=2))
                return 0
            print(json.dumps({
                "ok": False,
                "error": "router lock busy",
                "command": args.command,
            }, indent=2), file=sys.stderr)
            return 1

    exit_code = 0
    progress_fields: Dict[str, Any] = {}
    try:
        config = load_validated_json(CONFIG_PATH, default_config(), validator=validate_config, snapshot_path=CONFIG_LKG_PATH, kind="config")
        state = load_validated_json(STATE_PATH, default_state(), validator=validate_state, snapshot_path=STATE_LKG_PATH, kind="state", config_for_sanitize=config)
        ensure_account_state(config, state)
        state["version"] = max(int(state.get("version", 0) or 0), SCHEMA_VERSION)
        if args.command in {"status", "tick", "watchdog", "health-check"}:
            if not is_read_only(config):
                ingest_runtime_failover_signals(config, state)
                auto_hygiene_reconcile(config, state, reason=f"pre-dispatch:{args.command}")
                _refresh_integrity_artifacts(config, state)
                save_json(STATE_PATH, state)

        if args.command == "status":
            exit_code = cmd_status(config, state, args.json)
        elif args.command == "tick":
            exit_code = cmd_tick(config, state)
            progress_fields["lastTickAt"] = state.get("lastTickAt")
        elif args.command == "lease-acquire":
            exit_code = cmd_lease_acquire(config, state, args.lane, args.task_id, args.project, args.force_profile)
        elif args.command == "lease-release":
            exit_code = cmd_lease_release(config, state, args.lane, args.task_id, args.result)
        elif args.command == "override":
            exit_code = cmd_override_set(config, state, args.profile) if args.ov_cmd == "set" else cmd_override_clear(config, state)
        elif args.command == "control-pin":
            exit_code = cmd_control_surface_pin(config, state, args.profile, args.session_key, args.json)
        elif args.command == "control-release":
            exit_code = cmd_control_surface_release(config, state, args.session_key, args.json)
        elif args.command == "focus":
            exit_code = cmd_focus_set(config, state, args.project) if args.fo_cmd == "set" else cmd_focus_clear(config, state)
        elif args.command == "alert-test":
            exit_code = cmd_alert_test(config, state)
        elif args.command == "sync-profiles":
            exit_code = cmd_sync_profiles(config, state)
        elif args.command == "hygiene":
            exit_code = cmd_hygiene(config, state, args.json)
        elif args.command == "probe":
            exit_code = cmd_probe_usage(config, state, args.json)
        elif args.command == "verify":
            exit_code = cmd_verify(config, state, args.profile, args.json)
        elif args.command == "reconcile":
            exit_code = cmd_reconcile(config, state, args.profile, args.json)
        elif args.command == "audit":
            exit_code = cmd_audit(config, state, args.json)
        elif args.command == "watchdog":
            exit_code = cmd_watchdog(config, state, args.json) if getattr(args, "run_live", False) else cmd_watchdog_cached(config, state, args.json)
            progress_fields["watchdogHeartbeat"] = ((state.get("monitor", {}) or {}).get("watchdogHeartbeat") or {}) if isinstance(state, dict) else {}
        elif args.command == "health-check":
            exit_code = cmd_health_check(config, state, args.json)
            progress_fields["lastTruthAt"] = (((state.get("monitor", {}) or {}).get("healthTruth") or {}).get("lastRefreshAt")) if isinstance(state, dict) else None
        elif args.command == "account-name":
            if args.an_cmd == "set":
                exit_code = cmd_account_name_set(config, state, args.profile, args.name)
            else:
                raise RuntimeError(f"Unknown command: {args.command}")
        else:
            raise RuntimeError(f"Unknown command: {args.command}")
        if args.command in tracked_loop_commands:
            update_control_loop_progress(args.command, "success" if exit_code == 0 else "error", exitCode=exit_code, **progress_fields)
        return exit_code
    except Exception as exc:
        if args.command in tracked_loop_commands:
            update_control_loop_progress(args.command, "error", error=str(exc), exitCode=1, **progress_fields)
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    finally:
        release_router_lock(lock_fh)


if __name__ == "__main__":
    raise SystemExit(main())
