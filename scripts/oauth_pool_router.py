#!/usr/bin/env python3
"""
OAuth Pool Router for OpenAI Codex profiles.
Stdlib-only controller managing shared account pool with lease pinning,
retry/quarantine policy, and alerting.
"""
from __future__ import annotations

import argparse
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
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Tuple

BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-config.json"
STATE_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-state.json"
LOCK_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-router.lock"
HEALTH_LOCK_PATH = BASE_DIR / "ops" / "state" / "oauth-pool-health.lock"
BACKUP_DIR = BASE_DIR / "ops" / "state" / "backups"
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


def load_validated_json(path: Path, default_obj: Dict[str, Any], *, validator, snapshot_path: Path, kind: str) -> Dict[str, Any]:
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
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, indent=2, sort_keys=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


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


def append_history(state: Dict[str, Any], event: Dict[str, Any], cap: int = 500) -> None:
    h = state.setdefault("history", [])
    h.append(event)
    if len(h) > cap:
        del h[: len(h) - cap]


def default_config() -> Dict[str, Any]:
    return {
        "provider": "openai-codex",
        "accounts": [
            {"profileId": "openai-codex:default", "name": "OAuth-Primary", "enabled": True, "priority": 1, "projects": ["project-a", "project-b", "project-c"]},
        ],
        "managedAgents": [
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
            "defaultProjects": ["project-a", "project-b", "project-c"],
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
            "failOpenOnNoEligible": True,
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
            "respectUserOverride": True
        },
        "runtimeFailover": {
            "enabled": True,
            "scanLookbackMinutes": 90,
            "keepSeen": 500,
            "timeoutQuarantineMinutes": 5
        },
        "throttlePolicy": {
            "rateLimitBaseCooldownMinutes": 20,
            "maxCooldownMinutes": 720,
            "recentWindowMinutes": 15,
            "strongPenalty": 1000.0,
            "rateLimitPenalty": 320.0,
            "timeoutPenalty": 40.0,
            "activeLeasePenalty": 8.0
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
        "alerts": {"lastCriticalAt": None, "count": 0},
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
                "liveFailover": {"active": False, "kind": None, "minutes": None, "until": None, "raw": None, "source": None, "at": None},
                "throttleHealth": {"state": "clear", "cooldownUntil": None, "last429At": None, "lastTimeoutAt": None, "rateLimitCount": 0, "timeoutCount": 0},
                "failureEvents": [],
                "successEvents": [],
                "activeLeaseCount": 0,
                "lastAssignedAt": None,
                "canary": {"lastRunAt": None, "lastSuccessAt": None, "success": None, "latencyMs": None, "reason": None, "observedOrder": None},
            }
        else:
            ast[pid]["enabled"] = bool(a.get("enabled", True))
            ast[pid].setdefault("liveFailover", {"active": False, "kind": None, "minutes": None, "until": None, "raw": None, "source": None, "at": None})
            ast[pid].setdefault("throttleHealth", {"state": "clear", "cooldownUntil": None, "last429At": None, "lastTimeoutAt": None, "rateLimitCount": 0, "timeoutCount": 0})

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
        acc_for_penalty = dict((state.get("accounts", {}).get(pid, {}) or {}))
        acc_for_penalty["profileId"] = pid
        penalty = throttle_penalty(config, acc_for_penalty) + (active * float(throttle_policy(config).get("activeLeasePenalty", 8.0)))
        prio = account_priority(config, pid)
        order_hint = (100.0 - float(current_pos[pid])) if pid in current_pos else 0.0
        known_bias = 1 if not unknown_usage else 0
        non_tail_bias = 0 if low_five_tail_flag else 1

        ranking.append((known_bias, non_tail_bias, cap_sig - penalty, order_hint, cap - active, prio, pid))
        details.append({
            "profileId": pid,
            "knownBias": known_bias,
            "nonTailBias": non_tail_bias,
            "rawScore": cap_sig,
            "throttlePenalty": round(penalty, 2),
            "effectiveScore": round(cap_sig - penalty, 2),
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
        u = st.get("usage", {})
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



def normalize_runtime_failover_reason(reason: Optional[str], raw: Optional[str]) -> str:
    text = " ".join([str(reason or ""), str(raw or "")]).strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", text)
    if re.search(r"\b(429|rate[_ -]?limit|ratelimit|too many requests|too_many_requests|overloaded|temporarily unavailable|try again later|quota exceeded|usage limit)\b", text) or "toomanyrequests" in compact:
        return "rate_limit"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    return str(reason or "").strip()


def throttle_policy(config: Dict[str, Any]) -> Dict[str, Any]:
    return config.get("throttlePolicy", {}) if isinstance(config.get("throttlePolicy"), dict) else {}


def _future_max(existing: Optional[dt.datetime], candidate: dt.datetime) -> dt.datetime:
    return existing if existing and existing > candidate else candidate


def _cooldown_minutes_remaining(until: dt.datetime) -> int:
    return max(1, int(round((until - now_utc()).total_seconds() / 60.0)))


def apply_live_fail_penalty(config: Dict[str, Any], acc: Dict[str, Any], *, kind: str, minutes: int, raw: Optional[str], source: str = "runtime_failover") -> Dict[str, Any]:
    policy = throttle_policy(config)
    max_minutes = int(policy.get("maxCooldownMinutes", 720))
    minutes = min(max(1, int(minutes)), max_minutes)
    requested_until = now_utc() + dt.timedelta(minutes=minutes)

    prior_live = acc.get("liveFailover") if isinstance(acc.get("liveFailover"), dict) else {}
    prior_until = parse_iso(prior_live.get("until")) if isinstance(prior_live.get("until"), str) else None
    until = _future_max(prior_until if prior_live.get("active") and prior_live.get("kind") == kind else None, requested_until)
    effective_minutes = _cooldown_minutes_remaining(until)

    acc["liveFailover"] = {
        "active": True,
        "kind": kind,
        "minutes": effective_minutes,
        "until": until.isoformat(),
        "raw": raw,
        "source": source,
        "at": ts(),
    }

    throttle = acc.setdefault("throttleHealth", {})
    throttle["state"] = "throttled_now" if kind == "rate_limit" else "timeout_cooling"
    throttle["cooldownUntil"] = until.isoformat()
    if kind == "rate_limit":
        throttle["last429At"] = ts()
        throttle["rateLimitCount"] = int(throttle.get("rateLimitCount") or 0) + 1
    elif kind == "timeout":
        throttle["lastTimeoutAt"] = ts()
        throttle["timeoutCount"] = int(throttle.get("timeoutCount") or 0) + 1
    return {"until": until.isoformat(), "minutes": effective_minutes}


def clear_expired_live_failover(acc: Dict[str, Any]) -> None:
    lf = acc.get("liveFailover") if isinstance(acc.get("liveFailover"), dict) else {}
    if not lf.get("active"):
        return
    until = parse_iso(lf.get("until"))
    if until and now_utc() >= until:
        acc["liveFailover"] = {"active": False, "kind": None, "minutes": None, "until": None, "raw": None, "source": None, "at": None}
        th = acc.setdefault("throttleHealth", {})
        th["state"] = "clear"
        th["cooldownUntil"] = None


def is_live_failover_active(acc: Dict[str, Any]) -> bool:
    clear_expired_live_failover(acc)
    lf = acc.get("liveFailover") if isinstance(acc.get("liveFailover"), dict) else {}
    return bool(lf.get("active"))


def recent_event_count(events: List[Dict[str, Any]], reason_fragment: str, minutes: int) -> int:
    cutoff = now_utc() - dt.timedelta(minutes=max(1, minutes))
    count = 0
    for ev in events or []:
        at = parse_iso(ev.get("at")) if isinstance(ev, dict) else None
        if not at or at < cutoff:
            continue
        reason = str((ev or {}).get("reason") or "").lower()
        if reason_fragment in reason:
            count += 1
    return count


def throttle_penalty(config: Dict[str, Any], acc: Dict[str, Any]) -> float:
    policy = throttle_policy(config)
    window = int(policy.get("recentWindowMinutes", 15))
    penalty = 0.0
    if is_live_failover_active(acc) or is_quarantined(acc):
        penalty += float(policy.get("strongPenalty", 1000.0))
    failures = acc.get("failureEvents") if isinstance(acc.get("failureEvents"), list) else []
    penalty += recent_event_count(failures, "rate_limit", window) * float(policy.get("rateLimitPenalty", 140.0))
    penalty += recent_event_count(failures, "timeout", window) * float(policy.get("timeoutPenalty", 40.0))
    return penalty

def is_quarantined(acc: Dict[str, Any]) -> bool:
    q = acc.get("quarantine", {})
    if not q.get("active"):
        return False
    until = parse_iso(q.get("until"))
    if until and now_utc() >= until:
        q.update({"active": False, "until": None, "reason": None})
        return False
    return bool(q.get("active"))


def healthy_profiles(config: Dict[str, Any], state: Dict[str, Any]) -> List[str]:
    out = []
    cap = int(config.get("concurrencyCapPerAccount", 3))
    monitor_known = ((state.get("monitor", {}) or {}).get("knownProfiles", [])) if isinstance(state.get("monitor", {}), dict) else []
    known_profiles = set(monitor_known) if monitor_known else {a.get("profileId") for a in config.get("accounts", []) if a.get("profileId")}
    guards = config.get("routingGuards", {}) if isinstance(config.get("routingGuards"), dict) else {}
    min_week = float(guards.get("minWeekRemaining", 0.0))
    min_five = float(guards.get("minFiveHourRemaining", 0.0))
    require_known_usage = bool(guards.get("requireKnownUsage", True))
    for a in config.get("accounts", []):
        pid = a["profileId"]
        st = state["accounts"].get(pid, {})
        h = st.get("health", {})
        if not a.get("enabled", True):
            continue
        if known_profiles and pid not in known_profiles:
            continue
        if is_quarantined(st) or is_live_failover_active(st):
            continue
        if h.get("expired") or not h.get("healthy", True):
            continue
        u = st.get("usage", {})
        if require_known_usage and (u.get("source") == "unknown"):
            continue
        if isinstance(u.get("weekRemaining"), (int, float)) and float(u.get("weekRemaining")) <= max(0.0, min_week):
            continue
        if isinstance(u.get("fiveHourRemaining"), (int, float)) and float(u.get("fiveHourRemaining")) <= max(0.0, min_five):
            continue
        if active_leases_for_profile(state, pid) >= cap:
            continue
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
    observed: Dict[str, Dict[str, Any]] = {}
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
        return {
            "healthy": bool(observed_entry.get("healthy", True)),
            "expired": bool(observed_entry.get("expired", False)),
            "expiresAt": observed_entry.get("expiresAt"),
            "observedAt": observed_entry.get("observedAt", ts()),
            "reason": None,
            "missingConsecutive": 0,
            "missingSince": None,
            "stage": "healthy",
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


def telemetry_freshness(config: Dict[str, Any], usage: Dict[str, Any]) -> Dict[str, Any]:
    observed_at = parse_iso(usage.get("observedAt")) if isinstance(usage, dict) else None
    age_seconds = None
    if observed_at is not None:
        age_seconds = max(0, int((now_utc() - observed_at).total_seconds()))

    source = str(usage.get("source") or "unknown")
    if source == "per-profile":
        confidence = "high"
        factor = 1.0
    elif source in {"active-profile", "probe"}:
        confidence = "medium"
        factor = 0.8
    elif source == "stale-probe":
        confidence = "low"
        factor = 0.55
    else:
        confidence = "none"
        factor = 0.25

    if age_seconds is None:
        freshness = "unknown"
        factor *= 0.35
    elif age_seconds <= 600:
        freshness = "fresh"
    elif age_seconds <= 1800:
        freshness = "aging"
        factor *= 0.85
    elif age_seconds <= 7200:
        freshness = "stale"
        factor *= 0.65
    else:
        freshness = "very_stale"
        factor *= 0.4

    return {
        "observedAt": usage.get("observedAt"),
        "ageSeconds": age_seconds,
        "freshness": freshness,
        "confidence": confidence,
        "scoreFactor": round(max(0.0, min(1.0, factor)), 3),
        "source": source,
    }


def merge_health_update(config: Dict[str, Any], target_state: Dict[str, Any], observed: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    ensure_account_state(config, target_state)
    target_state.setdefault("monitor", {})["knownProfiles"] = sorted(list(observed.keys()))
    missing_profiles: List[str] = []
    unhealthy_profiles: List[str] = []

    for a in config.get("accounts", []):
        pid = a["profileId"]
        st = target_state["accounts"][pid]
        prev_h = st.get("health", {}) if isinstance(st.get("health"), dict) else {}
        st["health"] = evaluate_profile_health(config, prev_h, observed.get(pid))
        if pid not in observed:
            missing_profiles.append(pid)
        if st.get("health", {}).get("healthy") is False:
            unhealthy_profiles.append(pid)
        _ = is_quarantined(st)

    return {
        "missingProfiles": missing_profiles,
        "unhealthyProfiles": unhealthy_profiles,
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


def resolve_usage_profile(config: Dict[str, Any], state: Dict[str, Any]) -> Optional[str]:
    # Prefer explicit manual override when set.
    ov = state.get("override", {})
    if ov.get("enabled") and ov.get("profileId"):
        return ov.get("profileId")

    provider = config.get("provider", "openai-codex")
    agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
    order = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "standard"))
    if order and isinstance(order, list) and len(order) > 0:
        return order[0]
    return None


def observe_usage_by_profile(config: Dict[str, Any], state: Dict[str, Any], cli_timeout_tier: str = "standard") -> Dict[str, Dict[str, Any]]:
    # Avoid auth-order churn while active tasks are running.
    if any(l.get("active") for l in state.get("leases", {}).values()):
        return {}

    provider = config.get("provider", "openai-codex")
    agent_id = (config.get("usageProbe") or {}).get("agentId", "main")

    profile_ids = [a.get("profileId") for a in config.get("accounts", []) if a.get("enabled", True)]
    profile_ids = [p for p in profile_ids if p]
    if not profile_ids:
        return {}

    timeout_sec = timeout_tier(config, cli_timeout_tier)
    original_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec)
    results: Dict[str, Dict[str, Any]] = {}

    try:
        for pid in profile_ids:
            order = [pid] + [p for p in profile_ids if p != pid]
            if not set_auth_order(provider, agent_id, order, timeout_sec=timeout_sec):
                continue
            snap = observe_usage_snapshot(config)
            results[pid] = snap
    finally:
        if original_order:
            restored = [p for p in original_order if p in profile_ids] + [p for p in profile_ids if p not in original_order]
            set_auth_order(provider, agent_id, restored, timeout_sec=timeout_sec)
        else:
            fallback_order = [a.get("profileId") for a in sorted(config.get("accounts", []), key=lambda x: int(x.get("priority", 1)), reverse=True) if a.get("enabled", True)]
            set_auth_order(provider, agent_id, [p for p in fallback_order if p], timeout_sec=timeout_sec)

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


def live_canary_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = config.get("liveCanary", {}) if isinstance(config.get("liveCanary"), dict) else {}
    return {"enabled": bool(raw.get("enabled", True)), "intervalMinutes": max(5, int(raw.get("intervalMinutes", 30))), "timeoutTier": str(raw.get("timeoutTier", "quick")), "maxRuntimeSeconds": max(10, int(raw.get("maxRuntimeSeconds", 180))), "onlyWhenIdle": bool(raw.get("onlyWhenIdle", True))}


def canary_candidate_profiles(config: Dict[str, Any]) -> List[str]:
    return [a.get("profileId") for a in config.get("accounts", []) if a.get("profileId") and a.get("enabled", True)]


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
    profiles = canary_candidate_profiles(config)
    if not profiles:
        result["skipped"] = "no_enabled_profiles"
        return result
    cursor = int(lc.get("cursor", 0)) % len(profiles)
    pid = profiles[cursor]
    lc["cursor"] = (cursor + 1) % len(profiles)
    lc["lastRunAt"] = ts()
    lc["lastProfileId"] = pid
    provider = config.get("provider", "openai-codex")
    agent_id = ((config.get("usageProbe") or {}).get("agentId") or "main")
    timeout_sec = min(timeout_tier(config, settings["timeoutTier"]), settings["maxRuntimeSeconds"])
    original = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
    ordered = [pid] + [p for p in original if p != pid]
    started = time.monotonic()
    snap = {}
    observed_order = None
    ok = False
    reason = None
    try:
        if set_auth_order(provider, agent_id, ordered, timeout_sec=timeout_sec):
            observed_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
            snap = observe_usage_snapshot(config)
            ok = bool(snap.get("available"))
            reason = "ok" if ok else str(snap.get("error") or "usage_probe_unavailable")
        else:
            reason = "set_auth_order_failed"
    finally:
        if original:
            set_auth_order(provider, agent_id, original, timeout_sec=timeout_sec)
    event = {"at": ts(), "profileId": pid, "success": ok, "latencyMs": int((time.monotonic() - started) * 1000), "reason": reason, "fiveHourRemaining": snap.get("fiveHourRemaining"), "weekRemaining": snap.get("weekRemaining"), "observedOrder": observed_order}
    acct = state.setdefault("accounts", {}).setdefault(pid, {"profileId": pid})
    canary = acct.setdefault("canary", {})
    canary.update({"lastRunAt": event["at"], "lastSuccessAt": event["at"] if ok else canary.get("lastSuccessAt"), "success": ok, "latencyMs": event["latencyMs"], "reason": reason, "observedOrder": observed_order})
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

        u = st.get("usage", {})
        week = float(u.get("weekRemaining")) if isinstance(u.get("weekRemaining"), (int, float)) else 50.0
        five = float(u.get("fiveHourRemaining")) if isinstance(u.get("fiveHourRemaining"), (int, float)) else 50.0
        # Weekly capacity is the primary signal; 5h is secondary.
        cap_signal = (week * 4.0) + min(five, 50.0)
        score += int(cap_signal * (int(weights.get("remainingCapacity", 30)) / 100.0))
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
    for agent in config.get("managedAgents", []):
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
    ensure_account_state(config, state)
    runtime_info = ingest_runtime_failover_signals(config, state)
    auth_sync_info = sync_runtime_quarantine_to_auth_store(config, state)
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
        agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
        timeout_sec = timeout_tier(config, "quick")
        current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []

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
        f"Your action: {your_action or ('None right now.' if sev == 'INFO' else 'Run /oauth status if this repeats.')}",
    ]
    lines.extend(_format_status_lines(status))
    return "\n".join(lines)


def _advisor_capacity_status(advisor: Dict[str, Any]) -> str:
    pool = advisor.get("poolSummary") or {}
    action = pool.get("action") or advisor.get("headline") or "Monitor pool health."
    return "; ".join([
        f"capacity=CPH {float(pool.get('compositeHealthPct', 0.0)):.1f}%",
        f"ready={int(pool.get('eligibleCount', 0))}/{int(pool.get('enabledCount', 0))}",
        f"healthy={int(pool.get('healthyCount', 0))}/{int(pool.get('enabledCount', 0))}",
        f"action={action}",
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

    res = {"severity": sev, "code": code, "message": raw, "formatted": full, "channels": {}}
    for k in ("telegram", "discord"):
        sink = config.get("alerts", {}).get(k, {})
        force_profile_disabled = code == "PROFILE_DISABLED" and k == "telegram"
        enabled = bool(sink.get("enabled", False)) or force_profile_disabled
        if not enabled:
            res["channels"][k] = {"ok": False, "skipped": True}
            continue
        channel = str(sink.get("channel") or k)
        target = str(sink.get("target") or "")
        if not target:
            res["channels"][k] = {"ok": False, "skipped": True, "reason": "missing_target"}
            continue
        cmd = ["openclaw", "message", "send", "--channel", channel, "--target", target, "--message", full]
        rc, so, se = run_cmd(cmd, timeout=30)
        res["channels"][k] = {"ok": rc == 0, "code": rc, "stdout": so, "stderr": se, "cmd": " ".join(cmd)}
    if sev == "CRITICAL":
        state.setdefault("alerts", {})["lastCriticalAt"] = ts()
        state.setdefault("alerts", {})["count"] = int(state.setdefault("alerts", {}).get("count", 0)) + 1
    append_history(state, {
        "at": ts(),
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


def sync_runtime_quarantine_to_auth_store(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    out = {"ok": True, "updated": False, "path": None, "updatedProfiles": []}
    try:
        agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
        auth_path = openclaw_home() / "agents" / str(agent_id) / "agent" / "auth-profiles.json"
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

        usage = store.setdefault("usageStats", {})
        changed = False
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
        return out
    except Exception as exc:
        out["ok"] = False
        out["error"] = str(exc)
        return out


def openclaw_home() -> Path:
    env = os.environ.get("OPENCLAW_HOME")
    candidates = []
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(Path.home() / ".openclaw")
    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate
        except Exception:
            continue
    return candidates[0]


def session_rebind_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = config.get("sessionRebind", {}) if isinstance(config.get("sessionRebind"), dict) else {}
    return {
        "enabled": bool(raw.get("enabled", True)),
        "lookbackMinutes": max(1, int(raw.get("lookbackMinutes", 1440))),
        "respectUserOverride": bool(raw.get("respectUserOverride", True)),
    }


def session_store_path(agent_id: str) -> Path:
    return openclaw_home() / "agents" / str(agent_id) / "sessions" / "sessions.json"


def session_entry_matches_provider(entry: Dict[str, Any], provider: str) -> bool:
    model_provider = str(entry.get("modelProvider") or "").strip().lower()
    provider = str(provider or "").strip().lower()
    if model_provider:
        return model_provider == provider
    model = str(entry.get("model") or "").strip().lower()
    if provider == "openai-codex":
        return model.startswith("gpt-") or model.startswith("openai-codex/")
    return False


def sync_session_auth_overrides(config: Dict[str, Any], state: Dict[str, Any], target_order: Optional[List[str]] = None, reason: str = "tick") -> Dict[str, Any]:
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
    }
    if not cfg["enabled"]:
        return out

    provider = str(config.get("provider") or "openai-codex")
    candidate_order = list(target_order or [])
    if not candidate_order:
        agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
        current_order = get_auth_order(provider, agent_id, timeout_sec=timeout_tier(config, "health")) or []
        preview = build_effective_auth_order(config, state, current_order)
        candidate_order = list(preview.get("effectiveOrder") or current_order)

    target = candidate_order[0] if candidate_order else None
    out["targetProfileId"] = target
    if not target:
        out["ok"] = False
        out["error"] = "no_target_profile"
        return out

    now_ms = int(now_utc().timestamp() * 1000)
    cutoff = now_ms - (cfg["lookbackMinutes"] * 60 * 1000)

    for agent_id in config.get("managedAgents", []):
        path = session_store_path(str(agent_id))
        agent_info = {
            "path": str(path),
            "exists": path.exists(),
            "scanned": 0,
            "updated": 0,
            "preservedUser": 0,
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

        changed = False
        for session_key, entry in store.items():
            if not isinstance(entry, dict):
                continue
            updated_at = entry.get("updatedAt")
            if not isinstance(updated_at, (int, float)) or int(updated_at) < cutoff:
                continue
            if not session_entry_matches_provider(entry, provider):
                continue
            agent_info["scanned"] += 1
            current = str(entry.get("authProfileOverride") or "").strip() or None
            source = str(entry.get("authProfileOverrideSource") or "").strip() or None
            if cfg["respectUserOverride"] and source == "user" and current:
                agent_info["preservedUser"] += 1
                continue

            compaction = entry.get("compactionCount")
            desired_compaction = int(compaction) if isinstance(compaction, (int, float)) else 0
            stored_compaction = entry.get("authProfileOverrideCompactionCount")
            if (
                current == target
                and source == "auto"
                and isinstance(stored_compaction, (int, float))
                and int(stored_compaction) == desired_compaction
            ):
                continue

            entry["authProfileOverride"] = target
            entry["authProfileOverrideSource"] = "auto"
            entry["authProfileOverrideCompactionCount"] = desired_compaction
            entry["updatedAt"] = max(int(updated_at or 0), now_ms)
            store[session_key] = entry
            changed = True
            agent_info["updated"] += 1
            out["updatedSessions"].append({
                "agentId": str(agent_id),
                "sessionKey": session_key,
                "profileId": target,
                "source": "auto",
            })

        if changed:
            save_json(path, store)
        out["agents"][str(agent_id)] = agent_info

    out["updated"] = bool(out["updatedSessions"])
    state["sessionRebind"] = {
        "lastAt": ts(),
        "reason": reason,
        "targetProfileId": target,
        "updatedSessions": len(out["updatedSessions"]),
    }
    if out["updatedSessions"]:
        append_history(state, {
            "at": ts(),
            "type": "session_rebind",
            "reason": reason,
            "targetProfileId": target,
            "updatedSessions": out["updatedSessions"],
        })
    return out


def ingest_runtime_failover_signals(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    info = {
        "ok": True,
        "processed": 0,
        "rateLimited": 0,
        "timedOut": 0,
        "quarantined": [],
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

            pid = hash_map.get(str(payload.get("profileId") or ""))
            if not pid:
                continue
            acc = state.get("accounts", {}).get(pid)
            if not isinstance(acc, dict):
                continue

            raw_reason = str(payload.get("failoverReason") or payload.get("profileFailureReason") or "")
            raw = payload.get("rawErrorPreview")
            reason = normalize_runtime_failover_reason(raw_reason, raw)
            logical_key = "|".join([str(payload.get("runId") or ""), pid, reason, str(raw or "")[:160]])
            prev_logical_at = parse_iso(logical_seen.get(logical_key)) if isinstance(logical_seen, dict) else None
            if prev_logical_at and (t - prev_logical_at) < dt.timedelta(minutes=15):
                continue
            logical_seen[logical_key] = obj.get("time") or ts()

            if reason == "rate_limit":
                info["rateLimited"] += 1
                mins = _extract_retry_minutes(raw)
                base = int(throttle_policy(config).get("rateLimitBaseCooldownMinutes", 20))
                mins = min(max(mins, base, 5), int(throttle_policy(config).get("maxCooldownMinutes", 720)))
                until = now + dt.timedelta(minutes=mins)
                prior_q = acc.get("quarantine", {}) if isinstance(acc.get("quarantine"), dict) else {}
                prior_until = parse_iso(prior_q.get("until")) if isinstance(prior_q.get("until"), str) else None
                effective_until = _future_max(prior_until if prior_q.get("active") and str(prior_q.get("reason") or "").startswith("runtime_rate_limit") else None, until)
                effective_mins = _cooldown_minutes_remaining(effective_until)
                acc["quarantine"] = {
                    "active": True,
                    "until": effective_until.isoformat(),
                    "reason": f"runtime_rate_limit:{effective_mins}m",
                }
                apply_live_fail_penalty(config, acc, kind="rate_limit", minutes=effective_mins, raw=raw)
                append_history(state, {
                    "at": ts(),
                    "type": "runtime_failover_quarantine",
                    "profileId": pid,
                    "reason": "rate_limit",
                    "minutes": effective_mins,
                    "raw": raw,
                })
                info["quarantined"].append({"profileId": pid, "reason": "rate_limit", "minutes": effective_mins})
            elif reason == "timeout":
                info["timedOut"] += 1
                until = now + dt.timedelta(minutes=max(1, timeout_quarantine_min))
                prior_q = acc.get("quarantine", {}) if isinstance(acc.get("quarantine"), dict) else {}
                prior_until = parse_iso(prior_q.get("until")) if isinstance(prior_q.get("until"), str) else None
                effective_until = _future_max(prior_until if prior_q.get("active") and str(prior_q.get("reason") or "").startswith("runtime_timeout") else None, until)
                effective_mins = _cooldown_minutes_remaining(effective_until)
                acc["quarantine"] = {
                    "active": True,
                    "until": effective_until.isoformat(),
                    "reason": f"runtime_timeout:{effective_mins}m",
                }
                apply_live_fail_penalty(config, acc, kind="timeout", minutes=effective_mins, raw=raw)
                append_history(state, {
                    "at": ts(),
                    "type": "runtime_failover_quarantine",
                    "profileId": pid,
                    "reason": "timeout",
                    "minutes": effective_mins,
                })
                info["quarantined"].append({"profileId": pid, "reason": "timeout", "minutes": effective_mins})

        # persist bounded seen list
        seen_list = sorted(list(seen_set))
        scan_state["seenEventIds"] = seen_list[-recent_keep:]
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
    telemetry_scores: List[float] = []
    freshness_counts = {"fresh": 0, "aging": 0, "stale": 0, "very_stale": 0, "unknown": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0, "none": 0}

    for pid in enabled_ids:
        acc = (state.get("accounts", {}) or {}).get(pid, {})
        h = acc.get("health", {}) if isinstance(acc, dict) else {}
        if h.get("healthy", True) and not h.get("expired", False) and (not is_quarantined(acc)):
            healthy_ids.append(pid)

    for pid in eligible_ids:
        acc = (state.get("accounts", {}) or {}).get(pid, {})
        u = acc.get("usage", {}) if isinstance(acc, dict) else {}
        week = float(u.get("weekRemaining")) if isinstance(u.get("weekRemaining"), (int, float)) else 0.0
        five = float(u.get("fiveHourRemaining")) if isinstance(u.get("fiveHourRemaining"), (int, float)) else 0.0
        base_score = (w_week * week) + (w_five * five)
        telemetry = telemetry_freshness(config, u)
        effective_score = base_score * float(telemetry.get("scoreFactor") or 0.0)
        freshness_counts[str(telemetry.get("freshness") or "unknown")] += 1
        confidence_counts[str(telemetry.get("confidence") or "none")] += 1
        telemetry_scores.append(float(telemetry.get("scoreFactor") or 0.0) * 100.0)
        rows.append({
            "profileId": pid,
            "name": account_name(config, pid),
            "score": round(effective_score, 2),
            "rawScore": round(base_score, 2),
            "weekRemaining": week,
            "fiveHourRemaining": five,
            "source": u.get("source"),
            "telemetry": telemetry,
        })

    rows.sort(key=lambda x: x["score"], reverse=True)
    eligible_count = len(eligible_ids)
    top_n = min(eligible_count, max(min_top_n, int(math.ceil(top_fraction * eligible_count)))) if eligible_count > 0 else 0
    top_rows = rows[:top_n]
    routing_headroom = sum(x["score"] for x in top_rows) / top_n if top_n > 0 else 0.0
    raw_routing_headroom = sum(x["rawScore"] for x in top_rows) / top_n if top_n > 0 else 0.0
    coverage_pct = (eligible_count / enabled_count * 100.0) if enabled_count > 0 else 0.0
    health_pct = (len(healthy_ids) / enabled_count * 100.0) if enabled_count > 0 else 0.0
    telemetry_confidence_pct = sum(telemetry_scores) / len(telemetry_scores) if telemetry_scores else 0.0

    composite = ((w_head * routing_headroom) + (w_cov * coverage_pct) + (w_health * health_pct)) if enabled_count > 0 else 0.0
    composite = max(0.0, min(100.0, composite))
    used_pct = max(0.0, min(100.0, 100.0 - composite))

    return {
        "enabledCount": enabled_count,
        "healthyCount": len(healthy_ids),
        "eligibleCount": eligible_count,
        "coveragePct": round(coverage_pct, 2),
        "healthPct": round(health_pct, 2),
        "routingHeadroomPct": round(routing_headroom, 2),
        "rawRoutingHeadroomPct": round(raw_routing_headroom, 2),
        "telemetryConfidencePct": round(telemetry_confidence_pct, 2),
        "telemetryFreshnessCounts": freshness_counts,
        "telemetryConfidenceCounts": confidence_counts,
        "compositeHealthPct": round(composite, 2),
        "compositeUsedPct": round(used_pct, 2),
        "topN": top_n,
        "scoredEligible": rows,
        "topEligible": top_rows,
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
    cph = float(metrics.get("compositeHealthPct", 0.0))

    if enabled == 0 or eligible == 0 or ((recommendation or {}).get("level") == "critical"):
        state_label = "critical"
        headline = f"Pool critical · {eligible}/{enabled} ready · {healthy}/{enabled} healthy · headroom {headroom:.0f}% · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"
    elif (recommendation or {}).get("level") == "info":
        state_label = "tightening"
        headline = f"Pool tightening · {eligible}/{enabled} ready · {healthy}/{enabled} healthy · headroom {headroom:.0f}% · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"
    else:
        state_label = "healthy"
        headline = f"Pool healthy · {eligible}/{enabled} ready · {healthy}/{enabled} healthy · headroom {headroom:.0f}% · telemetry {metrics.get('telemetryConfidencePct', 0.0):.0f}%"

    return {
        "state": state_label,
        "headline": headline,
        "compositeHealthPct": round(cph, 2),
        "routingHeadroomPct": round(headroom, 2),
        "eligibleCount": eligible,
        "healthyCount": healthy,
        "enabledCount": enabled,
        "action": (recommendation or {}).get("message"),
    }


def capacity_recommendation(config: Dict[str, Any], state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    metrics = pool_usage_metrics(config, state)
    policy = config.get("poolUsagePolicy", {}) if isinstance(config.get("poolUsagePolicy"), dict) else {}
    warn_below = float(policy.get("warnBelow", 65.0))
    critical_below = float(policy.get("criticalBelow", 40.0))

    enabled = int(metrics.get("enabledCount", 0))
    eligible = int(metrics.get("eligibleCount", 0))
    cph = float(metrics.get("compositeHealthPct", 0.0))

    if enabled == 0:
        return {
            "level": "critical",
            "code": "POOL_NO_ENABLED",
            "message": "No enabled OAuth accounts configured. Add/enable accounts now.",
        }

    if eligible == 0:
        return {
            "level": "critical",
            "code": "POOL_NO_ELIGIBLE",
            "message": "No eligible OAuth accounts available. Restore/re-auth accounts now.",
        }

    if cph < critical_below:
        return {
            "level": "critical",
            "code": "POOL_CAPACITY_CRITICAL",
            "message": (
                f"Pool health critical (CPH={cph:.1f}%). "
                f"Eligible {eligible}/{enabled}. Add 1-2 accounts now."
            ),
        }

    if cph < warn_below:
        return {
            "level": "info",
            "code": "POOL_CAPACITY_TIGHT",
            "message": (
                f"Pool health tightening (CPH={cph:.1f}%). "
                f"Eligible {eligible}/{enabled}. Recommend adding 1 account soon."
            ),
        }

    return None


def sync_discovered_profiles(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    opts = config.get("autoProfileSync", {}) if isinstance(config.get("autoProfileSync"), dict) else {}
    if not opts.get("enabled", True):
        return {"changed": False, "added": [], "discovered": []}

    discovered = discover_provider_profile_ids(config)
    ignored = set(opts.get("ignoreProfileIds", []))
    discovered = [pid for pid in discovered if pid not in ignored]

    existing = {a.get("profileId") for a in config.get("accounts", [])}
    added: List[str] = []

    for pid in discovered:
        if pid in existing:
            continue
        config.setdefault("accounts", []).append({
            "profileId": pid,
            "name": pid,
            "enabled": bool(opts.get("autoEnableNewProfiles", True)),
            "priority": int(opts.get("defaultPriority", 1)),
            "projects": list(opts.get("defaultProjects", ["project-a", "project-b", "project-c"])),
        })
        existing.add(pid)
        added.append(pid)

    changed = bool(added)
    if changed:
        save_json(CONFIG_PATH, config)
        append_history(state, {"at": ts(), "type": "profile_sync", "added": added, "discovered": discovered})

    if changed and opts.get("alertOnNewProfile", True):
        named = [f"{account_name(config, pid)} ({pid})" for pid in added]
        send_alert(config, state, "INFO", f"Auto-registered new OAuth profile(s): {', '.join(named)}", code="PROFILE_DISCOVERED", impact="Routing pool inventory changed.", auto_action="Router registered discovered profile(s) using default settings.", your_action="Review priorities/projects when convenient.")

    return {"changed": changed, "added": added, "discovered": discovered}


def cmd_sync_profiles(config: Dict[str, Any], state: Dict[str, Any]) -> int:
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


def emit_lifecycle_advisor_alerts(config: Dict[str, Any], state: Dict[str, Any], advisor: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    mon = state.setdefault("monitor", {})
    prev = mon.setdefault("lifecycleAdvisor", {})
    current_primary = str(advisor.get("primary") or "HOLD")
    current_reviews = sorted([r.get("profileId") for r in advisor.get("reviews", []) if r.get("profileId")])
    previous_primary = str(prev.get("primary") or "HOLD")
    previous_reviews = sorted(prev.get("reviewProfiles") or [])

    changed_primary = current_primary != previous_primary
    changed_reviews = current_reviews != previous_reviews
    if not (changed_primary or changed_reviews):
        return events

    advisor_cfg = config.get("lifecycleAdvisor", {}) if isinstance(config.get("lifecycleAdvisor"), dict) else {}
    cooldown_min = max(5, int(advisor_cfg.get("alertCooldownMinutes", 180)))
    key = "lifecycle_advisor_state"
    if not should_emit_signal(state, key, cooldown_min):
        prev["primary"] = current_primary
        prev["reviewProfiles"] = current_reviews
        prev["updatedAt"] = ts()
        return events

    recommendation = advisor.get("recommendation") or {}
    if current_primary == "ADD":
        sev = "CRITICAL" if recommendation.get("level") == "critical" else "INFO"
        code = "ADVISOR_ADD_NOW" if recommendation.get("level") == "critical" else "ADVISOR_ADD_SOON"
        r = send_alert(
            config,
            state,
            sev,
            "Capacity pressure in OAuth pool",
            code=code,
            impact="Pool lifecycle advisor detected capacity pressure.",
            auto_action="Router continues balancing across healthy eligible profiles.",
            your_action="Add 1-2 accounts based on the recommendation severity.",
            status=_advisor_capacity_status(advisor),
        )
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
        events.append({"type": "ADVISOR_REVIEW", "alert": r})
    elif previous_primary in {"ADD", "REVIEW"}:
        r = send_alert(
            config,
            state,
            "INFO",
            "Pool lifecycle advisor is back to HOLD.",
            code="ADVISOR_HOLD",
            impact="No pool expansion or account review action is currently needed.",
            auto_action="Monitoring continues in the background.",
            your_action="None right now.",
            status=f"primary={current_primary}",
        )
        events.append({"type": "ADVISOR_HOLD", "alert": r})

    mark_signal(state, key)
    prev["primary"] = current_primary
    prev["reviewProfiles"] = current_reviews
    prev["updatedAt"] = ts()
    return events

def emit_monitor_alerts(config: Dict[str, Any], state: Dict[str, Any], cli_timeout_tier: str = "standard") -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    enabled_profiles = [a["profileId"] for a in config.get("accounts", []) if a.get("enabled", True)]
    healthy = healthy_profiles(config, state)
    mon = state.setdefault("monitor", {})
    exhaustion = mon.setdefault("exhaustion", {})
    enabled_state = mon.setdefault("enabledState", {})

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
        enabled_state[pid0] = now_enabled

    # Keep auth head aligned with usable pool. If current head becomes unusable
    # (exhausted/quarantined/unhealthy/expired), auto-evict it in the same monitor pass.
    provider = config.get("provider", "openai-codex")
    agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
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

        if h.get("expired"):
            key = f"expired:{pid}"
            if should_emit_signal(state, key, 10):
                r = send_alert(config, state, "CRITICAL", f"OAuth account {account_name(config, pid)} ({pid}) expired.", code="PROFILE_EXPIRED", impact="This profile cannot be used for routing until re-authenticated.", auto_action="Router excluded the expired profile.", your_action="Re-auth this profile now.", status=f"profile={pid}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})

        if h.get("healthy") is False:
            key = f"unhealthy:{pid}"
            if should_emit_signal(state, key, 10):
                reason = str(h.get("reason") or "")
                if reason == "not_reported_by_models_status":
                    r = send_alert(
                        config,
                        state,
                        "CRITICAL",
                        f"OAuth account {account_name(config, pid)} ({pid}) is missing/unusable (not reported by provider status).",
                        code="PROFILE_MISSING_OR_UNUSABLE",
                        impact="Profile likely deleted/unauthorized/unsubscribed and is excluded from routing.",
                        auto_action="Router removed this profile from safe routing decisions.",
                        your_action="Re-auth/restore this account now or keep it disabled.",
                        status=f"profile={pid}",
                    )
                else:
                    r = send_alert(config, state, "CRITICAL", f"OAuth account {account_name(config, pid)} ({pid}) is unhealthy.", code="PROFILE_UNHEALTHY", impact="Profile is excluded from safe routing.", auto_action="Router auto-routed away from this profile.", your_action="Investigate profile health/auth immediately.", status=f"profile={pid}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})

        runtime_quarantine = str(q.get("reason") or "").startswith("runtime_")
        if q.get("active") and (not runtime_quarantine):
            key = f"quarantine:{pid}:{q.get('reason')}"
            if should_emit_signal(state, key, 15):
                r = send_alert(config, state, "CRITICAL", f"OAuth account {account_name(config, pid)} ({pid}) quarantined ({q.get('reason')}).", code="PROFILE_QUARANTINED", impact="Profile temporarily removed from routing due to repeated failures.", auto_action="Router will re-allow after quarantine expiry.", your_action="Check cause only if quarantine keeps repeating.", status=f"profile={pid}")
                mark_signal(state, key)
                events.append({"type": key, "alert": r})

        # Runtime failover quarantines already represent known provider caps/timeouts.
        # Avoid duplicate per-profile weekly/5h alerts for those while quarantine is active.
        if runtime_quarantine:
            continue

        u = st.get("usage", {})
        wk = u.get("weekRemaining")
        fh = u.get("fiveHourRemaining")
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

    if truth_age is None:
        freshness = "missing"
        state_label = "degraded"
    elif truth_age <= fresh_sec and last_status == "ok":
        freshness = "fresh"
        state_label = "healthy"
    elif truth_age <= stale_sec and last_status in {"ok", "degraded"}:
        freshness = "aging"
        state_label = "degraded"
    else:
        freshness = "stale"
        state_label = "degraded"

    if unhealthy_profiles or missing_profiles:
        state_label = "degraded"
    if not healthy_profiles(config, state):
        state_label = "failed"

    return {
        "state": state_label,
        "lastTruthAt": last_truth_at,
        "truthAgeSec": round(truth_age, 2) if truth_age is not None else None,
        "truthFreshness": freshness,
        "lastTruthStatus": last_status,
        "missingTruthProfiles": missing_truth,
        "observedProfiles": observed_profiles,
        "missingProfiles": missing_profiles,
        "unhealthyProfiles": unhealthy_profiles,
        "degraded": state_label != "healthy",
    }


def cached_watchdog_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    hb = ((state.get("monitor", {}) or {}).get("watchdogHeartbeat") or {})
    at = parse_iso(hb.get("at")) if isinstance(hb, dict) else None
    age = (now_utc() - at).total_seconds() if at else None
    fresh = bool(hb.get("ok")) and age is not None and age <= 300
    return {
        "ok": fresh,
        "cached": True,
        "at": ts(),
        "heartbeat": hb,
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
        out = {"ok": True, "skipped": "health_lock_busy", "observedProfiles": [], "at": ts(), "fastPath": True}
        print(json.dumps(out, indent=2))
        return 0

    try:
        latest_state = load_json(STATE_PATH, default_state())
        ensure_account_state(config, latest_state)
        summary = cached_health_truth_summary(config, latest_state)
        out = {
            "ok": True,
            "fastPath": True,
            "lockPath": str(HEALTH_LOCK_PATH),
            "state": summary["state"],
            "lastTruthAt": summary["lastTruthAt"],
            "truthAgeSec": summary["truthAgeSec"],
            "truthFreshness": summary["truthFreshness"],
            "lastTruthStatus": summary["lastTruthStatus"],
            "modelsStatus": {
                "ok": summary["lastTruthStatus"] == "ok",
                "code": 0 if summary["lastTruthStatus"] == "ok" else 1,
                "timeoutSec": 0,
                "stderr": "",
                "stdoutBytes": 0,
                "source": "cached_truth",
            },
            "observedProfiles": summary["observedProfiles"],
            "missingTruthProfiles": summary["missingTruthProfiles"],
            "missingProfiles": summary["missingProfiles"],
            "unhealthyProfiles": summary["unhealthyProfiles"],
            "alertsTriggered": 0,
            "degraded": summary["degraded"],
            "persistResult": "not_applicable_fast_path",
        }
        if json_mode:
            print(json.dumps(out, indent=2))
        else:
            print(f"health-check {summary['state']}: freshness={summary['truthFreshness']} age={summary['truthAgeSec']}s observed={len(summary['observedProfiles'])}")
        return 0
    finally:
        release_router_lock(lock_fh)


def cmd_status(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool) -> int:
    ensure_account_state(config, state)
    for pid in state.get("accounts", {}):
        state["accounts"][pid]["activeLeaseCount"] = active_leases_for_profile(state, pid)
    eligible_profiles = set(healthy_profiles(config, state))

    rc_o, out_o, _ = run_cmd(["openclaw", "models", "auth", "order", "get", "--provider", config.get("provider", "openai-codex"), "--agent", "main", "--json"])
    order_info = None
    if rc_o == 0 and out_o:
        try:
            order_info = json.loads(out_o)
        except Exception:
            order_info = {"raw": out_o}

    current_order = []
    if isinstance(order_info, dict) and isinstance(order_info.get("order"), list):
        current_order = list(order_info.get("order") or [])

    preferred = preferred_healthy_order(config, state, current_order)
    preview_base = list(preferred.get("ordered") or [])
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        if pid and pid not in preview_base:
            preview_base.append(pid)

    order_preview = build_effective_auth_order(config, state, preview_base)
    effective_order = order_preview.get("effectiveOrder", []) if isinstance(order_preview, dict) else []
    current_prefix = effective_order[:len(current_order)] if current_order else []
    tail_truncation_only = bool(current_order) and (current_order == current_prefix)
    unknown_profiles = {
        p for p in effective_order
        if ((state.get("accounts", {}).get(p, {}) or {}).get("usage", {}) or {}).get("source") == "unknown"
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

    rec = capacity_recommendation(config, state)
    pool_metrics = pool_usage_metrics(config, state)
    pool_simple = pool_summary(pool_metrics, rec)

    order_trace = state.get("authOrderTrace", {}) if isinstance(state.get("authOrderTrace"), dict) else {}
    runtime_tail = current_order[1:] if len(current_order) > 1 else []
    policy_tail = effective_order[1:] if len(effective_order) > 1 else []
    runtime_tail_noise = [p for p in runtime_tail if p not in set(effective_order)]
    summary = {
        "at": ts(),
        "provider": config.get("provider"),
        "override": state.get("override", {}),
        "focus": state.get("focus", {}),
        "accounts": state.get("accounts", {}),
        "activeLeases": {k: v for k, v in state.get("leases", {}).items() if v.get("active")},
        "tasks": state.get("tasks", {}),
        "poolUsage": pool_metrics,
        "poolSummary": pool_simple,
        "telemetrySummary": {
            "confidencePct": pool_metrics.get("telemetryConfidencePct"),
            "freshnessCounts": pool_metrics.get("telemetryFreshnessCounts"),
            "confidenceCounts": pool_metrics.get("telemetryConfidenceCounts"),
            "rawRoutingHeadroomPct": pool_metrics.get("rawRoutingHeadroomPct"),
            "effectiveRoutingHeadroomPct": pool_metrics.get("routingHeadroomPct"),
        },
        "lifecycleAdvisor": build_lifecycle_advisor(config, state),
        "capacityRecommendation": (rec.get("message") if rec else None),
        "capacityRecommendationLevel": (rec.get("level") if rec else None),
        "currentAuthOrder": order_info,
        "effectiveAuthOrder": effective_order,
        "orderPolicyDrift": policy_drift,
        "orderRiskDrift": order_risk_drift,
        "orderRemovedIneligible": order_preview.get("removedIneligible", []) if isinstance(order_preview, dict) else [],
        "orderFailoverSafeDepth": safe_depth,
        "orderFailoverUnsafeProfiles": failover_unsafe,
        "routingEligibleProfiles": sorted(list(eligible_profiles)),
        "authOrderTrace": order_trace,
        "orderPresentation": {"activeHead": current_head, "policyHead": effective_head, "policySafeOrder": effective_order, "runtimeTail": runtime_tail, "policyTail": policy_tail, "runtimeTailNoise": runtime_tail_noise, "removedIneligible": order_preview.get("removedIneligible", []) if isinstance(order_preview, dict) else []},
        "liveCanary": state.get("liveCanary", {}),
        "recovery": state.get("recovery", {}),
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
        print(f"Active head: runtime={op.get('activeHead')} policy={op.get('policyHead')}")
        print(f"Policy-safe order: {op.get('policySafeOrder')}")
        print(f"Runtime tail noise: {op.get('runtimeTailNoise')}")
        ps = summary.get("poolSummary") or {}
        pu = summary.get("poolUsage") or {}
        if ps:
            print(f"Pool: {ps.get('headline')}")
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
        for pid, a in summary["accounts"].items():
            h, q, u = a.get("health", {}), a.get("quarantine", {}), a.get("usage", {})
            telemetry = telemetry_freshness(config, u)
            print(f"- {account_name(config, pid)} ({pid}): enabled={a.get('enabled')} eligible={(pid in eligible_profiles)} healthy={h.get('healthy')} stage={h.get('stage')} expired={h.get('expired')} leases={a.get('activeLeaseCount')} quarantine={q.get('active')} 5h={u.get('fiveHourRemaining')} week={u.get('weekRemaining')} source={u.get('source')} freshness={telemetry.get('freshness')} confidence={telemetry.get('confidence')}")
        print("Active Leases:")
        if summary["activeLeases"]:
            for k, v in summary["activeLeases"].items():
                print(f"- {k} -> {v.get('profileId')} (project={v.get('project')}, acquiredAt={v.get('acquiredAt')})")
        else:
            print("- none")
        if summary["capacityRecommendation"]:
            print(f"Recommendation: {summary['capacityRecommendation']}")
    return 0


def cmd_tick(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    ensure_account_state(config, state)
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

        if pid in usage_by_profile:
            snap = usage_by_profile[pid]
            st["usage"] = {
                "available": bool(snap.get("available", False)),
                "fiveHourRemaining": snap.get("fiveHourRemaining"),
                "weekRemaining": snap.get("weekRemaining"),
                "observedAt": snap.get("observedAt", ts()),
                "source": "per-profile",
            }
        elif usage_global.get("available") and usage_profile == pid:
            st["usage"] = {
                "available": True,
                "fiveHourRemaining": usage_global.get("fiveHourRemaining"),
                "weekRemaining": usage_global.get("weekRemaining"),
                "observedAt": usage_global.get("observedAt", ts()),
                "source": "active-profile",
            }
        else:
            # Preserve recent probe/per-profile telemetry for non-active accounts to avoid
            # dropping visibility to unknown between ticks.
            prev_u = st.get("usage", {}) if isinstance(st.get("usage"), dict) else {}
            retain_minutes = int((config.get("usageProbe") or {}).get("retainProbeMinutes", 180))
            prev_at = parse_iso(prev_u.get("observedAt"))
            can_retain = (
                prev_u.get("source") in {"probe", "per-profile", "stale-probe"}
                and prev_at is not None
                and (now_utc() - prev_at) <= dt.timedelta(minutes=retain_minutes)
                and (
                    isinstance(prev_u.get("fiveHourRemaining"), (int, float))
                    or isinstance(prev_u.get("weekRemaining"), (int, float))
                )
            )
            if can_retain:
                st["usage"] = {
                    "available": bool(prev_u.get("available", True)),
                    "fiveHourRemaining": prev_u.get("fiveHourRemaining"),
                    "weekRemaining": prev_u.get("weekRemaining"),
                    "observedAt": prev_u.get("observedAt", usage_global.get("observedAt", ts())),
                    "source": "stale-probe",
                }
            else:
                # Unknown per-account quota in global mode: do not mirror another account's usage.
                st["usage"] = {
                    "available": False,
                    "fiveHourRemaining": None,
                    "weekRemaining": None,
                    "observedAt": usage_global.get("observedAt", ts()),
                    "source": "unknown",
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
            agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
            timeout_sec = timeout_tier(config, "standard")
            current_order_hint = get_auth_order(provider, agent_id, timeout_sec=timeout_sec) or []
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

                if apply_order:
                    if policy_drift and high_risk_drift:
                        record_policy_reconcile_event(config, state, "dynamic", current_order, effective_order)
                    result = apply_auth_order(config, state, ordered, source="tick", reason="dynamic")
                    append_history(state, {
                        "at": ts(),
                        "type": "auth_order_apply",
                        "reason": "dynamic",
                        "top": candidate_top,
                        "delta": delta,
                        "plannedEffectiveOrder": effective_order,
                        "result": result,
                    })
                    alert_auth_order_drift(config, state, result, "dynamic")
                    rstate["lastAppliedAt"] = ts()
                    rstate["lastAppliedTop"] = candidate_top
                    rstate["lastAppliedOrder"] = effective_order
                else:
                    append_history(state, {
                        "at": ts(),
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
    ensure_account_state(config, state)
    task = task_record(state, lane, task_id)
    pid, meta = select_profile(config, state, lane, task_id, project, force_profile)

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
        agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
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
    known = {a["profileId"] for a in config.get("accounts", [])}
    if profile not in known:
        raise RuntimeError(f"Unknown profile: {profile}")
    state["override"] = {"enabled": True, "profileId": profile, "setAt": ts()}
    append_history(state, {"at": ts(), "type": "override_set", "profileId": profile})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "override": state["override"]}, indent=2))
    return 0


def cmd_override_clear(state: Dict[str, Any]) -> int:
    state["override"] = {"enabled": False, "profileId": None, "setAt": ts()}
    append_history(state, {"at": ts(), "type": "override_clear"})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "override": state["override"]}, indent=2))
    return 0


def cmd_focus_set(state: Dict[str, Any], project: str) -> int:
    state["focus"] = {"enabled": True, "project": project, "setAt": ts()}
    append_history(state, {"at": ts(), "type": "focus_set", "project": project})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "focus": state["focus"]}, indent=2))
    return 0


def cmd_focus_clear(state: Dict[str, Any]) -> int:
    state["focus"] = {"enabled": False, "project": None, "setAt": ts()}
    append_history(state, {"at": ts(), "type": "focus_clear"})
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "focus": state["focus"]}, indent=2))
    return 0


def cmd_alert_test(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    r = send_alert(config, state, "CRITICAL", "Alert test from oauth_pool_router.py", code="ALERT_TEST", impact="Synthetic test alert only.", auto_action="No runtime action taken.", your_action="No action.")
    save_json(STATE_PATH, state)
    print(json.dumps({"ok": True, "alert": r}, indent=2))
    return 0

def cmd_account_name_set(config: Dict[str, Any], state: Dict[str, Any], profile: str, name: str) -> int:
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


def cmd_probe_usage(config: Dict[str, Any], state: Dict[str, Any], json_mode: bool = False) -> int:
    ensure_account_state(config, state)
    active = {k: v for k, v in state.get("leases", {}).items() if v.get("active")}
    if active:
        raise RuntimeError("Cannot run probe while active leases exist (would reorder auth mid-task).")

    provider = config.get("provider", "openai-codex")
    agent_id = (config.get("usageProbe") or {}).get("agentId", "main")
    timeout_sec = timeout_tier(config, "standard")
    original_order = get_auth_order(provider, agent_id, timeout_sec=timeout_sec)
    override_before = dict(state.get("override", {}))

    # Force explicit per-profile probe regardless of background mode.
    probe = observe_usage_by_profile(config, state)
    observed_at = ts()

    # Update state with probe results for instant operator visibility.
    for a in config.get("accounts", []):
        pid = a.get("profileId")
        st = state.get("accounts", {}).get(pid, {})
        snap = probe.get(pid)
        if snap:
            st["usage"] = {
                "available": bool(snap.get("available", False)),
                "fiveHourRemaining": snap.get("fiveHourRemaining"),
                "weekRemaining": snap.get("weekRemaining"),
                "observedAt": snap.get("observedAt", observed_at),
                "source": "probe",
            }
            state["accounts"][pid] = st

    # Restore exact auth order and preserve override metadata.
    if original_order:
        set_auth_order(provider, agent_id, original_order, timeout_sec=timeout_sec)
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
    acq.add_argument("--project", choices=["project-a", "project-b", "project-c"], default=None)
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

    fo = sub.add_parser("focus")
    fosub = fo.add_subparsers(dest="fo_cmd", required=True)
    fos = fosub.add_parser("set")
    fos.add_argument("--project", required=True, choices=["project-a", "project-b", "project-c"])
    fosub.add_parser("clear")

    sub.add_parser("alert-test")
    sub.add_parser("sync-profiles")

    pr = sub.add_parser("probe")
    pr.add_argument("--json", action="store_true")

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
        "focus",
        "alert-test",
        "sync-profiles",
        "probe",
        "watchdog",
        "account-name",
    }

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

    try:
        config = load_validated_json(CONFIG_PATH, default_config(), validator=validate_config, snapshot_path=CONFIG_LKG_PATH, kind="config")
        state = load_validated_json(STATE_PATH, default_state(), validator=validate_state, snapshot_path=STATE_LKG_PATH, kind="state")
        ensure_account_state(config, state)
        state["version"] = max(int(state.get("version", 0) or 0), SCHEMA_VERSION)

        if args.command == "status":
            return cmd_status(config, state, args.json)
        if args.command == "tick":
            return cmd_tick(config, state)
        if args.command == "lease-acquire":
            return cmd_lease_acquire(config, state, args.lane, args.task_id, args.project, args.force_profile)
        if args.command == "lease-release":
            return cmd_lease_release(config, state, args.lane, args.task_id, args.result)
        if args.command == "override":
            return cmd_override_set(config, state, args.profile) if args.ov_cmd == "set" else cmd_override_clear(state)
        if args.command == "focus":
            return cmd_focus_set(state, args.project) if args.fo_cmd == "set" else cmd_focus_clear(state)
        if args.command == "alert-test":
            return cmd_alert_test(config, state)
        if args.command == "sync-profiles":
            return cmd_sync_profiles(config, state)
        if args.command == "probe":
            return cmd_probe_usage(config, state, args.json)
        if args.command == "watchdog":
            return cmd_watchdog(config, state, args.json) if getattr(args, "run_live", False) else cmd_watchdog_cached(config, state, args.json)
        if args.command == "health-check":
            return cmd_health_check(config, state, args.json)
        if args.command == "account-name":
            if args.an_cmd == "set":
                return cmd_account_name_set(config, state, args.profile, args.name)
        raise RuntimeError(f"Unknown command: {args.command}")
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    finally:
        release_router_lock(lock_fh)


if __name__ == "__main__":
    raise SystemExit(main())
