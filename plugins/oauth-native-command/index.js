import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_DIR = fileURLToPath(new URL('.', import.meta.url));
const DEFAULT_WORKSPACE_DIR = fileURLToPath(new URL('../../', import.meta.url));
const CALLBACK_NS = 'oauth';
let ACTIVE_API = null;

function resolveWorkspaceDir(api) {
  const pluginCfg = api?.pluginConfig || {};
  const candidates = [
    pluginCfg.workspacePath,
    api?.workspaceDir,
    process.env.OPENCLAW_WORKSPACE_DIR,
    process.cwd(),
    DEFAULT_WORKSPACE_DIR,
  ];
  for (const value of candidates) {
    const raw = String(value || '').trim();
    if (!raw) continue;
    return path.resolve(raw);
  }
  return path.resolve(MODULE_DIR, '../../');
}

function resolveRuntimePaths(api = ACTIVE_API) {
  const workspaceDir = resolveWorkspaceDir(api);
  const opsDir = path.join(workspaceDir, 'ops');
  return {
    workspaceDir,
    routerPath: path.join(opsDir, 'scripts', 'oauth_command_router.py'),
    statePath: path.join(opsDir, 'state', 'oauth-pool-state.json'),
    configPath: path.join(opsDir, 'state', 'oauth-pool-config.json'),
  };
}

function toList(value, fallback = []) {
  if (Array.isArray(value)) return value.map((v) => String(v)).filter(Boolean);
  return fallback;
}

function readJson(path, fallback = {}) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return fallback;
  }
}

function normalizeTelegramId(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  return raw.startsWith('telegram:') ? raw.slice('telegram:'.length) : raw;
}

function normalizeDiscordChannelId(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.startsWith('channel:')) return raw.slice('channel:'.length);
  return raw;
}

function shortName(profileId, fallback = '?') {
  const raw = String(profileId || fallback);
  const cleaned = raw.replace(/^codex-oauth-/i, '');
  return cleaned.slice(0, 18);
}

function fmtNum(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return String(Math.round(value));
}

function parseExpiry(value) {
  if (value === null || value === undefined || value === '') return null;
  try {
    if (typeof value === 'number') return new Date(value);
    return new Date(String(value));
  } catch {
    return null;
  }
}

function daysLeftFromDate(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return null;
  return (date.getTime() - Date.now()) / 86400000;
}

function fmtExpiry(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return 'exp ?';
  const fmt = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Sofia',
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  return `exp ${fmt.format(date)}`;
}

function shortIn(ms, fallback = 'unknown') {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return fallback;
  if (ms <= 0) return 'now';
  const totalMinutes = Math.max(1, Math.round(ms / 60000));
  if (totalMinutes < 60) return `${totalMinutes}m`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours < 48) return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours ? `${days}d ${remHours}h` : `${days}d`;
}

function fmtReset(resetAt, bucket) {
  const target = parseExpiry(resetAt);
  if (!(target instanceof Date) || Number.isNaN(target.getTime())) return bucket === 'week' ? 'wk reset unavailable' : '5h reset unavailable';
  const fmt = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Sofia',
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  const diffMs = target.getTime() - Date.now();
  return `${bucket === 'week' ? 'wk' : '5h'} resets by ${fmt.format(target)} (${shortIn(diffMs, 'unknown')})`;
}

function average(values) {
  const nums = values.filter((v) => typeof v === 'number' && Number.isFinite(v));
  if (!nums.length) return null;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function buildDeny(text) {
  return { text: `OAUTH DENY | ${text}` };
}

function resolveSessionKey(ctx) {
  const candidates = [ctx?.sessionKey, ctx?.commandTargetSessionKey, ctx?.session?.key, ctx?.sessionCtx?.sessionKey];
  for (const value of candidates) {
    const raw = String(value || '').trim();
    if (raw) return raw;
  }
  return '';
}

function runRouter(commandText, ctx = {}) {
  const runtime = resolveRuntimePaths();
  const args = [runtime.routerPath, '--json', commandText];
  const sessionKey = resolveSessionKey(ctx);
  if (sessionKey) args.push('--session-key', sessionKey);
  const res = spawnSync('python3', args, {
    cwd: runtime.workspaceDir,
    encoding: 'utf8',
    timeout: 120000,
    env: process.env,
  });
  const stdout = String(res.stdout || '').trim();
  const stderr = String(res.stderr || '').trim();
  if (res.error) return { ok: false, message: `OAUTH FAIL | ${res.error.message}` };
  if (res.status !== 0 && !stdout) return { ok: false, message: stderr || `OAUTH FAIL | exit=${res.status}` };
  try {
    return stdout ? JSON.parse(stdout) : { ok: false, message: stderr || 'OAUTH FAIL | empty response' };
  } catch {
    return { ok: false, message: stdout || stderr || `OAUTH FAIL | exit=${res.status}` };
  }
}

function isAllowed(ctx, api) {
  const pluginCfg = api.pluginConfig || {};
  const allowedTelegramSenderIds = toList(pluginCfg.telegramSenderIds, []).map(normalizeTelegramId);
  const allowedTelegramChatIds = toList(pluginCfg.telegramChatIds, []).map(normalizeTelegramId);
  const allowedDiscordChannelIds = toList(pluginCfg.discordChannelIds, []).map(normalizeDiscordChannelId);

  if (ctx.channel === 'telegram') {
    const sender = normalizeTelegramId(ctx.senderId || ctx.sender?.id || ctx.from || ctx.callback?.chatId);
    const chatId = normalizeTelegramId(ctx.channelId || ctx.to || ctx.callback?.chatId);
    const senderOk = (!!sender && allowedTelegramSenderIds.includes(sender)) || ctx?.auth?.isAuthorizedSender === true || ctx.isAuthorizedSender === true;
    if (!senderOk) return 'telegram sender not allowed';
    if (chatId && !allowedTelegramChatIds.includes(chatId) && ctx?.auth?.isAuthorizedSender !== true && ctx.isAuthorizedSender !== true) return 'telegram chat not allowed';
    return null;
  }
  if (ctx.channel === 'discord') {
    const channelId = normalizeDiscordChannelId(ctx.channelId || ctx.to || ctx.from || ctx.interaction?.channelId);
    if (!allowedDiscordChannelIds.includes(channelId)) return 'discord channel not allowed';
    if (ctx?.auth?.isAuthorizedSender === false || ctx.isAuthorizedSender === false) return 'discord sender not allowed';
    return null;
  }
  return `channel not supported (${ctx.channel || 'unknown'})`;
}
function deriveLegacySnapshot() {
  const config = readJson(resolveRuntimePaths().configPath, {});
  const state = readJson(resolveRuntimePaths().statePath, {});
  const defs = new Map((Array.isArray(config.accounts) ? config.accounts : []).map((a) => [String(a.profileId || ''), a]));
  const accounts = state.accounts && typeof state.accounts === 'object' ? state.accounts : {};
  const override = state.override && typeof state.override === 'object' ? state.override : {};
  const routing = state.routing && typeof state.routing === 'object' ? state.routing : {};
  const degraded = (((state.operations || {}).degradedMode) || {}).active === true;
  const emergencyLock = config.emergencyLock && typeof config.emergencyLock === 'object' ? config.emergencyLock : {};
  const emergencyActive = emergencyLock.enabled === true;
  const mode = emergencyActive ? 'EMERGENCY' : (degraded ? 'SAFE' : (override.enabled && override.profileId ? 'MANUAL' : 'AUTO'));
  const lastDecisionAt = parseExpiry(routing.lastDecisionAt);
  const lastAppliedAt = parseExpiry(routing.lastAppliedAt);
  const staleLastApplied = !!(routing.lastAppliedTop && lastDecisionAt && lastAppliedAt && lastAppliedAt < lastDecisionAt);
  const activeId = (override.enabled && override.profileId)
    || routing.currentTarget
    || routing.selectedTarget
    || (!staleLastApplied ? (routing.actuatedTarget || routing.lastAppliedTop) : null)
    || null;

  const rows = Object.entries(accounts).map(([profileId, acc]) => {
    const def = defs.get(profileId) || {};
    const health = acc.health || {};
    const usage = acc.usage || {};
    const auth = acc.auth || {};
    const quarantine = acc.quarantine || {};
    const expiresDate = parseExpiry(health.expiresAt);
    const daysLeft = daysLeftFromDate(expiresDate);
    const expired = Boolean(health.expired) || (typeof daysLeft === 'number' && daysLeft <= 0);
    const authStatus = String(auth.status || 'UNKNOWN').toUpperCase();
    const enabled = def.enabled !== false && acc.enabled !== false;
    const observedAt = usage.observedAt || health.observedAt || null;
    const healthy = enabled && authStatus === 'ALIVE' && health.healthy !== false && !expired;
    const five = typeof usage.fiveHourRemaining === 'number' ? usage.fiveHourRemaining : null;
    const week = typeof usage.weekRemaining === 'number' ? usage.weekRemaining : null;
    let capacityState = 'capacity_ok';
    if ((week !== null && week <= 0) || (five !== null && five <= 0)) capacityState = 'capacity_exhausted';
    else if ((week !== null && week <= 10) || (five !== null && five <= 10)) capacityState = 'capacity_tight';
    const reauthNow = expired || ['DEAD', 'UNAUTHORIZED', 'AUTH'].includes(authStatus);
    const reauthSoon = !reauthNow && typeof daysLeft === 'number' && daysLeft <= 2;
    const unknown = !enabled || authStatus === 'UNKNOWN';
    const quarantined = quarantine.active === true;
    const ready = healthy && !quarantined && capacityState !== 'capacity_exhausted';
    const resetBucket = capacityState === 'capacity_exhausted' ? ((week !== null && week <= 0) ? 'week' : '5h') : null;
    let dot = '🟢';
    if (capacityState === 'capacity_exhausted') dot = '⚫';
    else if (reauthNow) dot = '🔴';
    else if (unknown) dot = '⚪';
    else if (reauthSoon) dot = '🟡';
    else if (quarantined || capacityState === 'capacity_tight') dot = '🟠';
    let stateLabel = 'ready';
    if (capacityState === 'capacity_exhausted') { if (resetBucket === 'week') { if (usage.weekExhaustionState === 'confirmed_exhausted') stateLabel = fmtReset(usage.weekResetAtDerived || usage.weekResetAt, 'week'); else if (usage.weekExhaustionState === 'candidate_exhausted') stateLabel = 'wk exhaustion confirming'; else if (usage.weekExhaustionState === 'candidate_recovered') stateLabel = 'wk recovery confirming'; else stateLabel = 'wk reset unavailable'; } else { stateLabel = fmtReset(usage.fiveHourResetAt, '5h'); } }
    else if (reauthNow) stateLabel = expired ? 'expired' : 'dead';
    else if (quarantined) stateLabel = 'quarantine';
    else if (reauthSoon) stateLabel = `reauth ${daysLeft <= 1 ? '1d' : '2d'}`;
    else if (capacityState === 'capacity_tight') stateLabel = 'tight';
    return {
      profileId,
      name: String(def.name || profileId),
      enabled,
      dot,
      ready,
      healthy,
      reauthNow,
      reauthSoon,
      exhausted: capacityState === 'capacity_exhausted',
      stateLabel,
      fiveHourRemaining: five,
      weekRemaining: week,
      expiryText: reauthSoon || reauthNow ? fmtExpiry(expiresDate) : '',
      activeLeaseCount: Number(acc.activeLeaseCount || 0),
      isActive: profileId === activeId,
    };
  });

  rows.sort((a, b) => {
    if (a.isActive !== b.isActive) return a.isActive ? -1 : 1;
    const score = (r) => (r.dot === '🟢' ? 4 : r.dot === '🟠' ? 3 : r.dot === '⚪' ? 2 : 1);
    if (score(a) !== score(b)) return score(b) - score(a);
    const wA = typeof a.weekRemaining === 'number' ? a.weekRemaining : -1;
    const wB = typeof b.weekRemaining === 'number' ? b.weekRemaining : -1;
    return wB - wA;
  });

  const readyCount = rows.filter((r) => r.ready).length;
  const manualCheckCount = rows.filter((r) => r.telemetryUnauthorized).length;
  const healthyCount = rows.filter((r) => r.healthy).length;
  const reauthNowCount = rows.filter((r) => r.reauthNow).length;
  const reauthWarnCount = rows.filter((r) => r.reauthSoon).length;
  const exhaustedCount = rows.filter((r) => r.exhausted).length;
  const deadCount = rows.filter((r) => r.dot === '🔴').length;
  const leaseCount = rows.reduce((a, r) => a + r.activeLeaseCount, 0);
  const avg5 = average(rows.map((r) => r.fiveHourRemaining));
  const avgWeek = average(rows.map((r) => r.weekRemaining));

  const critical = reauthNowCount > 0 || deadCount > 0 || readyCount < 4;
  const warning = !critical && (exhaustedCount > 0 || reauthWarnCount >= 3 || (avgWeek !== null && avgWeek < 25));

  let summary = '✅ Pool healthy.';
  if (critical) summary = '⚠️ Pool weak. Reauth/add accounts now.';
  else if (warning) summary = '⚠️ Pool usable, but buffer is thinning.';

  let recommendation = '✅ No new accounts needed.';
  if (critical) recommendation = '➕ Add accounts now.';
  else if (warning) recommendation = '➕ Add 1 account soon for buffer.';

  const runtimeHead = activeId || routing.currentTarget || routing.selectedTarget || (!staleLastApplied ? (routing.actuatedTarget || routing.lastAppliedTop) : null) || null;
  const policyHead = routing.selectedTarget || routing.currentTarget || (!staleLastApplied ? (routing.lastAppliedTop || routing.actuatedTarget) : null) || activeId || null;
  const controlHead = routing.currentTarget || routing.selectedTarget || (!staleLastApplied ? (routing.actuatedTarget || routing.lastAppliedTop) : null) || activeId || policyHead || runtimeHead || null;
  const severity = critical ? 'CRITICAL' : (warning ? 'WARNING' : 'HEALTHY');

  return {
    mode,
    statusLabel: mode,
    emergencyActive,
    emergencyReason: String(emergencyLock.reason || ''),
    activeId,
    activeName: rows.find((r) => r.isActive)?.name || shortName(activeId || 'none', 'none'),
    runtimeHead,
    policyHead,
    controlHead,
    severity,
    summary,
    recommendation,
    readyCount,
    healthyCount,
    reauthNowCount,
    reauthWarnCount,
    exhaustedCount,
    deadCount,
    leaseCount,
    avg5,
    avgWeek,
    rows,
  };
}

function deriveSnapshot(ctx = {}) {
  try {
    return routerStatusSnapshot(runRouter('/oauth status', ctx));
  } catch {
    return deriveLegacySnapshot();
  }
}

function routerStatusSnapshot(liveStatus = null, ctx = {}) {
  if (!liveStatus || typeof liveStatus !== 'object') {
    try {
      liveStatus = runRouter('/oauth status', ctx);
    } catch {
      liveStatus = null;
    }
  }
  const state = readJson(resolveRuntimePaths().statePath, {});
  const accounts = state.accounts && typeof state.accounts === 'object' ? state.accounts : {};
  const routing = state.routing && typeof state.routing === 'object' ? state.routing : {};
  const currentTarget = String(routing.currentTarget || routing.selectedTarget || '');
  const nowMs = Date.now();
  const rows = Object.entries(accounts).map(([profileId, acc]) => {
    const auth = acc.auth || {};
    const verification = acc.verification || {};
    const health = acc.health || {};
    const usage = acc.usage || {};
    const authStatus = String(auth.status || 'UNKNOWN').toUpperCase();
    const verifyStatus = String(verification.status || 'UNKNOWN').toUpperCase();
    const stage = String(health.stage || '').toLowerCase();
    const five = typeof usage.fiveHourRemaining === 'number' ? usage.fiveHourRemaining : null;
    const week = typeof usage.weekRemaining === 'number' ? usage.weekRemaining : null;
    const observedAt = usage.observedAt || health.observedAt || null;
    const expiresAt = typeof health.expiresAt === 'number' ? health.expiresAt : null;
    const expired = health.expired === true || stage === 'expired';
    const daysLeft = expiresAt ? (expiresAt - nowMs) / 86400000 : null;
    const reauthNow = expired || authStatus === 'DEAD' || authStatus === 'UNAUTHORIZED' || authStatus === 'AUTH';
    const reauthSoon = !reauthNow && typeof daysLeft === 'number' && daysLeft <= 2;
    const exhausted = (typeof five === 'number' && five <= 0) || (typeof week === 'number' && week <= 0);
    const telemetryUnauthorized = !reauthNow && authStatus === 'ALIVE' && verifyStatus === 'VERIFIED' && String(usage.reason || '').toLowerCase() === 'http_401';
    const ready = verifyStatus === 'VERIFIED' && !reauthNow && !exhausted && !telemetryUnauthorized;
    const authOnly = !ready && !reauthNow && !exhausted && authStatus === 'ALIVE';
    const healthy = !reauthNow && !exhausted && !telemetryUnauthorized && (ready || authOnly || stage === 'healthy' || stage === 'ready');
    let dot = '⚪';
    if (ready) dot = '🟢';
    else if (reauthNow) dot = '🔴';
    else if (reauthSoon) dot = '🟡';
    else if (exhausted) dot = '⚫';
    else if (telemetryUnauthorized) dot = '🟡';
    else if (authOnly) dot = '🟠';
    let stateLabel = 'unknown';
    if (reauthNow) stateLabel = expired ? 'expired' : 'dead';
    else if (telemetryUnauthorized) stateLabel = 'manual check required';
    else if (reauthSoon) stateLabel = `reauth ${daysLeft <= 1 ? '1d' : '2d'}`;
    else if (exhausted) stateLabel = typeof week === 'number' && week <= 0 ? 'weekly exhausted' : '5h exhausted';
    else if (ready) stateLabel = 'ready';
    else if (authOnly) stateLabel = 'auth only';
    else if (stage) stateLabel = stage;
    let expiryText = '';
    if (typeof daysLeft === 'number' && daysLeft > 0) expiryText = `expires in ${shortIn(daysLeft * 86400000, 'unknown')}`;
    else if (reauthNow && expired) expiryText = `expired ${shortIn(Math.abs(daysLeft || 0) * 86400000, 'unknown')} ago`;
    let resetText = '';
    if (exhausted) { if (typeof week === 'number' && week <= 0) { if (usage.weekExhaustionState === 'confirmed_exhausted') resetText = fmtReset(usage.weekResetAtDerived || usage.weekResetAt, 'week'); else if (usage.weekExhaustionState === 'candidate_exhausted') resetText = 'wk exhaustion confirming'; else if (usage.weekExhaustionState === 'candidate_recovered') resetText = 'wk recovery confirming'; else resetText = 'wk reset unavailable'; } else { resetText = fmtReset(usage.fiveHourResetAt, '5h'); } }
    return {
      profileId: String(profileId),
      name: shortName(profileId),
      enabled: acc.enabled !== false,
      dot,
      ready,
      authOnly,
      healthy,
      reauthNow,
      reauthSoon,
      exhausted,
      stateLabel,
      fiveHourRemaining: five,
      weekRemaining: week,
      observedAt,
      expiryText,
      resetText,
      expiresAt,
      daysLeft,
      activeLeaseCount: Number(acc.activeLeaseCount || 0),
      isActive: String(profileId) === currentTarget,
      authSource: auth.source || null,
      usageSource: usage.source || null,
      usageTrust: usage.trust || null,
      frontloadedProfileId: usage.frontloadedProfileId || null,
      telemetryMismatch: usage.frontloadedProfileId && String(usage.frontloadedProfileId) !== String(profileId),
      telemetryUnauthorized,
    };
  });
  rows.sort((a, b) => {
    const rank = (r) => {
      if (r.isActive) return 100;
      if (r.ready) return 90;
      if (r.authOnly) return 75;
      if (r.reauthSoon) return 50;
      if (r.exhausted) return 30;
      if (r.reauthNow) return 10;
      return 0;
    };
    const ra = rank(a), rb = rank(b);
    if (ra !== rb) return rb - ra;
    const wa = typeof a.weekRemaining === 'number' ? a.weekRemaining : -1;
    const wb = typeof b.weekRemaining === 'number' ? b.weekRemaining : -1;
    if (wa !== wb) return wb - wa;
    const fa = typeof a.fiveHourRemaining === 'number' ? a.fiveHourRemaining : -1;
    const fb = typeof b.fiveHourRemaining === 'number' ? b.fiveHourRemaining : -1;
    if (fa !== fb) return fb - fa;
    return a.name.localeCompare(b.name);
  });
  const localReadyCount = rows.filter((r) => r.ready).length;
  const manualCheckCount = rows.filter((r) => r.telemetryUnauthorized).length;
  const localHealthyCount = rows.filter((r) => r.healthy).length;
  const reauthNowCount = rows.filter((r) => r.reauthNow).length;
  const reauthWarnCount = rows.filter((r) => r.reauthSoon).length;
  const localExhaustedCount = rows.filter((r) => r.exhausted).length;
  const deadCount = rows.filter((r) => r.reauthNow).length;
  const leaseCount = rows.reduce((a, r) => a + r.activeLeaseCount, 0);
  const avg = (vals) => {
    const nums = vals.filter((v) => typeof v === 'number');
    if (!nums.length) return null;
    return Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 10) / 10;
  };
  const avg5 = avg(rows.filter((r) => !r.reauthNow).map((r) => r.fiveHourRemaining));
  const avgWeek = avg(rows.filter((r) => !r.reauthNow).map((r) => r.weekRemaining));
  const alertFamilies = state.alerts && typeof state.alerts.families === 'object' ? state.alerts.families : {};
  const advisorFamily = alertFamilies.advisor_add && typeof alertFamilies.advisor_add === 'object' ? alertFamilies.advisor_add : null;
  const advisorMetric = advisorFamily && typeof advisorFamily.metric === 'number' ? Math.abs(advisorFamily.metric) : null;
  const poolSummary = liveStatus && typeof liveStatus.poolSummary === 'object' ? liveStatus.poolSummary : {};
  const advisor = liveStatus && typeof liveStatus.lifecycleAdvisor === 'object' ? liveStatus.lifecycleAdvisor : {};
  const advisorPoolSummary = advisor && typeof advisor.poolSummary === 'object' ? advisor.poolSummary : {};
  const compositeHealthPct = typeof poolSummary.compositeHealthPct === 'number'
    ? poolSummary.compositeHealthPct
    : typeof advisorPoolSummary.compositeHealthPct === 'number'
      ? advisorPoolSummary.compositeHealthPct
      : typeof (liveStatus && liveStatus.poolUsage && liveStatus.poolUsage.compositeHealthPct) === 'number'
        ? liveStatus.poolUsage.compositeHealthPct
        : advisorMetric;
  const advisorRecommendation = advisor && typeof advisor.recommendation === 'object' ? advisor.recommendation : {};
  let recommendation = String(poolSummary.action || liveStatus?.capacityRecommendation || advisorRecommendation.message || '').trim();
  let recommendationLevel = String(liveStatus?.capacityRecommendationLevel || poolSummary.state || advisorRecommendation.level || '').trim().toLowerCase();
  if (!recommendation) recommendation = 'No new accounts needed.';
  if (!recommendationLevel) recommendationLevel = 'ok';
  const poolUsage = liveStatus && typeof liveStatus.poolUsage === 'object' ? liveStatus.poolUsage : {};
  const stateCounts = poolUsage && typeof poolUsage.stateCounts === 'object' ? poolUsage.stateCounts : {};
  const readyCount = Number.isFinite(Number(poolSummary.fullyReadyCount)) ? Number(poolSummary.fullyReadyCount) : localReadyCount;
  const healthyCount = Number.isFinite(Number(poolSummary.healthyCount)) ? Number(poolSummary.healthyCount) : localHealthyCount;
  const exhaustedCount = (Number(stateCounts.exhausted || 0) + Number(stateCounts.hold || 0)) || localExhaustedCount;
  const drift = [];
  const runtimeHead = routing.currentTarget || null;
  const policyHead = routing.selectedTarget || runtimeHead || null;
  const controlHead = runtimeHead || policyHead || null;
  const heads = [runtimeHead, policyHead, controlHead].filter(Boolean);
  if (heads.length > 1 && new Set(heads).size > 1) {
    drift.push(`runtime=${shortName(runtimeHead || 'none', 'none')}`);
    drift.push(`policy=${shortName(policyHead || 'none', 'none')}`);
    drift.push(`control=${shortName(controlHead || 'none', 'none')}`);
  }
  return {
    mode: 'AUTO',
    statusLabel: 'AUTO',
    runtimeHead,
    policyHead,
    controlHead,
    activeName: shortName(runtimeHead || 'none', 'none'),
    summary: String((liveStatus && liveStatus.message) || 'OAUTH'),
    recommendation,
    recommendationLevel,
    driftHeads: drift,
    readyCount,
    healthyCount,
    reauthNowCount,
    reauthWarnCount,
    exhaustedCount,
    deadCount,
    leaseCount,
    avg5,
    avgWeek,
    compositeHealthPct,
    rows,
    raw: state,
  };
}

function parseCommandArgs(rawArgs) {
  const raw = String(rawArgs || '').trim();
  if (!raw) return { view: 'menu', commandText: '/oauth status' };
  const lower = raw.toLowerCase();
  if (lower === 'refresh' || lower === 'status') return { view: 'menu', commandText: '/oauth status' };
  if (lower === 'more') return { view: 'more', commandText: '/oauth help' };
  if (lower === 'help') return { view: 'help', commandText: '/oauth help' };
  if (lower === 'health') return { view: 'health', commandText: '/oauth health' };
  if (lower === 'probe') return { view: 'probe', commandText: '/oauth probe' };
  if (lower === 'auto' || lower === 'mode') return { view: 'mode-menu', commandText: '/oauth auto' };
  if (lower === 'accounts') return { view: 'accounts', commandText: '/oauth status' };
  if (lower === 'add' || lower === 'add account') return { view: 'add', commandText: '/oauth add' };
  if (lower === 'emergency-confirm') return { view: 'emergency-confirm', commandText: '/oauth emergency-status' };
  if (lower === 'reauth') return { view: 'reauth-menu', commandText: '/oauth status' };
  if (lower.startsWith('acct ')) return { view: 'acct', profileId: raw.slice(5).trim(), commandText: '/oauth status' };
  return { view: 'raw', commandText: `/oauth ${raw}` };
}

function callbackDataToCommand(callbackData) {
  const raw = String(callbackData || '').trim();
  if (raw === `${CALLBACK_NS}:menu`) return '/oauth';
  if (raw === `${CALLBACK_NS}:refresh`) return '/oauth refresh';
  if (raw === `${CALLBACK_NS}:status`) return '/oauth status';
  if (raw === `${CALLBACK_NS}:accounts`) return '/oauth accounts';
  if (raw === `${CALLBACK_NS}:more`) return '/oauth more';
  if (raw === `${CALLBACK_NS}:health`) return '/oauth health';
  if (raw === `${CALLBACK_NS}:probe`) return '/oauth probe';
  if (raw === `${CALLBACK_NS}:mode`) return '/oauth mode';
if (raw === `${CALLBACK_NS}:set-auto`) return '/oauth auto';
  if (raw === `${CALLBACK_NS}:add`) return '/oauth add';
  if (raw === `${CALLBACK_NS}:reauth-menu`) return '/oauth reauth';
  if (raw === `${CALLBACK_NS}:update-confirm`) return '/oauth update-confirm';
  if (raw === `${CALLBACK_NS}:emergency-confirm`) return '/oauth emergency-confirm';
  if (raw === `${CALLBACK_NS}:emergency-stop`) return '/oauth emergency-stop telegram-ui';
  if (raw === `${CALLBACK_NS}:emergency-resume`) return '/oauth emergency-resume';
  if (raw === `${CALLBACK_NS}:update-run`) return '/oauth openclaw update';
  if (raw.startsWith(`${CALLBACK_NS}:acct:`)) return `/oauth acct ${raw.slice(`${CALLBACK_NS}:acct:`.length)}`;
  if (raw.startsWith(`${CALLBACK_NS}:use:`)) return `/oauth use ${raw.slice(`${CALLBACK_NS}:use:`.length)}`;
  if (raw.startsWith(`${CALLBACK_NS}:reauth:`)) return `/oauth reauth ${raw.slice(`${CALLBACK_NS}:reauth:`.length)}`;
  return '/oauth';
}

function interactiveFromButtons(rows) {
  return {
    blocks: rows.map((row) => ({
      type: 'buttons',
      buttons: row.map((btn) => ({
        label: btn.text,
        value: callbackDataToCommand(btn.callback_data),
        style: btn.style === 'danger' ? 'danger' : btn.style === 'success' ? 'success' : 'primary',
      })),
    })),
  };
}
function mainMenuButtons(snapshot) {
  const secondRow = snapshot?.emergencyActive
    ? [
        { text: '▶ Resume', callback_data: `${CALLBACK_NS}:emergency-resume`, style: 'success' },
        { text: '❓ More', callback_data: `${CALLBACK_NS}:more` },
      ]
    : [
        { text: '🔐 Reauth', callback_data: `${CALLBACK_NS}:reauth-menu` },
        { text: '👥 Accounts', callback_data: `${CALLBACK_NS}:accounts` },
      ];
  return [
    [
      { text: '🔄 Refresh', callback_data: `${CALLBACK_NS}:refresh` },
      { text: '🎛 Mode', callback_data: `${CALLBACK_NS}:mode` },
    ],
    secondRow,
    [
      { text: '🧪 Health', callback_data: `${CALLBACK_NS}:health` },
      { text: '❓ More', callback_data: `${CALLBACK_NS}:more` },
    ],
  ];
}

function moreMenuButtons(snapshot) {
  const emergencyButton = snapshot?.emergencyActive
    ? { text: '▶ Resume System', callback_data: `${CALLBACK_NS}:emergency-resume`, style: 'success' }
    : { text: '🛑 Emergency Stop', callback_data: `${CALLBACK_NS}:emergency-confirm`, style: 'danger' };
  return [
    [
      { text: '➕ Add Account', callback_data: `${CALLBACK_NS}:add` },
      { text: '🧪 Health', callback_data: `${CALLBACK_NS}:health` },
    ],
    [
      { text: '👥 Accounts', callback_data: `${CALLBACK_NS}:accounts` },
      { text: '🔎 Probe', callback_data: `${CALLBACK_NS}:probe` },
    ],
    [ emergencyButton ],
    [{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:menu` }],
  ];
}

function accountButtons(rows, title = '👥 ACCOUNTS', action = 'acct') {
  const buttons = [];
  const lines = [title, ''];
  for (let i = 0; i < rows.length; i += 2) {
    const slice = rows.slice(i, i + 2);
    const row = slice.map((item) => ({
      text: `${item.dot} ${shortName(item.name || item.profileId || '?')}`,
      callback_data: action === 'reauth' ? `${CALLBACK_NS}:reauth:${item.profileId}` : `${CALLBACK_NS}:acct:${item.profileId}`,
    }));
    if (row.length) buttons.push(row);
    for (const item of slice) {
      const usage = `5h ${fmtNum(item.fiveHourRemaining)} | wk ${fmtNum(item.weekRemaining)}`;
      const expiry = item.expiryText ? ` | ${item.expiryText}` : '';
      const command = `/oauth ${action === 'reauth' ? 'reauth' : 'account'} ${item.profileId}`;
      lines.push(`${item.dot} ${shortName(item.name || item.profileId || '?')} — ${item.stateLabel}`);
      lines.push(`   ${usage}${expiry}`);
      lines.push(`   ${command}`);
    }
    if (i + 2 < rows.length) lines.push('');
  }
  buttons.push([{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:menu` }]);
  return { text: lines.join('\n').trim(), buttons };
}

function accountActionButtons(profileId) {
  return [
    [
      { text: 'Use', callback_data: `${CALLBACK_NS}:use:${profileId}`, style: 'success' },
      { text: 'Reauth', callback_data: `${CALLBACK_NS}:reauth:${profileId}` },
    ],
    [{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:reauth-menu` }],
  ];
}

function updateConfirmButtons() {
  return [[
    { text: 'Confirm update', callback_data: `${CALLBACK_NS}:update-run`, style: 'danger' },
    { text: 'Cancel', callback_data: `${CALLBACK_NS}:more` },
  ]];
}

function emergencyConfirmButtons() {
  return [[
    { text: 'Confirm STOP', callback_data: `${CALLBACK_NS}:emergency-stop`, style: 'danger' },
    { text: 'Cancel', callback_data: `${CALLBACK_NS}:more` },
  ]];
}

function modeMenuButtons(rows) {
  const buttons = [[{ text: '✅ Set AUTO', callback_data: `${CALLBACK_NS}:set-auto`, style: 'success' }]];
  for (let i = 0; i < rows.length; i += 2) {
    const row = rows.slice(i, i + 2).map((item) => ({
      text: `${item.dot} ${shortName(item.name || item.profileId || '?')}`,
      callback_data: `${CALLBACK_NS}:use:${item.profileId}`,
    }));
    if (row.length) buttons.push(row);
  }
  buttons.push([{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:menu` }]);
  return buttons;
}

function renderModeMenu(snapshot) {
  const lines = ['🎛 MODE'];
  lines.push(`Current: ${snapshot.mode} | Active: ${snapshot.activeName || 'none'}`);
  lines.push('Tap AUTO to release manual override, or pick an account to force.');
  lines.push('');
  for (const row of snapshot.rows) {
    const expiryPart = row.expiryText ? ` | ${row.expiryText}` : '';
    lines.push(`${row.dot} ${row.name} — ${row.stateLabel}`);
    lines.push(`   5h ${fmtNum(row.fiveHourRemaining)} | wk ${fmtNum(row.weekRemaining)}${expiryPart}`);
  }
  return lines.join('\n');
}

function renderDashboard(snapshot, headerMessage = null) {
  const lines = ['🧭 OAUTH'];
  if (headerMessage) lines.push(headerMessage);

  lines.push(`🤖 ${snapshot.statusLabel || snapshot.mode} · head=${shortName(snapshot.runtimeHead || 'none', 'none')}`);
  if (Array.isArray(snapshot.driftHeads) && snapshot.driftHeads.length) {
    lines.push(`⚠️ Head drift: ${snapshot.driftHeads.join(' | ')}`);
  }
  const cph = typeof snapshot.compositeHealthPct === 'number' ? snapshot.compositeHealthPct : null;
  const cphRounded = cph === null ? null : Math.round(cph * 10) / 10;
  const canonicalLevel = String(snapshot.recommendationLevel || snapshot.poolState || '').toLowerCase();
  const cphEmoji = cphRounded === null ? '⚪' : canonicalLevel === 'critical' ? '🔴' : canonicalLevel === 'warning' ? '🟡' : canonicalLevel === 'info' ? '🟡' : canonicalLevel === 'healthy' ? '🟢' : canonicalLevel === 'hold' ? '🟢' : cphRounded < 55 ? '🔴' : cphRounded < 75 ? '🟡' : '🟢';
  const cphBucket = cphRounded === null ? 'unknown' : canonicalLevel === 'critical' ? 'critical' : canonicalLevel === 'warning' ? 'warning' : canonicalLevel === 'info' ? 'tightening' : canonicalLevel === 'healthy' ? 'healthy' : canonicalLevel === 'hold' ? 'healthy' : cphRounded < 55 ? 'critical' : cphRounded < 75 ? 'tightening' : 'healthy';
  const cphText = cphRounded === null ? 'unknown' : `${cphRounded}%`;
  {
    const summaryParts = [
      `✅ Ready ${snapshot.readyCount}/${snapshot.rows.length}`,
      `❤️ Healthy ${snapshot.healthyCount}/${snapshot.rows.length}`,
    ];
    if ((snapshot.leaseCount || 0) > 0) summaryParts.push(`🔒 Leases ${snapshot.leaseCount}`);
    lines.push(summaryParts.join(' | '));
  }
  {
    const ops = [
      `🔐 Reauth ${snapshot.reauthNowCount} now / ${snapshot.reauthWarnCount} soon`,
      `⚫ Exhausted ${snapshot.exhaustedCount}`,
    ];
    if ((snapshot.manualCheckCount || 0) > 0) ops.push(`🟡 Manual check ${snapshot.manualCheckCount}`);
    lines.push(ops.join(' | '));
  }
  lines.push(`${cphEmoji} CPH ${cphText} — ${cphBucket} | Reserve 5h ${fmtNum(snapshot.avg5)} | wk ${fmtNum(snapshot.avgWeek)}`);
  if (snapshot.recommendationLevel || snapshot.recommendation) {
    const rec = String(snapshot.recommendation || '').trim() || 'No new accounts needed right now';
    lines.push(`🧠 ${rec}`);
  }

  const accountRows = snapshot.rows.filter((r) => r.ready || r.authOnly || r.reauthSoon || r.exhausted || r.reauthNow || r.telemetryUnauthorized);
  if (accountRows.length) {
    lines.push('');
    lines.push('Accounts');
    for (const row of accountRows) {
      const leader = row.isActive ? '👉 ' : '';
      lines.push(`${leader}${row.dot} ${row.name} — ${row.stateLabel}`);

      if (row.telemetryMismatch) {
        lines.push('   telemetry mismatch — inspect before trusting usage');
        continue;
      }

      if (row.telemetryUnauthorized) {
        let telemetry = 'manual check required | telemetry http_401';
        if (row.expiryText) telemetry += ` | ${row.expiryText}`;
        lines.push(`   ${telemetry}`);
        continue;
      }

      if (row.reauthNow) {
        lines.push(`   ${row.expiryText || 'reauth needed now'}`);
        continue;
      }

      if (row.exhausted) {
        lines.push(`   ${row.resetText || 'capacity exhausted'}`);
        continue;
      }

      let telemetry = `5h ${fmtNum(row.fiveHourRemaining)} | wk ${fmtNum(row.weekRemaining)}`;
      if (row.expiryText) telemetry += ` | ${row.expiryText}`;
      else if (row.authOnly) telemetry += ' | auth only';
      lines.push(`   ${telemetry}`);
    }
  }

  return lines.join('\n');
}

function buildResponse(parsed, payload, ctx = {}) {
  const usePayloadSnapshot = ['menu', 'status'].includes(parsed.view) && payload && typeof payload === 'object';
  const snapshot = usePayloadSnapshot ? routerStatusSnapshot(payload, ctx) : deriveSnapshot(ctx);
  let text = payload?.message || 'OAUTH OK';
  let buttons = mainMenuButtons(snapshot);

  if (parsed.view === 'menu' || parsed.view === 'status') {
    text = renderDashboard(snapshot, null);
    buttons = mainMenuButtons(snapshot);
  } else if (parsed.view === 'more') {
    text = '❓ OAUTH MORE\nChoose an operator action.';
    buttons = moreMenuButtons(snapshot);
  } else if (parsed.view === 'help') {
    text = payload?.message || 'OAuth commands';
    buttons = moreMenuButtons(snapshot);
  } else if (parsed.view === 'mode-menu') {
    text = renderModeMenu(snapshot);
    buttons = modeMenuButtons(snapshot.rows);
  } else if (parsed.view === 'accounts') {
    const out = accountButtons(snapshot.rows, '👥 ALL ACCOUNTS', 'acct');
    text = out.text;
    buttons = out.buttons;
  } else if (parsed.view === 'reauth-menu') {
    const urgent = snapshot.rows.filter((r) => r.reauthNow || r.reauthSoon);
    if (payload?.command === 'reauth') {
      text = payload.message;
      buttons = [[{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:menu` }]];
    } else {
      const source = urgent.length ? urgent : snapshot.rows;
      const out = accountButtons(source, urgent.length ? '🔐 REAUTH TARGETS' : '🔐 PICK ACCOUNT TO REAUTH', 'reauth');
      text = out.text;
      buttons = out.buttons;
    }
  } else if (parsed.view === 'acct') {
    const row = snapshot.rows.find((r) => r.profileId === parsed.profileId);
    text = row ? `${row.dot} ${row.name}\n5h ${fmtNum(row.fiveHourRemaining)} | wk ${fmtNum(row.weekRemaining)}${row.expiryText ? ` | ${row.expiryText}` : ''}\nState: ${row.stateLabel}` : `Account actions for ${parsed.profileId || '?'}`;
    buttons = accountActionButtons(parsed.profileId || '?');
  } else if (parsed.view === 'update-confirm') {
    text = '⚠️ OpenClaw update will run the real package update, then doctor --fix, gateway restart, and the upgrade gate. Continue?';
    buttons = updateConfirmButtons();
  } else if (parsed.view === 'emergency-confirm') {
    text = '🛑 Emergency stop will freeze automatic switching and hold the system in a safe halted state until resumed. Continue?';
    buttons = emergencyConfirmButtons();
  } else if (parsed.view === 'health') {
    text = `🧪 HEALTH\n${payload?.message || 'No data.'}`;
    buttons = moreMenuButtons(snapshot);
  } else if (parsed.view === 'probe') {
    text = `🔎 PROBE\n${payload?.message || 'No data.'}`;
    buttons = moreMenuButtons(snapshot);
  } else if (parsed.view === 'upgrade-gate') {
    text = `🛡 UPGRADE GATE\n${payload?.message || 'No data.'}`;
    buttons = moreMenuButtons(snapshot);
  } else if (['add', 'update'].includes(parsed.view)) {
    buttons = [[{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:more` }]];
  }

  return {
    text,
    buttons,
    interactive: interactiveFromButtons(buttons),
    channelData: { telegram: { buttons, refresh: { seconds: 20 } } },
  };
}
function routeInteractive(action, ctx) {
  switch (action.kind) {
    case 'menu':
    case 'refresh':
      return { parsed: { view: 'menu' }, payload: runRouter('/oauth status', ctx) };
    case 'more':
      return { parsed: { view: 'more' }, payload: { ok: true } };
    case 'status':
      return { parsed: { view: 'status' }, payload: { ok: true } };
    case 'health':
      return { parsed: { view: 'health' }, payload: runRouter('/oauth health', ctx) };
    case 'probe':
      return { parsed: { view: 'probe' }, payload: runRouter('/oauth probe', ctx) };
    case 'mode':
      return { parsed: { view: 'mode-menu' }, payload: { ok: true } };
    case 'set-auto':
      return { parsed: { view: 'menu' }, payload: runRouter('/oauth auto', ctx) };
    case 'accounts':
      return { parsed: { view: 'accounts' }, payload: { ok: true } };
    case 'reauth-menu':
      return { parsed: { view: 'reauth-menu' }, payload: { ok: true } };
    case 'acct':
      return { parsed: { view: 'acct', profileId: action.profileId }, payload: { ok: true } };
    case 'use':
      return { parsed: { view: 'menu' }, payload: runRouter(`/oauth use ${action.profileId}`, ctx) };
    case 'reauth':
      return { parsed: { view: 'reauth-menu' }, payload: runRouter(`/oauth reauth ${action.profileId}`, ctx) };
    case 'add':
      return { parsed: { view: 'add' }, payload: runRouter('/oauth add', ctx) };
    case 'emergency-confirm':
      return { parsed: { view: 'emergency-confirm' }, payload: runRouter('/oauth emergency-status', ctx) };
    case 'emergency-stop':
      return { parsed: { view: 'menu' }, payload: runRouter('/oauth emergency-stop telegram-ui', ctx) };
    case 'emergency-resume':
      return { parsed: { view: 'menu' }, payload: runRouter('/oauth emergency-resume', ctx) };
    default:
      return { parsed: { view: 'menu' }, payload: { ok: true } };
  }
}

function parseInteractivePayload(payload) {
  const raw = String(payload || '').trim();
  if (!raw || raw === 'menu') return { kind: 'menu' };
  if (['refresh', 'status', 'more', 'health', 'probe', 'accounts', 'mode', 'set-auto', 'reauth-menu', 'add', 'emergency-confirm', 'emergency-stop', 'emergency-resume'].includes(raw)) return { kind: raw };
  if (raw.startsWith('acct:')) return { kind: 'acct', profileId: raw.slice(5) };
  if (raw.startsWith('use:')) return { kind: 'use', profileId: raw.slice(4) };
  if (raw.startsWith('reauth:')) return { kind: 'reauth', profileId: raw.slice(7) };
  return { kind: 'menu' };
}

async function maybeSendTelegramMenu(api, ctx, parsed, response) {
  return null;
}

async function ackTelegramCallback(ctx) {
  try {
    if (ctx?.callbackQuery && typeof ctx.answerCallbackQuery === 'function') {
      await ctx.answerCallbackQuery();
      return true;
    }
    if (ctx?.callback && typeof ctx.callback?.id === 'string' && ctx.callback.id && ctx?.telegram?.api?.answerCallbackQuery) {
      await ctx.telegram.api.answerCallbackQuery(ctx.callback.id);
      return true;
    }
  } catch {}
  return false;
}

export default function register(api) {
  ACTIVE_API = api;
  api.registerCommand({
    name: 'oauth',
    nativeNames: { default: 'oauth' },
    description: 'OAuth pool operator dashboard and controls.',
    acceptsArgs: true,
    handler: async (ctx) => {
      const denyReason = isAllowed(ctx, api);
      if (denyReason) return { text: `OAUTH DENY | ${denyReason}` };
      const parsed = parseCommandArgs(ctx.args || '');
      let payload = parsed.commandText ? runRouter(parsed.commandText, ctx) : { ok: true, message: 'OAUTH OK' };
      if (['menu', 'status', 'accounts', 'reauth-menu', 'acct', 'mode-menu', 'more'].includes(parsed.view) && (!payload || typeof payload !== 'object')) {
        payload = { ok: true, command: parsed.view, message: '' };
      }
      return buildResponse(parsed, payload || { ok: true, command: parsed.view, message: '' });
    },
  });

api.registerInteractiveHandler({
    channel: 'telegram',
    namespace: CALLBACK_NS,
    handler: async (ctx) => {
      await ackTelegramCallback(ctx);
      const denyReason = isAllowed(ctx, api);
      if (denyReason) {
        await ctx.respond.editMessage({ text: `OAUTH DENY | ${denyReason}` });
        return { handled: true };
      }
      const action = parseInteractivePayload(ctx.callback?.payload || '');
      const heavyKinds = new Set(['reauth', 'health', 'probe', 'use', 'set-auto', 'emergency-stop', 'emergency-resume']);
      const cheapKinds = new Set(['menu', 'refresh', 'status', 'more', 'mode', 'accounts', 'reauth-menu', 'acct']);
      if (heavyKinds.has(action.kind)) {
        await ctx.respond.editMessage({
          text: '⏳ Working...',
          channelData: { telegram: { buttons: [[{ text: '⬅ Back', callback_data: `${CALLBACK_NS}:menu` }]] } }
        });
      }
      const { parsed, payload } = routeInteractive(action, ctx);
      const response = buildResponse(parsed, payload, ctx);
      await ctx.respond.editMessage(response);
      return { handled: true };
    },
  });

}
