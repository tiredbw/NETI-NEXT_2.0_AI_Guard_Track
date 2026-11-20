// Мок бэкенда в браузере: реализует контракт из docs/FRONTEND_PROMPT.md поверх памяти вкладки.

import { DEFAULT_POLICY_YAML } from './default-policy.js';
import { loadPolicy, detectEnv, decide } from './policy.js';
import { analyze } from './detector.js';
import { requestHash, maskSecrets, canonicalJson } from '../shared.js';

export const MOCK_ADMIN_TOKEN = 'admin-demo';
export const MOCK_AUDIT_TOKEN = 'audit-demo'; // Только чтение журнала, входящих и политики, как AUDIT_TOKEN у сервиса.
const CONFIRM_TTL_MS = 10 * 60 * 1000;
const SESSION_LIMITS = { max_turns: 20, ttl_minutes: 60 };

const now = () => new Date().toISOString();
const rid = (p) => `${p}_${Math.random().toString(36).slice(2, 10)}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function shortHash(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].slice(0, 4).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function createMockServer({ latency = [80, 420] } = {}) {
  const state = {
    policy: null, journal: [], inbox: [], checks: new Map(), confirmations: new Map(), sessions: new Map(), policyHistory: [],
  };
  const ready = (async () => {
    const loaded = loadPolicy(DEFAULT_POLICY_YAML);
    const version = `${loaded.policy.version}#${await shortHash(DEFAULT_POLICY_YAML)}`;
    state.policy = { yaml: DEFAULT_POLICY_YAML, obj: loaded.policy, version, updated_at: now(), updated_by: 'исходная политика кейса', comment: 'security_policy.yaml из комплекта' };
    state.policyHistory.push({ version, updated_at: state.policy.updated_at, updated_by: state.policy.updated_by, comment: state.policy.comment });
  })();

  async function runCheck(userPrompt, context, source, keepText = true) {
    const started = performance.now();
    await sleep(latency[0] + Math.random() * (latency[1] - latency[0]));
    const { intent, signals, historyEffect } = analyze({ user_prompt: userPrompt, context });
    const envText = [userPrompt, ...(context.history || []).filter((h) => h.role === 'user').slice(-1).map((h) => h.content)].join('\n');
    const envInfo = detectEnv(state.policy.obj, userPrompt);
    if (envInfo.env === 'unknown' && signals.some((s) => s.source === 'history')) Object.assign(envInfo, detectEnv(state.policy.obj, envText));
    const role = context.user_role;
    const d = decide(state.policy.obj, role, intent, envInfo);
    if (envInfo.mixed) d.explanation += ' В запросе упомянуты и prod, и nonprod — применено более строгое правило prod.';
    signals.push({ source: 'policy', label: 'Политика', detail: d.policy_rule || 'правило не потребовалось' });
    const result = {
      decision: d.decision, risk_level: d.risk_level, risk_category: d.risk_category, explanation: d.explanation,
      latency_ms: Math.round((performance.now() - started) * 10) / 10,
      check_id: rid('chk'), request_hash: await requestHash(userPrompt, context), policy_version: state.policy.version,
      tool: d.tool, env: d.env, policy_rule: d.policy_rule, signals,
    };
    state.checks.set(result.check_id, { result, userPrompt, context });
    state.journal.unshift({
      check_id: result.check_id, ts: now(), user_id: context.user_id, user_role: role, decision: result.decision,
      risk_level: result.risk_level, risk_category: result.risk_category, latency_ms: result.latency_ms,
      policy_version: result.policy_version, source, request_hash: result.request_hash, text_stored: keepText, policy_rule: result.policy_rule,
      // Внешний /v1/check хранится без текста и объяснения, как у сервиса: закрытый тест не оседает в журнале.
      prompt_masked: keepText ? maskSecrets(userPrompt) : '', explanation: keepText ? result.explanation : '',
    });
    return { result, historyEffect };
  }

  function deliver(check, userPrompt, context, confirmed) {
    const receipt = {
      receipt_id: rid('rcp'), check_id: check.check_id, received_at: now(), user_id: context.user_id,
      user_role: context.user_role, decision: check.decision, confirmed, prompt_masked: maskSecrets(userPrompt),
    };
    state.inbox.unshift(receipt);
    return receipt;
  }

  async function submit(userPrompt, context, source) {
    const { result, historyEffect } = await runCheck(userPrompt, context, source);
    if (result.decision === 'allow') return { check: result, status: 'forwarded', receipt: deliver(result, userPrompt, context, false), confirmation: null, historyEffect };
    if (result.decision === 'block') return { check: result, status: 'blocked', receipt: null, confirmation: null, historyEffect };
    const confirmation = { check_id: result.check_id, request_hash: result.request_hash, user_id: context.user_id, expires_at: new Date(Date.now() + CONFIRM_TTL_MS).toISOString() };
    state.confirmations.set(result.check_id, { ...confirmation, used: false, source });
    return { check: result, status: 'pending_confirmation', receipt: null, confirmation, historyEffect };
  }

  const ok = (body) => ({ status: 200, body });
  const fail = (status, error, detail) => ({ status, body: { error, detail } });

  function sessionView(s, withTurns = true) {
    const { turns, ...rest } = s;
    return withTurns ? { ...rest, turns } : rest;
  }
  function getSession(id, userId) {
    const s = state.sessions.get(id);
    if (!s) return [null, fail(404, 'not_found', 'Сессия не найдена')];
    if (s.user_id !== userId) return [null, fail(403, 'wrong_user', 'Сессия принадлежит другому пользователю')];
    if (Date.parse(s.expires_at) < Date.now()) { state.sessions.delete(id); return [null, fail(410, 'expired', 'Срок хранения сессии истёк')]; }
    return [s, null];
  }
  function sessionContext(s) {
    return {
      target_agent: 'it_ops_agent', user_role: s.user_role, user_id: s.user_id, user_name: s.user_name,
      system_prompt: s.system_prompt,
      history: s.turns.map((t) => ({ role: t.role, content: t.content })),
      attachments: [],
    };
  }

  async function handle(method, url, body = null, headers = {}) {
    await ready;
    const u = new URL(url, 'http://mock.local');
    const path = u.pathname;
    const q = Object.fromEntries(u.searchParams);

    if (method === 'GET' && path === '/health') return ok({ status: 'ok', mode: 'mock', model: 'правила мока', policy_version: state.policy.version });

    if (method === 'POST' && path === '/v1/check') {
      if (typeof body?.user_prompt !== 'string' || typeof body?.context !== 'object') return fail(400, 'invalid_input', 'Нужны user_prompt и context');
      const ui = String(headers['X-Guard-Client'] || headers['x-guard-client'] || '').toLowerCase() === 'ui';
      const { result } = await runCheck(body.user_prompt, body.context, ui ? 'ui_check' : 'check', ui);
      return ok(result);
    }
    if (method === 'POST' && path === '/v1/demo/submit') {
      const { historyEffect, ...r } = await submit(body.user_prompt, body.context, 'demo');
      return ok(r);
    }
    if (method === 'POST' && path === '/v1/demo/confirm') {
      const c = state.confirmations.get(body?.check_id);
      if (!c) return fail(404, 'not_found', 'Нет ожидающего подтверждения');
      if (c.user_id !== body.user_id) return fail(403, 'wrong_user', 'Подтвердить может только автор запроса');
      if (c.used) return fail(409, 'already_used', 'Подтверждение уже использовано');
      if (c.request_hash !== body.request_hash) return fail(409, 'request_changed', 'Запрос или контекст изменены — нужна повторная проверка');
      if (Date.parse(c.expires_at) < Date.now()) return fail(410, 'expired', 'Срок подтверждения истёк');
      c.used = true;
      const { result, userPrompt, context } = state.checks.get(c.check_id);
      const receipt = deliver(result, userPrompt, context, true);
      if (c.session_id && state.sessions.has(c.session_id)) {
        const s = state.sessions.get(c.session_id);
        const t = s.turns.find((x) => x.check_id === c.check_id);
        if (t) t.decision = 'confirm';
        s.turns.push({ index: s.turns.length, role: 'assistant', content: `Агент получил подтверждённый запрос (квитанция ${receipt.receipt_id}).`, ts: now() });
      }
      return ok({ status: 'forwarded', receipt });
    }
    // Журнал, входящие агента и политика закрыты токеном, как у сервиса: админ или аудитор читают, менять может только админ.
    const readerPaths = ['/v1/journal', '/v1/agent/inbox', '/v1/policy', '/v1/policy/history'];
    if ((method === 'GET' && readerPaths.includes(path)) || (method === 'POST' && path === '/v1/policy/validate')) {
      const t = headers['X-Admin-Token'] || headers['x-admin-token'];
      if (!t) return fail(401, 'unauthorized', 'Нужен заголовок X-Admin-Token');
      if (t !== MOCK_ADMIN_TOKEN && t !== MOCK_AUDIT_TOKEN) return fail(403, 'forbidden', 'Токен не даёт доступа к журналу и политике');
    }
    if (method === 'GET' && path === '/v1/agent/inbox') return ok({ items: state.inbox.slice(0, Number(q.limit) || 50) });

    if (method === 'GET' && path === '/v1/journal') {
      let items = state.journal;
      if (q.since) items = items.filter((e) => e.ts >= new Date(q.since).toISOString());
      if (q.until) items = items.filter((e) => e.ts <= new Date(q.until).toISOString());
      if (q.decision) items = items.filter((e) => e.decision === q.decision);
      if (q.category) items = items.filter((e) => e.risk_category === q.category);
      if (q.role) items = items.filter((e) => e.user_role === q.role);
      const offset = Number(q.offset) || 0, limit = Number(q.limit) || 50;
      return ok({ items: items.slice(offset, offset + limit), total: items.length });
    }

    if (method === 'GET' && path === '/v1/policy') {
      const { obj, ...p } = state.policy;
      return ok(p);
    }
    if (method === 'GET' && path === '/v1/policy/history') return ok({ items: [...state.policyHistory].reverse() });
    if (method === 'POST' && path === '/v1/policy/validate') {
      const r = loadPolicy(body?.yaml ?? '');
      return ok({ valid: r.ok, errors: r.errors });
    }
    if (method === 'PUT' && path === '/v1/policy') {
      const token = headers['X-Admin-Token'] || headers['x-admin-token'];
      if (!token) return fail(401, 'unauthorized', 'Нужен админ-токен');
      if (token !== MOCK_ADMIN_TOKEN) return fail(403, 'forbidden', 'Токен не даёт права менять политику');
      const r = loadPolicy(body?.yaml ?? '');
      if (!r.ok) return { status: 422, body: { error: 'invalid_policy', errors: r.errors } };
      const version = `${r.policy.version}#${await shortHash(body.yaml)}`;
      state.policy = { yaml: body.yaml, obj: r.policy, version, updated_at: now(), updated_by: 'policy-admin', comment: body.comment || '' };
      state.policyHistory.push({ version, updated_at: state.policy.updated_at, updated_by: 'policy-admin', comment: state.policy.comment });
      return ok({ version, updated_at: state.policy.updated_at, updated_by: 'policy-admin' });
    }

    if (method === 'POST' && path === '/v1/sessions') {
      if (!body?.user_id || !body?.user_role) return fail(400, 'invalid_input', 'Нужны user_id и user_role');
      const s = {
        session_id: rid('ses'), user_id: body.user_id, user_name: body.user_name || '', user_role: body.user_role,
        system_prompt: body.system_prompt || '', created_at: now(),
        expires_at: new Date(Date.now() + SESSION_LIMITS.ttl_minutes * 60000).toISOString(), limits: { ...SESSION_LIMITS }, turns: [],
      };
      state.sessions.set(s.session_id, s);
      return ok(sessionView(s));
    }
    if (method === 'GET' && path === '/v1/sessions') {
      const items = [...state.sessions.values()]
        .filter((s) => s.user_id === q.user_id && Date.parse(s.expires_at) >= Date.now())
        .map((s) => ({ ...sessionView(s, false), turn_count: s.turns.filter((t) => t.role === 'user').length }));
      return ok({ items: items.reverse() });
    }
    const sm = path.match(/^\/v1\/sessions\/([\w-]+)(\/messages)?$/);
    if (sm) {
      const [s, err] = getSession(sm[1], method === 'POST' ? body?.user_id : q.user_id);
      if (err) return err;
      if (method === 'GET' && !sm[2]) return ok(sessionView(s));
      if (method === 'DELETE' && !sm[2]) { state.sessions.delete(s.session_id); return ok({ deleted: true }); }
      if (method === 'POST' && sm[2]) {
        if (s.turns.filter((t) => t.role === 'user').length >= s.limits.max_turns) return fail(409, 'session_full', `Лимит ${s.limits.max_turns} реплик исчерпан — очистите или создайте сессию`);
        const ctx = { ...sessionContext(s), attachments: body.attachments || [] };
        const blockedBefore = s.turns.filter((t) => t.role === 'user' && t.decision === 'block');
        const r = await submit(body.user_prompt, ctx, 'session');
        if (r.historyEffect && blockedBefore.length) {
          const known = new Set(r.historyEffect.flagged.map((f) => f.turn));
          for (const t of blockedBefore) if (!known.has(t.index)) r.historyEffect.flagged.push({ turn: t.index, reason: 'заблокирована ранее' });
          r.historyEffect.flagged.sort((a, b) => a.turn - b.turn);
          if (!r.check.signals.some((x) => x.source === 'history')) {
            r.historyEffect.note = `В истории есть заблокированные реплики (${blockedBefore.map((t) => '№' + (t.index + 1)).join(', ')}): агенту они не передавались. Текущий запрос с ними не связан и оценён отдельно.`;
          }
        }
        s.turns.push({ index: s.turns.length, role: 'user', content: body.user_prompt, ts: now(), decision: r.check.decision, check_id: r.check.check_id });
        if (r.status === 'forwarded') s.turns.push({ index: s.turns.length, role: 'assistant', content: `Агент получил запрос (квитанция ${r.receipt.receipt_id}).`, ts: now() });
        if (r.confirmation) state.confirmations.get(r.check.check_id).session_id = s.session_id;
        const { historyEffect, ...rest } = r;
        return ok({ ...rest, history_effect: historyEffect || { turns_considered: 0, flagged: [], note: 'Это первая реплика сессии — истории нет.' }, session: sessionView(s) });
      }
    }
    return fail(404, 'not_found', `${method} ${path}`);
  }

  return { handle, ready, _state: state, _canonical: canonicalJson };
}
