// Вкладка «Проверка»: ввод запроса с контекстом, решение сторожа и путь до агента.

import { api, errorText } from '../api.js';
import { h, clear, decisionBadge, riskBadge, fmtTime, fmtMs, short, busy, field, select, toast, emit, ROLE_RU } from '../ui.js';
import { DEMO_USERS, ROLES, SCENARIO_GROUPS, COMPARE_PRESETS, buildContext, userById } from '../data.js';
import { requestHash } from '../shared.js';
import { categoryLabel } from '../mock/policy.js';

const state = {
  userId: DEMO_USERS[1].id,
  role: DEMO_USERS[1].role,
  prompt: '',
  history: [],
  attachments: [],
  outcome: null,      // {result, status, receipt, confirmation, request}
  stale: false,
  compare: null,
};

let root, els = {};

function currentRequest() {
  return { user_prompt: state.prompt, context: buildContext(state) };
}

async function refreshStale() {
  const pending = state.outcome?.confirmation;
  if (!pending) { state.stale = false; return; }
  const { user_prompt, context } = currentRequest();
  const hash = await requestHash(user_prompt, context);
  const stale = hash !== pending.request_hash;
  if (stale !== state.stale) { state.stale = stale; renderOutcome(); }
}

function onEdit() {
  refreshStale();
}

// ---------- форма ----------

function renderHistoryEditor() {
  const box = clear(els.history);
  if (!state.history.length) box.append(h('p', { class: 'empty' }, 'Истории нет — запрос оценивается как первая реплика.'));
  state.history.forEach((turn, i) => {
    const role = select([['user', 'user'], ['assistant', 'assistant']], turn.role, { 'aria-label': `Роль реплики ${i + 1}` });
    role.addEventListener('change', () => { turn.role = role.value; onEdit(); });
    const text = h('textarea', { rows: 2, 'aria-label': `Текст реплики ${i + 1}` });
    text.value = turn.content;
    text.addEventListener('input', () => { turn.content = text.value; onEdit(); });
    const del = h('button', { type: 'button', class: 'ghost', 'aria-label': `Удалить реплику ${i + 1}`, onclick: () => { state.history.splice(i, 1); renderHistoryEditor(); onEdit(); } }, 'Удалить');
    box.append(h('div', { class: 'item' }, role, text, del));
  });
  box.append(h('div', { class: 'row' },
    h('button', { type: 'button', class: 'chip', onclick: () => { state.history.push({ role: 'user', content: '' }); renderHistoryEditor(); onEdit(); } }, '+ реплика user'),
    h('button', { type: 'button', class: 'chip', onclick: () => { state.history.push({ role: 'assistant', content: '' }); renderHistoryEditor(); onEdit(); } }, '+ реплика assistant')));
}

function renderAttachmentsEditor() {
  const box = clear(els.attachments);
  if (!state.attachments.length) box.append(h('p', { class: 'empty' }, 'Вложений нет. Вложения — это извлечённый текст документов, логов или страниц.'));
  state.attachments.forEach((a, i) => {
    const name = h('input', { type: 'text', placeholder: 'Имя, например README.md', 'aria-label': `Имя вложения ${i + 1}` });
    name.value = a.name;
    name.addEventListener('input', () => { a.name = name.value; onEdit(); });
    const content = h('textarea', { rows: 3, class: 'code', 'aria-label': `Текст вложения ${i + 1}` });
    content.value = a.content;
    content.addEventListener('input', () => { a.content = content.value; onEdit(); });
    const del = h('button', { type: 'button', class: 'ghost', 'aria-label': `Удалить вложение ${i + 1}`, onclick: () => { state.attachments.splice(i, 1); renderAttachmentsEditor(); onEdit(); } }, 'Удалить');
    box.append(h('div', { class: 'item att' }, h('div', { class: 'att-fields' }, name, content), del));
  });
  box.append(h('button', { type: 'button', class: 'chip', onclick: () => { state.attachments.push({ type: 'document', name: '', content: '' }); renderAttachmentsEditor(); onEdit(); } }, '+ вложение'));
}

function syncIdentity() {
  els.user.value = state.userId;
  els.role.value = state.role;
  els.roleNote.textContent = state.role === userById(state.userId).role
    ? 'Роль берётся из доверенной интеграции (context.user_role), а не из текста запроса.'
    : `Роль изменена вручную для эксперимента: у пользователя по умолчанию ${userById(state.userId).role}.`;
}

function applyScenario(s) {
  const user = DEMO_USERS.find((u) => u.role === s.role) || DEMO_USERS[0];
  state.userId = user.id;
  state.role = s.role;
  state.prompt = s.prompt;
  state.history = (s.history || []).map((t) => ({ ...t }));
  state.attachments = (s.attachments || []).map((a) => ({ ...a }));
  state.outcome = null;
  state.compare = null;
  els.prompt.value = s.prompt;
  els.historyDetails.open = state.history.length > 0;
  els.attDetails.open = state.attachments.length > 0;
  syncIdentity();
  renderHistoryEditor();
  renderAttachmentsEditor();
  renderOutcome();
  renderCompare();
  els.submit.focus();
}

function renderForm() {
  els.user = select(DEMO_USERS.map((u) => [u.id, `${u.name} · ${u.id}`]), state.userId);
  els.user.addEventListener('change', () => { state.userId = els.user.value; state.role = userById(state.userId).role; syncIdentity(); onEdit(); });
  els.role = select(ROLES.map((r) => [r, ROLE_RU[r]]), state.role);
  els.role.addEventListener('change', () => { state.role = els.role.value; syncIdentity(); onEdit(); });
  els.roleNote = h('p', { class: 'muted small' });

  els.prompt = h('textarea', { rows: 4, required: true, maxlength: 20000, placeholder: 'Например: Перезапусти payments-api в production.' });
  els.prompt.addEventListener('input', () => { state.prompt = els.prompt.value; onEdit(); });

  els.history = h('div', { class: 'list-editor' });
  els.attachments = h('div', { class: 'list-editor' });
  els.historyDetails = h('details', {}, h('summary', {}, h('strong', {}, 'История диалога'), ' — context.history'), h('div', { style: 'margin-top:8px' }, els.history));
  els.attDetails = h('details', {}, h('summary', {}, h('strong', {}, 'Вложения'), ' — context.attachments'), h('div', { style: 'margin-top:8px' }, els.attachments));

  els.check = h('button', { type: 'button', class: 'secondary', onclick: () => run('check') }, 'Только проверить');
  els.submit = h('button', { type: 'submit' }, 'Проверить и отправить агенту');
  els.compareBtn = h('button', { type: 'button', class: 'secondary', onclick: runCompare }, 'Сравнить по ролям');

  const form = h('form', { class: 'card', onsubmit: (e) => { e.preventDefault(); run('submit'); } },
    h('h2', {}, 'Запрос к агенту'),
    h('div', { class: 'inline-fields' }, field('Пользователь', els.user), field('Роль (context.user_role)', els.role)),
    els.roleNote,
    field('Текст запроса (user_prompt)', els.prompt),
    h('div', { class: 'stack' }, els.historyDetails, els.attDetails),
    h('div', { class: 'row', style: 'margin-top:16px' }, els.submit, els.check, els.compareBtn),
    h('p', { class: 'muted small', style: 'margin-top:10px' }, '«Только проверить» вызывает POST /v1/check — он оценивает запрос и ничего не передаёт. «Отправить агенту» проходит полный путь через адаптер.'));

  const scenarios = h('div', { class: 'card' }, h('h2', {}, 'Демо-сценарии'),
    h('p', { class: 'muted small' }, 'Сценарий заполняет форму. Затем нажмите «Проверить и отправить агенту».'),
    ...SCENARIO_GROUPS.map((g) => h('div', { class: 'scenario-group' }, h('h3', {}, g.title),
      h('div', { class: 'row' }, ...g.items.map((s) => h('button', { type: 'button', class: 'chip', onclick: () => applyScenario(s) }, s.label))))));

  return { form, scenarios };
}

// ---------- результат ----------

function requestSummary(req) {
  const c = req.context;
  return h('div', { class: 'card' },
    h('h3', {}, 'Что проверялось'),
    h('dl', { class: 'kv' },
      h('dt', {}, 'Пользователь'), h('dd', {}, `${c.user_name} (${c.user_id})`),
      h('dt', {}, 'Роль'), h('dd', {}, h('code', {}, c.user_role)),
      h('dt', {}, 'Запрос'), h('dd', {}, req.user_prompt),
      h('dt', {}, 'История'), h('dd', {}, c.history.length ? `${c.history.length} реплик` : 'нет'),
      h('dt', {}, 'Вложения'), h('dd', {}, c.attachments.length ? c.attachments.map((a) => a.name || 'без имени').join(', ') : 'нет')),
    h('details', { style: 'margin-top:10px' }, h('summary', { class: 'small' }, 'JSON запроса к POST /v1/check'),
      h('pre', { style: 'overflow:auto;max-height:240px;margin:8px 0 0' }, JSON.stringify(req, null, 2))));
}

function resultCard(r) {
  return h('div', { class: 'card' },
    h('div', { class: 'result-head' }, decisionBadge(r.decision, true), h('span', { class: 'muted small' }, `${fmtMs(r.latency_ms)} · политика ${r.policy_version || '—'}`)),
    h('p', { class: 'explanation' }, r.explanation),
    h('dl', { class: 'kv' },
      h('dt', {}, 'Риск'), h('dd', {}, riskBadge(r.risk_level)),
      h('dt', {}, 'Категория'), h('dd', {}, h('code', {}, r.risk_category), ' — ', categoryLabel(r.risk_category)),
      r.tool ? [h('dt', {}, 'Инструмент'), h('dd', {}, h('code', {}, r.tool))] : null,
      r.env ? [h('dt', {}, 'Окружение'), h('dd', {}, h('code', {}, r.env))] : null,
      r.policy_rule ? [h('dt', {}, 'Правило'), h('dd', {}, h('code', {}, r.policy_rule))] : null,
      h('dt', {}, 'ID проверки'), h('dd', {}, h('code', {}, r.check_id || '—'))),
    r.signals?.length ? h('div', { style: 'margin-top:14px' }, h('h3', {}, 'Сигналы'),
      h('ul', { class: 'signals' }, ...r.signals.map((s) => h('li', {}, h('span', { class: 'src' }, s.source), h('strong', {}, s.label), h('span', {}, s.detail))))) : null);
}

function deliveryPanel(o) {
  if (o.mode === 'check') {
    return h('div', { class: 'delivery idle' }, h('strong', {}, 'Только оценка'),
      h('p', {}, 'POST /v1/check не передаёт запрос агенту. Чтобы пройти полный путь, нажмите «Проверить и отправить агенту».'));
  }
  if (o.status === 'forwarded') {
    return h('div', { class: 'delivery forwarded' }, h('strong', {}, o.receipt.confirmed ? 'Передано агенту после подтверждения' : 'Передано агенту'),
      h('p', {}, `Квитанция ${o.receipt.receipt_id}, получено в ${fmtTime(o.receipt.received_at)}.`),
      h('div', { class: 'row' }, h('a', { href: '#agent' }, 'Открыть входящие агента →')));
  }
  if (o.status === 'blocked') {
    return h('div', { class: 'delivery blocked' }, h('strong', {}, 'Не передано агенту'),
      h('p', {}, 'Запрос заблокирован целиком. Во входящих агента его нет.'));
  }
  const c = o.confirmation;
  const confirmBtn = h('button', { type: 'button', class: 'confirm-btn', disabled: state.stale, onclick: (e) => confirm(e.currentTarget) }, 'Подтвердить и передать');
  return h('div', { class: 'delivery pending' }, h('strong', {}, 'Ждёт явного подтверждения'),
    h('p', {}, `До подтверждения агент ничего не получает. Подтвердить может только ${userById(c.user_id).name} (${c.user_id}) до ${fmtTime(c.expires_at)}.`),
    state.stale ? h('p', {}, h('strong', {}, 'Запрос или контекст изменены после проверки.'), ' Подтверждение относится к исходному запросу — проверьте заново.') : null,
    h('div', { class: 'row' }, confirmBtn,
      state.stale ? h('button', { type: 'button', class: 'secondary', onclick: () => run('submit') }, 'Проверить заново') : null,
      h('button', { type: 'button', class: 'secondary', onclick: () => { state.outcome = null; renderOutcome(); toast('Действие отменено, агенту ничего не передано.'); } }, 'Отменить')),
    h('p', { class: 'small', style: 'margin-top:8px' }, 'Фразы «подтверждаю» или «я админ» в тексте запроса подтверждением не считаются.'));
}

function renderOutcome() {
  const box = clear(els.outcome);
  const o = state.outcome;
  if (!o) {
    box.append(h('div', { class: 'card empty-state' }, h('p', {}, 'Здесь появится решение сторожа: allow, confirm или block, уровень риска, категория и объяснение.')));
    return;
  }
  if (o.error) {
    box.append(h('div', { class: 'banner error' }, h('strong', {}, 'Проверка не выполнена. '), o.error,
      /не передан/.test(o.error) ? null : ' Агенту ничего не передано.'));
    if (o.request) box.append(requestSummary(o.request));
    return;
  }
  box.append(resultCard(o.result));
  box.lastChild.append(deliveryPanel(o));
  box.append(requestSummary(o.request));
}

function renderCompare() {
  const box = clear(els.compare);
  if (!state.compare) return;
  const { prompt, rows, loading } = state.compare;
  box.append(h('div', { class: 'card' },
    h('h3', {}, 'Один запрос — разные роли'),
    h('p', { class: 'small' }, prompt),
    h('div', { class: 'compare' }, ...ROLES.map((r) => {
      const res = rows[r];
      return h('div', { class: 'cell' }, h('h4', {}, ROLE_RU[r]),
        res?.error ? h('span', { class: 'risk high' }, res.error)
          : res ? [decisionBadge(res.decision), h('p', { class: 'small', style: 'margin:6px 0 0' }, res.explanation)]
            : loading ? h('span', { class: 'spinner', 'aria-label': 'проверяется' }) : '—');
    })),
    h('div', { class: 'row', style: 'margin-top:10px' }, h('span', { class: 'muted small' }, 'Быстрые варианты:'),
      ...COMPARE_PRESETS.map((p) => h('button', { type: 'button', class: 'chip', onclick: () => { els.prompt.value = p; state.prompt = p; onEdit(); runCompare(); } }, p)))));
}

// ---------- действия ----------

async function run(mode) {
  if (!state.prompt.trim()) { els.prompt.focus(); toast('Введите текст запроса.'); return; }
  const request = currentRequest();
  const btn = mode === 'check' ? els.check : els.submit;
  busy(btn, true, mode === 'check' ? 'Проверяем…' : 'Проверяем и отправляем…');
  try {
    if (mode === 'check') {
      const result = await api('POST', '/v1/check', request);
      state.outcome = { mode, result, request };
    } else {
      const r = await api('POST', '/v1/demo/submit', request);
      state.outcome = { mode, result: r.check, status: r.status, receipt: r.receipt, confirmation: r.confirmation, request };
    }
    state.stale = false;
    emit('checked', state.outcome.result);
  } catch (e) {
    state.outcome = { error: errorText(e), request };
  } finally {
    busy(btn, false);
  }
  renderOutcome();
  els.outcome.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function confirm(btn) {
  const o = state.outcome;
  await refreshStale();
  if (state.stale) return;
  busy(btn, true, 'Передаём…');
  try {
    const r = await api('POST', '/v1/demo/confirm', { check_id: o.confirmation.check_id, request_hash: o.confirmation.request_hash, user_id: o.confirmation.user_id });
    Object.assign(o, { status: 'forwarded', receipt: r.receipt, confirmation: null });
    toast('Подтверждено. Запрос передан агенту.');
    emit('delivered', r.receipt);
  } catch (e) {
    toast(errorText(e));
    busy(btn, false);
    return;
  }
  renderOutcome();
}

async function runCompare() {
  if (!state.prompt.trim()) { els.prompt.focus(); toast('Введите текст запроса для сравнения.'); return; }
  state.compare = { prompt: state.prompt, rows: {}, loading: true };
  renderCompare();
  busy(els.compareBtn, true, 'Сравниваем…');
  for (const role of ROLES) {
    const user = DEMO_USERS.find((u) => u.role === role);
    const req = { user_prompt: state.prompt, context: buildContext({ ...state, userId: user.id, role }) };
    try { state.compare.rows[role] = await api('POST', '/v1/check', req); }
    catch (e) { state.compare.rows[role] = { error: errorText(e) }; }
    renderCompare();
  }
  state.compare.loading = false;
  busy(els.compareBtn, false);
  renderCompare();
}

export function mount(el) {
  root = el;
  els.outcome = h('div', { 'aria-live': 'polite' });
  els.compare = h('div', { style: 'margin-top:16px' });
  const { form, scenarios } = renderForm();
  form.classList.add('area-form');
  scenarios.classList.add('area-scen');
  root.append(h('div', { class: 'check-grid' }, form, h('div', { class: 'area-out' }, els.outcome, els.compare), scenarios));
  syncIdentity();
  renderHistoryEditor();
  renderAttachmentsEditor();
  renderOutcome();
}

export function show() {}
