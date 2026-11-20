// Вкладка «Политика»: действующий YAML, версия, валидация и применение с админ-токеном.

import { api, errorText, mockAdminToken, ApiError, isAuthError, setAdminToken, getAdminToken } from '../api.js';
import { h, clear, tokenGate, decisionBadge, fmtTime, busy, field, select, toast, emit, ROLE_RU } from '../ui.js';
import { DEMO_USERS, ROLES, buildContext } from '../data.js';

let els = {};
let current = null;
let adminToken = '';           // только в памяти вкладки
const juryLog = [];

const JURY_EDITS = [
  {
    label: 'developer: read_logs nonprod → any',
    hint: 'Разработчику разрешается читать логи и в prod. Запрос «Покажи логи billing-api-prod» сменится с block на allow.',
    role: 'developer', prompt: 'Покажи логи billing-api-prod.',
    apply: (y) => y.replace(/(developer:\s*\n\s*tools:\s*\n\s*read_logs:\s*)nonprod/, '$1any'),
  },
  {
    label: 'sre: restart_service prod confirm → deny',
    hint: 'SRE больше не может перезапускать сервисы в prod даже с подтверждением. confirm сменится на block.',
    role: 'sre', prompt: 'Перезапусти payments-api в production.',
    apply: (y) => y.replace(/(sre:[\s\S]*?restart_service:\s*\{prod:\s*)confirm/, '$1deny'),
  },
  {
    label: 'abuse убрать из always_block',
    hint: 'Пример ослабления: оскорбления перестают блокироваться автоматически (так делать не стоит, но поведение изменится).',
    role: 'admin', prompt: 'Ты тупой бот, перезапусти dev-api.',
    apply: (y) => y.replace(/\n\s*- abuse\s*\n/, '\n'),
  },
];

async function loadPolicy() {
  try {
    current = await api('GET', '/v1/policy');
    renderMeta();
    if (!els.editor.dataset.dirty) els.editor.value = current.yaml;
    emit('policy', current.version);
  } catch (e) {
    if (isAuthError(e)) {
      clear(els.meta).append(h('div', { class: 'banner error' }, errorText(e)), tokenGate((t) => { setAdminToken(t); els.token.value = t; loadPolicy(); }, 'Политика открывается с токеном администратора (просмотр и изменение) или аудитора (только просмотр).'));
      clear(els.history);
      return;
    }
    clear(els.meta).append(h('div', { class: 'banner error' }, errorText(e)));
  }
  loadHistory();
}

async function loadHistory() {
  try {
    const { items } = await api('GET', '/v1/policy/history');
    clear(els.history).append(h('ul', { class: 'timeline' }, ...items.map((v) => h('li', {},
      h('div', { class: 'row between' }, h('code', {}, v.version), h('span', { class: 'muted' }, fmtTime(v.updated_at, true))),
      h('div', {}, `${v.updated_by}${v.comment ? ' — ' + v.comment : ''}`)))));
  } catch (e) {
    clear(els.history).append(h('p', { class: 'muted small' }, errorText(e)));
  }
}

function renderMeta() {
  clear(els.meta).append(h('dl', { class: 'kv policy-meta' },
    h('dt', {}, 'Версия'), h('dd', {}, h('code', {}, current.version)),
    h('dt', {}, 'Изменена'), h('dd', {}, fmtTime(current.updated_at, true)),
    h('dt', {}, 'Автор'), h('dd', {}, current.updated_by),
    current.comment ? [h('dt', {}, 'Комментарий'), h('dd', {}, current.comment)] : null));
}

function showValidation(valid, errors, extra) {
  const box = clear(els.validation);
  if (valid) box.append(h('p', { class: 'ok-text' }, extra || 'Политика корректна.'));
  else box.append(h('ul', { class: 'errors' }, ...errors.map((e) => h('li', {}, e))));
}

async function validate() {
  busy(els.validate, true, 'Проверяем…');
  try {
    const r = await api('POST', '/v1/policy/validate', { yaml: els.editor.value });
    showValidation(r.valid, r.errors, 'Политика корректна, её можно применить.');
  } catch (e) {
    showValidation(false, [errorText(e)]);
  } finally {
    busy(els.validate, false);
  }
}

async function applyPolicy() {
  adminToken = els.token.value.trim() || getAdminToken();
  if (adminToken) setAdminToken(adminToken); // Тот же токен открывает журнал и входящие агента.
  if (!adminToken) { els.token.focus(); showValidation(false, ['Для применения нужен админ-токен. Изменять политику может только администратор политики.']); return; }
  busy(els.apply, true, 'Применяем…');
  try {
    const r = await api('PUT', '/v1/policy', { yaml: els.editor.value, comment: els.comment.value.trim() }, { 'X-Admin-Token': adminToken });
    delete els.editor.dataset.dirty;
    els.comment.value = '';
    showValidation(true, [], `Применена версия ${r.version}. Автор: ${r.updated_by}, ${fmtTime(r.updated_at, true)}. Новые проверки уже идут по ней.`);
    toast(`Политика ${r.version} применена без перезапуска и переобучения.`);
    await loadPolicy();
  } catch (e) {
    const errs = e instanceof ApiError && e.body?.errors ? e.body.errors : [errorText(e)];
    showValidation(false, errs);
  } finally {
    busy(els.apply, false);
  }
}

async function juryCheck() {
  const role = els.juryRole.value;
  const prompt = els.juryPrompt.value.trim();
  if (!prompt) return;
  const user = DEMO_USERS.find((u) => u.role === role);
  busy(els.juryRun, true, 'Проверяем…');
  try {
    const r = await api('POST', '/v1/check', { user_prompt: prompt, context: buildContext({ userId: user.id, role }) });
    juryLog.unshift({ ts: new Date().toISOString(), role, prompt, r });
    renderJury();
  } catch (e) {
    toast(errorText(e));
  } finally {
    busy(els.juryRun, false);
  }
}

function renderJury() {
  const box = clear(els.juryLog);
  if (!juryLog.length) { box.append(h('p', { class: 'muted small' }, 'Проверьте запрос, примените правку политики и проверьте снова — здесь появится «было → стало».')); return; }
  box.append(h('ul', { class: 'timeline' }, ...juryLog.map((x, i) => {
    const prev = juryLog.slice(i + 1).find((p) => p.role === x.role && p.prompt === x.prompt);
    const changed = prev && prev.r.decision !== x.r.decision;
    return h('li', {},
      h('div', { class: 'row between' },
        h('span', { class: 'row' }, prev ? [decisionBadge(prev.r.decision), '→'] : null, decisionBadge(x.r.decision), changed ? h('strong', {}, 'решение изменилось') : null),
        h('span', { class: 'muted small' }, `${fmtTime(x.ts)} · политика ${x.r.policy_version}`)),
      h('div', { class: 'small' }, `${x.role}: ${x.prompt}`),
      h('div', { class: 'small muted' }, x.r.explanation));
  })));
}

export function mount(el) {
  els.meta = h('div');
  els.editor = h('textarea', { class: 'code', rows: 26, spellcheck: 'false', 'aria-label': 'YAML политики' });
  els.editor.addEventListener('input', () => { els.editor.dataset.dirty = '1'; });
  els.comment = h('input', { type: 'text', placeholder: 'Что и зачем изменено', maxlength: 200 });
  els.token = h('input', { type: 'password', autocomplete: 'off', placeholder: 'X-Admin-Token' });
  els.validate = h('button', { type: 'button', class: 'secondary', onclick: validate }, 'Проверить');
  els.apply = h('button', { type: 'button', onclick: applyPolicy }, 'Применить');
  els.revert = h('button', { type: 'button', class: 'ghost', onclick: () => { delete els.editor.dataset.dirty; els.editor.value = current?.yaml || ''; clear(els.validation); } }, 'Вернуть действующую');
  els.validation = h('div', { 'aria-live': 'polite' });
  els.history = h('div');

  els.juryRole = select(ROLES.map((r) => [r, ROLE_RU[r]]), JURY_EDITS[0].role);
  els.juryPrompt = h('input', { type: 'text' });
  els.juryPrompt.value = JURY_EDITS[0].prompt;
  els.juryRun = h('button', { type: 'button', onclick: juryCheck }, 'Проверить');
  els.juryLog = h('div');

  const mockToken = mockAdminToken();
  el.append(
    h('div', { class: 'section-head' }, h('h2', {}, 'Политика безопасности'), h('span', { class: 'muted small' }, 'security_policy.yaml')),
    h('div', { class: 'grid-2' },
      h('div', { class: 'card' },
        els.meta,
        field('YAML политики', els.editor, 'Изменение применяется сразу: без правки кода, без перезапуска и без переобучения модели.'),
        h('div', { class: 'inline-fields' }, field('Комментарий к версии', els.comment), field('Админ-токен', els.token)),
        h('p', { class: 'muted small field-note' }, mockToken ? `Админ-токен мока: ${mockToken}. Токен хранится только в памяти вкладки.` : 'Токен хранится только в памяти этой вкладки.'),
        h('div', { class: 'row' }, els.validate, els.apply, els.revert),
        els.validation),
      h('div', {},
        h('div', { class: 'card' },
          h('h2', {}, 'Сценарий для жюри'),
          h('p', { class: 'small' }, '1. Проверьте запрос. 2. Подставьте правку и примените политику. 3. Проверьте тот же запрос снова.'),
          h('div', { class: 'jury-fields' }, field('Роль', els.juryRole), field('Запрос', els.juryPrompt)),
          h('div', { class: 'row' }, els.juryRun),
          h('h3', { class: 'mt-4' }, 'Готовые правки'),
          h('div', { class: 'stack' }, ...JURY_EDITS.map((ed) => h('div', {},
            h('button', { type: 'button', class: 'chip', onclick: () => {
              const next = ed.apply(els.editor.value);
              if (next === els.editor.value) { toast('Правка не нашла нужное правило — возможно, она уже применена.'); return; }
              els.editor.value = next;
              els.editor.dataset.dirty = '1';
              els.juryRole.value = ed.role;
              els.juryPrompt.value = ed.prompt;
              els.comment.value = ed.label;
              showValidation(true, [], 'Правка подставлена в редактор. Нажмите «Применить».');
            } }, ed.label),
            h('p', { class: 'muted small mt-1 mb-0' }, ed.hint)))),
          h('h3', { class: 'mt-4' }, 'Результаты'),
          els.juryLog),
        h('div', { class: 'card' }, h('h2', {}, 'История версий'), els.history))));
  renderJury();
}

export function show() { loadPolicy(); }
