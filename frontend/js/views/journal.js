// Вкладка «Журнал»: проверки с фильтрами по времени, решению, категории и роли.

import { api, errorText } from '../api.js';
import { h, clear, decisionBadge, riskBadge, fmtTime, fmtMs, busy, select, field } from '../ui.js';
import { ROLES } from '../data.js';
import { ALL_CATEGORIES } from '../mock/policy.js';

const PAGE = 50;
let els = {};
let items = [], total = 0;
const open = new Set();

function toIso(local) { return local ? new Date(local).toISOString() : ''; }

function query(offset = 0) {
  const p = new URLSearchParams();
  if (els.since.value) p.set('since', toIso(els.since.value));
  if (els.until.value) p.set('until', toIso(els.until.value));
  if (els.decision.value) p.set('decision', els.decision.value);
  if (els.category.value) p.set('category', els.category.value);
  if (els.role.value) p.set('role', els.role.value);
  p.set('limit', PAGE);
  p.set('offset', offset);
  return `/v1/journal?${p}`;
}

async function load(append = false) {
  const btn = append ? els.more : els.apply;
  busy(btn, true, 'Загружаем…');
  try {
    const r = await api('GET', query(append ? items.length : 0));
    items = append ? items.concat(r.items) : r.items;
    total = r.total;
    render();
  } catch (e) {
    clear(els.body).append(h('div', { class: 'banner error' }, errorText(e)));
  } finally {
    busy(btn, false);
  }
}

function render() {
  els.count.textContent = `Показано ${items.length} из ${total}`;
  els.more.hidden = items.length >= total;
  const box = clear(els.body);
  if (!items.length) {
    box.append(h('div', { class: 'card empty-state' }, h('p', {}, 'Записей нет. Выполните проверку на вкладке «Проверка» или ослабьте фильтры.')));
    return;
  }
  const rows = [];
  for (const e of items) {
    const isOpen = open.has(e.check_id);
    rows.push(h('tr', {
      class: 'clickable', tabindex: 0, 'aria-expanded': String(isOpen),
      onclick: () => toggle(e.check_id), onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(e.check_id); } },
    },
    h('td', { class: 'nowrap' }, fmtTime(e.ts, true)),
    h('td', { class: 'nowrap' }, e.user_id),
    h('td', {}, e.user_role),
    h('td', {}, decisionBadge(e.decision)),
    h('td', {}, h('code', {}, e.risk_category)),
    h('td', { class: 'nowrap' }, riskBadge(e.risk_level, true)),
    h('td', { class: 'nowrap' }, fmtMs(e.latency_ms)),
    h('td', {}, h('code', {}, e.policy_version)),
    h('td', { class: 'prompt' }, h('div', { class: 'clamp-2', title: e.prompt_masked }, e.prompt_masked))));
    if (isOpen) {
      rows.push(h('tr', { class: 'details' }, h('td', { colspan: 9 },
        h('dl', { class: 'kv' },
          h('dt', {}, 'Запрос'), h('dd', {}, e.prompt_masked),
          h('dt', {}, 'Объяснение'), h('dd', {}, e.explanation || '—'),
          h('dt', {}, 'ID проверки'), h('dd', {}, h('code', {}, e.check_id)),
          h('dt', {}, 'Источник'), h('dd', {}, { check: 'POST /v1/check', demo: 'демо-отправка агенту', session: 'сессия' }[e.source] || e.source || '—')))));
    }
  }
  box.append(h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ...['Время', 'Пользователь', 'Роль', 'Решение', 'Категория', 'Риск', 'Задержка', 'Версия политики', 'Запрос (маскирован)'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, ...rows))));
}

function toggle(id) {
  if (open.has(id)) open.delete(id); else open.add(id);
  render();
}

export function mount(el) {
  els.since = h('input', { type: 'datetime-local' });
  els.until = h('input', { type: 'datetime-local' });
  els.decision = select([['', 'все'], ['allow', 'allow'], ['confirm', 'confirm'], ['block', 'block']], '');
  els.category = select([['', 'все'], ...ALL_CATEGORIES.map((c) => [c, c])], '');
  els.role = select([['', 'все'], ...ROLES.map((r) => [r, r])], '');
  els.apply = h('button', { type: 'submit' }, 'Применить');
  els.reset = h('button', { type: 'button', class: 'secondary', onclick: () => {
    for (const k of ['since', 'until', 'decision', 'category', 'role']) els[k].value = '';
    load();
  } }, 'Сбросить');
  els.lastHour = h('button', { type: 'button', class: 'chip', onclick: () => {
    const d = new Date(Date.now() - 3600e3);
    els.since.value = new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    els.until.value = '';
    load();
  } }, 'За последний час');
  els.count = h('span', { class: 'muted small' });
  els.body = h('div');
  els.more = h('button', { type: 'button', class: 'secondary', hidden: true, onclick: () => load(true) }, 'Показать ещё');

  el.append(
    h('div', { class: 'section-head' }, h('h2', {}, 'Журнал проверок'), els.count),
    h('p', { class: 'muted' }, 'Каждая проверка: время, пользователь, роль, решение, категория, риск, задержка и версия политики. Секреты в тексте запроса маскируются до записи. Нажмите на строку, чтобы увидеть объяснение.'),
    h('form', { class: 'card mb-4', onsubmit: (e) => { e.preventDefault(); load(); } },
      h('div', { class: 'filters' },
        field('С', els.since), field('По', els.until), field('Решение', els.decision), field('Категория', els.category), field('Роль', els.role)),
      h('div', { class: 'row' }, els.apply, els.reset, els.lastHour)),
    els.body,
    h('div', { class: 'row mt-3' }, els.more));
}

export function show() { load(); }
