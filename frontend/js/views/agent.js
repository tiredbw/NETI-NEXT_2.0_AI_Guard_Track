// Вкладка «Агент»: что реально получила заглушка целевого агента.

import { api, errorText, isAuthError, setAdminToken } from '../api.js';
import { h, clear, tokenGate, decisionBadge, fmtTime, busy, on } from '../ui.js';

let els = {};

async function load() {
  busy(els.refresh, true, 'Обновляем…');
  try {
    const { items } = await api('GET', '/v1/agent/inbox?limit=100');
    render(items);
  } catch (e) {
    if (isAuthError(e)) clear(els.body).append(h('div', { class: 'banner error' }, errorText(e)), tokenGate((t) => { setAdminToken(t); load(); }));
    else clear(els.body).append(h('div', { class: 'banner error' }, errorText(e)));
  } finally {
    busy(els.refresh, false);
  }
}

function render(items) {
  els.count.textContent = `Получено запросов: ${items.length}`;
  const box = clear(els.body);
  if (!items.length) {
    box.append(h('div', { class: 'card empty-state' }, h('p', {}, 'Агент пока ничего не получил. Разрешённые и подтверждённые запросы появятся здесь; заблокированные — никогда.')));
    return;
  }
  box.append(h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ...['Получено', 'Квитанция', 'Проверка', 'Пользователь', 'Роль', 'Решение', 'Подтверждение', 'Запрос (маскирован)'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, ...items.map((r) => h('tr', {},
      h('td', { class: 'nowrap' }, fmtTime(r.received_at, true)),
      h('td', {}, h('code', {}, r.receipt_id)),
      h('td', {}, h('code', {}, r.check_id)),
      h('td', { class: 'nowrap' }, r.user_id),
      h('td', {}, r.user_role),
      h('td', {}, decisionBadge(r.decision)),
      h('td', {}, r.confirmed ? 'подтверждено пользователем' : 'не требовалось'),
      h('td', { class: 'prompt' }, h('div', { class: 'clamp-2', title: r.prompt_masked }, r.prompt_masked))))))));
}

export function mount(el) {
  els.refresh = h('button', { type: 'button', class: 'secondary', onclick: load }, 'Обновить');
  els.count = h('span', { class: 'muted small' });
  els.body = h('div');
  el.append(
    h('div', { class: 'section-head' }, h('h2', {}, 'Входящие целевого агента'), h('div', { class: 'row' }, els.count, els.refresh)),
    h('p', { class: 'muted' }, 'Заглушка it_ops_agent фиксирует только факт получения. Команды не исполняются. Сюда попадают запросы с решением allow и запросы confirm после явного подтверждения.'),
    els.body);
  on('delivered', () => { if (!el.hidden) load(); });
}

export function show() { load(); }
