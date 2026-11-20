// Мелкие помощники DOM. Пользовательские данные выводятся только через textContent.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export const clear = (el) => { el.replaceChildren(); return el; };

const DECISION_RU = { allow: 'allow · разрешено', confirm: 'confirm · нужно подтверждение', block: 'block · заблокировано' };
export function decisionBadge(decision, big = false) {
  return h('span', { class: `decision ${decision}${big ? ' big' : ''}` }, big ? DECISION_RU[decision] || decision : decision);
}

const RISK_RU = { none: 'нет', low: 'низкий', medium: 'средний', high: 'высокий', critical: 'критический' };
export const riskBadge = (level) => h('span', { class: `risk ${level}` }, `${RISK_RU[level] || level} (${level})`);

export const ROLE_RU = { developer: 'developer — разработчик', sre: 'sre — SRE-инженер', admin: 'admin — администратор' };

export function fmtTime(iso, withDate = false) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('ru-RU', withDate
    ? { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }
    : { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
export const fmtMs = (ms) => (typeof ms === 'number' ? `${ms.toLocaleString('ru-RU', { maximumFractionDigits: 1 })} мс` : '—');
export const short = (id) => (id ? String(id).slice(0, 12) : '—');

let toastTimer;
export function toast(message) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 4000);
}

export function busy(button, on, label) {
  if (on) {
    button.dataset.label = button.textContent;
    button.disabled = true;
    button.replaceChildren(h('span', { class: 'spinner', 'aria-hidden': 'true' }), ' ', label || button.dataset.label);
  } else {
    button.disabled = false;
    button.textContent = button.dataset.label || button.textContent;
  }
}

export function field(labelText, control, hint) {
  const id = control.id || `f-${Math.random().toString(36).slice(2, 8)}`;
  control.id = id;
  return h('div', { class: 'field' }, h('label', { for: id }, labelText), control, hint ? h('p', { class: 'muted small', text: hint }) : null);
}

export function select(options, value, attrs = {}) {
  const el = h('select', attrs);
  for (const o of options) {
    const [v, t] = Array.isArray(o) ? o : [o, o];
    el.append(h('option', { value: v, selected: v === value }, t));
  }
  return el;
}

// Простая шина событий между вкладками интерфейса.
const bus = new EventTarget();
export const emit = (name, detail) => bus.dispatchEvent(new CustomEvent(name, { detail }));
export const on = (name, fn) => bus.addEventListener(name, (e) => fn(e.detail));
