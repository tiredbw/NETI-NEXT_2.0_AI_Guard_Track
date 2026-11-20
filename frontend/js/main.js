// Точка входа: режим (API или мок), здоровье сервиса и переключение вкладок.

import { api, isMock, apiOrigin, errorText, hasUserToken, clearAdminToken, onTokenChange } from './api.js';
import { on, toast } from './ui.js';
import * as check from './views/check.js';
import * as agent from './views/agent.js';
import * as journal from './views/journal.js';
import * as policy from './views/policy.js';
import * as sessions from './views/sessions.js';

const VIEWS = { check, agent, journal, policy, sessions };
const mounted = new Set();

function route() {
  const name = (location.hash || '#check').slice(1);
  const key = VIEWS[name] ? name : 'check';
  for (const sec of document.querySelectorAll('[data-view]')) sec.hidden = sec.dataset.view !== key;
  for (const a of document.querySelectorAll('.tabs a')) {
    if (a.getAttribute('href') === `#${key}`) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  const el = document.getElementById(`view-${key}`);
  if (!mounted.has(key)) { VIEWS[key].mount(el); mounted.add(key); }
  VIEWS[key].show();
}

function setVersion(v) {
  document.getElementById('policy-version').textContent = v || '—';
}

async function health() {
  const dot = document.getElementById('health-dot');
  const text = document.getElementById('health-text');
  const model = document.getElementById('health-model');
  const banner = document.getElementById('global-banner');
  try {
    const r = await api('GET', '/health');
    dot.className = 'dot ok';
    text.textContent = 'сервис работает';
    model.textContent = r.model ? ` · ${r.model}` : '';
    setVersion(r.policy_version);
    if (!isMock()) banner.hidden = true;
  } catch (e) {
    dot.className = 'dot bad';
    text.textContent = 'сервис недоступен';
    model.textContent = '';
    if (!isMock()) {
      banner.className = 'banner error';
      banner.replaceChildren(
        `${errorText(e)} Адрес API: ${apiOrigin()}. Проверки не выполняются, агенту ничего не передаётся. `,
        Object.assign(document.createElement('a'), { href: '?mock=1', textContent: 'Открыть демо в мок-режиме' }));
      banner.hidden = false;
    }
  }
}

function init() {
  const pill = document.getElementById('mode-pill');
  const banner = document.getElementById('global-banner');
  if (isMock()) {
    pill.className = 'pill mock';
    pill.textContent = 'мок-режим';
    banner.className = 'banner warn';
    banner.textContent = 'Мок-режим: ответы считает встроенный в браузер эмулятор на правилах и YAML-политике. Это демонстрация интерфейса, а не качество модели.';
    banner.hidden = false;
  } else {
    pill.className = 'pill api';
    pill.textContent = `API: ${apiOrigin().replace(/^https?:\/\//, '')}`;
  }
  const tokenPill = document.getElementById('token-pill');
  const syncToken = () => { tokenPill.hidden = !hasUserToken(); };
  tokenPill.addEventListener('click', () => { clearAdminToken(); toast('Токен сброшен: журнал, входящие агента и политика снова закрыты.'); });
  // Закрытые разделы перерисовываются с новым доступом; при отказе вкладка уже показывает форму сама.
  onTokenChange(({ reason }) => { syncToken(); if (reason !== 'rejected') route(); });
  syncToken();
  on('policy', setVersion);
  on('checked', (r) => r?.policy_version && setVersion(r.policy_version));
  window.addEventListener('hashchange', route);
  route();
  health();
  setInterval(health, 15000);
}

init();
