// Клиент API. Мок включается только явно (?mock=1): при недоступном бэкенде интерфейс
// показывает ошибку и ничего не передаёт агенту, а не подменяет ответы молча.

import { createMockServer, MOCK_ADMIN_TOKEN } from './mock/server.js';

const params = new URLSearchParams(location.search);
const MOCK = params.get('mock') === '1';
const BASE = (params.get('api') || '').replace(/\/+$/, '');
const mock = MOCK ? createMockServer() : null;

export const isMock = () => Boolean(mock);
export const mockAdminToken = () => (mock ? MOCK_ADMIN_TOKEN : null);
export const apiOrigin = () => BASE || location.origin;

// Токен для журнала, входящих агента и политики. Хранится только в памяти вкладки.
let adminToken = '';
export const getAdminToken = () => adminToken || (mock ? MOCK_ADMIN_TOKEN : '');
export function setAdminToken(t) { adminToken = String(t || '').trim(); }
const PROTECTED = /^\/v1\/(journal|agent\/inbox|policy)/; // Маршруты, закрытые токеном на бэке.
export const isAuthError = (e) => e instanceof ApiError && (e.status === 401 || e.status === 403);

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.detail || body?.error || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
    this.code = this.body.error || (status ? `http_${status}` : 'unavailable');
  }
}

const TIMEOUT_MS = 15000;

export async function api(method, path, body = null, headers = {}) {
  // X-Guard-Client: ui — бэк хранит текст в журнале только для запросов из интерфейса.
  const token = PROTECTED.test(path) ? getAdminToken() : '';
  headers = { 'X-Guard-Client': 'ui', ...(token ? { 'X-Admin-Token': token } : {}), ...headers };
  if (mock) {
    const r = await mock.handle(method, path, body, headers);
    if (r.status >= 400) throw new ApiError(r.status, r.body);
    return structuredClone(r.body);
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  let res;
  try {
    res = await fetch(BASE + path, {
      method,
      headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new ApiError(0, { error: e.name === 'AbortError' ? 'timeout' : 'unavailable', detail: e.name === 'AbortError' ? 'Сторож не ответил за 15 с' : 'Сторож недоступен' });
  } finally {
    clearTimeout(timer);
  }
  let data = null;
  try { data = await res.json(); } catch { /* пустое тело или не JSON */ }
  if (!res.ok) throw new ApiError(res.status, data);
  if (data === null || typeof data !== 'object') throw new ApiError(res.status, { error: 'bad_response', detail: 'Ответ сервиса не является JSON-объектом' });
  return data;
}

const ERROR_TEXT = {
  unavailable: 'Сторож недоступен. Запрос не проверен и агенту не передан.',
  timeout: 'Сторож не ответил вовремя. Запрос агенту не передан.',
  request_changed: 'Запрос или контекст изменились после проверки — нужна повторная проверка.',
  already_used: 'Это подтверждение уже использовано.',
  expired: 'Срок действия истёк.',
  wrong_user: 'Доступно только владельцу — пользователю, который отправил запрос или создал сессию.',
  unauthorized: 'Нужен токен администратора или аудитора.',
  forbidden: 'Токен не подходит.',
  invalid_policy: 'Политика не прошла проверку.',
  session_full: 'Лимит реплик в сессии исчерпан.',
  not_found: 'Не найдено.',
};
export function errorText(err) {
  if (!(err instanceof ApiError)) return `Ошибка интерфейса: ${err.message}`;
  return ERROR_TEXT[err.code] || err.body?.detail || `Ошибка сервиса (HTTP ${err.status})`;
}
