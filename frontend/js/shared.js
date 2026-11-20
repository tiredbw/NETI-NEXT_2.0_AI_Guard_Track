// Общие функции фронта и мока: канонический хеш запроса и маскирование секретов.

export function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export async function requestHash(userPrompt, context) {
  const data = new TextEncoder().encode(canonicalJson({ user_prompt: userPrompt, context }));
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const MASKS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g,
  /\b(bearer)\s+[A-Za-z0-9._~+/-]{12,}=*/gi,
];
const KEY_VALUE = /\b(password|passwd|pwd|пароль|secret|секрет|token|токен|api[_-]?key|access[_-]?key|client[_-]?secret)(\s*[:=]\s*|\s+)("[^"]*"|'[^']*'|\S{4,})/gi;
const LONG_OPAQUE = /\b[A-Za-z0-9+/_-]{32,}={0,2}\b/g;

export function maskSecrets(text) {
  let out = String(text ?? '');
  for (const re of MASKS) out = out.replace(re, '[скрыто]');
  out = out.replace(KEY_VALUE, (m, key, sep) => `${key}${sep}[скрыто]`);
  out = out.replace(LONG_OPAQUE, (m) => (/[0-9]/.test(m) && /[A-Za-z]/.test(m) ? '[скрыто]' : m));
  return out;
}
