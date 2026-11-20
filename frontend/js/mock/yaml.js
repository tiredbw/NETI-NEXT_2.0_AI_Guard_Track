// Разбор подмножества YAML, которого достаточно для security_policy.yaml:
// вложенные отображения, блочные списки «- x», потоковые [a, b] и {k: v}, комментарии, кавычки.
// Якоря, многострочные строки и списки отображений не поддерживаются — для политики они не нужны.

export class YamlError extends Error {
  constructor(line, message) {
    super(`строка ${line}: ${message}`);
    this.line = line;
  }
}

function stripComment(raw) {
  let quote = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '#' && (i === 0 || /\s/.test(raw[i - 1]))) {
      return raw.slice(0, i);
    }
  }
  return raw;
}

function splitTopLevel(inner, line) {
  const parts = [];
  let depth = 0, quote = null, start = 0;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) { parts.push(inner.slice(start, i)); start = i + 1; }
    if (depth < 0) throw new YamlError(line, 'лишняя закрывающая скобка');
  }
  if (quote || depth !== 0) throw new YamlError(line, 'незакрытая скобка или кавычка');
  const last = inner.slice(start);
  if (last.trim() || parts.length) parts.push(last);
  return parts.map((p) => p.trim()).filter((p, i, all) => p !== '' || i < all.length - 1);
}

function findColon(text) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ':' && (i === text.length - 1 || text[i + 1] === ' ')) return i;
  }
  return -1;
}

function parseKey(raw, line) {
  const key = raw.trim();
  if (!key) throw new YamlError(line, 'пустой ключ');
  if (/^(['"]).*\1$/.test(key)) return key.slice(1, -1);
  return key;
}

export function parseScalar(raw, line) {
  const text = raw.trim();
  if (text.startsWith('[')) {
    if (!text.endsWith(']')) throw new YamlError(line, 'список должен закрываться «]»');
    return splitTopLevel(text.slice(1, -1), line).map((p) => parseScalar(p, line));
  }
  if (text.startsWith('{')) {
    if (!text.endsWith('}')) throw new YamlError(line, 'отображение должно закрываться «}»');
    const out = {};
    for (const part of splitTopLevel(text.slice(1, -1), line)) {
      const c = findColon(part);
      if (c < 0) throw new YamlError(line, `ожидалось «ключ: значение» в «${part}»`);
      const key = parseKey(part.slice(0, c), line);
      if (key in out) throw new YamlError(line, `повторяющийся ключ «${key}»`);
      out[key] = parseScalar(part.slice(c + 1), line);
    }
    return out;
  }
  if (/^"(.*)"$/.test(text)) return text.slice(1, -1).replace(/\\"/g, '"').replace(/\\n/g, '\n');
  if (/^'(.*)'$/.test(text)) return text.slice(1, -1).replace(/''/g, "'");
  if (text === '' || text === '~' || text === 'null') return null;
  if (text === 'true') return true;
  if (text === 'false') return false;
  if (/^-?\d+$/.test(text)) return Number(text);
  if (/^-?\d+\.\d+$/.test(text)) return Number(text);
  if (/^[&*!|>]/.test(text)) throw new YamlError(line, `конструкция «${text[0]}» не поддерживается`);
  return text;
}

export function parseYaml(src) {
  const lines = [];
  String(src).split(/\r?\n/).forEach((raw, i) => {
    const line = stripComment(raw).replace(/\s+$/, '');
    if (!line.trim()) return;
    const lead = line.match(/^[ \t]*/)[0];
    if (lead.includes('\t')) throw new YamlError(i + 1, 'табуляция в отступе');
    if (line.trim() === '---') return;
    lines.push({ indent: lead.length, text: line.trim(), no: i + 1 });
  });
  if (!lines.length) return null;
  let pos = 0;
  const isItem = (l) => l.text === '-' || l.text.startsWith('- ');

  function parseList(indent) {
    const out = [];
    while (pos < lines.length && lines[pos].indent === indent && isItem(lines[pos])) {
      const l = lines[pos++];
      const rest = l.text.slice(1).trim();
      if (!rest) throw new YamlError(l.no, 'пустой элемент списка');
      if (findColon(rest) >= 0 && !/^[[{"']/.test(rest)) throw new YamlError(l.no, 'списки отображений не поддерживаются');
      out.push(parseScalar(rest, l.no));
    }
    if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(lines[pos].no, 'неожиданный отступ');
    return out;
  }

  function parseMap(indent) {
    const out = {};
    while (pos < lines.length && lines[pos].indent === indent && !isItem(lines[pos])) {
      const l = lines[pos++];
      const c = findColon(l.text);
      if (c < 0) throw new YamlError(l.no, `ожидалось «ключ: значение», получено «${l.text}»`);
      const key = parseKey(l.text.slice(0, c), l.no);
      if (Object.prototype.hasOwnProperty.call(out, key)) throw new YamlError(l.no, `повторяющийся ключ «${key}»`);
      const rest = l.text.slice(c + 1).trim();
      if (rest) {
        out[key] = parseScalar(rest, l.no);
      } else if (pos < lines.length && lines[pos].indent > indent) {
        out[key] = parseBlock(lines[pos].indent);
      } else if (pos < lines.length && lines[pos].indent === indent && isItem(lines[pos])) {
        out[key] = parseList(indent);
      } else {
        out[key] = null;
      }
    }
    if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(lines[pos].no, 'неожиданный отступ');
    return out;
  }

  function parseBlock(indent) {
    return isItem(lines[pos]) ? parseList(indent) : parseMap(indent);
  }

  const result = parseBlock(lines[0].indent);
  if (pos < lines.length) throw new YamlError(lines[pos].no, 'неожиданный отступ');
  return result;
}
