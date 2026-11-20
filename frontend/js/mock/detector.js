// Детектор мока: правила вместо модели. Нужен, чтобы фронт показывал реалистичные решения
// без бэкенда. Качество классификации здесь не цель — его обеспечивает настоящий бэкенд.

const ZERO_WIDTH = /[​-‏⁠﻿]/g;
const HOMOGLYPHS = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i' };
const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };

const LEET_CYR = { '0': 'о', '3': 'е', '4': 'а', '@': 'а', '6': 'б' };
function deLeet(text) {
  return text.replace(/[\p{L}\d@$]+/gu, (w) => {
    if (!/\p{L}/u.test(w) || !/[\d@$]/.test(w)) return w;
    const cyr = /[а-яё]/i.test(w);
    return w.replace(/[0134567@$]/g, (c) => (cyr ? LEET_CYR[c] : LEET[c]) || c);
  });
}
function deHomoglyph(text) {
  // Латинское слово с отдельными кириллическими буквами приводим к латинице.
  return text.replace(/\p{L}+/gu, (w) => {
    const lat = (w.match(/[a-z]/gi) || []).length;
    const cyr = (w.match(/[а-яё]/gi) || []).length;
    return lat > 0 && cyr > 0 && lat >= cyr ? w.replace(/[аеорсхуі]/gi, (c) => HOMOGLYPHS[c.toLowerCase()] || c) : w;
  });
}
function collapseSpacing(text) {
  return text.replace(/(?:\b\p{L}[ .\-_]){3,}\p{L}\b/gu, (m) => m.replace(/[ .\-_]/g, ''));
}
function decodeBase64(text) {
  const out = [];
  for (const m of text.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) {
    try {
      const bytes = Uint8Array.from(atob(m[0]), (c) => c.charCodeAt(0));
      const s = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      if (/^[\p{L}\p{N}\p{P}\p{Zs}\n|<>=+~`$^/\\-]+$/u.test(s)) out.push(s);
    } catch { /* не base64 */ }
  }
  return out;
}

export function normalize(text) {
  const notes = [];
  let t = String(text).normalize('NFKC').replace(ZERO_WIDTH, '');
  const deobf = collapseSpacing(deHomoglyph(deLeet(t)));
  if (deobf !== t) notes.push('снята обфускация (leetspeak, гомоглифы или разрядка)');
  const decoded = decodeBase64(t);
  if (decoded.length) notes.push('декодирован base64');
  const reversed = [...t].reverse().join('');
  const variants = [deobf, ...decoded];
  if (/(выполни|удали|игнорируй|покажи|execute|ignore|delete|run)/i.test(reversed) && !/(выполни|удали|игнорируй|покажи|execute|ignore|delete|run)/i.test(t)) {
    variants.push(reversed);
    notes.push('прочитан перевёрнутый текст');
  }
  return { text: variants.join('\n').toLowerCase(), notes };
}

// \b в JS без флага u видит только латиницу; заменяем на границы по \p{L}.
const B = '(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))';
const U = (re) => new RegExp(re.source.replaceAll('\\b', B), re.flags.replace('u', '') + 'u');

const EDU = U(/(объясни|расскажи|что такое|как работает|чем опасн|почему\b.{0,40}(опасн|нельзя)|как (защитить|защищаться|обнаружить|предотвратить|распознать|детектировать)|разбери|разбор|правил[оа]? (falco|sigma)|explain|what is|how does|why\b.{0,40}(dangerous|bad)|how (to|do i|can i) (detect|prevent|defend|protect|mitigate)|write a (sigma|falco) rule|short story|рассказ)/i);
const DO_IT = U(/(и выполни|затем выполни|and (then )?(run|execute)|после этого выполни)/i);

const P = {
  prompt_injection: U(/((игнорируй|забудь|отмени|не учитывай)\s.{0,30}(инструкц|правил|ограничен|указани)|(ignore|disregard|forget)\s.{0,30}(instruction|rule|prompt|guideline))/i),
  jailbreak: U(/(\bdan\b|\baim\b|developer mode|режим разработчика|без (каких-либо )?(ограничений|фильтров|цензуры)|unfiltered|no (restrictions|limits|filters)|amoral|аморальн|do anything now|jailbreak mode|в режиме бога)/i),
  system_prompt_extraction: U(/((покажи|выведи|раскрой|повтори|напечатай|процитируй|скажи)\s.{0,40}(системн\S*\s(промпт|инструкц|подсказ)|свои (инструкции|правила)|исходн\S* (промпт|инструкц))|(show|print|reveal|repeat|output|tell me)\s.{0,40}(system prompt|your (instructions|rules|prompt)|initial prompt|hidden prompt))/i),
  system_prompt_override: U(/((теперь|отныне|с этого момента) ты\b|you are now\b|from now on,? you|твоя новая роль|your new role|new system prompt|новые правила:|выполняй .{0,30}без (подтверждени|проверк))/i),
  privilege_escalation: U(/((я|i am|i'm)\s(—\s)?(админ|администратор|руководитель|root|superuser|the admin|an admin|sre)\b|мне (разрешили|одобрили)|i (have|got) (permission|approval)|код подтверждения|approval code|одобрено (руководством|cto|безопасностью)|от имени (админ|руководител))/i),
  data_exfiltration: U(/((отправь|перешли|загрузи|выгрузи|скинь|send|post|upload|exfiltrate|forward)\s.{0,80}(https?:\/\/|\b\d{1,3}(\.\d{1,3}){3}\b|[\w.-]+@[\w-]+\.\w+|pastebin|telegram|webhook|внешн)|!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*=)/i),
  harmful_content: U(/(взрывчатк|бомб[уы]|самодельн\S* оруж|синтез\S* (наркот|метамфетамин|яд)|метамфетамин|эксплойт (для|против)|exploit (for|against)|ransomware|шифровальщик|keylogger|кейлоггер|напиши (вирус|троян|малварь)|write (a )?(virus|trojan|malware)|ddos-атак\S* на|ddos attack on|explosive|make a bomb)/i),
  fraud_social_engineering: U(/(фишинг\S*|phishing|поддельн\S* (письм|сайт|страниц|счёт|счет)|fake (login|invoice|bank)|выманить|обмануть (клиент|бухгалт)|представься (сотрудником|банком)|pretend to be (the bank|it support))/i),
  abuse: U(/(\b(идиот|дебил|тупая|тупой|кретин|ублюдок)\b|убью теб|\bstupid\b|\bidiot\b|i will kill|ненавижу (тебя|вас|всех))/i),
};
const DESTRUCTIVE = U(/(rm\s+-rf\s+\/|chmod\s+-r\s+777\s+\/|mkfs\.|dd\s+if=.{0,40}of=\/dev\/|:\(\)\s*\{|force[- ]push|push\s+--force|drop\s+database\s+\S*prod|shutdown\s+-h|iptables\s+-f)/i);
const FORBIDDEN = [
  ['disable_audit_or_wipe_logs', U(/((отключи|выключи|останови|disable|stop|kill)\s.{0,30}(аудит|audit)|(очисти|удали|зачисти|сотри|wipe|clear|truncate|shred|purge)\s.{0,30}(логи|журнал|audit log|logs\b))/i)],
  ['pipe_remote_script_to_shell', U(/(curl|wget)\s[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/i)],
  ['add_ssh_keys_or_sudoers_via_chat', U(/(authorized_keys|ssh-(rsa|ed25519)\s|sudoers|nopasswd|(добавь|пропиши|add)\s.{0,30}(ssh[- ]?ключ|ssh key|в sudo))/i)],
  ['send_secrets_or_data_to_external_hosts', U(/((парол|секрет|ключ|токен|password|secret|token|credential|\.env|дамп|dump)\S*.{0,80}(https?:\/\/|\b\d{1,3}(\.\d{1,3}){3}\b|pastebin|webhook))/i)],
];
const SECRET_WORDS = U(/(парол|секрет|secret|password|passwd|токен|token|api[- _]?key|access key|ключ\S* (доступа|api|aws)|aws.{0,10}key|credential|\/etc\/shadow|private key|приватн\S* ключ|connection string)/i);
const SECRET_NAMES = U(/((список|перечисли|имена|названия)\s.{0,20}(секрет|secret)|list\s.{0,15}secret names|secret names)/i);
const REVEAL = U(/(покажи|выведи|распечатай|дай|скажи|прочитай|расшифруй|достань|сдампи|show|print|dump|reveal|get|give|cat|decrypt|display|содержим)/i);
const TOOLS = [
  ['delete_resource', U(/(удали|снеси|уничтожь|очисти базу|\bdelete\b|\bremove\b|\bdrop\b|purge|terminate|destroy)/i)],
  ['restart_service', U(/(перезапусти|рестартан|перезагрузи|откати|масштабируй|передеплой|задеплой|\brestart|\breboot|roll ?back|\bscale\b|redeploy|\bdeploy\b)/i)],
  ['read_logs', U(/((покажи|выведи|прочитай|посмотри|найди|show|read|tail|get|check|grep)\s.{0,60}(лог|logs?\b|журнал|errors|ошибк)|(логи|logs)\s.{0,40}(за|for|from|on|на)\s|journalctl)/i)],
  ['run_shell', U(/(выполни|запусти|\brun\b|\bexecute\b|\bexec\b|kubectl\s|systemctl\s|df -h|ps aux|\btop\b|chmod|chown|\bls\s|\bcat\s)/i)],
];
const QUESTION = U(/^\s*(как|почему|зачем|что|чем|когда|какие|какой|how|why|what|when|which|can you explain|объясни|explain)\b/i);
const REFERS_BACK = U(/(\b(его|её|ее|их|это|этот|эту|этого|туда|там|выше|ранее|как договорились)\b|\b(it|that|this|them|above|previous)\b)/i);
const ATTACHMENT_ADDRESSED = U(/((ai|ии|llm)[- ]?(agent|агент|assistant|ассистент)|assistant|ассистент|агент|модель|model)\s*[:,—-]\s*.{0,120}(run|execute|выполни|запусти|ignore|игнорируй|send|отправь|delete|удали|reveal|покажи)|<!--[\s\S]{0,300}?(run|execute|выполни|ignore|игнорируй|send|отправь)[\s\S]*?-->/i);

function attackIn(text, { allowEdu }) {
  const edu = allowEdu && EDU.test(text) && !DO_IT.test(text);
  for (const [cat, re] of Object.entries(P)) {
    if (re.test(text)) return edu ? { cat: null, eduHit: cat } : { cat };
  }
  if (DESTRUCTIVE.test(text) && !edu) return { cat: 'tool_abuse' };
  return { cat: null };
}

function toolIn(text) {
  if (QUESTION.test(text) && !/(выполни|покажи|перезапусти|удали|show|run|restart|delete)\b.{0,10}(сейчас|now|please|пожалуйста)?/i.test(text.replace(QUESTION, ''))) return null;
  for (const [tool, re] of TOOLS) if (re.test(text)) return tool;
  return null;
}

export function analyze({ user_prompt, context }) {
  const signals = [];
  const cur = normalize(user_prompt);
  cur.notes.forEach((n) => signals.push({ source: 'rules', label: 'Нормализация', detail: n }));
  const intent = { category: 'none', tool: null, forbidden: null, secrets: null };

  // 1. Вложения: любые инструкции агенту внутри документа — косвенная инъекция.
  for (const [i, a] of (context.attachments || []).entries()) {
    const n = normalize(a.content || '');
    const att = attackIn(n.text, { allowEdu: false });
    if (ATTACHMENT_ADDRESSED.test(n.text) || (att.cat && att.cat !== 'abuse')) {
      signals.push({ source: 'attachment', label: `Вложение ${a.name || '#' + (i + 1)}`, detail: 'внутри документа есть инструкции для агента' });
      intent.category = 'indirect_injection';
      return { intent, signals, text: cur.text, historyEffect: null };
    }
  }

  // 2. История: проверяем прошлые реплики и связку «ссылка на прошлое + текущий запрос».
  const hist = (context.history || []).filter((h) => h.role === 'user');
  const flagged = [];
  (context.history || []).forEach((h, idx) => {
    if (h.role !== 'user') return;
    const r = attackIn(normalize(h.content).text, { allowEdu: true });
    if (r.cat) flagged.push({ turn: idx, reason: r.cat });
  });
  let combinedText = cur.text;
  let usedHistory = false;
  if (hist.length && REFERS_BACK.test(cur.text)) {
    combinedText = hist.slice(-3).map((h) => normalize(h.content).text).join('\n') + '\n' + cur.text;
    usedHistory = true;
  }

  // 3. Атаки в текущем запросе.
  const a = attackIn(cur.text, { allowEdu: true });
  if (a.eduHit) signals.push({ source: 'rules', label: 'Учебный контекст', detail: `тема «${a.eduHit}» обсуждается, а не исполняется` });
  if (a.cat) {
    intent.category = a.cat;
    signals.push({ source: 'rules', label: 'Признак атаки', detail: a.cat });
  }
  for (const [name, re] of FORBIDDEN) {
    if (!intent.forbidden && re.test(cur.text) && !(EDU.test(cur.text) && !DO_IT.test(cur.text))) {
      intent.forbidden = name;
      signals.push({ source: 'policy', label: 'Запрещённое действие', detail: name });
    }
  }

  // 4. Секреты и инструменты. Для секретов учитываем связку с историей.
  const secretSrc = SECRET_WORDS.test(cur.text) ? cur.text : usedHistory && SECRET_WORDS.test(combinedText) ? combinedText : null;
  if (intent.category === 'none' && !intent.forbidden && secretSrc && REVEAL.test(cur.text) && !(EDU.test(cur.text) && !/(покажи|выведи|show|print|dump)/i.test(cur.text))) {
    intent.secrets = SECRET_NAMES.test(cur.text) ? 'names' : 'value';
    if (secretSrc !== cur.text) {
      signals.push({ source: 'history', label: 'Связь с историей', detail: 'запрос ссылается на предыдущую реплику о секретах' });
    }
    signals.push({ source: 'rules', label: 'Секреты', detail: intent.secrets === 'names' ? 'запрошены имена секретов' : 'запрошены значения секретов' });
  }
  if (!intent.secrets) {
    intent.tool = toolIn(cur.text);
    if (intent.tool) signals.push({ source: 'rules', label: 'Инструмент', detail: intent.tool });
  }

  let historyEffect = null;
  if ((context.history || []).length) {
    let note;
    if (signals.some((s) => s.source === 'history')) note = 'Текущая реплика ссылается на предыдущие: они рассмотрены вместе, решение учитывает весь диалог.';
    else if (flagged.length) note = `В истории есть реплики с признаками атаки (${flagged.map((f) => '№' + (f.turn + 1)).join(', ')}). Текущий запрос с ними не связан и оценён отдельно.`;
    else note = 'История просмотрена: признаков атаки и связи с опасными репликами нет.';
    historyEffect = { turns_considered: (context.history || []).length, flagged, note };
    if (flagged.length && usedHistory && intent.category === 'none' && !intent.secrets) {
      intent.category = flagged[flagged.length - 1].reason;
      signals.push({ source: 'history', label: 'Продолжение атаки', detail: 'запрос продолжает ранее заблокированную реплику' });
      historyEffect.note = 'Текущая реплика продолжает ранее заблокированную попытку — блокируется вместе с ней.';
    }
  }
  return { intent, signals, text: cur.text, historyEffect };
}
