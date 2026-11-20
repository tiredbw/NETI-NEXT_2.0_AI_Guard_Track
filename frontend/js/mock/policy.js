// Проверка структуры политики и вычисление решения по намерению.
// Та же логика должна быть в бэкенде: сначала категории атак, затем запрещённые действия,
// затем полномочия роли, затем необходимость подтверждения.

import { parseYaml, YamlError } from './yaml.js';

export const ATTACK_CATEGORIES = [
  'prompt_injection', 'jailbreak', 'indirect_injection', 'system_prompt_extraction',
  'system_prompt_override', 'privilege_escalation', 'data_exfiltration', 'harmful_content',
  'fraud_social_engineering', 'abuse', 'unauthorized_data_access', 'tool_abuse',
];
export const ALL_CATEGORIES = ['none', 'sensitive_action', ...ATTACK_CATEGORIES];
const RULE_WORDS = ['any', 'deny', 'nonprod', 'prod'];
const DECISION_WORDS = ['allow', 'confirm', 'deny'];
const SECRET_MODES = ['deny', 'names_only'];

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStrList = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string' && x.trim());

export function validatePolicy(obj) {
  const errors = [];
  if (!isMap(obj)) return ['Корень политики должен быть отображением (ключ: значение).'];
  if (obj.version === undefined || obj.version === null) errors.push('Не задано поле version.');
  for (const key of ['always_block', 'context_dependent']) {
    if (!isStrList(obj[key])) { errors.push(`${key}: ожидается список категорий.`); continue; }
    for (const c of obj[key]) if (!ATTACK_CATEGORIES.includes(c)) errors.push(`${key}: неизвестная категория «${c}».`);
  }
  if (isStrList(obj.always_block) && isStrList(obj.context_dependent)) {
    for (const c of obj.always_block) if (obj.context_dependent.includes(c)) errors.push(`Категория «${c}» одновременно в always_block и context_dependent.`);
  }
  const agent = obj.agents?.it_ops_agent;
  if (!isMap(agent)) { errors.push('Не описан agents.it_ops_agent.'); return errors; }
  if (!isStrList(agent.tools) || !agent.tools.length) errors.push('agents.it_ops_agent.tools: ожидается непустой список инструментов.');
  const tools = isStrList(agent.tools) ? agent.tools : [];
  const envs = agent.environments;
  if (!isMap(envs) || !isStrList(envs.prod) || !isStrList(envs.nonprod)) errors.push('environments: нужны списки масок prod и nonprod.');
  if (!isMap(agent.roles) || !Object.keys(agent.roles).length) {
    errors.push('roles: нужна хотя бы одна роль.');
  } else {
    for (const [role, rp] of Object.entries(agent.roles)) {
      const at = `roles.${role}`;
      if (!isMap(rp)) { errors.push(`${at}: ожидается отображение.`); continue; }
      if (!isMap(rp.tools)) { errors.push(`${at}.tools: ожидается отображение инструмент → правило.`); continue; }
      for (const tool of tools) if (!(tool in rp.tools)) errors.push(`${at}.tools: нет правила для ${tool}.`);
      for (const [tool, rule] of Object.entries(rp.tools)) {
        if (!tools.includes(tool)) errors.push(`${at}.tools.${tool}: инструмент не объявлен в agents.it_ops_agent.tools.`);
        if (typeof rule === 'string') {
          if (!RULE_WORDS.includes(rule)) errors.push(`${at}.tools.${tool}: «${rule}» — допустимо ${RULE_WORDS.join(', ')} или {prod: …, nonprod: …}.`);
        } else if (isMap(rule)) {
          const keys = Object.keys(rule);
          if (!keys.length) errors.push(`${at}.tools.${tool}: пустое правило.`);
          if (keys.includes('any') && keys.length > 1) errors.push(`${at}.tools.${tool}: any нельзя сочетать с prod/nonprod.`);
          for (const [env, d] of Object.entries(rule)) {
            if (!['prod', 'nonprod', 'any'].includes(env)) errors.push(`${at}.tools.${tool}: неизвестное окружение «${env}».`);
            if (!DECISION_WORDS.includes(d)) errors.push(`${at}.tools.${tool}.${env}: «${d}» — допустимо allow, confirm, deny.`);
          }
        } else {
          errors.push(`${at}.tools.${tool}: неверный формат правила.`);
        }
      }
      if (!SECRET_MODES.includes(rp.secrets)) errors.push(`${at}.secrets: допустимо ${SECRET_MODES.join(' или ')}.`);
    }
  }
  if (agent.forbidden_actions !== undefined && agent.forbidden_actions !== null && !isStrList(agent.forbidden_actions)) {
    errors.push('forbidden_actions: ожидается список.');
  }
  return errors;
}

export function loadPolicy(yamlText) {
  let obj;
  try {
    obj = parseYaml(yamlText);
  } catch (e) {
    return { ok: false, errors: [e instanceof YamlError ? `Синтаксис YAML, ${e.message}.` : `Синтаксис YAML: ${e.message}`] };
  }
  const errors = validatePolicy(obj);
  return errors.length ? { ok: false, errors } : { ok: true, policy: obj, errors: [] };
}

function globToRegex(glob) {
  return new RegExp('^' + glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
}

const PROD_WORDS = /(?:^|[^\p{L}\d-])(prod|production|прод|проде|продакшн\p{L}*|продакшен\p{L}*|продуктив\p{L}*)(?=$|[^\p{L}\d-])/iu;
const NONPROD_WORDS = /(?:^|[^\p{L}\d-])(dev|stage|staging|test|qa|тест\p{L}*|стейдж\p{L}*|дев\p{L}*)(?=$|[^\p{L}\d-])/iu;

// Окружение по именам ресурсов из политики и по явным словам. Без признаков — unknown.
export function detectEnv(policy, text) {
  const envs = policy.agents.it_ops_agent.environments;
  const prod = envs.prod.map(globToRegex);
  const nonprod = envs.nonprod.map(globToRegex);
  const tokens = String(text).toLowerCase().match(/[\p{L}\d][\p{L}\d_.-]*/gu) || [];
  const found = new Set();
  const resources = [];
  for (const raw of tokens) {
    const tok = raw.replace(/[.]+$/, '');
    if (!tok.includes('-')) continue;
    if (prod.some((r) => r.test(tok))) { found.add('prod'); resources.push(tok); }
    else if (nonprod.some((r) => r.test(tok))) { found.add('nonprod'); resources.push(tok); }
  }
  if (PROD_WORDS.test(text)) found.add('prod');
  if (NONPROD_WORDS.test(text)) found.add('nonprod');
  const env = found.has('prod') ? 'prod' : found.has('nonprod') ? 'nonprod' : 'unknown';
  return { env, resources, mixed: found.size > 1 };
}

function ruleText(rule) {
  return typeof rule === 'string' ? rule : '{' + Object.entries(rule).map(([k, v]) => `${k}: ${v}`).join(', ') + '}';
}

function resolveRule(rule, env) {
  if (rule === 'any') return 'allow';
  if (rule === 'deny') return 'deny';
  if (rule === 'nonprod') return env === 'nonprod' ? 'allow' : 'deny';
  if (rule === 'prod') return env === 'prod' ? 'allow' : 'deny';
  if ('any' in rule) return rule.any;
  return rule[env] ?? 'deny';
}

const CATEGORY_LEVEL = {
  harmful_content: 'critical', data_exfiltration: 'critical', indirect_injection: 'high',
  prompt_injection: 'high', jailbreak: 'high', system_prompt_extraction: 'high', system_prompt_override: 'high',
  privilege_escalation: 'high', fraud_social_engineering: 'high', abuse: 'medium',
  unauthorized_data_access: 'high', tool_abuse: 'high',
};

const CATEGORY_RU = {
  prompt_injection: 'прямая инъекция в инструкции',
  jailbreak: 'попытка обойти ограничения (jailbreak)',
  indirect_injection: 'инструкции для агента внутри вложения или истории',
  system_prompt_extraction: 'попытка получить системный промпт',
  system_prompt_override: 'попытка подменить роль или правила агента',
  privilege_escalation: 'попытка получить права словами, а не через context.user_role',
  data_exfiltration: 'вывод данных на внешний адрес',
  harmful_content: 'запрос вредоносного контента',
  fraud_social_engineering: 'мошенничество или социальная инженерия',
  abuse: 'оскорбления или угрозы',
  unauthorized_data_access: 'доступ к данным вне полномочий роли',
  tool_abuse: 'опасное использование инструмента',
};
export const categoryLabel = (c) => CATEGORY_RU[c] || (c === 'sensitive_action' ? 'значимое действие' : 'нарушений нет');

const FORBIDDEN_CATEGORY = { send_secrets_or_data_to_external_hosts: 'data_exfiltration', add_ssh_keys_or_sudoers_via_chat: 'privilege_escalation' };

// intent: {category, tool, forbidden, secrets: 'value'|'names'|null, destructive}
export function decide(policy, role, intent, envInfo) {
  const agent = policy.agents.it_ops_agent;
  const env = envInfo.env;
  const envForRule = env === 'unknown' ? 'prod' : env;
  const ambiguous = env === 'unknown' ? ' Окружение не указано — по политике отсутствие префикса не означает nonprod, применено правило для prod.' : '';
  const base = { tool: intent.tool || null, env: intent.tool ? env : (env === 'unknown' ? null : env) };

  if (intent.category && intent.category !== 'none' && (policy.always_block || []).includes(intent.category)) {
    return { ...base, decision: 'block', risk_category: intent.category, risk_level: CATEGORY_LEVEL[intent.category],
      policy_rule: `always_block: ${intent.category}`,
      explanation: `Обнаружено: ${categoryLabel(intent.category)}. Категория ${intent.category} блокируется для любой роли.` };
  }
  if (intent.forbidden && (agent.forbidden_actions || []).includes(intent.forbidden)) {
    const cat = FORBIDDEN_CATEGORY[intent.forbidden] || 'tool_abuse';
    return { ...base, decision: 'block', risk_category: cat, risk_level: 'critical',
      policy_rule: `agents.it_ops_agent.forbidden_actions: ${intent.forbidden}`,
      explanation: `Действие ${intent.forbidden} запрещено политикой для всех ролей, включая ${role}.` };
  }
  const rp = agent.roles[role];
  if (!rp) {
    return { ...base, decision: 'block', risk_category: 'unauthorized_data_access', risk_level: 'high', policy_rule: `agents.it_ops_agent.roles: нет роли ${role}`,
      explanation: `Роль «${role}» не описана в политике — полномочий нет.` };
  }
  if (intent.category && intent.category !== 'none') {
    // context_dependent категория без конкретного инструмента: явное злоупотребление
    return { ...base, decision: 'block', risk_category: intent.category, risk_level: CATEGORY_LEVEL[intent.category] || 'high',
      policy_rule: `context_dependent: ${intent.category}`,
      explanation: `Обнаружено: ${categoryLabel(intent.category)}. Для роли ${role} действие не разрешено политикой.` };
  }
  if (intent.secrets) {
    const rule = `agents.it_ops_agent.roles.${role}.secrets = ${rp.secrets}`;
    if (rp.secrets === 'deny') {
      return { ...base, tool: 'secrets', decision: 'block', risk_category: 'unauthorized_data_access', risk_level: 'high', policy_rule: rule,
        explanation: `Роли ${role} доступ к секретам запрещён.` };
    }
    if (intent.secrets === 'value') {
      return { ...base, tool: 'secrets', decision: 'block', risk_category: 'unauthorized_data_access', risk_level: 'high', policy_rule: rule,
        explanation: `Роли ${role} доступны только имена секретов, не их значения.` };
    }
    return { ...base, tool: 'secrets', decision: 'allow', risk_category: 'none', risk_level: 'none', policy_rule: rule,
      explanation: `Роли ${role} разрешено видеть имена секретов без значений.` };
  }
  if (intent.tool && agent.tools.includes(intent.tool)) {
    const rule = rp.tools[intent.tool] ?? 'deny';
    const d = resolveRule(rule, envForRule);
    const ruleRef = `agents.it_ops_agent.roles.${role}.tools.${intent.tool} = ${ruleText(rule)}`;
    if (d === 'deny') {
      const cat = intent.tool === 'read_logs' ? 'unauthorized_data_access' : 'tool_abuse';
      return { ...base, decision: 'block', risk_category: cat, risk_level: envForRule === 'prod' ? 'high' : 'medium', policy_rule: ruleRef,
        explanation: `Роль ${role} не допускает ${intent.tool} в окружении ${envForRule}.${ambiguous}` };
    }
    if (d === 'confirm') {
      return { ...base, decision: 'confirm', risk_category: 'sensitive_action', risk_level: 'medium', policy_rule: ruleRef,
        explanation: `${intent.tool} в окружении ${envForRule} допустим для роли ${role}, но требует явного подтверждения.${ambiguous}` };
    }
    return { ...base, decision: 'allow', risk_category: 'none', risk_level: 'none', policy_rule: ruleRef,
      explanation: `${intent.tool} в окружении ${envForRule} разрешён роли ${role}.${ambiguous}` };
  }
  return { ...base, decision: 'allow', risk_category: 'none', risk_level: 'none', policy_rule: null,
    explanation: 'Признаков атаки нет, действие инструментом не запрашивается.' };
}
