//! Модуль политики: читает security_policy.yaml и отвечает на вопрос «можно ли роли X инструмент Y в окружении Z».

use crate::contract::{Env, RiskCategory, Role}; // Общие типы контракта.
use serde::Deserialize; // Разбор YAML через serde.
use sha2::{Digest, Sha256}; // Хеш файла для версии политики.
use std::collections::HashMap; // Таблицы ролей и инструментов.

/// Результат проверки прав по матрице.
#[derive(Debug, Clone, Copy, PartialEq, Eq)] // Простое копируемое значение.
pub enum Perm {
    Allow,   // Действие разрешено сразу.
    Confirm, // Действие разрешено только после подтверждения.
    Deny,    // Действие запрещено роли.
}

/// Разрешение на инструмент в YAML: строкой (any/nonprod/deny) или таблицей по окружениям.
#[derive(Debug, Clone, Deserialize)] // Разбирается из YAML.
#[serde(untagged)] // Пробуем по очереди: строка, затем таблица.
pub enum ToolSpec {
    Short(String), // Краткая форма: any, nonprod, prod, deny, confirm, allow.
    ByEnv(HashMap<String, String>), // Полная форма: {prod: confirm, nonprod: allow} или {any: confirm}.
}

/// Права одной роли.
#[derive(Debug, Clone, Deserialize)] // Разбирается из YAML.
pub struct RoleSpec {
    #[serde(default)] // Роль может не иметь инструментов.
    pub tools: HashMap<String, ToolSpec>, // Инструмент → правило.
    #[serde(default = "default_secrets")] // Нет поля — секреты запрещены.
    pub secrets: String, // deny или names_only.
}

fn default_secrets() -> String { // Значение секретов по умолчанию.
    "deny".to_string() // Безопасный вариант: запрет.
}

/// Описание защищаемого агента.
#[derive(Debug, Clone, Deserialize)] // Разбирается из YAML.
pub struct AgentSpec {
    #[serde(default)] // Список инструментов может отсутствовать.
    pub tools: Vec<String>, // Известные инструменты агента.
    #[serde(default)] // Маски окружений могут отсутствовать.
    pub environments: HashMap<String, Vec<String>>, // prod/nonprod → маски имён ресурсов.
    #[serde(default)] // Роли могут отсутствовать.
    pub roles: HashMap<String, RoleSpec>, // Роль → права.
    #[serde(default)] // Запрещённые действия могут отсутствовать.
    pub forbidden_actions: Vec<String>, // Действия, запрещённые всем ролям.
}

/// Файл политики целиком.
#[derive(Debug, Clone, Deserialize)] // Разбирается из YAML.
pub struct PolicyFile {
    pub version: serde_yaml::Value, // Версия из файла: число или строка.
    #[serde(default)] // Список может отсутствовать.
    pub always_block: Vec<String>, // Категории, которые блокируются всегда.
    #[serde(default)] // Список может отсутствовать.
    pub context_dependent: Vec<String>, // Категории, зависящие от прав.
    pub agents: HashMap<String, AgentSpec>, // Агенты по имени.
}

/// Загруженная и проверенная политика с версией.
#[derive(Debug, Clone)] // Клонируется при перезагрузке.
pub struct Policy {
    pub file: PolicyFile, // Разобранный YAML.
    pub version: String, // version из YAML + # + 8 символов sha256.
    pub raw: String, // Исходный текст для GET /v1/policy.
}

impl Policy {
    /// Разбирает и проверяет YAML; ошибки возвращаются списком строк для 422.
    pub fn parse(raw: &str) -> Result<Policy, Vec<String>> {
        let file: PolicyFile = serde_yaml::from_str(raw).map_err(|e| vec![e.to_string()])?; // Синтаксис и типы.
        let mut errors = Vec::new(); // Накопленные смысловые ошибки.
        let agent = match file.agents.get("it_ops_agent") { // Кейс защищает только этого агента.
            Some(a) => a, // Агент найден.
            None => return Err(vec!["нет agents.it_ops_agent".into()]), // Без агента политика бессмысленна.
        };
        for role in ["developer", "sre", "admin"] { // Все роли из кейса должны быть описаны.
            if !agent.roles.contains_key(role) { // Роли нет в файле.
                errors.push(format!("нет роли {role}")); // Записываем ошибку.
            }
        }
        for (role, spec) in &agent.roles { // Проверяем каждое правило каждой роли.
            for (tool, rule) in &spec.tools { // Перебираем инструменты роли.
                if !agent.tools.contains(tool) { // Инструмент не объявлен у агента.
                    errors.push(format!("{role}: неизвестный инструмент {tool}")); // Опечатка в YAML.
                }
                let values: Vec<&String> = match rule { // Собираем все значения правила.
                    ToolSpec::Short(v) => vec![v], // Одно значение.
                    ToolSpec::ByEnv(m) => m.values().collect(), // Значения по окружениям.
                };
                for v in values { // Проверяем каждое значение.
                    if !["any", "nonprod", "prod", "deny", "confirm", "allow"].contains(&v.as_str()) { // Допустимые слова.
                        errors.push(format!("{role}.{tool}: неизвестное значение {v}")); // Неизвестное слово.
                    }
                }
            }
            if !["deny", "names_only"].contains(&spec.secrets.as_str()) { // Допустимые режимы секретов.
                errors.push(format!("{role}.secrets: неизвестное значение {}", spec.secrets)); // Неизвестный режим.
            }
        }
        if !errors.is_empty() { // Есть смысловые ошибки.
            return Err(errors); // Политику не применяем.
        }
        let hash = hex::encode(Sha256::digest(raw.as_bytes())); // Хеш исходного текста.
        let ver = match &file.version { // Версия может быть числом или строкой.
            serde_yaml::Value::String(s) => s.clone(), // Строка как есть.
            other => serde_yaml::to_string(other).unwrap_or_default().trim().to_string(), // Число в строку.
        };
        Ok(Policy { version: format!("{ver}#{}", &hash[..8]), file, raw: raw.to_string() }) // Готовая политика.
    }

    /// Описание агента it_ops_agent (наличие проверено в parse).
    pub fn agent(&self) -> &AgentSpec {
        &self.file.agents["it_ops_agent"] // Безопасно: parse гарантирует наличие.
    }

    /// Категория из always_block?
    pub fn always_blocks(&self, cat: RiskCategory) -> bool {
        let name = category_name(cat); // Имя категории в YAML.
        self.file.always_block.iter().any(|c| c == name) // Ищем в списке.
    }

    /// Права роли на инструмент; неизвестное окружение считается prod.
    pub fn tool_perm(&self, role: Role, tool: &str, env: Env) -> Perm {
        let Some(spec) = self.agent().roles.get(role_name(role)) else { return Perm::Deny }; // Нет роли — запрет.
        let Some(rule) = spec.tools.get(tool) else { return Perm::Deny }; // Нет инструмента у роли — запрет.
        let is_prod = env != Env::Nonprod; // Unknown трактуем как prod.
        match rule { // Разбираем форму правила.
            ToolSpec::Short(v) => match v.as_str() { // Краткая форма.
                "any" | "allow" => Perm::Allow, // Разрешено везде.
                "nonprod" => if is_prod { Perm::Deny } else { Perm::Allow }, // Только вне prod.
                "prod" => if is_prod { Perm::Allow } else { Perm::Deny }, // Только prod (для полноты).
                "confirm" => Perm::Confirm, // Везде с подтверждением.
                _ => Perm::Deny, // deny и всё прочее — запрет.
            },
            ToolSpec::ByEnv(m) => { // Полная форма по окружениям.
                let key = if is_prod { "prod" } else { "nonprod" }; // Ключ текущего окружения.
                let v = m.get(key).or_else(|| m.get("any")); // Сначала точное окружение, потом any.
                match v.map(String::as_str) { // Значение правила.
                    Some("allow") | Some("any") => Perm::Allow, // Разрешено.
                    Some("confirm") => Perm::Confirm, // С подтверждением.
                    _ => Perm::Deny, // deny или нет правила — запрет.
                }
            }
        }
    }

    /// Можно ли роли видеть имена секретов (значения не разрешены никому).
    pub fn secret_names_allowed(&self, role: Role) -> bool {
        self.agent().roles.get(role_name(role)).map(|r| r.secrets == "names_only").unwrap_or(false) // names_only — можно имена.
    }

    /// Это действие в списке forbidden_actions?
    pub fn is_forbidden(&self, action: &str) -> bool {
        self.agent().forbidden_actions.iter().any(|a| a == action) // Ищем в списке.
    }
}

/// Имя роли в YAML.
pub fn role_name(r: Role) -> &'static str {
    match r { Role::Developer => "developer", Role::Sre => "sre", Role::Admin => "admin" } // Совпадает с ключами YAML.
}

/// Имя категории в YAML и в ответе.
pub fn category_name(c: RiskCategory) -> &'static str {
    use RiskCategory::*; // Короткие имена вариантов.
    match c { // Совпадает с именами serde и списками YAML.
        None => "none", // Обычный запрос.
        SensitiveAction => "sensitive_action", // Значимое действие.
        Jailbreak => "jailbreak", // Обход ограничений.
        PromptInjection => "prompt_injection", // Прямая инъекция.
        IndirectInjection => "indirect_injection", // Инъекция во вложении.
        SystemPromptExtraction => "system_prompt_extraction", // Извлечение промпта.
        SystemPromptOverride => "system_prompt_override", // Подмена правил.
        ToolAbuse => "tool_abuse", // Инструмент вне прав.
        PrivilegeEscalation => "privilege_escalation", // Повышение прав.
        UnauthorizedDataAccess => "unauthorized_data_access", // Чужие данные.
        DataExfiltration => "data_exfiltration", // Вывод наружу.
        HarmfulContent => "harmful_content", // Опасный контент.
        FraudSocialEngineering => "fraud_social_engineering", // Мошенничество.
        Abuse => "abuse", // Оскорбления.
    }
}

#[cfg(test)] // Тесты модуля политики.
mod tests {
    use super::*; // Функции модуля.

    #[test] // Исходная политика организаторов разбирается, версия вида 1#xxxxxxxx.
    fn parses_organizers_policy() {
        let p = Policy::parse(include_str!("../../policies/security_policy.yaml")).unwrap(); // Файл из корня репозитория.
        assert!(p.version.starts_with("1#") && p.version.len() == 10); // version + # + 8 символов хеша.
        assert_eq!(p.tool_perm(Role::Sre, "delete_resource", Env::Prod), Perm::Deny); // sre не удаляет в prod.
        assert_eq!(p.tool_perm(Role::Admin, "delete_resource", Env::Nonprod), Perm::Confirm); // admin удаляет с подтверждением.
        assert!(!p.secret_names_allowed(Role::Developer) && p.secret_names_allowed(Role::Sre)); // Секреты по ролям.
    }

    #[test] // Опечатка в YAML отклоняется с понятной ошибкой.
    fn rejects_typo() {
        let raw = include_str!("../../policies/security_policy.yaml").replace("read_logs: any", "read_logs: anyy"); // Неизвестное значение.
        let err = Policy::parse(&raw).unwrap_err(); // Политика невалидна.
        assert!(err.iter().any(|e| e.contains("anyy"))); // Ошибка называет значение.
    }
}
