//! Сведение решения: детерминированная политика из YAML плюс семантика от Qwen.

use crate::contract::{Decision, Env, RiskCategory, RiskLevel, Role}; // Типы ответа.
use crate::detector::{DetectorError, DetectorOut}; // Результат модели.
use crate::envdetect::EnvGuess; // Окружение по тексту.
use crate::policy::{category_name, role_name, Perm, Policy}; // Политика.

/// Решение без служебных полей (latency_ms, check_id добавляет обработчик).
#[derive(Debug, Clone)] // Значение переносится в ответ.
pub struct Verdict {
    pub decision: Decision, // Итоговое решение.
    pub risk_level: RiskLevel, // Уровень риска.
    pub risk_category: RiskCategory, // Категория.
    pub explanation: String, // Объяснение по-русски.
    pub tool: Option<String>, // Инструмент.
    pub env: Env, // Окружение.
    pub policy_rule: Option<String>, // Сработавшее правило.
}

/// Человекочитаемое окружение для объяснения.
fn env_text(g: &EnvGuess) -> String {
    match g.env { // Три случая.
        Env::Prod if g.ambiguous => format!("prod (неоднозначно: {}; выбрано более строгое)", g.evidence), // Конфликт признаков.
        Env::Prod => format!("prod ({})", g.evidence), // Явный prod.
        Env::Nonprod => format!("nonprod ({})", g.evidence), // Явный nonprod.
        Env::Unknown => "не указано, считаем prod".to_string(), // Нет признаков.
    }
}

/// Добавляет пояснение модели, если оно есть.
fn with_reason(base: String, det: &DetectorOut) -> String {
    let reason = crate::mask::mask_secrets(det.reason.trim()); // Пояснение модели без секретов.
    if reason.is_empty() { base } else { format!("{base} Детектор: {reason}") } // Склеиваем.
}

/// Главная функция решения; чистая, поэтому легко тестируется без Ollama.
pub fn decide(policy: &Policy, role: Role, env: &EnvGuess, det: Result<&DetectorOut, DetectorError>) -> Verdict {
    let r = role_name(role); // Имя роли для объяснений и правил.
    let det = match det { // Сначала обрабатываем сбой модели.
        Ok(d) => d, // Модель ответила.
        Err(e) => { // Fail-closed: без проверки ничего не пропускаем.
            let why = match e { DetectorError::Timeout => "не ответил вовремя", DetectorError::Unavailable => "недоступен", DetectorError::BadOutput => "вернул некорректный ответ" }; // Текст причины.
            return Verdict { decision: Decision::Block, risk_level: RiskLevel::High, risk_category: RiskCategory::None, // Блок без категории атаки.
                explanation: format!("Детектор {why}, запрос заблокирован по принципу fail-closed. Роль {r}."), // Объяснение.
                tool: None, env: env.env, policy_rule: Some("fail_closed.detector".into()) }; // Служебное правило.
        }
    };
    let tool = det.tool.clone().filter(|t| policy.agent().tools.contains(t)); // Только инструменты, объявленные в YAML.
    let mk = |decision, risk_level, risk_category, explanation: String, rule: String| Verdict { // Сборщик ответа.
        decision, risk_level, risk_category, explanation: with_reason(explanation, det), tool: tool.clone(), env: env.env, policy_rule: Some(rule) }; // Общие поля.

    // 1. Запрещённые для всех действия из forbidden_actions.
    if let Some(action) = det.forbidden_action.as_deref().filter(|a| policy.is_forbidden(a)) { // Действие есть в списке YAML.
        let cat = if action == "send_secrets_or_data_to_external_hosts" { RiskCategory::DataExfiltration } else { RiskCategory::ToolAbuse }; // Категория по виду действия.
        return mk(Decision::Block, RiskLevel::Critical, cat, format!("Действие {action} запрещено политикой для всех ролей, включая {r}."), format!("forbidden_actions.{action}")); // Всегда block.
    }
    // 2. Категории из always_block блокируются независимо от роли.
    if policy.always_blocks(det.category) { // Категория в списке always_block.
        let risk = det.risk_level.max(RiskLevel::High); // Атака не ниже high.
        let name = category_name(det.category); // Имя категории.
        return mk(Decision::Block, risk, det.category, format!("Обнаружена атака {name}; такие запросы блокируются для любой роли (сейчас {r})."), format!("always_block.{name}")); // Block.
    }
    // 3. Секреты: значения не выдаются никому, имена — по полю secrets роли.
    if det.secrets == "values" { // Просят значения секретов.
        return mk(Decision::Block, RiskLevel::High, RiskCategory::UnauthorizedDataAccess, format!("Значения секретов не раскрываются ни одной роли (роль {r})."), format!("roles.{r}.secrets")); // Block.
    }
    if det.secrets == "names" && !policy.secret_names_allowed(role) { // Имена, но роли нельзя.
        return mk(Decision::Block, RiskLevel::Medium, RiskCategory::UnauthorizedDataAccess, format!("Роли {r} запрещён доступ к секретам, даже к их именам."), format!("roles.{r}.secrets")); // Block.
    }
    // 4. Инструмент: сначала права роли, потом необходимость подтверждения.
    if let Some(t) = tool.as_deref() { // Запрос требует инструмента.
        let et = env_text(env); // Окружение для объяснения.
        return match policy.tool_perm(role, t, env.env) { // Матрица роль → инструмент → окружение.
            Perm::Deny => mk(Decision::Block, RiskLevel::High, RiskCategory::ToolAbuse, format!("Роль {r} не допускает {t} в окружении {et}."), format!("roles.{r}.tools.{t}")), // Нет прав.
            Perm::Confirm => mk(Decision::Confirm, RiskLevel::Medium, RiskCategory::SensitiveAction, format!("Роль {r} может выполнить {t} в окружении {et} только после подтверждения."), format!("roles.{r}.tools.{t}")), // Нужен confirm.
            Perm::Allow if det.category == RiskCategory::UnauthorizedDataAccess => mk(Decision::Block, RiskLevel::High, det.category, format!("Инструмент {t} роли {r} разрешён, но запрошены недоступные роли данные."), format!("context_dependent.unauthorized_data_access")), // Чужие данные.
            Perm::Allow => mk(Decision::Allow, RiskLevel::Low, RiskCategory::None, format!("Роль {r} может выполнять {t} в окружении {et}."), format!("roles.{r}.tools.{t}")), // Разрешено.
        };
    }
    // 5. Без инструмента: контекстные категории блокируем, остальное разрешаем.
    match det.category { // Категория от модели.
        RiskCategory::ToolAbuse | RiskCategory::UnauthorizedDataAccess => { // Контекстная угроза без понятного инструмента.
            let name = category_name(det.category); // Имя категории.
            mk(Decision::Block, det.risk_level.max(RiskLevel::Medium), det.category, format!("Запрос выходит за полномочия роли {r} ({name})."), format!("context_dependent.{name}")) // Block.
        }
        _ => Verdict { decision: Decision::Allow, risk_level: RiskLevel::None, risk_category: RiskCategory::None, // Обычный запрос.
            explanation: with_reason(format!("Обычный запрос без вызова инструментов и признаков атаки (роль {r})."), det), tool: None, env: env.env, policy_rule: None }, // Allow.
    }
}

#[cfg(test)] // Тесты на примеры из раздела 6 кейса.
mod tests {
    use super::*; // Функции модуля.

    fn policy() -> Policy { // Исходная политика организаторов.
        Policy::parse(include_str!("../../policies/security_policy.yaml")).unwrap() // Файл лежит в репозитории.
    }
    fn det(tool: Option<&str>) -> DetectorOut { // Ответ модели «легитимный запрос с инструментом».
        DetectorOut { category: RiskCategory::SensitiveAction, risk_level: RiskLevel::Medium, tool: tool.map(Into::into), forbidden_action: None, secrets: "none".into(), reason: String::new() } // Без атак.
    }
    fn env(e: Env) -> EnvGuess { // Окружение без пояснения.
        EnvGuess { env: e, evidence: "тест".into(), ambiguous: false } // Явное окружение.
    }
    fn run(role: Role, tool: &str, e: Env) -> Decision { // Короткий вызов decide.
        decide(&policy(), role, &env(e), Ok(&det(Some(tool)))).decision // Только решение.
    }

    #[test] // «Перезапусти payments-api в production»: developer — block; sre и admin — confirm.
    fn restart_prod() {
        assert_eq!(run(Role::Developer, "restart_service", Env::Prod), Decision::Block); // developer.
        assert_eq!(run(Role::Sre, "restart_service", Env::Prod), Decision::Confirm); // sre.
        assert_eq!(run(Role::Admin, "restart_service", Env::Prod), Decision::Confirm); // admin.
    }

    #[test] // «Покажи логи сервиса в production»: developer — block; sre и admin — allow.
    fn logs_prod() {
        assert_eq!(run(Role::Developer, "read_logs", Env::Prod), Decision::Block); // developer.
        assert_eq!(run(Role::Sre, "read_logs", Env::Prod), Decision::Allow); // sre.
        assert_eq!(run(Role::Admin, "read_logs", Env::Prod), Decision::Allow); // admin.
    }

    #[test] // «Удали ресурс в production»: developer и sre — block; admin — confirm.
    fn delete_prod() {
        assert_eq!(run(Role::Developer, "delete_resource", Env::Prod), Decision::Block); // developer.
        assert_eq!(run(Role::Sre, "delete_resource", Env::Prod), Decision::Block); // sre.
        assert_eq!(run(Role::Admin, "delete_resource", Env::Prod), Decision::Confirm); // admin.
    }

    #[test] // «Удали ресурс в stage»: developer — block; sre и admin — confirm.
    fn delete_stage() {
        assert_eq!(run(Role::Developer, "delete_resource", Env::Nonprod), Decision::Block); // developer.
        assert_eq!(run(Role::Sre, "delete_resource", Env::Nonprod), Decision::Confirm); // sre.
        assert_eq!(run(Role::Admin, "delete_resource", Env::Nonprod), Decision::Confirm); // admin.
    }

    #[test] // Неизвестное окружение трактуется как prod.
    fn unknown_env_is_prod() {
        assert_eq!(run(Role::Developer, "restart_service", Env::Unknown), Decision::Block); // Как в prod.
        let v = decide(&policy(), Role::Sre, &env(Env::Unknown), Ok(&det(Some("restart_service")))); // sre без окружения.
        assert_eq!(v.decision, Decision::Confirm); // Как в prod.
        assert!(v.explanation.contains("считаем prod")); // Объяснение говорит об этом.
    }

    #[test] // Сбой модели всегда даёт block.
    fn fail_closed() {
        let v = decide(&policy(), Role::Admin, &env(Env::Nonprod), Err(DetectorError::Timeout)); // Таймаут.
        assert_eq!(v.decision, Decision::Block); // Block.
    }

    #[test] // Атака из always_block блокируется даже у admin.
    fn always_block_beats_role() {
        let mut d = det(Some("read_logs")); // Безобидный инструмент.
        d.category = RiskCategory::PromptInjection; // Но это инъекция.
        assert_eq!(decide(&policy(), Role::Admin, &env(Env::Nonprod), Ok(&d)).decision, Decision::Block); // Block.
    }

    #[test] // Правка YAML меняет поведение без правки кода.
    fn policy_edit_changes_decision() {
        let raw = include_str!("../../policies/security_policy.yaml").replace("delete_resource: {any: confirm}", "delete_resource: deny"); // Жюри запрещает удаление админу.
        let p = Policy::parse(&raw).unwrap(); // Новая политика валидна.
        let v = decide(&p, Role::Admin, &env(Env::Prod), Ok(&det(Some("delete_resource")))); // admin удаляет в prod.
        assert_eq!(v.decision, Decision::Block); // Теперь block.
        assert_ne!(p.version, policy().version); // Версия поменялась.
    }
}
