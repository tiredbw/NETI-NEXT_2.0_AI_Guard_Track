//! Типы JSON-контракта AstraGuard v0: общие для сервиса, тестов и моков фронта.

use serde::{Deserialize, Serialize}; // Сериализация и разбор JSON через serde.
use uuid::Uuid; // Идентификаторы подтверждений.

/// Решение сторожа по запросу.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] // Копируемый enum с JSON-представлением.
#[serde(rename_all = "snake_case")] // В JSON значения пишутся в нижнем регистре.
pub enum Decision {
    Allow,   // Запрос безопасен и передаётся агенту.
    Block,   // Запрос заблокирован.
    Confirm, // Нужно подтверждение человека перед выполнением.
}

/// Уровень риска из фиксированного набора.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)] // Ord позволяет брать максимум из нескольких сигналов.
#[serde(rename_all = "snake_case")] // В JSON значения пишутся в нижнем регистре.
pub enum RiskLevel {
    None,     // Риска нет.
    Low,      // Низкий риск.
    Medium,   // Средний риск, обычно подтверждение.
    High,     // Высокий риск, блокировка.
    Critical, // Критический риск, блокировка без вариантов.
}

/// Категория угрозы из раздела 6 кейса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] // Копируемый enum с JSON-представлением.
#[serde(rename_all = "snake_case")] // В JSON значения пишутся в snake_case.
pub enum RiskCategory {
    None,                   // Обычный разрешённый запрос.
    SensitiveAction,        // Допустимое значимое действие с подтверждением.
    Jailbreak,              // Обход ограничений через роль или сценарий.
    PromptInjection,        // Прямая инъекция инструкций.
    IndirectInjection,      // Инструкции во вложениях, логах, документах.
    SystemPromptExtraction, // Попытка узнать системный промпт.
    SystemPromptOverride,   // Попытка подменить роль или правила агента.
    ToolAbuse,              // Инструмент вне полномочий роли.
    PrivilegeEscalation,    // Выдаёт себя за админа или другого пользователя.
    UnauthorizedDataAccess, // Чужие или недоступные роли данные.
    DataExfiltration,       // Вывод данных на внешний адрес.
    HarmfulContent,         // Оружие, наркотики, вредоносный код.
    FraudSocialEngineering, // Фишинг и мошенничество.
    Abuse,                  // Оскорбления, угрозы, дискриминация.
}

/// Окружение, выведенное сторожем из текста (наше поле).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] // Копируемый enum с JSON-представлением.
#[serde(rename_all = "snake_case")] // В JSON значения пишутся в нижнем регистре.
pub enum Env {
    Prod,    // Найдены признаки prod.
    Nonprod, // Найдены признаки dev/stage/test.
    Unknown, // Признаков нет; права считаем как для prod.
}

/// Роль пользователя из context.user_role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)] // Роль служит ключом в матрице прав.
#[serde(rename_all = "snake_case")] // В JSON значения пишутся в нижнем регистре.
pub enum Role {
    Developer, // Разработчик.
    Sre,       // SRE.
    Admin,     // Администратор.
}

/// Реплика истории диалога.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура реплики.
pub struct HistoryTurn {
    pub role: String,    // user или assistant.
    pub content: String, // Текст реплики.
}

/// Вложение: уже извлечённый текст документа.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура вложения.
pub struct Attachment {
    #[serde(default, rename = "type")] // type — ключевое слово Rust, поэтому переименовываем.
    pub kind: Option<String>, // Тип материала, обычно document.
    #[serde(default)] // Имя может отсутствовать.
    pub name: Option<String>, // Имя файла, только для объяснения.
    #[serde(default)] // Пустое вложение допустимо.
    pub content: String, // Текст, в котором может прятаться инъекция.
}

/// Контекст запроса от доверенной интеграции.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура контекста.
pub struct Context {
    #[serde(default)] // Во всех примерах it_ops_agent, но поле может не прийти.
    pub target_agent: Option<String>, // Защищаемый агент.
    pub user_role: Role, // Единственный источник полномочий.
    #[serde(default)] // Идентификатор может не прийти.
    pub user_id: Option<String>, // Идентификатор пользователя.
    #[serde(default)] // Имя может не прийти.
    pub user_name: Option<String>, // Имя пользователя.
    #[serde(default)] // Системный промпт может не прийти.
    pub system_prompt: Option<String>, // Описание агента; наружу не выводится.
    #[serde(default)] // История может быть пустой.
    pub history: Vec<HistoryTurn>, // Предыдущие реплики.
    #[serde(default)] // Вложений может не быть.
    pub attachments: Vec<Attachment>, // Вложения.
}

/// Тело POST /v1/check в формате организаторов.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура запроса.
pub struct CheckRequest {
    pub user_prompt: String, // Текущая инструкция пользователя.
    pub context: Context, // Роль, история и вложения.
}

/// Ответ POST /v1/check; всегда HTTP 200.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура ответа.
pub struct CheckResponse {
    pub decision: Decision, // Итоговое решение.
    pub risk_level: RiskLevel, // Уровень риска.
    pub risk_category: RiskCategory, // Основная категория угрозы.
    pub explanation: String, // Объяснение по-русски без секретов и системного промпта.
    pub latency_ms: f64, // Время обработки на сервере; организаторы перезаписывают своим замером.
    pub check_id: String, // Идентификатор проверки вида chk_… для журнала.
    pub request_hash: String, // sha256 канонического JSON {user_prompt, context}; фронт считает так же.
    pub tool: Option<String>, // Инструмент из запроса или null.
    pub env: Env, // Окружение после разбора (наше поле).
    pub policy_rule: Option<String>, // Сработавшее правило политики или null.
    pub policy_version: String, // Версия политики: version из YAML и хеш файла.
    pub signals: Vec<Signal>, // Какие слои что увидели; фронт показывает их в разборе.
}

/// Сигнал одного слоя проверки.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура сигнала.
pub struct Signal {
    pub source: String, // rules, model, policy, history или attachment.
    pub label: String, // Короткая метка.
    pub detail: String, // Подробность без секретов.
}

/// Ответ POST /v1/demo/submit.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура ответа демо.
pub struct DemoSubmitResponse {
    pub check: CheckResponse, // Результат проверки.
    pub forwarded: bool, // Передан ли запрос заглушке агента.
    pub agent_reply: Option<String>, // Ответ заглушки, если запрос передан.
    pub confirm_id: Option<Uuid>, // Id подтверждения при decision = confirm.
}

/// Строка журнала.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура записи журнала.
pub struct JournalItem {
    pub check_id: String, // Идентификатор проверки вида chk_….
    pub created_at: String, // Время в RFC 3339.
    pub user_id: Option<String>, // Пользователь.
    pub role: Role, // Роль пользователя.
    pub decision: Decision, // Решение.
    pub risk_level: RiskLevel, // Уровень риска.
    pub risk_category: RiskCategory, // Категория.
    pub latency_ms: f64, // Задержка.
    pub policy_version: String, // Версия политики на момент проверки.
    pub prompt_masked: String, // Запрос с замаскированными секретами.
}

/// Ответ GET /v1/journal.
#[derive(Debug, Clone, Serialize, Deserialize)] // Страница журнала.
pub struct JournalPage {
    pub items: Vec<JournalItem>, // Записи страницы.
    pub next_cursor: Option<String>, // Курсор следующей страницы или null.
}

