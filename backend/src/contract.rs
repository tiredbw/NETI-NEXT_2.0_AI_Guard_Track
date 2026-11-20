//! Типы JSON-контракта AstraGuard v0: общие для сервиса, тестов и моков фронта.

use serde::{Deserialize, Serialize}; // Сериализация и разбор JSON через serde.

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

/// Квитанция заглушки агента: факт получения разрешённого запроса.
#[derive(Debug, Clone, Serialize, Deserialize)] // Элемент входящих агента.
pub struct Receipt {
    pub receipt_id: String, // Идентификатор вида rcp_….
    pub check_id: String, // Проверка, по которой запрос передан.
    pub received_at: String, // Время получения, RFC 3339 UTC.
    pub user_id: Option<String>, // Пользователь.
    pub user_role: Role, // Роль.
    pub decision: Decision, // allow или confirm.
    pub confirmed: bool, // Передан после явного подтверждения.
    pub prompt_masked: String, // Запрос без значений секретов.
}

/// Ожидающее подтверждение для решения confirm.
#[derive(Debug, Clone, Serialize, Deserialize)] // Часть ответа submit.
pub struct Confirmation {
    pub check_id: String, // Проверка, которую подтверждают.
    pub request_hash: String, // Хеш неизменного запроса.
    pub user_id: Option<String>, // Кто может подтвердить.
    pub expires_at: String, // До какого момента, RFC 3339 UTC.
}

/// Ответ POST /v1/demo/submit и основа ответа сессии.
#[derive(Debug, Clone, Serialize, Deserialize)] // Структура ответа демо.
pub struct SubmitResponse {
    pub check: CheckResponse, // Результат проверки.
    pub status: String, // forwarded, blocked или pending_confirmation.
    pub receipt: Option<Receipt>, // Квитанция, если передано агенту.
    pub confirmation: Option<Confirmation>, // Подтверждение, если решение confirm.
}

/// Тело POST /v1/demo/confirm.
#[derive(Debug, Clone, Deserialize)] // Разбирается из JSON.
pub struct ConfirmRequest {
    pub check_id: String, // Какую проверку подтверждаем.
    pub request_hash: String, // Хеш запроса, который видел пользователь.
    pub user_id: Option<String>, // Кто подтверждает.
}

/// Строка журнала проверок.
#[derive(Debug, Clone, Serialize, Deserialize)] // Запись журнала.
pub struct JournalEntry {
    pub check_id: String, // Идентификатор проверки.
    pub ts: String, // Время, RFC 3339 UTC с миллисекундами.
    pub user_id: Option<String>, // Пользователь.
    pub user_role: Role, // Роль.
    pub decision: Decision, // Решение.
    pub risk_level: RiskLevel, // Уровень риска.
    pub risk_category: RiskCategory, // Категория.
    pub latency_ms: f64, // Задержка проверки.
    pub policy_version: String, // Версия политики на момент проверки.
    pub prompt_masked: String, // Запрос без значений секретов.
    pub explanation: String, // Объяснение решения.
    pub source: String, // check, demo или session.
}

/// Реплика сохранённой сессии.
#[derive(Debug, Clone, Serialize, Deserialize)] // Элемент истории сессии.
pub struct Turn {
    pub index: usize, // Номер реплики с нуля.
    pub role: String, // user или assistant.
    pub content: String, // Текст реплики.
    pub ts: String, // Время, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")] // У реплик агента решения нет.
    pub decision: Option<Decision>, // Решение по реплике пользователя.
    #[serde(skip)] // Внутреннее поле: связь с подтверждением.
    pub check_id: Option<String>, // Проверка этой реплики.
}

/// Ограничения сессии.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)] // Часть ответа сессии.
pub struct SessionLimits {
    pub max_turns: usize, // Максимум реплик пользователя.
    pub ttl_minutes: u64, // Срок хранения с момента создания.
}

/// Изолированная сессия пользователя.
#[derive(Debug, Clone, Serialize, Deserialize)] // Ответ API сессий.
pub struct Session {
    pub session_id: String, // Идентификатор ses_….
    pub user_id: String, // Владелец; чужие пользователи сессию не видят.
    pub user_name: String, // Имя для контекста.
    pub user_role: Role, // Роль владельца.
    #[serde(skip)] // Системный промпт наружу не отдаём.
    pub system_prompt: String, // Описание агента для контекста.
    pub created_at: String, // Время создания.
    pub expires_at: String, // Время удаления.
    #[serde(skip)] // Для проверки срока.
    pub expires_unix: u64, // Срок в секундах Unix.
    pub limits: SessionLimits, // Ограничения.
    pub turns: Vec<Turn>, // История.
}

/// Отмеченная реплика истории.
#[derive(Debug, Clone, Serialize, Deserialize)] // Часть history_effect.
pub struct FlaggedTurn {
    pub turn: usize, // Номер реплики.
    pub reason: String, // Почему отмечена.
}

/// Как история сессии повлияла на решение.
#[derive(Debug, Clone, Serialize, Deserialize)] // Часть ответа сессии.
pub struct HistoryEffect {
    pub turns_considered: usize, // Сколько реплик ушло в context.history.
    pub flagged: Vec<FlaggedTurn>, // Ранее заблокированные реплики.
    pub note: String, // Пояснение для человека.
}

/// Сведения о версии политики.
#[derive(Debug, Clone, Serialize, Deserialize)] // Элемент истории политики.
pub struct PolicyVersionInfo {
    pub version: String, // Версия.
    pub updated_at: String, // Когда применена.
    pub updated_by: String, // Кто применил.
    pub comment: String, // Что изменено.
}
