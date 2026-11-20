//! HTTP-слой: маршруты Axum, состояние приложения, перезагрузка политики.

use crate::contract::{CheckRequest, CheckResponse, Signal}; // Контракт /v1/check.
use crate::detector::{build_user_message, Detector}; // Клиент Qwen.
use crate::policy::Policy; // Политика.
use crate::{decide, envdetect, normalize}; // Остальные модули.
use arc_swap::ArcSwap; // Атомарная замена политики без блокировок.
use axum::extract::{DefaultBodyLimit, State}; // Экстракторы Axum.
use axum::http::{HeaderMap, StatusCode}; // Заголовки и коды ответа.
use axum::response::{IntoResponse, Response}; // Ответы.
use axum::routing::{get, post}; // Методы маршрутов.
use axum::{Json, Router}; // JSON и роутер.
use serde_json::json; // Сборка JSON-ответов.
use std::path::PathBuf; // Путь к файлу политики.
use std::sync::Arc; // Общее состояние между запросами.
use std::time::Instant; // Замер задержки.

/// Общее состояние сервиса.
pub struct AppState {
    pub policy: ArcSwap<Policy>, // Текущая политика; каждый запрос берёт снимок.
    pub policy_path: PathBuf, // Файл, из которого перечитываем политику.
    pub detector: Detector, // Клиент Ollama.
    pub admin_token: Option<String>, // Токен админа для изменения политики; None — изменение выключено.
}

/// Ошибка в формате {"error": {"code", "message"}}.
fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, Json(json!({"error": {"code": code, "message": message.into()}}))).into_response() // Единый формат ошибок.
}

/// Проверяет заголовок X-Admin-Token.
fn is_admin(state: &AppState, headers: &HeaderMap) -> bool {
    match (&state.admin_token, headers.get("x-admin-token").and_then(|v| v.to_str().ok())) { // Токен сервера и токен запроса.
        (Some(expected), Some(got)) => expected == got, // Совпадают — админ.
        _ => false, // Иначе нет.
    }
}

/// POST /v1/check: только оценка, ничего не исполняет и никуда не передаёт.
async fn check(State(state): State<Arc<AppState>>, body: axum::body::Bytes) -> Response {
    let started = Instant::now(); // Начало замера.
    let raw: serde_json::Value = match serde_json::from_slice(&body) { // Сначала как произвольный JSON: нужен для request_hash.
        Ok(v) => v, // Корректный JSON.
        Err(e) => return error(StatusCode::BAD_REQUEST, "INVALID_INPUT", e.to_string()), // Не JSON.
    };
    let request_hash = canonical_hash(&raw); // Хеш до любых преобразований.
    let req: CheckRequest = match serde_json::from_value(raw) { // Затем строго по контракту.
        Ok(r) => r, // Корректный запрос.
        Err(e) => return error(StatusCode::BAD_REQUEST, "INVALID_INPUT", e.to_string()), // Нет обязательных полей.
    };
    let policy = state.policy.load_full(); // Снимок политики: версия в ответе совпадёт с проверкой.
    let prompt = normalize::normalize(&req.user_prompt); // Нормализованный запрос.
    let agent = policy.agent(); // Маски окружений из YAML.
    let empty = Vec::new(); // Пустой список масок на случай их отсутствия.
    let prod_masks = agent.environments.get("prod").unwrap_or(&empty); // Маски prod.
    let nonprod_masks = agent.environments.get("nonprod").unwrap_or(&empty); // Маски nonprod.
    let mut env_text = prompt.clone(); // Окружение ищем в запросе.
    for turn in req.context.history.iter().filter(|t| t.role == "user").rev().take(2) { // И в двух последних репликах пользователя.
        env_text.push(' '); // Разделитель.
        env_text.push_str(&turn.content); // Текст реплики.
    }
    for (_, hidden) in normalize::hidden_variants(&req.user_prompt) { // Окружение ищем и в раскодированных вариантах.
        env_text.push(' '); // Разделитель.
        env_text.push_str(&hidden); // Раскодированный текст.
    }
    let env = envdetect::detect(&env_text, prod_masks, nonprod_masks); // Детерминированное окружение (доли миллисекунды).
    let message = build_user_message(&req, &prompt); // Сообщение для модели.
    let det = state.detector.classify(&message).await; // Вызов Qwen; занимает почти всё время ответа.
    let v = decide::decide(&policy, req.context.user_role, &env, det.as_ref().map_err(|e| *e)); // Сводим политику и модель.
    let mut signals = Vec::new(); // Разбор по слоям для фронта.
    match &det { // Что сказала модель.
        Ok(d) => signals.push(Signal { source: "model".into(), label: format!("{:?}", d.category).to_lowercase(), detail: crate::mask::mask_secrets(&d.reason) }), // Категория и пояснение.
        Err(e) => signals.push(Signal { source: "model".into(), label: "error".into(), detail: format!("{e:?}") }), // Сбой модели.
    }
    signals.push(Signal { source: "policy".into(), label: format!("{:?}", v.decision).to_lowercase(), detail: v.policy_rule.clone().unwrap_or_else(|| "нет правила".into()) }); // Сработавшее правило.
    if !env.evidence.is_empty() { signals.push(Signal { source: "rules".into(), label: "env".into(), detail: env.evidence.clone() }); } // Откуда окружение.
    let mut explanation = v.explanation; // Объяснение.
    if explanation.chars().count() > 1000 { explanation = explanation.chars().take(1000).collect(); } // Держим ответ далеко от 64 KiB.
    let resp = CheckResponse {
        decision: v.decision, risk_level: v.risk_level, risk_category: v.risk_category, explanation, // Основные поля.
        latency_ms: (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0, // Задержка с точностью 0.1 мс.
        check_id: format!("chk_{}", uuid::Uuid::new_v4().simple()), // Идентификатор для журнала.
        request_hash, // Хеш исходного запроса.
        tool: v.tool, env: v.env, policy_rule: v.policy_rule, policy_version: policy.version.clone(), signals, // Наши поля.
    };
    tracing::info!(check_id = %resp.check_id, decision = ?resp.decision, category = ?resp.risk_category, latency_ms = resp.latency_ms, "check"); // Журнал без текста запроса.
    Json(resp).into_response() // HTTP 200.
}

/// sha256 от JSON {user_prompt, context} с отсортированными ключами и без пробелов, как JSON.stringify на фронте.
pub fn canonical_hash(raw: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256}; // Хеш.
    let subset = json!({"context": raw["context"], "user_prompt": raw["user_prompt"]}); // Только эти два поля.
    let text = serde_json::to_string(&subset).unwrap_or_default(); // serde_json без preserve_order сортирует ключи и пишет без пробелов.
    hex::encode(Sha256::digest(text.as_bytes())) // Hex-строка.
}

/// GET /health: готовность модели и версия политики.
async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "mode": std::env::var("GUARD_MODE").unwrap_or_else(|_| "gpu".into()), "model": state.detector.cfg.model, "policy_version": state.policy.load().version})) // Короткий статус.
}

/// GET /v1/policy: действующая политика и её версия.
async fn get_policy(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let p = state.policy.load(); // Текущий снимок.
    Json(json!({"version": p.version, "yaml": p.raw})) // Версия и текст.
}

/// PUT /v1/policy: валидирует, сохраняет в файл и применяет новую политику (только админ).
async fn put_policy(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if !is_admin(&state, &headers) { return error(StatusCode::FORBIDDEN, "FORBIDDEN", "нужен X-Admin-Token"); } // Только админ.
    let Some(raw) = body["yaml"].as_str() else { return error(StatusCode::UNPROCESSABLE_ENTITY, "POLICY_INVALID", "нет поля yaml") }; // Текст обязателен.
    let author = body["author"].as_str().unwrap_or("unknown"); // Автор изменения.
    match Policy::parse(raw) { // Сначала валидация.
        Ok(p) => {
            if let Err(e) = std::fs::write(&state.policy_path, raw) { return error(StatusCode::INTERNAL_SERVER_ERROR, "POLICY_WRITE_FAILED", e.to_string()); } // Сохраняем на диск.
            let version = p.version.clone(); // Новая версия.
            state.policy.store(Arc::new(p)); // Атомарно применяем.
            tracing::info!(%version, %author, "policy updated"); // Фиксируем автора и время в логе.
            Json(json!({"version": version})).into_response() // Ответ с версией.
        }
        Err(details) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": {"code": "POLICY_INVALID", "details": details}}))).into_response(), // Ошибки валидации.
    }
}

/// POST /v1/policy/reload: перечитывает файл политики с диска (только админ).
async fn reload_policy(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_admin(&state, &headers) { return error(StatusCode::FORBIDDEN, "FORBIDDEN", "нужен X-Admin-Token"); } // Только админ.
    match reload_from_disk(&state) { // Перечитываем.
        Ok(version) => Json(json!({"version": version})).into_response(), // Новая версия.
        Err(details) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": {"code": "POLICY_INVALID", "details": details}}))).into_response(), // Старая политика остаётся.
    }
}

/// Читает файл политики и применяет его, если он валиден.
pub fn reload_from_disk(state: &AppState) -> Result<String, Vec<String>> {
    let raw = std::fs::read_to_string(&state.policy_path).map_err(|e| vec![e.to_string()])?; // Текст файла.
    let p = Policy::parse(&raw)?; // Валидация.
    let version = p.version.clone(); // Версия.
    if version != state.policy.load().version { // Файл действительно изменился.
        state.policy.store(Arc::new(p)); // Применяем.
        tracing::info!(%version, "policy reloaded"); // Пишем в лог.
    }
    Ok(version) // Возвращаем версию.
}

/// Собирает роутер со всеми маршрутами.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/check", post(check)) // Главный endpoint оценки.
        .route("/health", get(health)) // Проверка живости.
        .route("/v1/policy", get(get_policy).put(put_policy)) // Просмотр и изменение политики.
        .route("/v1/policy/reload", post(reload_policy)) // Перезагрузка с диска.
        .layer(DefaultBodyLimit::max(1024 * 1024)) // Тело не больше 1 MiB, как в starter_api.py.
        .with_state(state) // Общее состояние.
}

#[cfg(test)] // Тесты HTTP-слоя.
mod tests {
    #[test] // request_hash совпадает с хешем, который считает фронт через JSON.stringify с сортировкой ключей.
    fn request_hash_matches_frontend() {
        let raw = serde_json::json!({"user_prompt": "Перезапусти payments-api / \"prod\"", "context": {"user_role": "sre", "history": [{"role": "user", "content": "привет"}], "attachments": []}}); // Тот же запрос, что в проверке на node.
        assert_eq!(super::canonical_hash(&raw), "1ae38b7290194dab576a4445048a7be2de0a07ad181c75e29e7369dc275edb22"); // Значение посчитано node-скриптом.
    }
}
