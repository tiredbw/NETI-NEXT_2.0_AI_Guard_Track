//! HTTP-слой: маршруты Axum по контракту docs/FRONTEND_PROMPT.md, состояние приложения, перезагрузка политики.

use crate::contract::{
    CheckRequest, CheckResponse, Confirmation, ConfirmRequest, Decision, FlaggedTurn, HistoryEffect, JournalEntry, PolicyVersionInfo,
    Receipt, Role, Session, SessionLimits, Signal, SubmitResponse, Turn,
};
use crate::detector::{build_user_message, Detector};
use crate::policy::Policy;
use crate::store::{self, now_iso, unix_now, Pending, Store};
use crate::{decide, envdetect, mask, normalize, web};
use arc_swap::ArcSwap;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Общее состояние сервиса.
pub struct AppState {
    pub policy: ArcSwap<Policy>, // Текущая политика; каждый запрос берёт снимок.
    pub policy_path: PathBuf, // Файл, из которого перечитываем политику.
    pub detector: Detector, // Клиент Ollama.
    pub tfidf: Option<crate::tfidf::Tfidf>, // TF-IDF-классификатор; None — файл модели не найден.
    pub admin_token: Option<String>, // Токен админа для изменения политики; None — изменение выключено.
    pub audit_token: Option<String>, // Токен только для чтения журнала, входящих агента и политики; None — читать может только админ.
    pub store: Store, // Журнал, входящие агента, подтверждения, сессии, история политики.
    pub frontend_dir: Option<PathBuf>, // Каталог фронтенда для раздачи со своего origin.
    pub cors_origins: Vec<String>, // Origin отдельного dev-сервера фронта.
}

/// Ошибка в формате контракта: {"error": "<code>", "detail": "<текст>"}.
pub fn error(status: StatusCode, code: &str, detail: impl Into<String>) -> Response {
    (status, Json(json!({"error": code, "detail": detail.into()}))).into_response()
}

fn store_error((status, code, detail): (u16, &str, &str)) -> Response {
    error(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST), code, detail)
}

/// Проверка X-Admin-Token: 401 без токена, 403 при неверном или выключенном управлении.
fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let got = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).filter(|s| !s.is_empty());
    match (&state.admin_token, got) {
        (_, None) => Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "Нужен заголовок X-Admin-Token")),
        (None, Some(_)) => Err(error(StatusCode::FORBIDDEN, "forbidden", "Управление политикой выключено: ADMIN_TOKEN не задан")),
        (Some(expected), Some(t)) if token_eq(expected, t) => Ok(()),
        _ => Err(error(StatusCode::FORBIDDEN, "forbidden", "Токен не даёт права менять политику")),
    }
}

/// Проверка права читать журнал, входящие агента и политику: подходит токен админа или токен аудитора.
/// Без заданных токенов чтение закрыто: журнал не должен открываться всем, кто достучался до порта.
fn require_reader(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let got = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).filter(|s| !s.is_empty());
    let Some(t) = got else { return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "Нужен заголовок X-Admin-Token")) }; // Токена нет — 401.
    let known = [&state.admin_token, &state.audit_token]; // Админ может всё, аудитор только читать.
    if known.iter().any(|k| k.as_deref().is_some_and(|k| token_eq(k, t))) { return Ok(()); } // Совпал один из токенов.
    if known.iter().all(|k| k.is_none()) { return Err(error(StatusCode::FORBIDDEN, "forbidden", "Чтение закрыто: ADMIN_TOKEN и AUDIT_TOKEN не заданы")); } // Токены не настроены.
    Err(error(StatusCode::FORBIDDEN, "forbidden", "Токен не даёт доступа к журналу и политике")) // Неверный токен.
}

/// Сравнение токенов за время, не зависящее от места первого расхождения.
fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes()); // Сравниваем байты.
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0 // Без раннего выхода.
}

/// Запрос пришёл из нашего интерфейса: фронт ставит X-Guard-Client: ui. Тестовый клиент организаторов его не ставит.
fn from_ui(headers: &HeaderMap) -> bool {
    headers.get("x-guard-client").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("ui"))
}

// ---------- оценка ----------

/// Полная проверка: разбор, окружение, Qwen, политика. Ничего не исполняет и никуда не передаёт.
async fn evaluate(state: &AppState, raw: Value) -> Result<(CheckResponse, CheckRequest), Response> {
    let started = Instant::now();
    let request_hash = canonical_hash(&raw); // Хеш до любых преобразований.
    let req: CheckRequest = serde_json::from_value(raw).map_err(|e| error(StatusCode::BAD_REQUEST, "invalid_input", e.to_string()))?;
    let policy = state.policy.load_full(); // Снимок: версия в ответе совпадёт с проверкой.
    let prompt = normalize::normalize(&req.user_prompt);
    let agent = policy.agent();
    let empty = Vec::new();
    let prod_masks = agent.environments.get("prod").unwrap_or(&empty);
    let nonprod_masks = agent.environments.get("nonprod").unwrap_or(&empty);
    let mut env_text = prompt.clone();
    for turn in req.context.history.iter().filter(|t| t.role == "user").rev().take(2) {
        env_text.push(' ');
        env_text.push_str(&turn.content);
    }
    for (_, hidden) in normalize::hidden_variants(&req.user_prompt) {
        env_text.push(' ');
        env_text.push_str(&hidden);
    }
    let env = envdetect::detect(&env_text, prod_masks, nonprod_masks);
    let variants = normalize::hidden_variants(&req.user_prompt); // Раскодированные варианты запроса.
    let tf = state.tfidf.as_ref().map(|t| (t.score(&req, &variants), t.threshold, t.backstop)); // TF-IDF до Qwen: микросекунды.
    let blockable = |c: crate::contract::RiskCategory| { // Категория, которую политика блокирует.
        let name = crate::policy::category_name(c);
        policy.always_blocks(c) || policy.file.context_dependent.iter().any(|x| x == name)
    };
    // Быстрый фильтр (TFIDF_PREFILTER): уверенная атака блокируется без вызова Qwen.
    let prefiltered = match (state.tfidf.as_ref().and_then(|t| t.prefilter), tf) {
        (Some(limit), Some((s, _, _))) if s.p_attack >= limit && blockable(s.category) => Some(s),
        _ => None,
    };
    let det = if let Some(s) = prefiltered {
        Ok(crate::detector::DetectorOut { category: s.category, risk_level: crate::contract::RiskLevel::High, tool: None, forbidden_action: None, action: "execute".into(), secrets: "none".into(),
            reason: format!("Qwen не вызывался: быстрый фильтр TF-IDF уверен в атаке (p={:.2}).", s.p_attack) })
    } else {
        let mut message = build_user_message(&req, &prompt);
        if let (Some(true), Some((s, _, _))) = (state.tfidf.as_ref().map(|t| t.hint), tf) { // Подсказка классификатора для Qwen (TFIDF_HINT).
            message.push_str(&format!("<classifier p_attack=\"{:.2}\" category=\"{}\">Оценка независимого классификатора по словам. Он часто ошибается на вопросах и учебных запросах, решай по смыслу.</classifier>\n", s.p_attack, crate::policy::category_name(s.category)));
        }
        state.detector.classify(&message).await // Почти всё время ответа.
    };
    let model_reason = det.as_ref().ok().map(|d| d.reason.clone()).unwrap_or_default(); // Пояснение самой модели для сигнала model.
    let followup = crate::history::secret_followup(&req, &prompt); // Просьба выдать секреты, о которых шла речь раньше.
    let rule_hit = crate::rules::check(&prompt, &variants, req.context.user_role); // Детерминированные правила.
    let mut inferred_tool: Option<&'static str> = None; // Инструмент, найденный правилами вместо Qwen.
    let det = det.map(|mut d| {
        if let Some(word) = &followup {
            if d.secrets != "values" { d.secrets = "values".into(); d.reason = format!("реплика ссылается на предыдущую о «{word}» и просит выдать содержимое"); }
        }
        if let Some(hit) = &rule_hit { crate::rules::apply(&mut d, hit); } // Правила только усиливают ответ модели.
        let weak = matches!(d.category, crate::contract::RiskCategory::None | crate::contract::RiskCategory::SensitiveAction); // Атаки модель не увидела.
        if weak && (d.tool.is_none() || d.action == "ask") { // Qwen не назвал инструмент или счёл просьбу вопросом («требует уточнения»), а текст — явная просьба действия.
            if let Some(t) = crate::rules::infer_tool(&prompt).filter(|t| env.env != crate::contract::Env::Unknown || (*t == "delete_resource" && crate::rules::names_infra(&prompt))) { // Без окружения — только удаление названного ресурса.
                if d.tool.is_none() { d.tool = Some(t.into()); } // Инструмент модели, если назван, остаётся.
                d.action = "execute".into(); inferred_tool = Some(t); // Дальше обычная матрица прав из YAML.
            }
        }
        d
    });
    let mut v = decide::decide(&policy, req.context.user_role, &env, det.as_ref().map_err(|e| *e));
    if let (Some(hit), Ok(_)) = (&rule_hit, &det) {
        if hit.hard_block && v.decision != Decision::Block { // Разрушительная команда: block для любой роли.
            v.decision = Decision::Block;
            v.risk_level = crate::contract::RiskLevel::Critical;
            v.risk_category = hit.category;
            v.explanation = format!("Запрос заблокирован: {}. Такие команды не выполняются ни в одной роли.", hit.detail);
            v.policy_rule = Some(hit.rule.into());
        }
    }
    if let (Some((s, threshold, true)), Ok(_)) = (tf, &det) {
        let cat = crate::policy::category_name(s.category); // Категория по классификатору.
        let skip = crate::rules::backstop_skip(&prompt, !req.context.attachments.is_empty(), !req.context.history.is_empty(), !variants.is_empty(), s.category); // «Объясни», «не меняя ничего», инъекция без вложений.
        if v.decision == Decision::Allow && s.p_attack >= threshold && blockable(s.category) && !skip { // Qwen пропустил, классификатор уверен.
            v.decision = Decision::Block;
            v.risk_level = crate::contract::RiskLevel::High;
            v.risk_category = s.category;
            v.explanation = format!("Классификатор TF-IDF уверенно видит атаку {cat} (p={:.2}), хотя основной детектор её не отметил. Запрос заблокирован как страховка.", s.p_attack);
            v.policy_rule = Some("backstop.tfidf".into());
        }
    }
    let mut signals = Vec::new();
    match &det {
        Ok(d) => signals.push(Signal { source: "model".into(), label: if prefiltered.is_some() { "skipped".into() } else { crate::policy::category_name(d.category).into() }, detail: mask::mask_secrets(&model_reason) }),
        Err(e) => signals.push(Signal { source: "model".into(), label: "error".into(), detail: format!("{e:?}") }),
    }
    if let Some((s, threshold, _)) = tf { signals.push(Signal { source: "tfidf".into(), label: crate::policy::category_name(s.category).into(), detail: format!("p(атака)={:.2}, порог {:.2}", s.p_attack, threshold) }); }
    if let Some(hit) = &rule_hit { signals.push(Signal { source: "rules".into(), label: hit.rule.into(), detail: hit.detail.into() }); }
    if let Some(t) = inferred_tool { signals.push(Signal { source: "rules".into(), label: "rules.tool_from_verb".into(), detail: format!("модель не назвала инструмент, по глаголу просьбы это {t}") }); }
    signals.push(Signal { source: "policy".into(), label: format!("{:?}", v.decision).to_lowercase(), detail: v.policy_rule.clone().unwrap_or_else(|| "нет правила".into()) });
    if !env.evidence.is_empty() { signals.push(Signal { source: "rules".into(), label: "env".into(), detail: env.evidence.clone() }); }
    if !req.context.attachments.is_empty() { signals.push(Signal { source: "attachment".into(), label: "вложения".into(), detail: format!("{} шт. переданы детектору как данные", req.context.attachments.len()) }); }
    if !req.context.history.is_empty() { signals.push(Signal { source: "history".into(), label: "история".into(), detail: format!("реплик передано детектору: {}", req.context.history.len()) }); }
    if let Some(word) = &followup { signals.push(Signal { source: "history".into(), label: "ссылка на секреты".into(), detail: format!("текущая реплика продолжает разговор о «{word}» и просит выдать содержимое") }); }
    let mut explanation = v.explanation;
    if explanation.chars().count() > 1000 { explanation = explanation.chars().take(1000).collect(); } // Далеко от 64 KiB.
    let resp = CheckResponse {
        decision: v.decision, risk_level: v.risk_level, risk_category: v.risk_category, explanation,
        latency_ms: (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        check_id: format!("chk_{}", uuid::Uuid::new_v4().simple()),
        request_hash, tool: v.tool, env: v.env, policy_rule: v.policy_rule, policy_version: policy.version.clone(), signals,
    };
    tracing::info!(check_id = %resp.check_id, role = ?req.context.user_role, decision = ?resp.decision, category = ?resp.risk_category, latency_ms = resp.latency_ms, policy = %resp.policy_version, "check"); // Без текста запроса.
    Ok((resp, req))
}

/// Пишет проверку в журнал. Текст (маскированный) хранится только для запросов из интерфейса;
/// для внешних вызовов /v1/check остаются хеш, решение и метаданные, чтобы закрытый тест не оседал в журнале.
fn journal(state: &AppState, r: &CheckResponse, req: &CheckRequest, source: &str, keep_text: bool) {
    let (prompt_masked, explanation) = if keep_text {
        (mask::mask_secrets(&req.user_prompt), mask::mask_secrets(&r.explanation)) // Демо: текст без значений секретов.
    } else {
        (String::new(), String::new()) // Внешний вызов: ни текста, ни объяснения (модель может цитировать запрос).
    };
    state.store.journal_push(JournalEntry {
        check_id: r.check_id.clone(), ts: now_iso(), user_id: req.context.user_id.clone(), user_role: req.context.user_role,
        decision: r.decision, risk_level: r.risk_level, risk_category: r.risk_category, latency_ms: r.latency_ms,
        policy_version: r.policy_version.clone(), prompt_masked, explanation, source: source.into(),
        request_hash: r.request_hash.clone(), text_stored: keep_text, policy_rule: r.policy_rule.clone(),
    });
}

/// sha256 от JSON {user_prompt, context} с отсортированными ключами и без пробелов, как JSON.stringify на фронте.
pub fn canonical_hash(raw: &Value) -> String {
    use sha2::{Digest, Sha256};
    let subset = json!({"context": raw["context"], "user_prompt": raw["user_prompt"]});
    let text = serde_json::to_string(&subset).unwrap_or_default(); // serde_json без preserve_order сортирует ключи.
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn parse_body(body: &[u8]) -> Result<Value, Response> {
    serde_json::from_slice(body).map_err(|e| error(StatusCode::BAD_REQUEST, "invalid_json", e.to_string()))
}

/// POST /v1/check: только оценка.
async fn check(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let raw = match parse_body(&body) { Ok(v) => v, Err(e) => return e };
    let ui = from_ui(&headers); // Текст сохраняем только для демо из интерфейса.
    match evaluate(&state, raw).await {
        Ok((r, req)) => { journal(&state, &r, &req, if ui { "ui_check" } else { "check" }, ui); Json(r).into_response() }
        Err(e) => e,
    }
}

// ---------- демо-передача агенту ----------

/// Решение → передача заглушке агента, блокировка или ожидание подтверждения.
fn route_to_agent(state: &AppState, check: CheckResponse, req: &CheckRequest, session_id: Option<String>) -> SubmitResponse {
    let receipt = Receipt {
        receipt_id: format!("rcp_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]), check_id: check.check_id.clone(), received_at: now_iso(),
        user_id: req.context.user_id.clone(), user_role: req.context.user_role, decision: check.decision, confirmed: false,
        prompt_masked: mask::mask_secrets(&req.user_prompt),
    };
    match check.decision {
        Decision::Allow => SubmitResponse { status: "forwarded".into(), receipt: Some(state.store.deliver(receipt)), confirmation: None, check },
        Decision::Block => SubmitResponse { status: "blocked".into(), receipt: None, confirmation: None, check },
        Decision::Confirm => {
            let expires = unix_now() + store::CONFIRM_TTL_SECS;
            let confirmation = Confirmation { check_id: check.check_id.clone(), request_hash: check.request_hash.clone(), user_id: req.context.user_id.clone(), expires_at: store::iso_from(expires, 0) };
            state.store.pending_put(Pending { confirmation: confirmation.clone(), expires_unix: expires, used: false, receipt_base: receipt, session_id });
            SubmitResponse { status: "pending_confirmation".into(), receipt: None, confirmation: Some(confirmation), check }
        }
    }
}

/// POST /v1/demo/submit: проверка и, при allow, передача заглушке агента.
async fn demo_submit(State(state): State<Arc<AppState>>, body: axum::body::Bytes) -> Response {
    let raw = match parse_body(&body) { Ok(v) => v, Err(e) => return e };
    match evaluate(&state, raw).await {
        Ok((r, req)) => { journal(&state, &r, &req, "demo", true); Json(route_to_agent(&state, r, &req, None)).into_response() }
        Err(e) => e,
    }
}

/// POST /v1/demo/confirm: одноразовое подтверждение неизменного запроса его автором.
async fn demo_confirm(State(state): State<Arc<AppState>>, Json(body): Json<ConfirmRequest>) -> Response {
    let p = match state.store.pending_take(&body.check_id, &body.request_hash, body.user_id.as_deref()) { Ok(p) => p, Err(e) => return store_error(e) };
    let receipt = state.store.deliver(Receipt { confirmed: true, received_at: now_iso(), ..p.receipt_base });
    if let Some(sid) = p.session_id {
        let text = format!("Агент получил подтверждённый запрос (квитанция {}).", receipt.receipt_id);
        state.store.session_update(&sid, |s| {
            let index = s.turns.len();
            s.turns.push(Turn { index, role: "assistant".into(), content: text, ts: now_iso(), decision: None, check_id: None });
        });
    }
    Json(json!({"status": "forwarded", "receipt": receipt})).into_response()
}

#[derive(Deserialize)]
struct LimitQuery { limit: Option<usize> }

/// GET /v1/agent/inbox: что реально получила заглушка агента.
async fn agent_inbox(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(q): Query<LimitQuery>) -> Response {
    if let Err(e) = require_reader(&state, &headers) { return e; } // Только с токеном.
    Json(json!({"items": state.store.inbox(q.limit.unwrap_or(50).min(500))})).into_response()
}

// ---------- журнал ----------

#[derive(Deserialize)]
struct JournalQuery { since: Option<String>, until: Option<String>, decision: Option<String>, category: Option<String>, role: Option<String>, user_id: Option<String>, limit: Option<usize>, offset: Option<usize> }

/// GET /v1/journal: фильтры по времени, решению, категории и роли.
async fn journal_list(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(q): Query<JournalQuery>) -> Response {
    if let Err(e) = require_reader(&state, &headers) { return e; } // Только с токеном.
    let since = q.since.filter(|s| !s.is_empty());
    let until = q.until.filter(|s| !s.is_empty());
    let (items, total) = state.store.journal_query(|e| {
        since.as_deref().is_none_or(|s| e.ts.as_str() >= s)
            && until.as_deref().is_none_or(|u| e.ts.as_str() <= u)
            && q.decision.as_deref().is_none_or(|d| d.is_empty() || json_name(&e.decision) == d)
            && q.category.as_deref().is_none_or(|c| c.is_empty() || json_name(&e.risk_category) == c)
            && q.role.as_deref().is_none_or(|r| r.is_empty() || json_name(&e.user_role) == r)
            && q.user_id.as_deref().is_none_or(|u| u.is_empty() || e.user_id.as_deref() == Some(u)) // Фильтр по пользователю.
    }, q.offset.unwrap_or(0), q.limit.unwrap_or(50).min(500));
    Json(json!({"items": items, "total": total})).into_response()
}

/// GET /v1/users/{user_id}/history: история запросов пользователя для аудитора.
/// Только чтение журнала: на решения /v1/check история пользователя не влияет (проверки по кейсу независимы).
async fn user_history(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(user_id): Path<String>, Query(q): Query<JournalQuery>) -> Response {
    if let Err(e) = require_reader(&state, &headers) { return e; } // Только с токеном.
    let (all, total) = state.store.journal_query(|e| e.user_id.as_deref() == Some(user_id.as_str()), 0, usize::MAX); // Все записи пользователя, свежие первыми.
    let mut by_decision: std::collections::BTreeMap<String, usize> = Default::default(); // Сколько allow/confirm/block.
    let mut by_category: std::collections::BTreeMap<String, usize> = Default::default(); // Категории атак.
    for e in &all {
        *by_decision.entry(json_name(&e.decision)).or_default() += 1;
        if e.risk_category != crate::contract::RiskCategory::None && e.risk_category != crate::contract::RiskCategory::SensitiveAction { *by_category.entry(json_name(&e.risk_category)).or_default() += 1; }
    }
    let hour_ago = store::iso_from(unix_now().saturating_sub(3600), 0); // Граница последнего часа.
    let blocks_last_hour = all.iter().filter(|e| e.decision == Decision::Block && e.ts.as_str() >= hour_ago.as_str()).count(); // Недавние блокировки.
    let items: Vec<_> = all.into_iter().skip(q.offset.unwrap_or(0)).take(q.limit.unwrap_or(50).min(500)).collect(); // Страница истории.
    Json(json!({"user_id": user_id, "total": total, "by_decision": by_decision, "attack_categories": by_category,
        "blocks_last_hour": blocks_last_hour, "items": items})).into_response()
}

/// Имя enum так, как оно выглядит в JSON (snake_case).
fn json_name<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|x| x.as_str().map(str::to_owned)).unwrap_or_default()
}

// ---------- политика ----------

/// GET /v1/policy: действующая политика, версия, автор и время.
async fn get_policy(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = require_reader(&state, &headers) { return e; } // Только с токеном.
    let p = state.policy.load();
    let meta = state.store.policy_current();
    Json(json!({
        "version": p.version, "yaml": p.raw,
        "updated_at": meta.as_ref().map(|m| m.updated_at.clone()),
        "updated_by": meta.as_ref().map(|m| m.updated_by.clone()),
        "comment": meta.as_ref().map(|m| m.comment.clone()).unwrap_or_default(),
    })).into_response()
}

/// GET /v1/policy/history: версии, новые сверху.
async fn policy_history(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = require_reader(&state, &headers) { return e; } // Только с токеном.
    Json(json!({"items": state.store.policy_history()})).into_response()
}

#[derive(Deserialize)]
struct PolicyBody { yaml: Option<String>, comment: Option<String> }

/// POST /v1/policy/validate: проверка без применения, с токеном админа или аудитора.
async fn validate_policy(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<PolicyBody>) -> Response {
    if let Err(e) = require_reader(&state, &headers) { return e; } // Только с токеном.
    match Policy::parse(body.yaml.as_deref().unwrap_or("")) {
        Ok(_) => Json(json!({"valid": true, "errors": []})).into_response(),
        Err(errors) => Json(json!({"valid": false, "errors": errors})).into_response(),
    }
}

/// PUT /v1/policy: валидирует, сохраняет в файл и применяет (только админ).
async fn put_policy(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if let Err(e) = require_admin(&state, &headers) { return e; } // Сначала права, потом разбор тела.
    let body: PolicyBody = match serde_json::from_slice(&body) { Ok(b) => b, Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_json", e.to_string()) };
    let Some(raw) = body.yaml.as_deref() else { return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_policy", "Нет поля yaml") };
    match Policy::parse(raw) {
        Ok(p) => {
            if let Err(e) = std::fs::write(&state.policy_path, raw) { return error(StatusCode::INTERNAL_SERVER_ERROR, "policy_write_failed", e.to_string()); }
            let info = PolicyVersionInfo { version: p.version.clone(), updated_at: now_iso(), updated_by: "policy-admin".into(), comment: body.comment.unwrap_or_default() };
            state.policy.store(Arc::new(p));
            state.store.policy_record(info.clone());
            tracing::info!(version = %info.version, by = %info.updated_by, comment = %info.comment, "policy updated");
            Json(json!({"version": info.version, "updated_at": info.updated_at, "updated_by": info.updated_by})).into_response()
        }
        Err(errors) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "invalid_policy", "detail": "Политика не прошла проверку", "errors": errors}))).into_response(),
    }
}

/// POST /v1/policy/reload: перечитывает файл политики с диска (только админ).
async fn reload_policy(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = require_admin(&state, &headers) { return e; }
    match reload_from_disk(&state) {
        Ok(version) => Json(json!({"version": version})).into_response(),
        Err(errors) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "invalid_policy", "detail": "Файл политики невалиден, действует прежняя версия", "errors": errors}))).into_response(),
    }
}

/// Читает файл политики и применяет его, если он валиден и изменился.
pub fn reload_from_disk(state: &AppState) -> Result<String, Vec<String>> {
    let raw = std::fs::read_to_string(&state.policy_path).map_err(|e| vec![e.to_string()])?;
    let p = Policy::parse(&raw)?;
    let version = p.version.clone();
    if version != state.policy.load().version {
        state.policy.store(Arc::new(p));
        state.store.policy_record(PolicyVersionInfo { version: version.clone(), updated_at: now_iso(), updated_by: "файл на диске".into(), comment: "изменение security_policy.yaml".into() });
        tracing::info!(%version, "policy reloaded");
    }
    Ok(version)
}

// ---------- сессии ----------

#[derive(Deserialize)]
struct NewSession { user_id: String, #[serde(default)] user_name: String, user_role: Role, #[serde(default)] system_prompt: String }

#[derive(Deserialize)]
struct UserQuery { user_id: Option<String> }

#[derive(Deserialize)]
struct NewMessage { user_id: String, user_prompt: String, #[serde(default)] attachments: Vec<Value> }

fn session_summary(s: &Session) -> Value {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("turns");
        o.insert("turn_count".into(), json!(s.turns.iter().filter(|t| t.role == "user").count()));
    }
    v
}

/// POST /v1/sessions.
async fn session_create(State(state): State<Arc<AppState>>, Json(b): Json<NewSession>) -> Response {
    if b.user_id.trim().is_empty() { return error(StatusCode::BAD_REQUEST, "invalid_input", "Нужен user_id"); }
    let now = unix_now();
    let expires = now + store::SESSION_TTL_MINUTES * 60;
    let s = Session {
        session_id: format!("ses_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]), user_id: b.user_id, user_name: b.user_name, user_role: b.user_role,
        system_prompt: b.system_prompt, created_at: now_iso(), expires_at: store::iso_from(expires, 0), expires_unix: expires,
        limits: SessionLimits { max_turns: store::SESSION_MAX_TURNS, ttl_minutes: store::SESSION_TTL_MINUTES }, turns: Vec::new(),
    };
    state.store.session_put(s.clone());
    Json(s).into_response()
}

/// GET /v1/sessions?user_id=: только свои сессии.
async fn session_list(State(state): State<Arc<AppState>>, Query(q): Query<UserQuery>) -> Json<Value> {
    let items: Vec<Value> = q.user_id.as_deref().map(|u| state.store.sessions_of(u).iter().map(session_summary).collect()).unwrap_or_default();
    Json(json!({"items": items}))
}

/// GET /v1/sessions/{id}?user_id=.
async fn session_get(State(state): State<Arc<AppState>>, Path(id): Path<String>, Query(q): Query<UserQuery>) -> Response {
    match state.store.session_get(&id, q.user_id.as_deref().unwrap_or("")) { Ok(s) => Json(s).into_response(), Err(e) => store_error(e) }
}

/// DELETE /v1/sessions/{id}?user_id=.
async fn session_delete(State(state): State<Arc<AppState>>, Path(id): Path<String>, Query(q): Query<UserQuery>) -> Response {
    match state.store.session_delete(&id, q.user_id.as_deref().unwrap_or("")) { Ok(()) => Json(json!({"deleted": true})).into_response(), Err(e) => store_error(e) }
}

/// POST /v1/sessions/{id}/messages: история сессии становится context.history.
async fn session_message(State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(b): Json<NewMessage>) -> Response {
    let s = match state.store.session_get(&id, &b.user_id) { Ok(s) => s, Err(e) => return store_error(e) };
    let user_turns = s.turns.iter().filter(|t| t.role == "user").count();
    if user_turns >= s.limits.max_turns { return error(StatusCode::CONFLICT, "session_full", format!("Лимит {} реплик исчерпан — очистите или создайте сессию", s.limits.max_turns)); }
    let history: Vec<Value> = s.turns.iter().map(|t| json!({"role": t.role, "content": t.content})).collect();
    let raw = json!({"user_prompt": b.user_prompt, "context": {
        "target_agent": "it_ops_agent", "user_role": s.user_role, "user_id": s.user_id, "user_name": s.user_name,
        "system_prompt": s.system_prompt, "history": history, "attachments": b.attachments,
    }});
    let (r, req) = match evaluate(&state, raw).await { Ok(x) => x, Err(e) => return e };
    journal(&state, &r, &req, "session", true);
    let flagged: Vec<FlaggedTurn> = s.turns.iter().filter(|t| t.role == "user" && t.decision == Some(Decision::Block)).map(|t| FlaggedTurn { turn: t.index, reason: "заблокирована ранее".into() }).collect();
    let nums = flagged.iter().map(|f| format!("№{}", f.turn + 1)).collect::<Vec<_>>().join(", ");
    let note = if s.turns.is_empty() {
        "Это первая реплика сессии — истории нет.".to_string()
    } else if !flagged.is_empty() && r.decision == Decision::Block {
        format!("В истории есть заблокированные реплики ({nums}). Текущий запрос оценён вместе с ними и тоже заблокирован.")
    } else if !flagged.is_empty() {
        format!("В истории есть заблокированные реплики ({nums}): агенту они не передавались. Текущий запрос оценён вместе с историей и признан допустимым.")
    } else {
        format!("Детектор получил запрос вместе с историей (реплик: {}); решение учитывает весь диалог.", s.turns.len())
    };
    let effect = HistoryEffect { turns_considered: s.turns.len(), flagged, note };
    let check_id = r.check_id.clone();
    let decision = r.decision;
    let sub = route_to_agent(&state, r, &req, Some(id.clone()));
    let receipt_id = sub.receipt.as_ref().map(|x| x.receipt_id.clone());
    state.store.session_update(&id, |s| {
        let index = s.turns.len();
        s.turns.push(Turn { index, role: "user".into(), content: b.user_prompt.clone(), ts: now_iso(), decision: Some(decision), check_id: Some(check_id) });
        if let Some(rid) = receipt_id {
            let index = s.turns.len();
            s.turns.push(Turn { index, role: "assistant".into(), content: format!("Агент получил запрос (квитанция {rid})."), ts: now_iso(), decision: None, check_id: None });
        }
    });
    let session = match state.store.session_get(&id, &b.user_id) { Ok(s) => s, Err(e) => return store_error(e) };
    let mut v = serde_json::to_value(&sub).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("history_effect".into(), serde_json::to_value(&effect).unwrap_or_default());
        o.insert("session".into(), serde_json::to_value(&session).unwrap_or_default());
    }
    Json(v).into_response()
}

// ---------- служебное ----------

/// GET /health: готовность модели и версия политики.
async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({"status": "ok", "mode": std::env::var("GUARD_MODE").unwrap_or_else(|_| "gpu".into()), "model": state.detector.cfg.model, "num_ctx": crate::detector::num_ctx(), "policy_version": state.policy.load().version}))
}

/// Собирает роутер со всеми маршрутами.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/check", post(check))
        .route("/health", get(health))
        .route("/v1/demo/submit", post(demo_submit))
        .route("/v1/demo/confirm", post(demo_confirm))
        .route("/v1/agent/inbox", get(agent_inbox))
        .route("/v1/journal", get(journal_list))
        .route("/v1/users/{user_id}/history", get(user_history))
        .route("/v1/policy", get(get_policy).put(put_policy))
        .route("/v1/policy/validate", post(validate_policy))
        .route("/v1/policy/history", get(policy_history))
        .route("/v1/policy/reload", post(reload_policy))
        .route("/v1/sessions", post(session_create).get(session_list))
        .route("/v1/sessions/{id}", get(session_get).delete(session_delete))
        .route("/v1/sessions/{id}/messages", post(session_message))
        .fallback(web::static_files)
        .layer(axum::middleware::from_fn_with_state(state.clone(), web::cors))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // Тело не больше 1 MiB, как в starter_api.py.
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #[test] // request_hash совпадает с хешем, который считает фронт через JSON.stringify с сортировкой ключей.
    fn request_hash_matches_frontend() {
        let raw = serde_json::json!({"user_prompt": "Перезапусти payments-api / \"prod\"", "context": {"user_role": "sre", "history": [{"role": "user", "content": "привет"}], "attachments": []}});
        assert_eq!(super::canonical_hash(&raw), "1ae38b7290194dab576a4445048a7be2de0a07ad181c75e29e7369dc275edb22");
    }

    #[test] // Сравнение токенов: равные совпадают, разные и разной длины нет.
    fn token_compare() {
        assert!(super::token_eq("abc123", "abc123")); // Совпадение.
        assert!(!super::token_eq("abc123", "abc124")); // Последний символ другой.
        assert!(!super::token_eq("abc", "abc123")); // Разная длина.
    }

    #[test] // Признак интерфейса: только заголовок X-Guard-Client: ui.
    fn ui_header() {
        let mut h = axum::http::HeaderMap::new(); // Пустые заголовки — внешний клиент.
        assert!(!super::from_ui(&h)); // Без заголовка текст не хранится.
        h.insert("x-guard-client", "UI".parse().unwrap()); // Регистр не важен.
        assert!(super::from_ui(&h)); // Интерфейс.
    }
}
