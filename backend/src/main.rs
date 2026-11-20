//! Точка входа: читает настройки, загружает политику, прогревает модель и запускает сервер.

use arc_swap::ArcSwap; // Атомарная ссылка на политику.
use astraguard::app::{reload_from_disk, router, AppState}; // HTTP-слой.
use astraguard::detector::{Detector, OllamaConfig}; // Клиент Qwen.
use astraguard::contract::PolicyVersionInfo; // Запись истории политики.
use astraguard::policy::Policy; // Политика.
use astraguard::store::{now_iso, Store}; // Хранилище демо и время.
use std::path::PathBuf; // Пути к фронтенду и журналу.
use std::sync::Arc; // Общее состояние.
use std::time::Duration; // Период слежения за файлом.

#[tokio::main] // Асинхронный рантайм tokio.
async fn main() {
    tracing_subscriber::fmt().with_target(false).init(); // Логи в stdout.
    let policy_path = std::env::var("POLICY_PATH").unwrap_or_else(|_| "../policies/security_policy.yaml".into()); // Путь к YAML.
    let raw = std::fs::read_to_string(&policy_path).unwrap_or_else(|e| panic!("не читается {policy_path}: {e}")); // Читаем файл.
    let policy = Policy::parse(&raw).unwrap_or_else(|e| panic!("политика невалидна: {e:?}")); // Без валидной политики не стартуем.
    tracing::info!(version = %policy.version, "policy loaded"); // Версия в лог.
    let detector = Detector::new(OllamaConfig::from_env()); // Клиент Ollama.
    let frontend_dir = std::env::var("FRONTEND_DIR").unwrap_or_else(|_| "../frontend".into()); // Фронтенд раздаётся с того же origin.
    let frontend_dir = Some(PathBuf::from(frontend_dir)).filter(|p| p.join("index.html").is_file()); // Нет index.html — только API.
    tracing::info!(frontend = ?frontend_dir, "static frontend");
    let journal_path = std::env::var("JOURNAL_PATH").unwrap_or_else(|_| "../data/journal.jsonl".into()); // Журнал проверок в JSONL; пусто — только память.
    let journal_path = Some(PathBuf::from(journal_path)).filter(|p| !p.as_os_str().is_empty());
    let cors_origins: Vec<String> = std::env::var("CORS_ORIGINS").unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".into())
        .split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(); // Только для отдельного dev-сервера фронта.
    let state = Arc::new(AppState { // Общее состояние.
        policy: ArcSwap::from_pointee(policy), // Начальная политика.
        policy_path: policy_path.into(), // Файл для перезагрузки.
        detector: detector.clone(), // Детектор.
        admin_token: std::env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty()), // Токен админа из окружения.
        audit_token: std::env::var("AUDIT_TOKEN").ok().filter(|t| !t.is_empty()), // Токен аудитора: только чтение.
        store: Store::new(journal_path), // Журнал, входящие агента, подтверждения, сессии.
        frontend_dir, // Каталог фронтенда; None — сервис отдаёт только API.
        cors_origins, // Origin отдельного dev-сервера фронта.
    });
    state.store.policy_record(PolicyVersionInfo { version: state.policy.load().version.clone(), updated_at: now_iso(), updated_by: "файл при запуске".into(), comment: state.policy_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default() }); // Первая версия в истории; без полного пути на диске.
    let watcher = state.clone(); // Копия для фоновой задачи.
    tokio::spawn(async move { // Слежение за файлом политики раз в секунду.
        loop { // Бесконечный цикл.
            tokio::time::sleep(Duration::from_secs(1)).await; // Пауза.
            if let Err(e) = reload_from_disk(&watcher) { tracing::warn!(?e, "policy file invalid, keeping previous"); } // Невалидный файл не ломает сервис.
        }
    });
    let ok = detector.warmup().await; // Загружаем модель в память до первого запроса.
    tracing::info!(model = %detector.cfg.model, ready = ok, "detector warmup"); // Готовность модели.
    let addr = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8000".into()); // Адрес сервера.
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind"); // Открываем порт.
    tracing::info!(%addr, "listening"); // Адрес в лог.
    axum::serve(listener, router(state)).await.expect("server"); // Запускаем сервер.
}
