//! Точка входа: читает настройки, загружает политику, прогревает модель и запускает сервер.

use arc_swap::ArcSwap; // Атомарная ссылка на политику.
use astraguard::app::{reload_from_disk, router, AppState}; // HTTP-слой.
use astraguard::detector::{Detector, OllamaConfig}; // Клиент Qwen.
use astraguard::policy::Policy; // Политика.
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
    let state = Arc::new(AppState { // Общее состояние.
        policy: ArcSwap::from_pointee(policy), // Начальная политика.
        policy_path: policy_path.into(), // Файл для перезагрузки.
        detector: detector.clone(), // Детектор.
        admin_token: std::env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty()), // Токен админа из окружения.
    });
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
