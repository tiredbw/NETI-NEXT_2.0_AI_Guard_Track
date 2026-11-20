//! AstraGuard: сторож для it_ops_agent на Rust/Axum.

pub mod app; // HTTP-слой.
pub mod contract; // JSON-контракт.
pub mod decide; // Сведение решения.
pub mod detector; // Клиент Qwen через Ollama.
pub mod envdetect; // Окружение по тексту.
pub mod history; // Опасные просьбы, разбитые на несколько реплик.
pub mod mask; // Маскирование секретов.
pub mod normalize; // Нормализация текста.
pub mod policy; // YAML-политика.
pub mod rules; // Детерминированные правила-страховка.
pub mod tfidf; // TF-IDF-классификатор: второй сигнал и страховка.
pub mod store; // Журнал, входящие агента, подтверждения, сессии.
pub mod web; // Раздача фронтенда и CORS.
