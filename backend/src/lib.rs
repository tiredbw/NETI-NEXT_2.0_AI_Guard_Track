//! AstraGuard: сторож для it_ops_agent на Rust/Axum.

pub mod contract; // JSON-контракт.
pub mod envdetect; // Окружение по тексту.
pub mod mask; // Маскирование секретов.
pub mod normalize; // Нормализация текста.
pub mod policy; // YAML-политика.
