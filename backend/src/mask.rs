//! Маскирование секретов в журнале и объяснениях.

use regex::Regex; // Регулярные выражения.
use std::sync::LazyLock; // Компилируем один раз.

static KV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(password|passwd|pwd|пароль|token|токен|secret|секрет|api[_-]?key|ключ)(\s*[:=]\s*|\s+)("[^"]*"|\S+)"#).unwrap()); // Пары «ключ: значение».
static LONG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:[A-Za-z0-9+/_\-]{32,}={0,2}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b").unwrap()); // Длинные токены и известные форматы ключей.

/// Заменяет значения секретов на ***.
pub fn mask_secrets(text: &str) -> String {
    let step = KV.replace_all(text, "$1$2***"); // Значения после ключевых слов.
    LONG.replace_all(&step, "***").into_owned() // Длинные похожие на ключ строки.
}

#[cfg(test)] // Тесты модуля.
mod tests {
    #[test] // Пароль и токен скрываются.
    fn masks() {
        let m = super::mask_secrets("пароль: hunter2 и token=ghp_abcdefghijklmnopqrstuvwxyz123456"); // Строка с секретами.
        assert!(!m.contains("hunter2") && !m.contains("ghp_")); // Значений не осталось.
    }
}
