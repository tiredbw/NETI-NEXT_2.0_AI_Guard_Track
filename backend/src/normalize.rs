//! Нормализация текста перед моделью. Сейчас минимальная; полную (leetspeak, base64, гомоглифы, перевёрнутый текст) добавит Бэк-1.

/// Убирает невидимые символы и схлопывает пробелы.
pub fn normalize(text: &str) -> String {
    let cleaned: String = text.chars().filter(|c| !matches!(c, '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}')).collect(); // Невидимые и мягкие переносы.
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ") // Одиночные пробелы.
}
